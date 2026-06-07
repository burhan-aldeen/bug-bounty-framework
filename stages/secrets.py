import re

from core.logger import get_logger
from core.models import AliveHost, SecretFinding, SecretType, Severity

logger = get_logger("stages.secrets")

SECRET_PATHS: list[str] = [
    "/.env", "/.git/config", "/.git/HEAD",
    "/phpinfo.php", "/info.php",
    "/wp-config.php.bak", "/config.json",
    "/backup.sql", "/dump.sql",
    "/robots.txt", "/sitemap.xml",
    "/crossdomain.xml", "/client-access-policy.xml",
    "/.htaccess", "/.htpasswd",
    "/swagger.json", "/api-docs",
    "/.aws/credentials", "/.azure/credentials",
    "/.npmrc", "/.pypirc",
]

JS_KEY_PATTERNS: list[re.Pattern] = [
    re.compile(r'["\'](?:api[_-]?key|apikey|api_key)["\']\s*[:=]\s*["\'][^"\']+["\']', re.I),
    re.compile(r'["\'](?:secret|token|password|auth)["\']\s*[:=]\s*["\'][^"\']+["\']', re.I),
    re.compile(r'["\'](?:aws_access_key_id|aws_secret_access_key|AZURE_)["\']', re.I),
    re.compile(r'(?:sk-[a-zA-Z0-9]{20,}|pk-[a-zA-Z0-9]{20,})'),
    re.compile(r'(?:ghp_[a-zA-Z0-9]{36,}|github_pat_[a-zA-Z0-9]{36,})'),
]


async def run(hosts: list[AliveHost], urls: list[str]) -> list[SecretFinding]:
    logger.info("stage=secrets hosts=%d urls=%d", len(hosts), len(urls))
    secrets: list[SecretFinding] = []

    exposed = await _check_exposed_paths(hosts)
    secrets.extend(exposed)

    js_secrets = await _check_js_files(urls)
    secrets.extend(js_secrets)

    logger.info("stage=secrets done secrets=%d", len(secrets))
    return secrets


async def _check_exposed_paths(hosts: list[AliveHost]) -> list[SecretFinding]:
    secrets: list[SecretFinding] = []
    try:
        import httpx
        client = httpx.AsyncClient(timeout=10.0, verify=False)
    except ImportError:
        logger.warning("httpx not installed, skipping exposed path checks")
        return secrets

    async with client:
        for host in hosts:
            base_url = host.url.rstrip("/")
            for path in SECRET_PATHS:
                try:
                    response = await client.get(f"{base_url}{path}")
                    code = response.status_code
                    if code in (200, 401, 403):
                        secrets.append(
                            SecretFinding(
                                url=f"{base_url}{path}",
                                secret_type=SecretType.CONFIG_EXPOSED,
                                match=f"HTTP {code} — file accessible",
                                severity=Severity.CRITICAL if path in ("/.env", "/.git/config")
                                else Severity.HIGH,
                            )
                        )
                except Exception as exc:
                    logger.debug("failed to probe %s%s: %s", base_url, path, exc)
    return secrets


async def _check_js_files(urls: list[str]) -> list[SecretFinding]:
    secrets: list[SecretFinding] = []
    js_urls = [u for u in urls if u.endswith(".js")]
    if not js_urls:
        return secrets

    try:
        import httpx
        client = httpx.AsyncClient(timeout=10.0, verify=False)
    except ImportError:
        logger.warning("httpx not installed, skipping JS analysis")
        return secrets

    async with client:
        for js_url in js_urls[:20]:
            try:
                response = await client.get(js_url)
                if response.status_code != 200:
                    continue
                body = response.text
                for pattern in JS_KEY_PATTERNS:
                    for match in pattern.finditer(body):
                        secrets.append(
                            SecretFinding(
                                url=js_url,
                                secret_type=SecretType.JS_SECRET,
                                match=match.group(0)[:100],
                                severity=Severity.CRITICAL,
                                detail="Hardcoded credential found in JavaScript file",
                            )
                        )
            except Exception as exc:
                logger.debug("failed to fetch JS %s: %s", js_url, exc)

    return secrets
