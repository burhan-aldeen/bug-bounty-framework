import asyncio
import logging
import re

from core.logger import get_logger
from core.models import AliveHost, SecretFinding, SecretType, Severity

logger = get_logger("stages.secrets")

logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)

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
    try:
        import httpx
    except ImportError:
        logger.warning("httpx not installed, skipping exposed path checks")
        return []

    sem = asyncio.Semaphore(50)
    secrets: list[SecretFinding] = []

    async with httpx.AsyncClient(timeout=10.0, verify=False) as client:

        async def probe(url: str, path: str) -> SecretFinding | None:
            async with sem:
                try:
                    response = await client.get(url)
                    if response.status_code in (200, 401, 403):
                        return SecretFinding(
                            url=url,
                            secret_type=SecretType.CONFIG_EXPOSED,
                            match=f"HTTP {response.status_code} — file accessible",
                            severity=Severity.CRITICAL if path in ("/.env", "/.git/config")
                            else Severity.HIGH,
                        )
                except Exception:
                    pass
            return None

        tasks = []
        total = len(hosts) * len(SECRET_PATHS)
        logger.info("secrets: probing %d paths across %d hosts", total, len(hosts))
        for host in hosts:
            base = host.url.rstrip("/")
            for path in SECRET_PATHS:
                tasks.append(probe(f"{base}{path}", path))

        batch_size = 100
        for i in range(0, len(tasks), batch_size):
            batch = tasks[i:i + batch_size]
            results = await asyncio.gather(*batch)
            secrets.extend(r for r in results if r is not None)
            logger.info("secrets: %d/%d paths checked, %d found", min(i + batch_size, len(tasks)), total, len(secrets))

    logger.info("secrets: %d exposed paths found", len(secrets))
    return secrets


async def _check_js_files(urls: list[str]) -> list[SecretFinding]:
    js_urls = [u for u in urls if u.endswith(".js")]
    if not js_urls:
        return []

    try:
        import httpx
    except ImportError:
        logger.warning("httpx not installed, skipping JS analysis")
        return []

    sem = asyncio.Semaphore(20)
    secrets: list[SecretFinding] = []

    async with httpx.AsyncClient(timeout=10.0, verify=False) as client:

        async def scan_js(js_url: str) -> list[SecretFinding]:
            async with sem:
                try:
                    response = await client.get(js_url)
                    if response.status_code != 200:
                        return []
                    body = response.text
                    found = []
                    for pattern in JS_KEY_PATTERNS:
                        for match in pattern.finditer(body):
                            found.append(
                                SecretFinding(
                                    url=js_url,
                                    secret_type=SecretType.JS_SECRET,
                                    match=match.group(0)[:100],
                                    severity=Severity.CRITICAL,
                                    detail="Hardcoded credential found in JavaScript file",
                                )
                            )
                    return found
                except Exception:
                    return []

        scanned = min(len(js_urls), 50)
        tasks = [scan_js(u) for u in js_urls[:scanned]]
        results = await asyncio.gather(*tasks)
        for r in results:
            secrets.extend(r)

    logger.info("secrets: %d JS files scanned, %d secrets found", scanned, len(secrets))
    return secrets
