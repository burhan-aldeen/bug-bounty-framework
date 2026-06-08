import asyncio
import logging
import re
import tempfile
from pathlib import Path

from core.logger import get_logger
from core.models import AliveHost, SecretFinding, SecretType, Severity

logger = get_logger("stages.secrets")

logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)

SENSITIVE_PATHS: list[tuple[str, SecretType, Severity]] = [
    ("/.git/config", SecretType.GIT_EXPOSED, Severity.CRITICAL),
    ("/.env", SecretType.ENV_EXPOSED, Severity.CRITICAL),
    ("/phpinfo.php", SecretType.CONFIG_EXPOSED, Severity.HIGH),
    ("/info.php", SecretType.CONFIG_EXPOSED, Severity.HIGH),
    ("/wp-config.php.bak", SecretType.CONFIG_EXPOSED, Severity.HIGH),
    ("/config.json", SecretType.CONFIG_EXPOSED, Severity.HIGH),
    ("/backup.sql", SecretType.CONFIG_EXPOSED, Severity.CRITICAL),
    ("/dump.sql", SecretType.CONFIG_EXPOSED, Severity.CRITICAL),
    ("/swagger.json", SecretType.CONFIG_EXPOSED, Severity.MEDIUM),
    ("/api-docs", SecretType.CONFIG_EXPOSED, Severity.MEDIUM),
    ("/.aws/credentials", SecretType.CONFIG_EXPOSED, Severity.CRITICAL),
    ("/.azure/credentials", SecretType.CONFIG_EXPOSED, Severity.CRITICAL),
    ("/.npmrc", SecretType.CONFIG_EXPOSED, Severity.MEDIUM),
    ("/.pypirc", SecretType.CONFIG_EXPOSED, Severity.MEDIUM),
    ("/health", SecretType.DEBUG_ENDPOINT, Severity.LOW),
    ("/metrics", SecretType.DEBUG_ENDPOINT, Severity.MEDIUM),
    ("/actuator", SecretType.DEBUG_ENDPOINT, Severity.MEDIUM),
    ("/actuator/env", SecretType.DEBUG_ENDPOINT, Severity.HIGH),
    ("/debug", SecretType.DEBUG_ENDPOINT, Severity.MEDIUM),
    ("/console", SecretType.DEBUG_ENDPOINT, Severity.HIGH),
    ("/server-status", SecretType.DEBUG_ENDPOINT, Severity.MEDIUM),
    ("/crossdomain.xml", SecretType.CONFIG_EXPOSED, Severity.LOW),
    ("/client-access-policy.xml", SecretType.CONFIG_EXPOSED, Severity.LOW),
    ("/.htaccess", SecretType.CONFIG_EXPOSED, Severity.MEDIUM),
    ("/.htpasswd", SecretType.CONFIG_EXPOSED, Severity.HIGH),
    ("/robots.txt", SecretType.CONFIG_EXPOSED, Severity.LOW),
    ("/sitemap.xml", SecretType.CONFIG_EXPOSED, Severity.LOW),
]

JS_SECRET_PATTERNS: list[re.Pattern] = [
    re.compile(r'["\'](?:api[_-]?key|apikey|api_key)["\']\s*[:=]\s*["\'][^"\']+["\']', re.I),
    re.compile(r'["\'](?:secret|token|password|auth)["\']\s*[:=]\s*["\'][^"\']+["\']', re.I),
    re.compile(r'["\'](?:aws_access_key_id|aws_secret_access_key|AZURE_)["\']', re.I),
    re.compile(r'(?:sk-[a-zA-Z0-9]{20,}|pk-[a-zA-Z0-9]{20,})'),
    re.compile(r'(?:ghp_[a-zA-Z0-9]{36,}|github_pat_[a-zA-Z0-9]{36,})'),
    re.compile(r'(?:firebase|stripe|sentry_dsn|slack_token)', re.I),
]


async def run(hosts: list[AliveHost], all_urls: list[str], output_dir: Path | None = None) -> list[SecretFinding]:
    logger.info("secrets: hosts=%d urls=%d", len(hosts), len(all_urls))
    secrets: list[SecretFinding] = []

    # Phase 3: JS Secrets
    js_secrets = await _check_js_files(all_urls, output_dir)
    secrets.extend(js_secrets)

    # Phase 4: Exposed Paths
    exposed = await _check_exposed_paths(hosts)
    secrets.extend(exposed)

    logger.info("secrets: %d total secrets found", len(secrets))
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
        async def probe(url: str, path: str, st: SecretType, sev: Severity) -> SecretFinding | None:
            async with sem:
                try:
                    response = await client.get(url)
                    if response.status_code in (200, 401, 403):
                        return SecretFinding(
                            url=url,
                            secret_type=st,
                            match=f"HTTP {response.status_code} — {len(response.content)} bytes",
                            severity=sev,
                            detail=f"Exposed: {path}",
                        )
                except Exception:
                    pass
            return None

        tasks = []
        total = len(hosts) * len(SENSITIVE_PATHS)
        logger.info("secrets: probing %d paths across %d hosts", total, len(hosts))
        for host in hosts:
            base = host.url.rstrip("/")
            for path, st, sev in SENSITIVE_PATHS:
                tasks.append(probe(f"{base}{path}", path, st, sev))

        batch_size = 100
        for i in range(0, len(tasks), batch_size):
            batch = tasks[i:i + batch_size]
            results = await asyncio.gather(*batch)
            secrets.extend(r for r in results if r is not None)
            logger.info("secrets: %d/%d paths checked, %d found",
                        min(i + batch_size, len(tasks)), total, len(secrets))

    logger.info("secrets: %d exposed paths found", len(secrets))
    return secrets


async def _check_js_files(all_urls: list[str], output_dir: Path | None = None) -> list[SecretFinding]:
    js_urls = [u for u in all_urls if u.endswith(".js")]
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
                    for pattern in JS_SECRET_PATTERNS:
                        for match in pattern.finditer(body):
                            found.append(
                                SecretFinding(
                                    url=js_url,
                                    secret_type=SecretType.JS_SECRET,
                                    match=match.group(0)[:100],
                                    severity=Severity.CRITICAL,
                                    detail="Hardcoded credential in JS file",
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
