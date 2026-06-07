import asyncio

from core.logger import get_logger
from core.models import AliveHost, ScanResult, Subdomain
from tools import subfinder, httpx_tool, gau, katana, gospider

logger = get_logger("stages.recon")


async def run(domain: str) -> ScanResult:
    result = ScanResult(target=domain)
    logger.info("stage=recon target=%s", domain)

    subdomains = await _enumerate_subdomains(domain)
    result.subdomains = subdomains

    if subdomains:
        domains = list(dict.fromkeys(s.domain for s in subdomains))
        result.alive_hosts = await _check_alive(domains)
    else:
        logger.warning("recon: no subdomains found, trying root domain")
        result.alive_hosts = await _check_alive([domain])

    result.urls = await _collect_urls(domain, result.alive_hosts)

    logger.info(
        "stage=recon done subdomains=%d alive=%d urls=%d",
        len(result.subdomains),
        len(result.alive_hosts),
        len(result.urls),
    )
    return result


async def enumerate_subdomains(domain: str) -> list[Subdomain]:
    logger.debug("recon/enum: %s", domain)
    return await _enumerate_subdomains(domain)


async def check_alive(domains: list[str]) -> list[AliveHost]:
    logger.debug("recon/alive: %d hosts", len(domains))
    return await _check_alive(domains)


async def collect_urls(domain: str, hosts: list[AliveHost]) -> list[str]:
    logger.debug("recon/urls: %s (%d hosts)", domain, len(hosts))
    return await _collect_urls(domain, hosts)


async def _enumerate_subdomains(domain: str) -> list[Subdomain]:
    tasks = []
    for tool_fn in [subfinder.run]:
        tasks.append(_safe_run(tool_fn, domain))

    results = await asyncio.gather(*tasks, return_exceptions=True)
    all_subdomains: list[Subdomain] = []
    seen: set[str] = set()

    for r in results:
        if isinstance(r, list):
            for s in r:
                if s.domain not in seen:
                    seen.add(s.domain)
                    all_subdomains.append(s)

    all_subdomains.sort(key=lambda x: x.domain)
    return all_subdomains


async def _check_alive(domains: list[str]) -> list[AliveHost]:
    try:
        return await httpx_tool.run(domains)
    except FileNotFoundError:
        logger.warning("httpx not installed, skipping alive check")
        return []


async def _collect_urls(domain: str, hosts: list[AliveHost]) -> list[str]:
    urls: list[str] = []
    seen: set[str] = set()

    host_urls = [h.url for h in hosts if h.url]

    tool_tasks = []

    try:
        gau_results = await gau.run(domain)
        for u in gau_results:
            if u not in seen:
                seen.add(u)
                urls.append(u)
    except FileNotFoundError:
        logger.warning("gau not installed, skipping")

    if host_urls:
        try:
            katana_results = await katana.run(host_urls)
            for u in katana_results:
                if u not in seen:
                    seen.add(u)
                    urls.append(u)
        except FileNotFoundError:
            logger.warning("katana not installed, skipping")

        try:
            gospider_results = await gospider.run(host_urls)
            for u in gospider_results:
                if u not in seen:
                    seen.add(u)
                    urls.append(u)
        except FileNotFoundError:
            logger.warning("gospider not installed, skipping")

    return urls


async def _safe_run(fn, *args) -> list:
    try:
        return await fn(*args)
    except FileNotFoundError:
        logger.warning("tool %s not installed, skipping", fn.__module__)
        return []
    except Exception as exc:
        logger.warning("tool %s failed: %s", fn.__module__, exc)
        return []
