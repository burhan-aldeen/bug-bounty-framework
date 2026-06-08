import asyncio
from pathlib import Path

from core.logger import get_logger
from core.models import AliveHost, Subdomain
from tools import assetfinder, subfinder, amass, crtsh
from tools import httpx_tool, katana, waybackurls, gau, gospider

logger = get_logger("stages.recon")


async def enumerate_subdomains(target: str) -> list[Subdomain]:
    tasks = [
        _safe_run(assetfinder.run, target),
        _safe_run(subfinder.run, target),
        _safe_run(amass.run, target),
        _safe_run(crtsh.run, target),
    ]
    results = await asyncio.gather(*tasks)
    seen: set[str] = set()
    merged: list[Subdomain] = []
    for subs in results:
        for s in subs:
            if s.domain not in seen:
                seen.add(s.domain)
                merged.append(s)
    logger.info("recon: %d unique subdomains for %s", len(merged), target)
    return merged


async def check_alive(
    domains: list[str], output_dir: Path | None = None
) -> list[AliveHost]:
    return await httpx_tool.run(domains, output_dir=output_dir)


async def collect_urls(target: str, host_urls: list[AliveHost]) -> list[str]:
    urls: list[str] = [h.url for h in host_urls]
    if not urls:
        return []

    tasks = [
        _safe_run_urls(katana.run, urls),
        _safe_run_urls(waybackurls.run, target),
        _safe_run_urls(gau.run, target),
        _safe_run_urls(gospider.run, urls),
    ]
    results = await asyncio.gather(*tasks)

    seen: set[str] = set()
    merged: list[str] = []
    for url_list in results:
        for u in url_list:
            if u not in seen:
                seen.add(u)
                merged.append(u)

    # Filter noise
    exclude = (".css", ".jpg", ".jpeg", ".png", ".gif", ".svg", ".woff", ".woff2", ".ico", ".mp4", ".mp3", ".zip", ".rar", ".tar", ".gz")
    merged = [u for u in merged if not u.lower().endswith(exclude)]

    logger.info("recon: %d unique urls collected for %s", len(merged), target)
    return merged


async def _safe_run(fn, *args):
    try:
        return await fn(*args)
    except FileNotFoundError:
        logger.warning("%s not installed, skipping", fn.__name__ if hasattr(fn, "__name__") else "tool")
        return []
    except Exception as exc:
        logger.warning("%s failed: %s", fn.__name__ if hasattr(fn, "__name__") else "tool", exc)
        return []


async def _safe_run_urls(fn, *args):
    try:
        return await fn(*args)
    except FileNotFoundError:
        logger.warning("%s not installed, skipping", fn.__name__ if hasattr(fn, "__name__") else "tool")
        return []
    except Exception as exc:
        logger.warning("%s failed: %s", fn.__name__ if hasattr(fn, "__name__") else "tool", exc)
        return []
