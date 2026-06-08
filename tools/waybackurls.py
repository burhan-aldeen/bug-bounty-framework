from core.logger import get_logger
from core.runner import run_captured, require_tool

logger = get_logger("tools.waybackurls")


async def run(domain: str) -> list[str]:
    require_tool("waybackurls")
    cmd = ["waybackurls", domain]
    logger.info("waybackurls: fetching for %s", domain)
    result = await run_captured(cmd)
    return parse_output(result.stdout)


def parse_output(stdout: str) -> list[str]:
    urls: list[str] = []
    for line in stdout.strip().splitlines():
        line = line.strip()
        if line and line.startswith("http"):
            urls.append(line)
    if not urls:
        logger.warning("waybackurls: no urls found")
    logger.info("waybackurls: %d urls collected", len(urls))
    return urls
