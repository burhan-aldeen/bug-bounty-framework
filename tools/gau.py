from core.logger import get_logger
from core.runner import run_captured, require_tool

logger = get_logger("tools.gau")


async def run(domain: str) -> list[str]:
    require_tool("gau")
    cmd = ["gau", domain, "--silent"]
    logger.info("gau: fetching urls for %s", domain)
    result = await run_captured(cmd)
    return parse_output(result.stdout)


def parse_output(stdout: str) -> list[str]:
    urls = []
    for line in stdout.strip().splitlines():
        line = line.strip()
        if line:
            urls.append(line)
    if not urls:
        logger.warning("gau: no urls found")
    logger.info("gau: %d urls collected", len(urls))
    return urls
