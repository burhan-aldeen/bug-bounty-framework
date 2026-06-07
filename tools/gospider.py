import re

from core.logger import get_logger
from core.runner import run_captured, require_tool

logger = get_logger("tools.gospider")


async def run(urls: list[str]) -> list[str]:
    require_tool("gospider")
    urls_str = "\n".join(urls) if len(urls) > 1 else urls[0]
    cmd = [
        "gospider",
        "-s", urls_str,
        "-t", "20",
        "--json",
    ]
    logger.info("gospider: crawling %d urls", len(urls))
    result = await run_captured(cmd)
    return parse_output(result.stdout)


def parse_output(stdout: str) -> list[str]:
    urls = []
    url_pattern = re.compile(r'"output":\s*"([^"]+)"')
    for match in url_pattern.finditer(stdout):
        url = match.group(1)
        if url and not any(url.endswith(ext) for ext in (".css", ".jpg", ".png", ".ico", ".svg")):
            urls.append(url)
    if not urls:
        logger.warning("gospider: no urls found")
    logger.info("gospider: %d urls collected", len(urls))
    return urls
