from core.logger import get_logger
from core.runner import run_captured, require_tool

logger = get_logger("tools.katana")


async def run(urls: list[str], depth: int = 3) -> list[str]:
    require_tool("katana")
    input_data = "\n".join(urls)
    cmd = [
        "katana",
        "-silent",
        "-d", str(depth),
        "-jc",
        "-kf",
        "-em", "js,png,jpg,css",
    ]
    logger.info("katana: crawling %d urls to depth %d", len(urls), depth)
    result = await run_captured(cmd, stdin_data=input_data.encode())
    return parse_output(result.stdout)


def parse_output(stdout: str) -> list[str]:
    urls = []
    for line in stdout.strip().splitlines():
        line = line.strip()
        if line and not line.startswith("["):
            urls.append(line)
    if not urls:
        logger.warning("katana: no urls found")
    logger.info("katana: %d urls collected", len(urls))
    return urls
