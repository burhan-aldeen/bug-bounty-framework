from core.logger import get_logger
from core.runner import run_captured, require_tool

logger = get_logger("tools.gf")


async def run(pattern: str, urls_file: str) -> list[str]:
    require_tool("gf")
    cmd = ["gf", pattern, urls_file]
    logger.info("gf: filtering %s patterns", pattern)
    result = await run_captured(cmd)
    return parse_output(result.stdout, pattern)


def parse_output(stdout: str, pattern: str = "") -> list[str]:
    urls: list[str] = []
    for line in stdout.strip().splitlines():
        line = line.strip()
        if line and line.startswith("http"):
            urls.append(line)
    logger.info("gf %s: %d candidates", pattern, len(urls))
    return urls
