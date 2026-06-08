from core.logger import get_logger
from core.runner import run_captured, require_tool

logger = get_logger("tools.qsreplace")


async def run(urls: list[str], replacement: str) -> list[str]:
    require_tool("qsreplace")
    if not urls:
        return []
    input_data = "\n".join(urls).encode("utf-8")
    cmd = ["qsreplace", replacement]
    result = await run_captured(cmd, stdin_data=input_data)
    return parse_output(result.stdout)


def parse_output(stdout: str) -> list[str]:
    urls: list[str] = []
    for line in stdout.strip().splitlines():
        line = line.strip()
        if line and line.startswith("http"):
            urls.append(line)
    logger.info("qsreplace: %d urls generated", len(urls))
    return urls
