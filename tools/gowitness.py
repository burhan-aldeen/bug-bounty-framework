from pathlib import Path

from core.logger import get_logger
from core.runner import run_captured, require_tool

logger = get_logger("tools.gowitness")


async def run(urls_file: str, output_dir: Path) -> list[str]:
    require_tool("gowitness")
    cmd = ["gowitness", "file", "-f", urls_file, "-P", str(output_dir)]
    logger.info("gowitness: taking screenshots")
    result = await run_captured(cmd)
    return parse_output(result.stdout)


def parse_output(stdout: str) -> list[str]:
    paths: list[str] = []
    for line in stdout.strip().splitlines():
        line = line.strip()
        if line and not line.startswith("["):
            paths.append(line)
    logger.info("gowitness: %d screenshots", len(paths))
    return paths
