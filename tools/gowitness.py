from pathlib import Path

from core.logger import get_logger
from core.runner import run_captured, require_tool

logger = get_logger("tools.gowitness")


async def run(urls: list[str], output_dir: Path = Path("screenshots")) -> list[Path]:
    require_tool("gowitness")
    output_dir.mkdir(parents=True, exist_ok=True)
    input_data = "\n".join(urls)
    cmd = [
        "gowitness",
        "file",
        "-f", "-",
        "-P", str(output_dir),
    ]
    logger.info("gowitness: capturing %d urls", len(urls))
    result = await run_captured(cmd, input_data=input_data.encode())
    return parse_output(result.stdout, output_dir)


def parse_output(stdout: str, output_dir: Path) -> list[Path]:
    screenshots = []
    for line in stdout.strip().splitlines():
        line = line.strip()
        if line and not line.startswith("["):
            screenshots.append(output_dir / line)
    if not screenshots:
        logger.warning("gowitness: no screenshots captured")
    logger.info("gowitness: %d screenshots", len(screenshots))
    return screenshots
