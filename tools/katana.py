import tempfile
from pathlib import Path

from core.logger import get_logger
from core.runner import run_captured, require_tool

logger = get_logger("tools.katana")


async def run(urls: list[str]) -> list[str]:
    require_tool("katana")
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
    tmp.close()
    try:
        tmp_path = tmp.name
        Path(tmp_path).write_text("\n".join(urls), encoding="utf-8")

        cmd = [
            "katana", "-silent", "-d", "5", "-jc", "-kf",
            "-em", "js,png,jpg,css",
            "-list", tmp_path,
        ]
        logger.info("katana: crawling %d urls to depth 5", len(urls))
        result = await run_captured(cmd)
        return parse_output(result.stdout)
    finally:
        Path(tmp_path).unlink(missing_ok=True)


def parse_output(stdout: str) -> list[str]:
    urls: list[str] = []
    for line in stdout.strip().splitlines():
        line = line.strip()
        if line and line.startswith("http"):
            urls.append(line)
    if not urls:
        logger.warning("katana: no urls found")
    logger.info("katana: %d urls collected", len(urls))
    return urls
