import tempfile
from pathlib import Path

from core.logger import get_logger
from core.runner import run_captured, require_tool

logger = get_logger("tools.gospider")


async def run(urls: list[str]) -> list[str]:
    require_tool("gospider")
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
    tmp.close()
    try:
        tmp_path = tmp.name
        Path(tmp_path).write_text("\n".join(urls), encoding="utf-8")

        cmd = ["gospider", "-S", tmp_path, "-t", "20", "--json"]
        logger.info("gospider: crawling %d urls", len(urls))
        result = await run_captured(cmd)
        return parse_output(result.stdout)
    finally:
        Path(tmp_path).unlink(missing_ok=True)


def parse_output(stdout: str) -> list[str]:
    import re
    urls: list[str] = []
    exclude = (".css", ".jpg", ".png", ".ico", ".svg", ".woff", ".woff2")
    for line in stdout.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        match = re.search(r'"output":\s*"([^"]+)"', line)
        if match:
            url = match.group(1)
            if not url.lower().endswith(exclude):
                urls.append(url)
    if not urls:
        logger.warning("gospider: no urls found")
    logger.info("gospider: %d urls collected", len(urls))
    return urls
