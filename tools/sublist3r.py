import tempfile
from pathlib import Path

from core.logger import get_logger
from core.models import Subdomain
from core.runner import run_captured, require_tool

logger = get_logger("tools.sublist3r")


async def run(domain: str) -> list[Subdomain]:
    require_tool("sublist3r")
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
    tmp.close()
    try:
        cmd = ["sublist3r", "-d", domain, "-n", "-o", tmp.name]
        logger.info("sublist3r: enumerating %s", domain)
        result = await run_captured(cmd)
        output_path = Path(tmp.name)
        if output_path.exists() and output_path.stat().st_size > 0:
            stdout = output_path.read_text(encoding="utf-8", errors="replace")
        else:
            stdout = result.stdout
        return parse_output(stdout, "sublist3r")
    finally:
        Path(tmp.name).unlink(missing_ok=True)


def parse_output(stdout: str, source: str = "sublist3r") -> list[Subdomain]:
    seen: set[str] = set()
    subs: list[Subdomain] = []
    for line in stdout.strip().splitlines():
        line = line.strip().lower()
        if not line or line.startswith("[") or line.startswith("-"):
            continue
        if line not in seen:
            seen.add(line)
            subs.append(Subdomain(domain=line, source=source))
    if not subs:
        logger.warning("sublist3r: no subdomains found")
    logger.info("sublist3r: found %d subdomains", len(subs))
    return subs
