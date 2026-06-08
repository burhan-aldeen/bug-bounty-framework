import tempfile
from pathlib import Path

from core.logger import get_logger
from core.models import Subdomain
from core.runner import run_captured, require_tool

logger = get_logger("tools.amass")


async def run(domain: str) -> list[Subdomain]:
    require_tool("amass")
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
    tmp.close()
    try:
        cmd = ["amass", "enum", "-passive", "-d", domain, "-o", tmp.name]
        logger.info("amass: enumerating %s", domain)
        result = await run_captured(cmd)
        output_path = Path(tmp.name)
        stdout = ""
        if output_path.exists() and output_path.stat().st_size > 0:
            stdout = output_path.read_text(encoding="utf-8", errors="replace")
        if not stdout.strip():
            stdout = result.stdout
        return parse_output(stdout, "amass")
    finally:
        Path(tmp.name).unlink(missing_ok=True)


def parse_output(stdout: str, source: str = "amass") -> list[Subdomain]:
    subs: list[Subdomain] = []
    seen: set[str] = set()
    for line in stdout.strip().splitlines():
        line = line.strip().lower()
        if not line:
            continue
        if line not in seen:
            seen.add(line)
            subs.append(Subdomain(domain=line, source=source))
    if not subs:
        logger.warning("amass: no subdomains found")
    logger.info("amass: found %d subdomains", len(subs))
    return subs
