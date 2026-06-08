import tempfile
from pathlib import Path

from core.logger import get_logger
from core.models import Subdomain
from core.runner import run_captured, require_tool

logger = get_logger("tools.amass")


async def run(domains: list[str]) -> list[Subdomain]:
    require_tool("amass")
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
    tmp_path = Path(tmp.name)
    try:
        tmp.write("\n".join(domains))
        tmp.close()
        cmd = [
            "amass", "enum",
            "-passive",
            "-norecursive",
            "-noalts",
            "-df", str(tmp_path),
        ]
        logger.info("amass: enumerating %d root domains", len(domains))
        result = await run_captured(cmd)
    finally:
        if tmp_path.exists():
            tmp_path.unlink(missing_ok=True)
    return parse_output(result.stdout, "amass")


def parse_output(stdout: str, source: str = "amass") -> list[Subdomain]:
    seen: set[str] = set()
    subs: list[Subdomain] = []
    for line in stdout.strip().splitlines():
        line = line.strip().lower()
        if line and line not in seen:
            seen.add(line)
            subs.append(Subdomain(domain=line, source=source))
    if not subs:
        logger.warning("amass: no subdomains found")
    logger.info("amass: found %d subdomains", len(subs))
    return subs
