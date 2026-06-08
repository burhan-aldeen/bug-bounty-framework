from core.logger import get_logger
from core.models import Subdomain
from core.runner import run_captured, require_tool

logger = get_logger("tools.sublist3r")


async def run(domain: str) -> list[Subdomain]:
    require_tool("sublist3r")
    cmd = ["sublist3r", "-d", domain, "-n", "-o", "/dev/stdout"]
    logger.info("sublist3r: enumerating %s", domain)
    result = await run_captured(cmd)
    return parse_output(result.stdout, "sublist3r")


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
