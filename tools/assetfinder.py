from core.logger import get_logger
from core.models import Subdomain
from core.runner import run_captured, require_tool

logger = get_logger("tools.assetfinder")


async def run(domain: str) -> list[Subdomain]:
    require_tool("assetfinder")
    cmd = ["assetfinder", "--subs-only", domain]
    logger.info("assetfinder: enumerating %s", domain)
    result = await run_captured(cmd)
    return parse_output(result.stdout, "assetfinder")


def parse_output(stdout: str, source: str = "assetfinder") -> list[Subdomain]:
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
        logger.warning("assetfinder: no subdomains found")
    logger.info("assetfinder: found %d subdomains", len(subs))
    return subs
