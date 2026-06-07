from core.logger import get_logger
from core.models import Subdomain
from core.runner import run_captured, require_tool

logger = get_logger("tools.subfinder")


async def run(domain: str, sources: list[str] | None = None) -> list[Subdomain]:
    require_tool("subfinder")
    cmd = ["subfinder", "-d", domain, "-all", "-silent"]
    logger.info("subfinder: enumerating %s", domain)
    result = await run_captured(cmd)
    return parse_output(result.stdout, "subfinder")


def parse_output(stdout: str, source: str = "subfinder") -> list[Subdomain]:
    domains = []
    for line in stdout.strip().splitlines():
        line = line.strip().lower()
        if line and not line.startswith("["):
            domains.append(Subdomain(domain=line, source=source))
    if not domains:
        logger.warning("subfinder: no subdomains found")
    logger.info("subfinder: found %d subdomains", len(domains))
    return domains
