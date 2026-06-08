import json
import urllib.request

from core.logger import get_logger
from core.models import Subdomain
from core.runner import run_captured

logger = get_logger("tools.crtsh")


async def run(domain: str) -> list[Subdomain]:
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    cmd = ["curl", "-s", "--max-time", "30", url]
    logger.info("crtsh: querying %s", domain)
    result = await run_captured(cmd)
    return parse_output(result.stdout, "crtsh")


def parse_output(stdout: str, source: str = "crtsh") -> list[Subdomain]:
    seen: set[str] = set()
    subs: list[Subdomain] = []
    try:
        data = json.loads(stdout)
        for entry in data:
            raw = entry.get("name_value", "")
            for name in raw.split("\n"):
                name = name.strip().lower()
                if name and name not in seen and not name.startswith("*"):
                    seen.add(name)
                    subs.append(Subdomain(domain=name, source=source))
    except (json.JSONDecodeError, TypeError):
        logger.warning("crtsh: failed to parse response")
    if not subs:
        logger.warning("crtsh: no subdomains found")
    logger.info("crtsh: found %d subdomains", len(subs))
    return subs
