import json

from core.logger import get_logger
from core.models import Subdomain

logger = get_logger("tools.crtsh")


async def run(domain: str) -> list[Subdomain]:
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    logger.info("crtsh: querying %s", domain)
    try:
        import httpx
        async with httpx.AsyncClient(timeout=30.0, verify=False) as c:
            response = await c.get(url)
            return parse_output(response.text, "crtsh")
    except ImportError:
        logger.warning("httpx not installed, skipping crtsh")
        return []
    except Exception as exc:
        logger.warning("crtsh request failed: %s", exc)
        return []


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
