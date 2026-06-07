import json

from core.logger import get_logger
from core.models import AliveHost
from core.runner import run_captured, require_tool

logger = get_logger("tools.httpx")


async def run(
    domains: list[str],
    ports: str = "80,443,8080,8443,3000",
) -> list[AliveHost]:
    require_tool("httpx")
    input_data = "\n".join(domains)
    cmd = [
        "httpx",
        "-silent",
        "-ports", ports,
        "-status-code",
        "-title",
        "-tech-detect",
        "-cdn",
        "-content-length",
        "-json",
    ]
    logger.info("httpx: probing %d hosts", len(domains))
    result = await run_captured(cmd, input_data=input_data.encode())
    return parse_output(result.stdout)


def parse_output(stdout: str) -> list[AliveHost]:
    hosts = []
    for line in stdout.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            hosts.append(
                AliveHost(
                    url=data.get("url", ""),
                    status_code=data.get("status_code", 0),
                    title=data.get("title", ""),
                    tech=data.get("tech", []) or [],
                    cdn=bool(data.get("cdn", False)),
                    content_length=data.get("content_length", 0),
                    headers=data.get("headers", {}),
                )
            )
        except (json.JSONDecodeError, KeyError) as exc:
            logger.warning("httpx: failed to parse line: %s", exc)
    if not hosts:
        logger.warning("httpx: no alive hosts found")
    logger.info("httpx: %d hosts alive", len(hosts))
    return hosts
