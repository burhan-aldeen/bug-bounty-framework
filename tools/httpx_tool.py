import json
import tempfile
from pathlib import Path

from core.logger import get_logger
from core.models import AliveHost
from core.runner import run_captured, require_tool

logger = get_logger("tools.httpx")


async def run(
    domains: list[str],
    ports: str = "80,443",
    extra_flags: list[str] | None = None,
) -> list[AliveHost]:
    require_tool("httpx")
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
        "-timeout", "5",
        "-retries", "1",
        "-threads", "100",
        "-no-fallback",
    ]
    if extra_flags:
        cmd.extend(extra_flags)

    # write domains to temp file — more reliable than stdin with 1000+ hosts
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
    tmp_path = Path(tmp.name)
    try:
        tmp.write("\n".join(domains))
        tmp.close()
        cmd.extend(["-l", str(tmp_path)])
        logger.info("httpx: probing %d hosts", len(domains))
        result = await run_captured(cmd)
    finally:
        if tmp_path.exists():
            tmp_path.unlink(missing_ok=True)

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
