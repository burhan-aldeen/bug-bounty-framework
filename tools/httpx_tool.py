import asyncio
import json
import shutil
import sys
import tempfile
from pathlib import Path

from core.logger import get_logger
from core.models import AliveHost

logger = get_logger("tools.httpx")

_HTTPX_TIMEOUT = 600


async def run(
    domains: list[str],
    ports: str = "80,443",
    output_dir: Path | None = None,
) -> list[AliveHost]:
    executable = shutil.which("httpx")
    if executable is None:
        raise FileNotFoundError("tool not installed: httpx")

    cmd = [
        "httpx",
        "-silent",
        "-ports", ports,
        "-status-code",
        "-title",
        "-location",
        "-server",
        "-cname",
        "-follow-redirects",
        "-tech-detect",
        "-json",
        "-timeout", "5",
        "-retries", "1",
        "-threads", "200",
        "--ip",
    ]

    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
    tmp_path = Path(tmp.name)
    out_lines: list[str] = []
    save_path = (output_dir / "httpx_results.txt") if output_dir else None

    try:
        tmp.write("\n".join(domains))
        tmp.close()
        cmd.extend(["-l", str(tmp_path)])
        logger.info("httpx: probing %d hosts", len(domains))
        logger.info("running: %s", " ".join(cmd))

        process = await asyncio.create_subprocess_exec(
            executable,
            *cmd[1:],
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        while True:
            line_bytes = await process.stdout.readline()
            if not line_bytes:
                break
            line = line_bytes.decode("utf-8", errors="replace").rstrip()
            if line:
                buf = getattr(sys.stdout, "buffer", None)
                try:
                    if buf:
                        buf.write((line + "\n").encode("utf-8"))
                        buf.flush()
                except Exception:
                    pass
                out_lines.append(line)

        await asyncio.wait_for(process.wait(), timeout=_HTTPX_TIMEOUT)

    except TimeoutError:
        logger.warning("httpx timed out after %ds", _HTTPX_TIMEOUT)
    finally:
        if tmp_path.exists():
            tmp_path.unlink(missing_ok=True)

    stdout = "\n".join(out_lines)

    if save_path:
        save_path.parent.mkdir(parents=True, exist_ok=True)
        save_path.write_text(stdout, encoding="utf-8")
        logger.info("httpx results saved to %s (%d lines)", save_path, len(out_lines))

    return parse_output(stdout)


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
