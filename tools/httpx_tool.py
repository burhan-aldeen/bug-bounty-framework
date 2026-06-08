import asyncio
import json
import shutil
import sys
import tempfile
from pathlib import Path

from core.logger import get_logger
from core.models import AliveHost
from core.runner import run_captured

logger = get_logger("tools.httpx")

_HTTPX_FLAGS = [
    "-silent",
    "-ports", "80,443,8080,8443,3000",
    "-status-code", "-title", "-tech-detect", "-cdn",
    "-json",
]
_HTTPX_TIMEOUT = 600


async def run(
    domains: list[str],
    output_dir: Path | None = None,
) -> list[AliveHost]:
    tool = "httpx"
    executable = shutil.which(tool)
    if executable is None:
        logger.warning("httpx not installed, skipping")
        return []

    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
    try:
        tmp.write("\n".join(domains))
        tmp.close()

        cmd = [executable] + _HTTPX_FLAGS + ["-l", tmp.name]
        logger.info("httpx: probing %d hosts", len(domains))

        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        out_lines: list[str] = []
        buf = getattr(sys.stdout, "buffer", None)

        while True:
            line_bytes = await process.stdout.readline()
            if not line_bytes:
                break
            line = line_bytes.decode("utf-8", errors="replace").rstrip()
            if line:
                try:
                    if buf:
                        buf.write((line + "\n").encode("utf-8"))
                        buf.flush()
                except Exception:
                    pass
                out_lines.append(line)

        stderr = await process.stderr.read()
        await asyncio.wait_for(process.wait(), timeout=_HTTPX_TIMEOUT)

        stdout = "\n".join(out_lines)

        if output_dir:
            save_path = output_dir / "httpx_results.txt"
            save_path.parent.mkdir(parents=True, exist_ok=True)
            save_path.write_text(stdout, encoding="utf-8")
            logger.info("httpx results saved to %s (%d lines)", save_path, len(out_lines))

        result = parse_output(stdout)
        logger.info("httpx: %d hosts alive", len(result))
        return result

    except TimeoutError:
        logger.warning("httpx timed out")
        return []
    except Exception as exc:
        logger.warning("httpx failed: %s", exc)
        return []
    finally:
        Path(tmp.name).unlink(missing_ok=True)


def parse_output(stdout: str) -> list[AliveHost]:
    hosts: list[AliveHost] = []
    for line in stdout.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            host = AliveHost(
                url=data.get("url", ""),
                status_code=data.get("status_code", 0),
                title=data.get("title", ""),
                tech=data.get("tech", []),
                cdn=data.get("cdn", False),
                content_length=data.get("content_length", 0),
                headers=data.get("headers", {}),
            )
            if data.get("a"):
                host.ip = data["a"][0] if isinstance(data["a"], list) else data["a"]
            if data.get("cname"):
                host.cname = data["cname"][0] if isinstance(data["cname"], list) else data["cname"]
            hosts.append(host)
        except json.JSONDecodeError:
            continue
    return hosts
