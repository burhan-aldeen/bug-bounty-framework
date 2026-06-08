import asyncio
import shutil
from collections.abc import Coroutine

from core.logger import get_logger
from core.models import ToolResult

logger = get_logger("runner")

_TOOL_TIMEOUTS: dict[str, int] = {
    "subfinder": 120,
    "httpx": 600,
    "nuclei": 300,
    "sqlmap": 600,
    "gau": 120,
    "katana": 300,
    "gospider": 300,
    "dalfox": 300,
    "gowitness": 300,
}


def require_tool(tool: str) -> str:
    executable = shutil.which(tool)
    if executable is None:
        raise FileNotFoundError(f"tool not installed: {tool}")
    return executable


async def run_captured(
    command: list[str], timeout: int | None = None, stdin_data: bytes | None = None
) -> ToolResult:
    tool = command[0]
    executable = shutil.which(tool)
    if executable is None:
        logger.warning("tool not installed, skipping: %s", tool)
        return ToolResult(
            tool=tool, returncode=127, stdout="", stderr="missing tool", skipped=True
        )

    effective_timeout = _TOOL_TIMEOUTS.get(tool, timeout or 60)
    logger.info("running: %s", " ".join(command))

    try:
        process = await asyncio.create_subprocess_exec(
            executable,
            *command[1:],
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(
            process.communicate(input=stdin_data), timeout=effective_timeout
        )
        result = ToolResult(
            tool=tool,
            returncode=process.returncode or 0,
            stdout=stdout.decode("utf-8", errors="replace"),
            stderr=stderr.decode("utf-8", errors="replace"),
        )
        logger.debug("tool %s exited with code %d", tool, result.returncode)
        if result.returncode != 0:
            logger.warning("tool %s non-zero exit: %d", tool, result.returncode)
        return result
    except TimeoutError:
        logger.warning("tool timed out: %s", tool)
        return ToolResult(
            tool=tool, returncode=124, stdout="", stderr="timeout"
        )
    except OSError as exc:
        logger.warning("tool failed to start: %s: %s", tool, exc)
        return ToolResult(
            tool=tool, returncode=126, stdout="", stderr=str(exc)
        )


async def run_live(
    command: list[str], timeout: int | None = None
) -> ToolResult:
    return await run_captured(command, timeout)


async def run_concurrent(
    coros: list[Coroutine], limit: int = 5
) -> list[ToolResult]:
    semaphore = asyncio.Semaphore(limit)

    async def limited(coro: Coroutine) -> ToolResult:
        async with semaphore:
            return await coro

    tasks = [limited(c) for c in coros]
    return await asyncio.gather(*tasks, return_exceptions=False)
