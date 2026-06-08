from core.logger import get_logger
from core.models import Finding, FindingType, Severity
from core.runner import run_captured, require_tool

logger = get_logger("tools.tplmap")


async def run(url: str, param: str = "name") -> list[Finding]:
    require_tool("tplmap")
    cmd = [
        "tplmap", "-u", url,
        "--engine", "asterisk",
    ]
    logger.info("tplmap: testing %s", url)
    result = await run_captured(cmd)

    if "Vulnerable" in result.stdout or "tplmap" in result.stdout.lower():
        return [
            Finding(
                finding_type=FindingType.SSTI,
                url=url,
                parameter=param,
                severity=Severity.CRITICAL,
                confidence=0.7,
                detail=f"SSTI detected: {result.stdout[:200]}",
            )
        ]
    return []
