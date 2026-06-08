from core.logger import get_logger
from core.models import Finding, FindingType, Severity
from core.runner import run_captured, require_tool

logger = get_logger("tools.sqlmap")


async def run(urls: list[str]) -> list[Finding]:
    require_tool("sqlmap")
    if not urls:
        return []
    input_data = "\n".join(urls).encode("utf-8")
    cmd = [
        "sqlmap", "-m", "-",
        "--batch", "--level=2", "--risk=1",
        "--random-agent",
        "--output-dir=sqlmap_logs",
    ]
    logger.info("sqlmap: scanning %d targets", len(urls))
    result = await run_captured(cmd, stdin_data=input_data)
    return parse_output(result.stdout + result.stderr)


def parse_output(stdout: str) -> list[Finding]:
    import re
    findings: list[Finding] = []
    pattern = re.compile(
        r"(?:Parameter|GET|POST)[\s:]+[\"']?(\w+)[\"']?\s+.*?(?:vulnerable|injectable)",
        re.I,
    )
    for match in pattern.finditer(stdout):
        findings.append(
            Finding(
                finding_type=FindingType.SQLI,
                url="",
                parameter=match.group(1),
                severity=Severity.CRITICAL,
                confidence=0.8,
                detail=f"SQLi in parameter: {match.group(1)}",
            )
        )
    if not findings:
        logger.warning("sqlmap: no vulnerabilities found")
    logger.info("sqlmap: %d findings", len(findings))
    return findings
