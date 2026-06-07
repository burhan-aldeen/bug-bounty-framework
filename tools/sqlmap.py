import re

from core.logger import get_logger
from core.models import Finding, FindingType, Severity
from core.runner import run_captured, require_tool

logger = get_logger("tools.sqlmap")


async def run(urls: list[str]) -> list[Finding]:
    require_tool("sqlmap")
    input_file = "\n".join(urls)
    cmd = [
        "sqlmap",
        "-m", "-",
        "--batch",
        "--level=3",
        "--risk=2",
        "--random-agent",
        "--output-dir=sqlmap_logs",
    ]
    logger.info("sqlmap: testing %d urls", len(urls))
    result = await run_captured(cmd, stdin_data=input_file.encode())
    return parse_output(result.stdout + result.stderr)


def parse_output(text: str) -> list[Finding]:
    findings = []
    vuln_pattern = re.compile(
        r"(?:Parameter|GET|POST)\s+[\"']?(\w+)[\"']?\s+.*?(?:vulnerable|injectable)",
        re.IGNORECASE,
    )
    for match in vuln_pattern.finditer(text):
        findings.append(
            Finding(
                finding_type=FindingType.SQLI,
                url="",
                parameter=match.group(1),
                detail="sqlmap flagged parameter as injectable",
                severity=Severity.CRITICAL,
                confidence=0.8,
            )
        )
    if not findings:
        logger.warning("sqlmap: no SQLi findings")
    logger.info("sqlmap: %d SQLi findings", len(findings))
    return findings
