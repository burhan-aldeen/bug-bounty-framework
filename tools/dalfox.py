from core.logger import get_logger
from core.models import Finding, FindingType, Severity
from core.runner import run_captured, require_tool

logger = get_logger("tools.dalfox")


async def run(urls: list[str]) -> list[Finding]:
    require_tool("dalfox")
    if not urls:
        return []
    input_data = "\n".join(urls).encode("utf-8")
    cmd = [
        "dalfox", "pipe",
        "--skip-bav", "--skip-mining-all",
        "--waf-evasion",
    ]
    logger.info("dalfox: scanning %d urls", len(urls))
    result = await run_captured(cmd, stdin_data=input_data)
    return parse_output(result.stdout)


def parse_output(stdout: str) -> list[Finding]:
    import json
    findings: list[Finding] = []
    for line in stdout.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            findings.append(
                Finding(
                    finding_type=FindingType.XSS,
                    url=data.get("data", ""),
                    parameter=data.get("param", ""),
                    payload=data.get("payload", ""),
                    severity=Severity.HIGH,
                    confidence=data.get("confidence", 0.8),
                    detail=f"XSS: {data.get('evidence', '')}",
                )
            )
        except json.JSONDecodeError:
            continue
    if not findings:
        logger.warning("dalfox: no findings")
    logger.info("dalfox: %d findings", len(findings))
    return findings
