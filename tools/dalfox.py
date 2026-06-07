import json

from core.logger import get_logger
from core.models import Finding, FindingType, Severity
from core.runner import run_captured, require_tool

logger = get_logger("tools.dalfox")


async def run(urls: list[str]) -> list[Finding]:
    require_tool("dalfox")
    input_data = "\n".join(urls)
    cmd = [
        "dalfox",
        "pipe",
        "--skip-bav",
        "--skip-mining-all",
        "--waf-evasion",
        "--json",
    ]
    logger.info("dalfox: scanning %d urls", len(urls))
    result = await run_captured(cmd, input_data=input_data.encode())
    return parse_output(result.stdout)


def parse_output(stdout: str) -> list[Finding]:
    findings = []
    for line in stdout.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            findings.append(
                Finding(
                    finding_type=FindingType.XSS,
                    url=data.get("url", ""),
                    parameter=data.get("param", None),
                    payload=data.get("payload", None),
                    confidence=data.get("confidence", 0.5),
                    detail=data.get("message", ""),
                    severity=Severity.HIGH,
                )
            )
        except (json.JSONDecodeError, KeyError) as exc:
            logger.warning("dalfox: failed to parse line: %s", exc)
    if not findings:
        logger.warning("dalfox: no XSS findings")
    logger.info("dalfox: %d XSS findings", len(findings))
    return findings
