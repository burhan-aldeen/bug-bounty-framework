import json

from core.logger import get_logger
from core.models import Finding, FindingType, Severity
from core.runner import run_captured, require_tool

logger = get_logger("tools.nuclei")

SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


async def run(
    targets: list[str],
    templates: str = "xss,sql-injection,rce,ssrf",
    severity: str = "medium,high,critical",
) -> list[Finding]:
    require_tool("nuclei")
    input_data = "\n".join(targets)
    cmd = [
        "nuclei",
        "-silent",
        "-t", templates,
        "-severity", severity,
        "-json",
    ]
    logger.info("nuclei: scanning %d targets with %s", len(targets), templates)
    result = await run_captured(cmd, stdin_data=input_data.encode())
    return parse_output(result.stdout)


def parse_output(stdout: str) -> list[Finding]:
    findings = []
    for line in stdout.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            raw_type = str(data.get("type", data.get("info", {}).get("name", "unknown"))).lower()
            if "xss" in raw_type:
                ft = FindingType.XSS
            elif "sql" in raw_type:
                ft = FindingType.SQLI
            elif "ssrf" in raw_type:
                ft = FindingType.SSRF
            elif "rce" in raw_type or "command" in raw_type:
                ft = FindingType.RCE
            elif "ssti" in raw_type or "template" in raw_type:
                ft = FindingType.SSTI
            elif "redirect" in raw_type or "open-redirect" in raw_type:
                ft = FindingType.OPEN_REDIRECT
            else:
                ft = FindingType.XSS

            raw_sev = str(data.get("info", {}).get("severity", "medium")).lower()
            severity = SEVERITY_MAP.get(raw_sev, Severity.MEDIUM)
            matched = data.get("matched-at", data.get("host", ""))
            findings.append(
                Finding(
                    finding_type=ft,
                    url=matched,
                    detail=data.get("info", {}).get("name", raw_type),
                    severity=severity,
                    confidence=0.7,
                )
            )
        except (json.JSONDecodeError, KeyError) as exc:
            logger.warning("nuclei: failed to parse line: %s", exc)
    if not findings:
        logger.warning("nuclei: no findings detected")
    logger.info("nuclei: %d findings", len(findings))
    return findings
