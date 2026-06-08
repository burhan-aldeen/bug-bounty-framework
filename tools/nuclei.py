from core.logger import get_logger
from core.models import Finding, FindingType, Severity
from core.runner import run_captured, require_tool

logger = get_logger("tools.nuclei")


async def run(urls: list[str], templates: str = "xss", severity: str = "medium,high,critical") -> list[Finding]:
    require_tool("nuclei")
    if not urls:
        return []
    input_data = "\n".join(urls).encode("utf-8")
    cmd = [
        "nuclei", "-silent",
        "-t", templates,
        "-severity", severity,
        "-json",
    ]
    logger.info("nuclei: scanning %d targets with %s", len(urls), templates)
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
            info = data.get("info", {})
            raw_type = str(info.get("name", "")).lower()
            severity_str = info.get("severity", "medium")
            severity_map = {
                "info": Severity.INFO, "low": Severity.LOW,
                "medium": Severity.MEDIUM, "high": Severity.HIGH,
                "critical": Severity.CRITICAL,
            }
            sev = severity_map.get(severity_str, Severity.MEDIUM)

            if "xss" in raw_type:
                ft = FindingType.XSS
            elif "sql" in raw_type:
                ft = FindingType.SQLI
            elif "ssrf" in raw_type:
                ft = FindingType.SSRF
            elif "rce" in raw_type or "command" in raw_type:
                ft = FindingType.RCE
            elif "redirect" in raw_type or "open-redirect" in raw_type:
                ft = FindingType.OPEN_REDIRECT
            elif "ssti" in raw_type or "template" in raw_type:
                ft = FindingType.SSTI
            else:
                ft = FindingType.XSS

            findings.append(
                Finding(
                    finding_type=ft,
                    url=data.get("host", data.get("matched-at", "")),
                    detail=f"{info.get('name', '')} - {info.get('description', '')}",
                    severity=sev,
                    confidence=0.7,
                )
            )
        except json.JSONDecodeError:
            continue
    if not findings:
        logger.warning("nuclei: no findings detected")
    logger.info("nuclei: %d findings", len(findings))
    return findings
