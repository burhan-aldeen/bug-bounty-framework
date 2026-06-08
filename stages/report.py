import datetime

from core.logger import get_logger
from core.models import Finding, Report, ScanResult

logger = get_logger("stages.report")


async def run(result: ScanResult, config=None) -> Report:
    from core.config import Config
    cfg = config or Config()

    findings_text = _build_findings_text(result)

    ai_summary = ""
    if findings_text.strip():
        try:
            from core.agent import generate_ai_summary
            ai_summary = await generate_ai_summary(findings_text, config=cfg)
        except Exception as exc:
            logger.warning("AI summary failed: %s", exc)

    report = Report(
        target=result.target,
        timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        findings=result.findings,
        secrets=result.secrets,
        ai_summary=ai_summary,
    )

    logger.info(
        "stage=report done findings=%d secrets=%d ai=%s",
        len(report.findings), len(report.secrets),
        "yes" if ai_summary else "no",
    )
    return report


def _build_findings_text(result: ScanResult) -> str:
    lines: list[str] = []
    if result.findings:
        lines.append("## Findings")
        for f in result.findings:
            lines.append(f"- [{f.severity.value.upper()}][{f.finding_type.value}] {f.url}")
            if f.parameter:
                lines.append(f"  Parameter: {f.parameter}")
            if f.payload:
                lines.append(f"  Payload: {f.payload}")
            lines.append(f"  {f.detail}")
    if result.secrets:
        lines.append("## Secrets")
        for s in result.secrets:
            lines.append(f"- [{s.severity.value.upper()}] {s.url} ({s.secret_type.value})")
    return "\n".join(lines)
