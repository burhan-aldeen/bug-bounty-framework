from core.agent import generate_ai_summary
from core.config import Config
from core.logger import get_logger
from core.models import Finding, Report, ScanResult, SecretFinding

logger = get_logger("stages.report")


async def run(result: ScanResult, config: Config | None = None) -> Report:
    logger.info("stage=report target=%s", result.target)

    findings_text = _build_findings_text(result.findings, result.secrets)
    cfg = config or Config()
    ai_summary = await generate_ai_summary(
        findings_text,
        model=cfg.ollama.model or cfg.openai.model,
        url=cfg.ollama.url,
        api_key=cfg.openai.api_key,
    )

    import datetime
    report = Report(
        target=result.target,
        findings=result.findings,
        secrets=result.secrets,
        ai_summary=ai_summary,
        timestamp=datetime.datetime.now().isoformat(),
    )

    logger.info(
        "stage=report done findings=%d secrets=%d ai=%s",
        len(report.findings),
        len(report.secrets),
        "yes" if report.ai_summary else "no",
    )
    return report


def _build_findings_text(findings: list[Finding], secrets: list[SecretFinding]) -> str:
    lines = []
    for f in findings:
        lines.append(
            f"- [{f.severity.value}] {f.finding_type.value}: {f.url} "
            f"(param={f.parameter}, confidence={f.confidence})"
        )
    for s in secrets:
        lines.append(
            f"- [{s.severity.value}] secret {s.secret_type.value}: {s.url} "
            f"(match={s.match[:60]})"
        )
    return "\n".join(lines) if lines else "No findings or secrets detected."
