from core.logger import get_logger
from core.models import Finding, FindingType, Severity
from tools import dalfox, sqlmap, nuclei

logger = get_logger("stages.hunt")


async def run(urls: list[str]) -> list[Finding]:
    logger.info("stage=hunt urls=%d", len(urls))
    findings: list[Finding] = []

    xss_findings = await _run_xss(urls)
    findings.extend(xss_findings)

    sqli_findings = await _run_sqli(urls)
    findings.extend(sqli_findings)

    nuclei_findings = await _run_nuclei(urls)
    findings.extend(nuclei_findings)

    logger.info("stage=hunt done findings=%d", len(findings))
    return findings


async def _run_xss(urls: list[str]) -> list[Finding]:
    param_urls = [u for u in urls if "=" in u]
    if not param_urls:
        logger.info("hunt/xss: no parameterized urls to test")
        return []

    try:
        return await dalfox.run(param_urls)
    except FileNotFoundError:
        logger.warning("dalfox not installed, skipping XSS scan")
        return []
    except Exception as exc:
        logger.warning("dalfox failed: %s", exc)
        return []


async def _run_sqli(urls: list[str]) -> list[Finding]:
    param_urls = [u for u in urls if "=" in u]
    if not param_urls:
        return []

    try:
        return await sqlmap.run(param_urls)
    except FileNotFoundError:
        logger.warning("sqlmap not installed, skipping SQLi scan")
        return []
    except Exception as exc:
        logger.warning("sqlmap failed: %s", exc)
        return []


async def _run_nuclei(urls: list[str]) -> list[Finding]:
    try:
        return await nuclei.run(urls, templates="xss,sql-injection,ssrf,rce")
    except FileNotFoundError:
        logger.warning("nuclei not installed, skipping template scan")
        return []
    except Exception as exc:
        logger.warning("nuclei failed: %s", exc)
        return []
