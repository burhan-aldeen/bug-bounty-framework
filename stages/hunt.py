import asyncio
import tempfile
from pathlib import Path

from core.logger import get_logger
from core.models import Finding
from tools import gf, dalfox, nuclei, sqlmap, qsreplace, httpx_tool, tplmap

logger = get_logger("stages.hunt")

SSRF_COLLABORATOR = "http://169.254.169.254/latest/meta-data"
OPEN_REDIRECT_TEST = "https://evil.com"


async def run(all_urls: list[str], alive_urls: list[str]) -> list[Finding]:
    logger.info("hunt: processing %d urls", len(all_urls))
    all_findings: list[Finding] = []

    # Phase 2a: Parameter Extraction
    urls_with_params = [u for u in all_urls if "=" in u]
    param_names = _extract_param_names(urls_with_params)
    logger.info("hunt: %d params extracted, %d urls with params", len(param_names), len(urls_with_params))

    # Save urls to temp file for gf
    all_urls_file = _save_to_temp(all_urls)
    try:
        # GF patterns
        xss_candidates = await _safe_run_gf(gf.run, "xss", all_urls_file)
        sqli_candidates = await _safe_run_gf(gf.run, "sqli", all_urls_file)
        logger.info("hunt: gf xss=%d sqli=%d", len(xss_candidates), len(sqli_candidates))

        # Phase 2b: XSS
        if xss_candidates:
            dalfox_findings = await _safe_run_xss(dalfox.run, xss_candidates)
            all_findings.extend(dalfox_findings)
        nuclei_xss = await _safe_run_xss(nuclei.run, alive_urls, "~/nuclei-templates/xss/", "medium,high")
        all_findings.extend(nuclei_xss)

        # Phase 2c: SQLi
        if sqli_candidates:
            sqlmap_findings = await _safe_run_sqli(sqlmap.run, sqli_candidates)
            all_findings.extend(sqlmap_findings)
        nuclei_sqli = await _safe_run_sqli(nuclei.run, alive_urls, "~/nuclei-templates/sql-injection/", "critical")
        all_findings.extend(nuclei_sqli)

        # Phase 2d: SSRF / Open Redirect
        ssrf_redirect_candidates = [u for u in urls_with_params if _is_ssrf_candidate(u)]
        if ssrf_redirect_candidates:
            ssrf_findings = await _test_ssrf(ssrf_redirect_candidates)
            all_findings.extend(ssrf_findings)
            redirect_findings = await _test_open_redirect(ssrf_redirect_candidates)
            all_findings.extend(redirect_findings)

        # Phase 2e: RCE / SSTI
        nuclei_rce = await _safe_run_rce(nuclei.run, alive_urls, "~/nuclei-templates/rce/", "critical")
        all_findings.extend(nuclei_rce)
        ssti_candidates = [u for u in urls_with_params if _is_ssti_candidate(u)]
        for url in ssti_candidates[:5]:  # Limit SSTI tests
            ssti_findings = await _safe_run_rce(tplmap.run, url)
            all_findings.extend(ssti_findings)
    finally:
        Path(all_urls_file).unlink(missing_ok=True)

    logger.info("hunt: total %d findings", len(all_findings))
    return all_findings


def _extract_param_names(urls: list[str]) -> list[str]:
    names: set[str] = set()
    for url in urls:
        if "?" in url:
            qs = url.split("?")[1].split("&")
            for param in qs:
                if "=" in param:
                    names.add(param.split("=")[0])
    return sorted(names)


def _save_to_temp(lines: list[str]) -> str:
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
    tmp.write("\n".join(lines) + "\n")
    tmp.close()
    return tmp.name


def _is_ssrf_candidate(url: str) -> bool:
    keywords = ["url=", "uri=", "redirect=", "next=", "return=", "continue=",
                 "callback=", "target=", "dest=", "destination=", "forward=",
                 "image=", "file=", "path="]
    return any(k in url.lower() for k in keywords)


def _is_ssti_candidate(url: str) -> bool:
    keywords = ["name=", "template=", "view=", "page=", "search=", "q=",
                 "message=", "content="]
    return any(k in url.lower() for k in keywords)


async def _test_ssrf(candidates: list[str]) -> list[Finding]:
    if not candidates:
        return []
    replaced = await qsreplace.run(candidates[:100], SSRF_COLLABORATOR)
    if not replaced:
        return []
    alive = await httpx_tool.run(replaced[:50])
    findings = []
    for h in alive:
        if "instance-id" in h.title or "instance-id" in str(h.content_length):
            findings.append(
                Finding(
                    finding_type=FindingType.SSRF,
                    url=h.url,
                    severity=Severity.CRITICAL,
                    confidence=0.6,
                    detail="AWS Metadata SSRF detected",
                )
            )
    logger.info("hunt/ssrf: %d findings", len(findings))
    return findings


async def _test_open_redirect(candidates: list[str]) -> list[Finding]:
    if not candidates:
        return []
    replaced = await qsreplace.run(candidates[:100], OPEN_REDIRECT_TEST)
    if not replaced:
        return []
    findings = []
    for url in replaced[:50]:
        if "evil.com" in url:
            findings.append(
                Finding(
                    finding_type=FindingType.OPEN_REDIRECT,
                    url=url,
                    severity=Severity.MEDIUM,
                    confidence=0.4,
                    detail="Open redirect candidate",
                )
            )
    logger.info("hunt/redirect: %d findings", len(findings))
    return findings


async def _safe_run_gf(fn, *args):
    try:
        return await fn(*args)
    except (FileNotFoundError, Exception) as exc:
        logger.warning("gf failed: %s", exc)
        return []


async def _safe_run_xss(fn, *args):
    try:
        return await fn(*args)
    except (FileNotFoundError, Exception) as exc:
        logger.warning("xss tool failed: %s", exc)
        return []


async def _safe_run_sqli(fn, *args):
    try:
        return await fn(*args)
    except (FileNotFoundError, Exception) as exc:
        logger.warning("sqli tool failed: %s", exc)
        return []


async def _safe_run_rce(fn, *args):
    try:
        return await fn(*args)
    except (FileNotFoundError, Exception) as exc:
        logger.warning("rce tool failed: %s", exc)
        return []


# Need to import FindingType and Severity at the end to avoid circular
from core.models import FindingType, Severity
