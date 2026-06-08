from core.logger import get_logger
from core.models import AliveHost, Finding, FindingType, Severity

logger = get_logger("stages.api_hack")

GRAPHQL_PROBE_QUERY: str = '{"query":"query {__schema{queryType{name}}}"}'


async def run(
    hosts: list[AliveHost], urls: list[str]
) -> list[Finding]:
    logger.info("stage=api_hack hosts=%d urls=%d", len(hosts), len(urls))
    findings: list[Finding] = []

    graphql_findings = await _check_graphql_introspection(hosts)
    findings.extend(graphql_findings)

    idor_findings = _check_idor_candidates(urls)
    findings.extend(idor_findings)

    jwt_findings = await _check_jwt(hosts)
    findings.extend(jwt_findings)

    header_findings = _check_header_bypass(urls)
    findings.extend(header_findings)

    param_pollution = _check_parameter_pollution(urls)
    findings.extend(param_pollution)

    logger.info("stage=api_hack done findings=%d", len(findings))
    return findings


async def _check_graphql_introspection(hosts: list[AliveHost]) -> list[Finding]:
    findings: list[Finding] = []
    try:
        import httpx
    except ImportError:
        logger.warning("httpx not installed, skipping GraphQL introspection")
        return findings
    async with httpx.AsyncClient(timeout=15.0, verify=False) as client:
        for host in hosts:
            if "graphql" in host.url.lower():
                try:
                    response = await client.post(
                        host.url,
                        headers={"Content-Type": "application/json"},
                        content=GRAPHQL_PROBE_QUERY,
                    )
                    body = response.text
                    if "__schema" in body or "queryType" in body:
                        findings.append(
                            Finding(
                                finding_type=FindingType.GRAPHQL,
                                url=host.url,
                                detail="GraphQL introspection is enabled",
                                severity=Severity.HIGH,
                                confidence=0.9,
                            )
                        )
                except Exception as exc:
                    logger.warning("graphql probe failed for %s: %s", host.url, exc)
    return findings


def _check_idor_candidates(urls: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    for url in urls:
        if any(p in url.lower() for p in ["/api/", "/v1/", "/v2/", "/user/", "/admin/", "/id="]):
            if "=" in url:
                findings.append(
                    Finding(
                        finding_type=FindingType.IDOR,
                        url=url,
                        detail="IDOR candidate — check authorization on this endpoint",
                        severity=Severity.MEDIUM,
                        confidence=0.3,
                    )
                )
    return findings


async def _check_jwt(hosts: list[AliveHost]) -> list[Finding]:
    findings: list[Finding] = []
    for host in hosts:
        auth = host.headers.get("authorization", host.headers.get("Authorization", ""))
        if "bearer" in auth.lower() or "jwt" in host.url.lower():
            findings.append(
                Finding(
                    finding_type=FindingType.JWT,
                    url=host.url,
                    detail="JWT authentication detected — verify token handling",
                    severity=Severity.MEDIUM,
                    confidence=0.4,
                )
            )
    return findings


def _check_header_bypass(urls: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    admin_urls = [u for u in urls if any(
        p in u.lower() for p in ["/admin", "/dashboard", "/internal", "/console"]
    )]
    for url in admin_urls:
        findings.append(
            Finding(
                finding_type=FindingType.IDOR,
                url=url,
                detail="Admin/internal endpoint — test header-based bypass (X-Forwarded-Host, X-Original-URL, X-Forwarded-For)",
                severity=Severity.HIGH,
                confidence=0.4,
            )
        )
    return findings


def _check_parameter_pollution(urls: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    for url in urls:
        if "?" in url and "=" in url:
            params = url.split("?")[1].split("&")
            if len(params) >= 2:
                param_names = [p.split("=")[0] for p in params if "=" in p]
                if len(param_names) != len(set(param_names)):
                    findings.append(
                        Finding(
                            finding_type=FindingType.IDOR,
                            url=url,
                            detail="Duplicate parameter detected — test parameter pollution",
                            severity=Severity.MEDIUM,
                            confidence=0.5,
                        )
                    )
    return findings
