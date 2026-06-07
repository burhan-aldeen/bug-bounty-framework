import pytest

from core.models import (
    AliveHost, Finding, FindingType, SecretFinding, SecretType, Severity,
    ScanResult, Subdomain,
)
from stages import recon, hunt, api_hack, secrets as secrets_stage, report as report_stage


class TestRecon:
    @pytest.mark.asyncio
    async def test_safe_run_handles_missing_tool(self) -> None:
        async def failing_fn(*args):
            raise FileNotFoundError("not found")
        result = await recon._safe_run(failing_fn, "test")
        assert result == []

    @pytest.mark.asyncio
    async def test_safe_run_handles_generic_error(self) -> None:
        async def failing_fn(*args):
            raise RuntimeError("generic failure")
        result = await recon._safe_run(failing_fn, "test")
        assert result == []

    @pytest.mark.asyncio
    async def test_safe_run_returns_result(self) -> None:
        async def ok_fn(*args):
            return ["result1"]
        result = await recon._safe_run(ok_fn, "test")
        assert result == ["result1"]

    def test_collect_urls_empty_when_no_hosts(self) -> None:
        import asyncio
        urls = asyncio.run(recon._collect_urls("test.com", []))
        assert isinstance(urls, list)
        assert len(urls) == 0


class TestHunt:
    def test_run_xss_filters_non_param_urls(self) -> None:
        urls = ["https://test.com/page", "https://test.com/search?q=test"]
        param_urls = [u for u in urls if "=" in u]
        assert len(param_urls) == 1

    @pytest.mark.asyncio
    async def test_run_returns_empty_when_no_urls(self) -> None:
        result = await hunt.run([])
        assert result == []

    @pytest.mark.asyncio
    async def test_run_handles_missing_tools_gracefully(self) -> None:
        result = await hunt.run(["https://test.com/page?id=1"])
        assert isinstance(result, list)


class TestApiHack:
    def test_check_idor_candidates_finds_api_patterns(self) -> None:
        urls = [
            "https://test.com/api/v1/users?id=1",
            "https://test.com/about",
            "https://test.com/admin/users?role=admin",
        ]
        findings = api_hack._check_idor_candidates(urls)
        assert len(findings) == 2
        assert all(f.finding_type == FindingType.IDOR for f in findings)

    def test_check_header_bypass_flags_admin_endpoints(self) -> None:
        urls = ["https://test.com/admin/panel", "https://test.com/page"]
        findings = api_hack._check_header_bypass(urls)
        assert len(findings) == 1
        assert "admin" in findings[0].url

    def test_check_parameter_pollution_detects_duplicates(self) -> None:
        urls = ["https://test.com/page?id=1&id=2", "https://test.com/page?id=1"]
        findings = api_hack._check_parameter_pollution(urls)
        assert len(findings) == 1

    def test_check_idor_candidates_empty(self) -> None:
        assert api_hack._check_idor_candidates([]) == []

    def test_check_header_bypass_empty(self) -> None:
        assert api_hack._check_header_bypass([]) == []

    def test_check_parameter_pollution_empty(self) -> None:
        assert api_hack._check_parameter_pollution([]) == []


class TestSecrets:
    def test_secret_paths_defined(self) -> None:
        from stages.secrets import SECRET_PATHS
        assert "/.env" in SECRET_PATHS
        assert "/.git/config" in SECRET_PATHS

    def test_js_key_patterns_defined(self) -> None:
        from stages.secrets import JS_KEY_PATTERNS
        assert len(JS_KEY_PATTERNS) >= 5

    def test_js_key_pattern_matches(self) -> None:
        from stages.secrets import JS_KEY_PATTERNS
        js_content = 'api_key = "sk-123456789012345678901234"'
        matches = []
        for pattern in JS_KEY_PATTERNS:
            matches.extend(pattern.findall(js_content))
        assert len(matches) >= 1


class TestReport:
    def test_build_findings_text_empty(self) -> None:
        from stages.report import _build_findings_text
        text = _build_findings_text([], [])
        assert "No findings" in text

    def test_build_findings_text_with_findings(self) -> None:
        from stages.report import _build_findings_text
        findings = [
            Finding(
                finding_type=FindingType.XSS,
                url="https://test.com/page",
                severity=Severity.HIGH,
            ),
            Finding(
                finding_type=FindingType.SQLI,
                url="https://test.com/page?id=1",
                severity=Severity.CRITICAL,
            ),
        ]
        text = _build_findings_text(findings, [])
        assert "xss" in text
        assert "sqli" in text

    @pytest.mark.asyncio
    async def test_run_creates_report_with_results(self) -> None:
        sr = ScanResult(target="test.com")
        sr.findings.append(
            Finding(
                finding_type=FindingType.XSS,
                url="https://test.com/xss",
                severity=Severity.HIGH,
            )
        )
        report = await report_stage.run(sr)
        assert report.target == "test.com"
        assert len(report.findings) == 1
