import pytest

from core.models import Finding, FindingType, Severity, SecretFinding, SecretType


class TestReport:
    def test_build_findings_text_empty(self):
        from stages.report import _build_findings_text
        from core.models import ScanResult
        result = ScanResult(target="test.com")
        text = _build_findings_text(result)
        assert text == ""

    def test_build_findings_text_with_findings(self):
        from stages.report import _build_findings_text
        from core.models import ScanResult
        result = ScanResult(target="test.com")
        result.findings.append(
            Finding(url="http://test.com/xss", finding_type=FindingType.XSS,
                    severity=Severity.HIGH, detail="XSS found")
        )
        text = _build_findings_text(result)
        assert "xss" in text.lower()
        assert "http://test.com/xss" in text

    @pytest.mark.asyncio
    async def test_run_creates_report_with_results(self):
        from stages.report import run
        from core.models import ScanResult
        result = ScanResult(target="test.com")
        result.findings.append(
            Finding(url="http://test.com/test", finding_type=FindingType.XSS,
                    severity=Severity.HIGH, detail="test")
        )
        report = await run(result)
        assert report.target == "test.com"
        assert len(report.findings) == 1


class TestSecrets:
    def test_secret_paths_defined(self):
        from output.writer import SENSITIVE_PATHS
        assert len(SENSITIVE_PATHS) > 0
        assert "/.env" in SENSITIVE_PATHS
        assert "/.git/config" in SENSITIVE_PATHS

    def test_js_key_patterns_defined(self):
        from stages.secrets import JS_SECRET_PATTERNS
        assert len(JS_SECRET_PATTERNS) > 0

    def test_js_key_pattern_matches(self):
        from stages.secrets import JS_SECRET_PATTERNS
        import re
        for p in JS_SECRET_PATTERNS:
            assert p.search('"api_key": "abc123"') is not None
            break
