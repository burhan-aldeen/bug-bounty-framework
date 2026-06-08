import pytest

from core.config import Config, ScanConfig, OllamaConfig, OpenAIConfig
from core.models import (
    Subdomain, AliveHost, Finding, SecretFinding, ToolResult,
    Report, ScanResult, Severity, FindingType, SecretType,
)


class TestModels:
    def test_subdomain_defaults(self):
        s = Subdomain(domain="test.example.com", source="test")
        assert s.domain == "test.example.com"
        assert s.source == "test"

    def test_alive_host_defaults(self):
        h = AliveHost(url="http://example.com", status_code=200)
        assert h.url == "http://example.com"
        assert h.status_code == 200
        assert h.tech == []
        assert h.headers == {}

    def test_finding_enum_values(self):
        assert FindingType.XSS.value == "xss"
        assert FindingType.SQLI.value == "sqli"
        assert FindingType.SSRF.value == "ssrf"
        assert FindingType.RCE.value == "rce"

    def test_secret_finding_defaults(self):
        s = SecretFinding(url="http://example.com/.env", secret_type=SecretType.ENV_EXPOSED)
        assert s.url == "http://example.com/.env"
        assert s.secret_type == SecretType.ENV_EXPOSED

    def test_tool_result_skipped(self):
        t = ToolResult(tool="test", returncode=127, stdout="", stderr="missing", skipped=True)
        assert t.skipped is True
        assert t.returncode == 127

    def test_severity_values(self):
        assert Severity.INFO.value == "info"
        assert Severity.LOW.value == "low"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.HIGH.value == "high"
        assert Severity.CRITICAL.value == "critical"


class TestConfig:
    def test_default_config(self):
        c = Config()
        assert c.scan.authorized is False
        assert c.scan.quick is False
        assert c.ollama.url == "http://localhost:11434"
        assert c.openai.api_key == ""

    def test_ollama_config_defaults(self):
        o = OllamaConfig()
        assert o.url == "http://localhost:11434"
        assert o.model == "llama3.2"
        assert o.timeout_seconds == 60

    def test_openai_config_defaults(self):
        o = OpenAIConfig()
        assert o.model == "gpt-4o-mini"
        assert o.timeout_seconds == 60


class TestRunner:
    @pytest.mark.asyncio
    async def test_run_captured_missing_tool(self):
        from core.runner import run_captured
        result = await run_captured(["nonexistent_tool_xyz"])
        assert result.skipped is True
        assert result.returncode == 127

    @pytest.mark.asyncio
    async def test_run_captured_successful(self):
        from core.runner import run_captured
        result = await run_captured(["python", "-c", "print('hello')"])
        assert result.returncode == 0
        assert "hello" in result.stdout

    @pytest.mark.asyncio
    async def test_run_captured_failing(self):
        from core.runner import run_captured
        result = await run_captured(["python", "-c", "import sys; sys.exit(1)"])
        assert result.returncode == 1

    def test_require_tool_missing(self):
        from core.runner import require_tool
        with pytest.raises(FileNotFoundError):
            require_tool("nonexistent_tool_xyz")

    def test_require_tool_found(self):
        from core.runner import require_tool
        path = require_tool("python")
        assert path is not None
        assert len(path) > 0

    def test_anew_merge(self):
        from core.runner import anew_merge
        existing: set[str] = {"a", "b"}
        new = ["b", "c", "d"]
        added = anew_merge(new, existing)
        assert added == ["c", "d"]
        assert existing == {"a", "b", "c", "d"}

    def test_anew_merge_empty(self):
        from core.runner import anew_merge
        existing: set[str] = {"a"}
        added = anew_merge([], existing)
        assert added == []
