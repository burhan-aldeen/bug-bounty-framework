import datetime
import logging

import pytest

from core.config import Config, RuntimeConfig, OllamaConfig, ScanConfig
from core.logger import configure_logging, get_logger
from core.models import (
    Severity,
    FindingType,
    SecretType,
    Subdomain,
    AliveHost,
    Finding,
    SecretFinding,
    ToolResult,
    Report,
    ScanResult,
)
from core.runner import require_tool, run_captured, ToolResult as TR


class TestModels:
    def test_subdomain_defaults(self) -> None:
        s = Subdomain(domain="test.com", source="crt.sh")
        assert s.domain == "test.com"
        assert s.source == "crt.sh"

    def test_alive_host_defaults(self) -> None:
        h = AliveHost(
            url="https://test.com", status_code=200, title="Test"
        )
        assert h.url == "https://test.com"
        assert h.status_code == 200
        assert h.title == "Test"
        assert h.tech == []
        assert h.cdn is False

    def test_finding_enum_values(self) -> None:
        assert FindingType.XSS.value == "xss"
        assert FindingType.SQLI.value == "sqli"
        assert Severity.CRITICAL.value == "critical"

    def test_secret_finding_defaults(self) -> None:
        sf = SecretFinding(
            url="https://test.com/.env",
            secret_type=SecretType.ENV_FILE,
            match="DB_PASSWORD",
        )
        assert sf.severity == Severity.HIGH

    def test_tool_result_skipped(self) -> None:
        tr = ToolResult(
            tool="nonexistent",
            returncode=127,
            stdout="",
            stderr="missing tool",
            skipped=True,
        )
        assert tr.skipped is True

    def test_report_defaults(self) -> None:
        r = Report(target="test.com", timestamp=datetime.datetime.now().isoformat())
        assert r.findings == []
        assert r.secrets == []

    def test_scan_result_aggregation(self) -> None:
        sr = ScanResult(target="test.com")
        sr.subdomains.append(Subdomain("a.test.com", "subfinder"))
        sr.findings.append(
            Finding(
                finding_type=FindingType.XSS,
                url="https://a.test.com",
                severity=Severity.HIGH,
            )
        )
        assert len(sr.subdomains) == 1
        assert len(sr.findings) == 1


class TestConfig:
    def test_default_config(self) -> None:
        cfg = Config()
        assert isinstance(cfg.runtime, RuntimeConfig)
        assert isinstance(cfg.ollama, OllamaConfig)
        assert isinstance(cfg.scan, ScanConfig)
        assert cfg.runtime.concurrency == 5

    def test_ollama_config_defaults(self) -> None:
        oc = OllamaConfig()
        assert oc.url == "http://localhost:11434"
        assert oc.model == "qwen3.5:9b"
        assert oc.enabled is True


class TestLogger:
    def test_configure_logging(self, tmp_path: pytest.TempPathFactory) -> None:
        log_file = tmp_path / "test.log"
        configure_logging(str(log_file), "DEBUG")
        logger = get_logger("test_logger")
        logger.info("test message")
        assert logger.getEffectiveLevel() == logging.DEBUG
        assert logger.name == "test_logger"

    def test_logger_reinit_skips(self, tmp_path: pytest.TempPathFactory) -> None:
        configure_logging(str(tmp_path / "a.log"), "INFO")
        root_handlers_before = len(logging.getLogger().handlers)
        configure_logging(str(tmp_path / "b.log"), "INFO")
        root_handlers_after = len(logging.getLogger().handlers)
        assert root_handlers_after == root_handlers_before


class TestRunner:
    @pytest.mark.asyncio
    async def test_run_captured_missing_tool(self) -> None:
        result = await run_captured(["nonexistent_tool_xyz"])
        assert result.returncode == 127
        assert result.skipped is True
        assert result.stderr == "missing tool"

    @pytest.mark.asyncio
    async def test_run_captured_successful(self) -> None:
        result = await run_captured(["python", "-c", "print('hello')"])
        assert result.returncode == 0
        assert "hello" in result.stdout

    @pytest.mark.asyncio
    async def test_run_captured_failing(self) -> None:
        result = await run_captured(["python", "-c", "raise SystemExit(1)"])
        assert result.returncode == 1

    def test_require_tool_missing(self) -> None:
        with pytest.raises(FileNotFoundError):
            require_tool("nonexistent_tool_xyz")

    def test_require_tool_found(self) -> None:
        path = require_tool("python")
        assert path is not None
        assert "python" in path.lower()
