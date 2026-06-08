import datetime
import json
from pathlib import Path

import pytest

from core.models import Finding, FindingType, Report, SecretFinding, SecretType, Severity
from output.writer import write_json, write_csv, write_md, write_all


@pytest.fixture
def sample_report() -> Report:
    return Report(
        target="test.com",
        timestamp=datetime.datetime(2026, 6, 8, 12, 0, 0).isoformat(),
        findings=[
            Finding(
                finding_type=FindingType.XSS,
                url="https://test.com/search?q=1",
                parameter="q",
                payload="<script>alert(1)</script>",
                confidence=0.9,
                severity=Severity.HIGH,
                detail="Reflected XSS detected",
            ),
            Finding(
                finding_type=FindingType.SQLI,
                url="https://api.test.com/users?id=1",
                parameter="id",
                confidence=0.7,
                severity=Severity.CRITICAL,
                detail="SQL Injection candidate",
            ),
        ],
        secrets=[
            SecretFinding(
                url="https://test.com/.env",
                secret_type=SecretType.ENV_EXPOSED,
                match="DB_PASSWORD=secret123",
                severity=Severity.CRITICAL,
            ),
        ],
        ai_summary="Test AI summary",
    )


class TestWriter:
    def test_write_json(self, sample_report: Report, tmp_path: Path) -> None:
        path = write_json(sample_report, tmp_path)
        assert path.exists()
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["target"] == "test.com"
        assert len(data["findings"]) == 2
        assert data["ai_summary"] == "Test AI summary"

    def test_write_csv(self, sample_report: Report, tmp_path: Path) -> None:
        path = write_csv(sample_report, tmp_path)
        assert path.exists()
        content = path.read_text(encoding="utf-8")
        assert "Vulnerability,URL,Payload,Impact" in content
        assert "XSS" in content
        assert "SQLI" in content

    def test_write_md(self, sample_report: Report, tmp_path: Path) -> None:
        path = write_md(sample_report, tmp_path)
        assert path.exists()
        content = path.read_text(encoding="utf-8")
        assert "# Bug Bounty Report" in content
        assert "sqli" in content
        assert "Secrets Found" in content
        assert "AI Analysis Summary" in content

    def test_write_all(self, sample_report: Report, tmp_path: Path) -> None:
        paths = write_all(sample_report, tmp_path)
        assert "json" in paths
        assert "csv" in paths
        assert "md" in paths
        for p in paths.values():
            assert p.exists()

    def test_write_json_empty_findings(self, tmp_path: Path) -> None:
        report = Report(
            target="test.com",
            timestamp=datetime.datetime.now().isoformat(),
        )
        path = write_json(report, tmp_path)
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["findings"] == []
        assert data["secrets"] == []
