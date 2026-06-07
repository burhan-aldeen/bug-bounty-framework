import pytest

from core.models import Subdomain, AliveHost, Finding
from tools import subfinder, httpx_tool, gau, katana, gospider, gowitness
from tools import nuclei, dalfox, sqlmap


class TestSubfinder:
    def test_parse_output_returns_subdomains(self) -> None:
        stdout = "admin.test.com\napi.test.com\nwww.test.com\n"
        result = subfinder.parse_output(stdout)
        assert len(result) == 3
        assert all(isinstance(s, Subdomain) for s in result)
        assert result[0].domain == "admin.test.com"
        assert result[0].source == "subfinder"

    def test_parse_output_empty(self) -> None:
        assert subfinder.parse_output("") == []

    def test_parse_output_skips_bracket_lines(self) -> None:
        stdout = "[INF] Starting subfinder\nadmin.test.com\n"
        result = subfinder.parse_output(stdout)
        assert len(result) == 1


class TestHttpxTool:
    def test_parse_output_valid_json(self) -> None:
        stdout = (
            '{"url":"https://test.com","status_code":200,"title":"Test",'
            '"tech":["react"],"cdn":false,"content_length":1234,"headers":{}}\n'
            '{"url":"https://api.test.com","status_code":403,"title":"Forbidden",'
            '"tech":[],"cdn":true,"content_length":0,"headers":{}}\n'
        )
        result = httpx_tool.parse_output(stdout)
        assert len(result) == 2
        assert isinstance(result[0], AliveHost)
        assert result[0].url == "https://test.com"
        assert result[0].status_code == 200
        assert result[1].cdn is True

    def test_parse_output_invalid_json_skipped(self) -> None:
        stdout = "not json\n"
        result = httpx_tool.parse_output(stdout)
        assert result == []

    def test_parse_output_empty(self) -> None:
        assert httpx_tool.parse_output("") == []


class TestGau:
    def test_parse_output_returns_urls(self) -> None:
        stdout = "https://test.com/page1\nhttps://test.com/page2\n"
        result = gau.parse_output(stdout)
        assert len(result) == 2
        assert result[0] == "https://test.com/page1"

    def test_parse_output_empty(self) -> None:
        assert gau.parse_output("") == []


class TestKatana:
    def test_parse_output_returns_urls(self) -> None:
        stdout = "https://test.com/a\nhttps://test.com/b\n"
        result = katana.parse_output(stdout)
        assert len(result) == 2

    def test_parse_output_empty(self) -> None:
        assert katana.parse_output("") == []


class TestGospider:
    def test_parse_output_returns_urls(self) -> None:
        stdout = '{"output":"https://test.com/page"}\n{"output":"https://test.com/api"}\n'
        result = gospider.parse_output(stdout)
        assert len(result) == 2

    def test_parse_output_filters_extensions(self) -> None:
        stdout = '{"output":"https://test.com/a.css"}\n{"output":"https://test.com/a.jpg"}\n{"output":"https://test.com/page"}\n'
        result = gospider.parse_output(stdout)
        assert len(result) == 1
        assert result[0] == "https://test.com/page"

    def test_parse_output_empty(self) -> None:
        assert gospider.parse_output("") == []


class TestGowitness:
    def test_parse_output_returns_paths(self, tmp_path: pytest.TempPathFactory) -> None:
        stdout = "test.com.png\napi.test.com.png\n"
        result = gowitness.parse_output(stdout, tmp_path)
        assert len(result) == 2
        assert result[0] == tmp_path / "test.com.png"

    def test_parse_output_empty(self, tmp_path: pytest.TempPathFactory) -> None:
        assert gowitness.parse_output("", tmp_path) == []


class TestNuclei:
    def test_parse_output_xss_finding(self) -> None:
        stdout = (
            '{"host":"https://test.com","type":"xss","matched-at":"https://test.com/search",'
            '"info":{"name":"XSS Detection","severity":"high"}}\n'
        )
        result = nuclei.parse_output(stdout)
        assert len(result) == 1
        assert result[0].finding_type.value == "xss"
        assert result[0].severity.value == "high"

    def test_parse_output_sqli_finding(self) -> None:
        stdout = (
            '{"host":"https://test.com","type":"sql-injection","matched-at":"https://test.com?id=1",'
            '"info":{"name":"SQL Injection","severity":"critical"}}\n'
        )
        result = nuclei.parse_output(stdout)
        assert len(result) == 1
        assert result[0].finding_type.value == "sqli"

    def test_parse_output_invalid_json(self) -> None:
        stdout = "not json\n"
        result = nuclei.parse_output(stdout)
        assert result == []

    def test_parse_output_empty(self) -> None:
        assert nuclei.parse_output("") == []


class TestDalfox:
    def test_parse_output_finding(self) -> None:
        stdout = (
            '{"url":"https://test.com/search","param":"q","payload":"<script>alert(1)</script>",'
            '"confidence":0.9,"message":"XSS found"}\n'
        )
        result = dalfox.parse_output(stdout)
        assert len(result) == 1
        assert result[0].finding_type.value == "xss"
        assert result[0].parameter == "q"
        assert result[0].confidence == 0.9

    def test_parse_output_empty(self) -> None:
        assert dalfox.parse_output("") == []


class TestSqlmap:
    def test_parse_output_vulnerable(self) -> None:
        stdout = "Parameter 'id' is vulnerable. Do you want to exploit?\n"
        result = sqlmap.parse_output(stdout)
        assert len(result) == 1
        assert result[0].finding_type.value == "sqli"
        assert result[0].parameter == "id"

    def test_parse_output_no_vuln(self) -> None:
        stdout = "All tested parameters are not injectable.\n"
        result = sqlmap.parse_output(stdout)
        assert result == []

    def test_parse_output_empty(self) -> None:
        assert sqlmap.parse_output("") == []



