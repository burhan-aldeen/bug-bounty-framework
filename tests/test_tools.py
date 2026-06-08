from tools.subfinder import parse_output as parse_subfinder
from tools.assetfinder import parse_output as parse_assetfinder
from tools.crtsh import parse_output as parse_crtsh
from tools.httpx_tool import parse_output as parse_httpx
from tools.gau import parse_output as parse_gau
from tools.katana import parse_output as parse_katana
from tools.gospider import parse_output as parse_gospider
from tools.gowitness import parse_output as parse_gowitness
from tools.nuclei import parse_output as parse_nuclei
from tools.dalfox import parse_output as parse_dalfox
from tools.sqlmap import parse_output as parse_sqlmap


class TestSubfinder:
    def test_parse_output_returns_subdomains(self):
        data = "sub1.example.com\nsub2.example.com\n"
        result = parse_subfinder(data, "subfinder")
        assert len(result) == 2
        assert result[0].domain == "sub1.example.com"

    def test_parse_output_empty(self):
        assert parse_subfinder("", "subfinder") == []

    def test_parse_output_skips_bracket_lines(self):
        data = "[INFO] loading config\nsub.example.com\n"
        result = parse_subfinder(data, "subfinder")
        assert len(result) == 1


class TestAssetfinder:
    def test_parse_output_returns_subdomains(self):
        data = "sub1.example.com\nsub2.example.com\n"
        result = parse_assetfinder(data, "assetfinder")
        assert len(result) == 2
        assert result[0].domain == "sub1.example.com"

    def test_parse_output_empty(self):
        assert parse_assetfinder("", "assetfinder") == []


class TestCrtsh:
    def test_parse_output_returns_subdomains(self):
        data = '[{"name_value":"sub1.example.com\\nsub2.example.com"}]'
        result = parse_crtsh(data, "crtsh")
        assert len(result) == 2

    def test_parse_output_invalid_json(self):
        assert parse_crtsh("invalid", "crtsh") == []

    def test_parse_output_skips_wildcard(self):
        data = '[{"name_value":"*.example.com\\nsub.example.com"}]'
        result = parse_crtsh(data, "crtsh")
        assert len(result) == 1
        assert result[0].domain == "sub.example.com"


class TestHttpxTool:
    def test_parse_output_valid_json(self):
        data = '{"url":"http://example.com","status_code":200,"title":"Test","tech":[],"cdn":false,"content_length":100}'
        result = parse_httpx(data)
        assert len(result) == 1
        assert result[0].url == "http://example.com"
        assert result[0].status_code == 200

    def test_parse_output_empty(self):
        assert parse_httpx("") == []

    def test_parse_output_invalid_json_skipped(self):
        data = '{"url":"http://example.com"}\nnot json\n{"url":"http://test.com"}'
        result = parse_httpx(data)
        assert len(result) == 2


class TestGau:
    def test_parse_output_returns_urls(self):
        data = "http://example.com/path\nhttp://example.com/other\n"
        result = parse_gau(data)
        assert len(result) == 2

    def test_parse_output_empty(self):
        assert parse_gau("") == []


class TestKatana:
    def test_parse_output_returns_urls(self):
        data = "http://example.com/page1\nhttp://example.com/page2\n"
        result = parse_katana(data)
        assert len(result) == 2

    def test_parse_output_empty(self):
        assert parse_katana("") == []


class TestGospider:
    def test_parse_output_returns_urls(self):
        data = '{"output":"http://example.com/page"}\n{"output":"http://example.com/other"}'
        result = parse_gospider(data)
        assert len(result) == 2

    def test_parse_output_empty(self):
        assert parse_gospider("") == []


class TestGowitness:
    def test_parse_output_returns_paths(self):
        data = "screenshot1.png\nscreenshot2.png\n"
        result = parse_gowitness(data)
        assert len(result) == 2

    def test_parse_output_empty(self):
        assert parse_gowitness("") == []


class TestNuclei:
    def test_parse_output_xss_finding(self):
        data = '{"host":"http://example.com","info":{"name":"Reflected XSS","severity":"high","description":"XSS test"}}'
        result = parse_nuclei(data)
        assert len(result) == 1
        assert result[0].finding_type.value == "xss"

    def test_parse_output_sqli_finding(self):
        data = '{"host":"http://example.com","info":{"name":"SQL Injection","severity":"critical","description":"SQLi test"}}'
        result = parse_nuclei(data)
        assert len(result) == 1
        assert result[0].finding_type.value == "sqli"

    def test_parse_output_empty(self):
        assert parse_nuclei("") == []


class TestDalfox:
    def test_parse_output_finding(self):
        data = '{"data":"http://example.com","param":"q","payload":"<script>","evidence":"test"}'
        result = parse_dalfox(data)
        assert len(result) == 1
        assert result[0].finding_type.value == "xss"

    def test_parse_output_empty(self):
        assert parse_dalfox("") == []


class TestSqlmap:
    def test_parse_output_vulnerable(self):
        data = "Parameter: id (GET) vulnerable"
        result = parse_sqlmap(data)
        assert len(result) == 1

    def test_parse_output_no_vuln(self):
        assert parse_sqlmap("all clear") == []

    def test_parse_output_empty(self):
        assert parse_sqlmap("") == []
