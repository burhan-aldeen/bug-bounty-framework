from dataclasses import dataclass, field
from enum import Enum


class Severity(Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingType(Enum):
    XSS = "xss"
    SQLI = "sqli"
    SSRF = "ssrf"
    OPEN_REDIRECT = "open_redirect"
    RCE = "rce"
    SSTI = "ssti"
    GRAPHQL = "graphql"
    IDOR = "idor"
    JWT = "jwt"
    HEADER_BYPASS = "header_bypass"
    PARAM_POLLUTION = "param_pollution"
    SECRET = "secret"
    EXPOSED_PATH = "exposed_path"


class SecretType(Enum):
    API_KEY = "api_key"
    TOKEN = "token"
    PASSWORD = "password"
    AWS_KEY = "aws_key"
    JWT_SECRET = "jwt_secret"
    GIT_EXPOSED = "git_exposed"
    ENV_EXPOSED = "env_exposed"
    JS_SECRET = "js_secret"
    CONFIG_EXPOSED = "config_exposed"
    DEBUG_ENDPOINT = "debug_endpoint"


@dataclass
class Subdomain:
    domain: str = ""
    source: str = ""


@dataclass
class AliveHost:
    url: str = ""
    status_code: int = 0
    title: str = ""
    tech: list[str] = field(default_factory=list)
    cdn: bool = False
    content_length: int = 0
    headers: dict[str, str] = field(default_factory=dict)
    ip: str = ""
    cname: str = ""


@dataclass
class Finding:
    finding_type: FindingType = FindingType.XSS
    url: str = ""
    parameter: str = ""
    payload: str = ""
    confidence: float = 0.5
    severity: Severity = Severity.MEDIUM
    detail: str = ""


@dataclass
class SecretFinding:
    url: str = ""
    secret_type: SecretType = SecretType.CONFIG_EXPOSED
    match: str = ""
    severity: Severity = Severity.HIGH
    detail: str = ""


@dataclass
class ToolResult:
    tool: str = ""
    returncode: int = 0
    stdout: str = ""
    stderr: str = ""
    skipped: bool = False


@dataclass
class Report:
    target: str = ""
    timestamp: str = ""
    findings: list[Finding] = field(default_factory=list)
    secrets: list[SecretFinding] = field(default_factory=list)
    ai_summary: str = ""


@dataclass
class ScanResult:
    target: str = ""
    subdomains: list[Subdomain] = field(default_factory=list)
    alive_hosts: list[AliveHost] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    secrets: list[SecretFinding] = field(default_factory=list)
    params: list[str] = field(default_factory=list)
    xss_candidates: list[str] = field(default_factory=list)
    sqli_candidates: list[str] = field(default_factory=list)
