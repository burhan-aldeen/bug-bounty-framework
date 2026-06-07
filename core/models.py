from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingType(str, Enum):
    XSS = "xss"
    SQLI = "sqli"
    SSRF = "ssrf"
    OPEN_REDIRECT = "open_redirect"
    JWT = "jwt"
    IDOR = "idor"
    GRAPHQL = "graphql"
    SSTI = "ssti"
    RCE = "rce"
    SECRET = "secret"


class SecretType(str, Enum):
    API_KEY = "api_key"
    ENV_FILE = "env_file"
    GIT_EXPOSED = "git_exposed"
    HARDCODED_CREDENTIAL = "hardcoded_credential"
    CONFIG_EXPOSED = "config_exposed"
    JS_SECRET = "js_secret"


@dataclass
class Subdomain:
    domain: str
    source: str


@dataclass
class AliveHost:
    url: str
    status_code: int
    title: str
    tech: list[str] = field(default_factory=list)
    cdn: bool = False
    content_length: int = 0
    headers: dict[str, str] = field(default_factory=dict)


@dataclass
class Finding:
    finding_type: FindingType
    url: str
    parameter: Optional[str] = None
    payload: Optional[str] = None
    confidence: float = 0.5
    detail: str = ""
    severity: Severity = Severity.MEDIUM


@dataclass
class SecretFinding:
    url: str
    secret_type: SecretType
    match: str
    severity: Severity = Severity.HIGH
    detail: str = ""


@dataclass
class ToolResult:
    tool: str
    returncode: int
    stdout: str
    stderr: str
    skipped: bool = False


@dataclass
class Report:
    target: str
    findings: list[Finding] = field(default_factory=list)
    secrets: list[SecretFinding] = field(default_factory=list)
    ai_summary: Optional[str] = None
    timestamp: str = ""


@dataclass
class ScanResult:
    target: str
    subdomains: list[Subdomain] = field(default_factory=list)
    alive_hosts: list[AliveHost] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    secrets: list[SecretFinding] = field(default_factory=list)
