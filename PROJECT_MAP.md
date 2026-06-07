# Bug Bounty Framework — Project Map

Date: 2026-06-08

## [TECH_STACK]

| Component | Version | Source |
|---|---|---|
| Python | 3.14.2 | `python --version` |
| Go | 1.26.3 | `go version` |

### Python stdlib (all confirmed)

`asyncio`, `csv`, `dataclasses`, `enum`, `json`, `logging.handlers`, `pathlib`, `queue`, `re`, `shutil`, `subprocess`, `threading`, `typing`

### Third-party packages

| Package | Version | Use |
|---|---|---|
| httpx | 0.28.1 | Async HTTP for Ollama agent |
| aiohttp | 3.13.5 | Alternate async HTTP |
| ollama | 0.6.1 | Ollama Python SDK |
| pydantic | 2.13.4 | Config validation |
| PyYAML | 6.0.3 | Config file parsing |
| pytest | 9.0.3 | Test runner |
| rich | 15.0.0 | CLI formatting |

### External CLI tools

| Tool | PATH | Status |
|---|---|---|
| subfinder | v2.14.0 | ✅ Found |
| httpx | (projectdiscovery) | ✅ Found |
| assetfinder | (tomnomnom) | ✅ Found |
| naabu | (projectdiscovery) | ✅ Found |
| dnsx | (projectdiscovery) | ✅ Found |
| ffuf | v2.1.0-dev | ✅ Found |
| chaos | (projectdiscovery) | ✅ Found |
| katana | — | ❌ Not found |
| nuclei | — | ❌ Not found |
| dalfox | — | ❌ Not found |
| gau | — | ❌ Not found |
| gospider | — | ❌ Not found |
| gf | — | ❌ Not found |
| anew | — | ❌ Not found |
| gowitness | — | ❌ Not found |
| qsreplace | — | ❌ Not found |
| amass | — | ❌ Not found |
| jwt_tool | — | ❌ Not found |
| waybackurls | — | ❌ Not found |
| sqlmap | (binary) | ❌ Not found (Python pkg 1.10.5 avail) |

## [SYSTEM_FLOW]

```
target domain
    │
    ▼
┌──────────────────────────────────────────────────────────────┐
│  Stage 1 — Recon                                             │
│  Input:  domain: str                                         │
│  Tools:  subfinder, assetfinder, chaos, crt.sh (curl)        │
│  Output: subdomains: list[str]                               │
│  ─────────────────────────────────────                       │
│  httpx (alive check) → live_hosts: list[AliveHost]           │
│  gau, katana, gospider → urls: list[str]                     │
└──────────────────────────────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────────────────────────────┐
│  Stage 2 — Hunt                                              │
│  Input:  urls: list[str], live_hosts: list[AliveHost]        │
│  Tools:  gf → xss/sqli candidates; dalfox → XSS;             │
│          sqlmap → SQLi; qsreplace → SSRF/open redirect;      │
│          nuclei → CVE/template scans                          │
│  Output: findings: list[Finding]                              │
└──────────────────────────────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────────────────────────────┐
│  Stage 3 — API Hacking                                       │
│  Input:  live_hosts: list[AliveHost], urls: list[str]        │
│  Tools:  httpx (GraphQL probe), jwt_tool → JWT analysis,     │
│          parameter pollution tests, header manipulation       │
│  Output: api_findings: list[Finding]                          │
└──────────────────────────────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────────────────────────────┐
│  Stage 4 — Secrets                                           │
│  Input:  live_hosts: list[AliveHost]                         │
│  Tools:  httpx → .env, .git/config, js file analysis,        │
│          gospider → JS crawling                               │
│  Output: secrets: list[SecretFinding]                         │
└──────────────────────────────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────────────────────────────┐
│  Stage 5 — Report                                            │
│  Input:  All prior stage outputs                             │
│  Tools:  gowitness → screenshots; agent.py → AI draft        │
│  Output: report.json, report.csv, report.md                  │
└──────────────────────────────────────────────────────────────┘
```

## [ARCHITECTURE]

```
framework/
├── main.py                  CLI entrypoint (≤ 80 lines)
├── core/
│   ├── __init__.py
│   ├── models.py            All dataclasses + enums. Zero logic.
│   ├── config.py            Config dataclass. Single source of truth.
│   ├── runner.py            run_captured() + run_live() only.
│   ├── logger.py            QueueHandler async-safe. Zero print().
│   └── agent.py             Ollama HTTP client. Graceful fallback.
├── stages/
│   ├── __init__.py
│   ├── recon.py             Stage 1 orchestration
│   ├── hunt.py              Stage 2 orchestration
│   ├── api_hack.py          Stage 3 orchestration
│   ├── secrets.py           Stage 4 orchestration
│   └── report.py            Stage 5 orchestration
├── tools/
│   ├── __init__.py
│   ├── subfinder.py         run() + parse_output() + ToolNotFoundError
│   ├── httpx_tool.py
│   ├── katana.py
│   ├── nuclei.py
│   ├── dalfox.py
│   ├── sqlmap.py
│   ├── gau.py
│   ├── gospider.py
│   └── gowitness.py
├── output/
│   ├── __init__.py
│   └── writer.py            write_json() + write_csv() + write_md()
├── tests/
│   ├── __init__.py
│   ├── conftest.py          Shared mocks/fixtures
│   ├── test_core.py
│   ├── test_agent.py
│   ├── test_tools.py
│   ├── test_stages.py
│   └── test_writer.py
└── PROJECT_MAP.md           Living architecture document
```

## [DATA_MODELS]

```python
@dataclass
class Subdomain:
    domain: str
    source: str

@dataclass
class AliveHost:
    url: str
    status_code: int
    title: str
    tech: list[str]
    cdn: bool
    content_length: int

@dataclass
class Finding:
    type: str          # xss, sqli, ssrf, open_redirect, jwt, idor, graphql
    url: str
    parameter: str | None
    payload: str | None
    confidence: float  # 0.0 - 1.0
    detail: str

@dataclass
class SecretFinding:
    url: str
    secret_type: str   # api_key, .env, .git, hardcoded_credential
    match: str
    severity: str      # critical, high, medium, low

@dataclass
class Report:
    target: str
    findings: list[Finding]
    secrets: list[SecretFinding]
    ai_summary: str | None
    timestamp: str
```

## [MILESTONES]

| Milestone | Goal | Verifiable Test | Status |
|---|---|---|---|
| M0 | Environment audit | `python -m pytest tests/test_env.py` | ✅ DONE |
| M1 | Core layer | models/config/logger/runner all instantiate | ✅ DONE |
| M2 | AI Agent | agent.py handles Ollama + fallback | ✅ DONE |
| M3 | Tool wrappers | All tools/ files run + parse + test | ✅ DONE |
| M4 | Stage implementations | All stages/ orchestrate correctly | ✅ DONE |
| M5 | Output + Integration | writer.py + end-to-end dry run | ✅ DONE |
| M6 | Test suite + Finalize | All tests pass, orphans empty | ✅ DONE |

## [ASSUMPTIONS]

1. Framework runs on Windows (PowerShell). Subprocess calls use platform-appropriate syntax.
2. Missing tools log WARNING and return empty results — never crash.
3. Ollama is the default AI provider; cloud providers are not implemented in this build.
4. No SQLite or database persistence — all output is file-based.
5. The `--authorized` flag is required for all scans (same pattern as bughunter-ai).
6. Target domain must be explicitly provided; no auto-scoping.
7. Python 3.14.2 is the runtime; type hints use `list[str]` syntax (3.9+).

## [ORPHANS & PENDING]

All milestones complete. No orphans at ship time.

### Resolved during build

- `core/runner.py` — added `stdin_data` parameter for tools that require piped input (httpx, katana, nuclei, dalfox, sqlmap, gospider, gowitness).
- `stages/secrets.py` — replaced curl-based HTTP probing with Python `httpx` for Windows compatibility (`NUL` vs `/dev/null` issue).
- `core/agent.py` — uses `ollama` package (v0.6.1) with graceful fallback if package or server is unavailable.
- `tests/test_core.py` — fixed `logger.level` → `logger.getEffectiveLevel()` for Python 3.14 compatibility.
- `tests/test_stages.py` — replaced integration tests (which called real tools) with unit tests using mock functions.

### Future (not implemented, out of scope)

- Cloud AI provider fallback (OpenAI/Gemini/Anthropic) — only Ollama is implemented.
- Shodan/ASN integration for recon enrichment.
- Nuclei template auto-downloader.
- WebSocket/SSE-based real-time progress reporting.
