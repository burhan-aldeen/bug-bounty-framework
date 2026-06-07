from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class RuntimeConfig:
    concurrency: int = 5
    timeout_seconds: int = 60
    retries: int = 2
    per_host_delay: float = 1.0


@dataclass
class OllamaConfig:
    url: str = "http://localhost:11434"
    model: str = "qwen3.5:9b"
    timeout_seconds: int = 120
    enabled: bool = True


@dataclass
class ScanConfig:
    target: str = ""
    authorized: bool = False
    quick: bool = False
    output_dir: Path = Path("output")
    subdomains_file: Path | None = None


@dataclass
class Config:
    runtime: RuntimeConfig = field(default_factory=RuntimeConfig)
    ollama: OllamaConfig = field(default_factory=OllamaConfig)
    scan: ScanConfig = field(default_factory=ScanConfig)
