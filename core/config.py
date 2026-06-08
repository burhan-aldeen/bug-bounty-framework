from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ScanConfig:
    target: str = ""
    authorized: bool = False
    quick: bool = False
    output_dir: Path = Path("output")
    subs_list: Path | None = None
    targets_file: Path | None = None


@dataclass
class OllamaConfig:
    url: str = "http://localhost:11434"
    model: str = "llama3.2"
    timeout_seconds: int = 60


@dataclass
class OpenAIConfig:
    api_key: str = ""
    model: str = "gpt-4o-mini"
    timeout_seconds: int = 60


@dataclass
class Config:
    scan: ScanConfig = field(default_factory=ScanConfig)
    ollama: OllamaConfig = field(default_factory=OllamaConfig)
    openai: OpenAIConfig = field(default_factory=OpenAIConfig)
