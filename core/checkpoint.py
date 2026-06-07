import json
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any

from core.logger import get_logger
from core.models import AliveHost, Finding, SecretFinding, Severity, Subdomain

logger = get_logger("checkpoint")

CHECKPOINT_DIR = ".checkpoint"


def _cp_dir(output_dir: Path) -> Path:
    return output_dir / CHECKPOINT_DIR


def _phase_path(output_dir: Path) -> Path:
    return _cp_dir(output_dir) / "phase"


def _data_path(output_dir: Path, name: str) -> Path:
    return _cp_dir(output_dir) / f"{name}.json"


def _serialize(obj: Any) -> Any:
    if is_dataclass(obj):
        return asdict(obj)
    return obj


def save_phase(output_dir: Path, phase: int, name: str, data: Any) -> None:
    cp = _cp_dir(output_dir)
    cp.mkdir(parents=True, exist_ok=True)
    _phase_path(output_dir).write_text(str(phase))
    _data_path(output_dir, name).write_text(json.dumps(data, default=_serialize, indent=2))
    logger.debug("checkpoint saved: phase=%d %s", phase, name)


def load_phase(output_dir: Path, phase: int, name: str) -> Any | None:
    path = _data_path(output_dir, name)
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return None


def completed_phase(output_dir: Path) -> int:
    path = _phase_path(output_dir)
    if not path.exists():
        return 0
    try:
        return int(path.read_text().strip())
    except (ValueError, OSError):
        return 0


def clear(output_dir: Path) -> None:
    cp = _cp_dir(output_dir)
    if cp.exists():
        for f in cp.iterdir():
            f.unlink()
        cp.rmdir()
        logger.debug("checkpoints cleared")


def rebuild_subdomains(raw: list[list[dict]]) -> list[list[Subdomain]]:
    return [[Subdomain(**s) for s in group] for group in raw]


def rebuild_alive(raw: list[dict]) -> list[AliveHost]:
    return [_alive_from_dict(d) for d in raw]


def rebuild_findings(raw: list[dict]) -> list[Finding]:
    return [_finding_from_dict(d) for d in raw]


def rebuild_secrets(raw: list[dict]) -> list[SecretFinding]:
    return [SecretFinding(**d) for d in raw]


def _alive_from_dict(d: dict) -> AliveHost:
    return AliveHost(
        url=d["url"],
        status_code=d.get("status_code", 0),
        title=d.get("title", ""),
        tech=d.get("tech", []),
        cdn=d.get("cdn", False),
        content_length=d.get("content_length", 0),
        headers=d.get("headers", {}),
    )


def _finding_from_dict(d: dict) -> Finding:
    return Finding(
        finding_type=d["finding_type"],
        url=d["url"],
        parameter=d.get("parameter"),
        payload=d.get("payload"),
        confidence=d.get("confidence", 0.5),
        detail=d.get("detail", ""),
        severity=Severity(d.get("severity", "medium")),
    )
