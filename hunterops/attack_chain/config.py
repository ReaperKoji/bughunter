from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from hunterops.runtime_paths import resolve_path


def load_attack_pipeline(path: str | Path) -> dict[str, Any]:
    resolved = resolve_path(path)
    if not resolved.exists():
        raise FileNotFoundError(f"Attack pipeline config not found: {resolved}")
    raw = resolved.read_text(encoding="utf-8")
    data = yaml.safe_load(raw) or {}
    if "pipeline" in data and isinstance(data.get("pipeline"), dict):
        return data["pipeline"]
    return data


def resolve_path_from_cfg(value: str | Path, *, base: Path | None = None) -> Path:
    return resolve_path(value, base=base, prefer_existing=False)
