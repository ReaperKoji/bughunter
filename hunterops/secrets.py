from __future__ import annotations

import os
from pathlib import Path

from hunterops.runtime_paths import resolve_path


def read_secret(name: str, default: str = "") -> str:
    key = str(name or "").strip()
    if not key:
        return default
    direct = os.getenv(key, "").strip()
    if direct:
        return direct
    file_env = os.getenv(f"{key}_FILE", "").strip()
    if file_env:
        path = resolve_path(file_env, prefer_existing=True)
        try:
            return path.read_text(encoding="utf-8").strip()
        except Exception:
            return default
    cred_dir = os.getenv("CREDENTIALS_DIRECTORY", "").strip()
    if cred_dir:
        path = Path(cred_dir) / key
        if path.exists():
            try:
                return path.read_text(encoding="utf-8").strip()
            except Exception:
                return default
    return default
