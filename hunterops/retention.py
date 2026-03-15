from __future__ import annotations

import time
from pathlib import Path
from typing import Callable


def cleanup_old_files(root: Path, max_age_seconds: int, log: Callable[[str], None] | None = None) -> int:
    if max_age_seconds <= 0:
        return 0
    if not root.exists():
        return 0
    now = time.time()
    removed = 0
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        try:
            age = now - path.stat().st_mtime
        except Exception:
            continue
        if age >= max_age_seconds:
            try:
                path.unlink()
                removed += 1
            except Exception:
                continue
    if removed and log:
        log(f"retention_cleanup removed_files={removed} root={root}")
    return removed
