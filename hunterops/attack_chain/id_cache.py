from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from hunterops.runtime_paths import resolve_path, ensure_directory


class IdCache:
    def __init__(self, path: str | Path, ttl_seconds: int = 86400) -> None:
        self.path = resolve_path(str(path))
        self.ttl_seconds = max(60, int(ttl_seconds))
        ensure_directory(self.path.parent)
        self._cache: dict[str, dict[str, dict[str, float]]] = {}
        self._loaded = False

    def _load(self) -> None:
        if self._loaded:
            return
        if self.path.exists():
            try:
                raw = json.loads(self.path.read_text(encoding="utf-8"))
                if isinstance(raw, dict):
                    self._cache = raw
            except Exception:
                self._cache = {}
        self._loaded = True

    def _persist(self) -> None:
        try:
            self.path.write_text(json.dumps(self._cache, ensure_ascii=True, indent=2), encoding="utf-8")
        except Exception:
            pass

    def _prune(self) -> None:
        now = time.time()
        for program, buckets in list(self._cache.items()):
            for kind, values in list((buckets or {}).items()):
                for key, ts in list((values or {}).items()):
                    if now - float(ts or 0.0) > self.ttl_seconds:
                        values.pop(key, None)
                if not values:
                    buckets.pop(kind, None)
            if not buckets:
                self._cache.pop(program, None)

    def add(self, program: str, kind: str, value: str) -> None:
        self._load()
        program = str(program or "default").strip().lower()
        kind = str(kind or "generic").strip().lower()
        value = str(value or "").strip()
        if not value:
            return
        self._prune()
        self._cache.setdefault(program, {}).setdefault(kind, {})[value] = time.time()
        self._persist()

    def get(self, program: str, kind: str) -> list[str]:
        self._load()
        program = str(program or "default").strip().lower()
        kind = str(kind or "generic").strip().lower()
        self._prune()
        values = list((self._cache.get(program, {}) or {}).get(kind, {}).keys())
        return values


DEFAULT_ID_CACHE = IdCache("data/cache/idor_ids.json", ttl_seconds=86400)

