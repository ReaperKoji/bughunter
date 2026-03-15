from __future__ import annotations

import time
from typing import Any

from hunterops.metrics import inc_cache_hit, inc_cache_miss
from hunterops.storage import PostgresStorage
from hunterops.url_utils import normalize_endpoint


def _normalize_endpoint_key(raw: str) -> str:
    return normalize_endpoint(raw)


class EndpointCache:
    """Shared endpoint cache with local + optional persistent storage."""

    def __init__(
        self,
        *,
        storage: PostgresStorage | None,
        enabled: bool,
        ttl_seconds: int,
        max_entries: int = 50000,
    ) -> None:
        self.storage = storage
        self.enabled = bool(enabled)
        self.ttl_seconds = max(0, int(ttl_seconds))
        self.max_entries = max(0, int(max_entries))
        self._local: dict[tuple[str, str, str], float] = {}

    def _key(self, plugin: str, target: str, endpoint: str) -> tuple[str, str, str]:
        return (str(plugin).strip().lower(), str(target).strip().lower(), _normalize_endpoint_key(endpoint))

    def _prune_local(self, now: float) -> None:
        if not self._local:
            return
        ttl = max(0, int(self.ttl_seconds))
        if ttl > 0:
            for key, ts in list(self._local.items()):
                if (now - float(ts)) > ttl:
                    self._local.pop(key, None)
        if self.max_entries > 0 and len(self._local) > self.max_entries:
            items = sorted(self._local.items(), key=lambda row: row[1])
            for key, _ in items[: max(0, len(items) - self.max_entries)]:
                self._local.pop(key, None)

    def was_seen(self, *, plugin: str, target: str, endpoint: str) -> bool:
        if not self.enabled or self.ttl_seconds <= 0:
            return False
        now = time.time()
        self._prune_local(now)
        key = self._key(plugin, target, endpoint)
        ts = self._local.get(key)
        if ts is not None and (now - float(ts)) <= self.ttl_seconds:
            inc_cache_hit()
            return True
        if self.storage is None:
            inc_cache_miss()
            return False
        try:
            seen = self.storage.endpoint_seen_recently(
                plugin=str(plugin),
                target=str(target),
                endpoint=_normalize_endpoint_key(endpoint),
                ttl_seconds=int(self.ttl_seconds),
            )
            if seen:
                inc_cache_hit()
            else:
                inc_cache_miss()
            return seen
        except Exception:
            inc_cache_miss()
            return False

    def mark_seen(self, *, plugin: str, target: str, endpoint: str) -> None:
        if not self.enabled or self.ttl_seconds <= 0:
            return
        now = time.time()
        self._prune_local(now)
        key = self._key(plugin, target, endpoint)
        self._local[key] = now
        if self.storage is None:
            return
        try:
            self.storage.mark_endpoint_seen(
                plugin=str(plugin),
                target=str(target),
                endpoint=_normalize_endpoint_key(endpoint),
            )
        except Exception:
            return

    def mark_many(self, *, plugin: str, target: str, endpoints: list[str]) -> None:
        for ep in endpoints or []:
            if not isinstance(ep, str) or not ep.strip():
                continue
            self.mark_seen(plugin=plugin, target=target, endpoint=ep)
