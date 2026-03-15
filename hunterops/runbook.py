from __future__ import annotations

import json
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from hunterops.runtime_paths import resolve_path


def _now_ts() -> float:
    return time.time()


def _to_iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def _from_iso(raw: str) -> float:
    return datetime.fromisoformat(raw.replace("Z", "+00:00")).timestamp()


@dataclass
class RunbookOverride:
    paused: bool = False
    pause_reason: str = ""
    pause_until: float | None = None
    rate_multiplier: float | None = None
    rate_until: float | None = None
    blocked_hosts: dict[str, float] = None

    def __post_init__(self) -> None:
        if self.blocked_hosts is None:
            self.blocked_hosts = {}


class RunbookManager:
    def __init__(self, cfg: dict[str, Any] | None = None) -> None:
        settings = cfg if isinstance(cfg, dict) else {}
        self.enabled = bool(settings.get("enabled", True))
        self.override_path = resolve_path(
            settings.get("override_path", "data/runtime/runbook_override.json"),
            prefer_existing=False,
        )
        self.auto_pause_fp_rate = float(settings.get("auto_pause_fp_rate", 0.6) or 0.6)
        self.auto_pause_error_rate = float(settings.get("auto_pause_error_rate", 0.3) or 0.3)
        self.auto_reduce_rate_error_rate = float(settings.get("auto_reduce_rate_error_rate", 0.2) or 0.2)
        self.auto_blacklist_403_429_threshold = int(settings.get("auto_blacklist_403_429_threshold", 5) or 5)
        self.pause_minutes = int(settings.get("pause_minutes", 15) or 15)
        self.reduce_rate_multiplier = float(settings.get("reduce_rate_multiplier", 0.5) or 0.5)
        self.reduce_rate_minutes = int(settings.get("reduce_rate_minutes", 20) or 20)
        self.blacklist_minutes = int(settings.get("blacklist_minutes", 15) or 15)
        self._cache: RunbookOverride | None = None
        self._cache_mtime: float = 0.0

    def _load(self) -> RunbookOverride:
        if not self.enabled:
            return RunbookOverride()
        path = self.override_path
        if not path.exists():
            self._cache = RunbookOverride()
            self._cache_mtime = 0.0
            return self._cache
        try:
            mtime = float(path.stat().st_mtime)
        except Exception:
            mtime = 0.0
        if self._cache and abs(mtime - self._cache_mtime) < 0.001:
            return self._cache
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            data = {}
        override = RunbookOverride(
            paused=bool(data.get("paused", False)),
            pause_reason=str(data.get("pause_reason", "")),
            pause_until=_from_iso(data["pause_until"]) if data.get("pause_until") else None,
            rate_multiplier=float(data.get("rate_multiplier")) if data.get("rate_multiplier") is not None else None,
            rate_until=_from_iso(data["rate_until"]) if data.get("rate_until") else None,
            blocked_hosts={
                str(k): _from_iso(v) if isinstance(v, str) else float(v)
                for k, v in (data.get("blocked_hosts", {}) or {}).items()
            },
        )
        self._cache = override
        self._cache_mtime = mtime
        return override

    def _write(self, override: RunbookOverride, reason: str = "") -> None:
        if not self.enabled:
            return
        payload = {
            "updated_at": _to_iso(_now_ts()),
            "paused": bool(override.paused),
            "pause_reason": str(reason or override.pause_reason),
            "pause_until": _to_iso(override.pause_until) if override.pause_until else "",
            "rate_multiplier": override.rate_multiplier if override.rate_multiplier is not None else "",
            "rate_until": _to_iso(override.rate_until) if override.rate_until else "",
            "blocked_hosts": {k: _to_iso(v) for k, v in (override.blocked_hosts or {}).items()},
        }
        self.override_path.parent.mkdir(parents=True, exist_ok=True)
        self.override_path.write_text(json.dumps(payload, ensure_ascii=True, indent=2), encoding="utf-8")
        self._cache = override
        try:
            self._cache_mtime = float(self.override_path.stat().st_mtime)
        except Exception:
            self._cache_mtime = 0.0

    def is_paused(self) -> tuple[bool, str]:
        override = self._load()
        if not override.paused:
            return False, ""
        if override.pause_until and _now_ts() >= override.pause_until:
            override.paused = False
            override.pause_until = None
            self._write(override, reason="pause_expired")
            return False, ""
        return True, override.pause_reason or "runbook_pause"

    def is_host_blocked(self, host: str) -> bool:
        override = self._load()
        if not host:
            return False
        until = override.blocked_hosts.get(host)
        if until is None:
            return False
        if _now_ts() >= until:
            override.blocked_hosts.pop(host, None)
            self._write(override, reason="block_expired")
            return False
        return True

    def apply_policy(self, policy: dict[str, Any]) -> dict[str, Any]:
        if not self.enabled:
            return policy
        override = self._load()
        multiplier = override.rate_multiplier if override.rate_multiplier is not None else 1.0
        if override.rate_until and _now_ts() >= override.rate_until:
            override.rate_multiplier = None
            override.rate_until = None
            self._write(override, reason="rate_override_expired")
            multiplier = 1.0
        if multiplier <= 0:
            multiplier = 1.0
        for key in ("per_host_rpm", "per_target_rpm", "concurrency_per_host"):
            if key in policy and isinstance(policy[key], (int, float)):
                value = max(1, int(float(policy[key]) * multiplier))
                policy[key] = value
        return policy

    def pause(self, *, minutes: int, reason: str) -> None:
        if not self.enabled:
            return
        override = self._load()
        override.paused = True
        override.pause_reason = reason
        override.pause_until = _now_ts() + (minutes * 60)
        self._write(override, reason=reason)

    def reduce_rate(self, *, multiplier: float, minutes: int, reason: str) -> None:
        if not self.enabled:
            return
        override = self._load()
        override.rate_multiplier = max(0.1, float(multiplier))
        override.rate_until = _now_ts() + (minutes * 60)
        self._write(override, reason=reason)

    def block_host(self, host: str, *, minutes: int, reason: str) -> None:
        if not self.enabled or not host:
            return
        override = self._load()
        override.blocked_hosts[str(host).strip().lower()] = _now_ts() + (minutes * 60)
        self._write(override, reason=reason)

    def auto_actions(self, *, fp_rate: float, error_rate: float) -> list[str]:
        actions: list[str] = []
        if not self.enabled:
            return actions
        if fp_rate >= self.auto_pause_fp_rate or error_rate >= self.auto_pause_error_rate:
            self.pause(minutes=self.pause_minutes, reason="auto_pause_high_fp_or_error")
            actions.append("pause")
            return actions
        if error_rate >= self.auto_reduce_rate_error_rate:
            self.reduce_rate(
                multiplier=self.reduce_rate_multiplier,
                minutes=self.reduce_rate_minutes,
                reason="auto_reduce_rate_high_error",
            )
            actions.append("reduce_rate")
        return actions
