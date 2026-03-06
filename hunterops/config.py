from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml
from hunterops.runtime_paths import resolve_path


def load_config(path: Path | str) -> dict[str, Any]:
    resolved = resolve_path(path)
    if not resolved.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    suffix = resolved.suffix.lower()
    raw = resolved.read_text(encoding="utf-8")
    if suffix in {".yaml", ".yml"}:
        return yaml.safe_load(raw) or {}
    if suffix == ".json":
        return json.loads(raw)
    raise ValueError("Unsupported config format. Use YAML or JSON.")


def get_runtime(config: dict[str, Any]) -> dict[str, Any]:
    raw = config.get("runtime", {})
    runtime = dict(raw) if isinstance(raw, dict) else {}

    def _as_int(key: str, default: int) -> int:
        try:
            return int(runtime.get(key, default))
        except Exception:
            return int(default)

    def _as_float(key: str, default: float) -> float:
        try:
            return float(runtime.get(key, default))
        except Exception:
            return float(default)

    def _as_bool(key: str, default: bool) -> bool:
        value = runtime.get(key, default)
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.strip().lower() in {"1", "true", "yes", "on"}
        return bool(value)

    def _as_list(key: str, default: list[Any] | None = None) -> list[Any]:
        value = runtime.get(key, default if default is not None else [])
        return value if isinstance(value, list) else (default if default is not None else [])

    runtime["concurrency"] = max(1, _as_int("concurrency", 8))
    runtime["timeout_seconds"] = max(1, _as_int("timeout_seconds", 25))
    runtime["task_timeout_seconds"] = max(30.0, _as_float("task_timeout_seconds", float(runtime["timeout_seconds"]) * 4.0))
    runtime["batch_heartbeat_seconds"] = max(5.0, _as_float("batch_heartbeat_seconds", 15.0))
    runtime["rate_limit_per_sec"] = max(0.1, _as_float("rate_limit_per_sec", 4.0))
    runtime["max_retries"] = max(0, _as_int("max_retries", 2))
    runtime["backoff_base_seconds"] = max(0.0, _as_float("backoff_base_seconds", 1.2))
    runtime["task_queue_size"] = max(100, _as_int("task_queue_size", 2000))
    runtime["enable_recursive_tasks"] = _as_bool("enable_recursive_tasks", True)
    runtime["recursion_max_depth"] = max(1, _as_int("recursion_max_depth", 5))
    runtime["recursion_max_tasks"] = max(1, _as_int("recursion_max_tasks", 500))
    runtime["recursion_max_tasks_step"] = max(1, _as_int("recursion_max_tasks_step", 150))
    runtime["recursion_max_tasks_cap"] = max(runtime["recursion_max_tasks"], _as_int("recursion_max_tasks_cap", 5000))
    runtime["feedback_max_retries"] = max(0, _as_int("feedback_max_retries", 2))
    runtime["feedback_base_delay_seconds"] = max(0.0, _as_float("feedback_base_delay_seconds", 1.2))
    runtime["feedback_max_delay_seconds"] = max(runtime["feedback_base_delay_seconds"], _as_float("feedback_max_delay_seconds", 25.0))
    runtime["feedback_streak_threshold"] = max(1, _as_int("feedback_streak_threshold", 3))
    runtime["feedback_hard_pause_seconds"] = max(1.0, _as_float("feedback_hard_pause_seconds", 60.0))
    runtime["max_tasks_per_target"] = max(50, _as_int("max_tasks_per_target", 1200))
    runtime["max_rounds_per_target"] = max(1, _as_int("max_rounds_per_target", 6))
    runtime["stealth_mode"] = _as_bool("stealth_mode", True)
    runtime["plugin_profile"] = str(runtime.get("plugin_profile", "safe") or "safe").strip().lower() or "safe"
    runtime["adaptive_levels"] = runtime.get("adaptive_levels", {}) if isinstance(runtime.get("adaptive_levels"), dict) else {}
    runtime["proxies"] = _as_list("proxies", [])
    runtime["user_agents"] = _as_list("user_agents", [])
    runtime["wordlists"] = runtime.get("wordlists", {"default": "wordlists/common.txt"}) if isinstance(runtime.get("wordlists"), dict) else {"default": "wordlists/common.txt"}

    return runtime
