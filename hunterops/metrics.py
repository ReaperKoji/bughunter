from __future__ import annotations

from pathlib import Path
from typing import Any

try:
    from prometheus_client import Counter, Gauge, Histogram, start_http_server, generate_latest, REGISTRY
except Exception:  # pragma: no cover
    Counter = Gauge = Histogram = None  # type: ignore
    start_http_server = None  # type: ignore
    generate_latest = None  # type: ignore
    REGISTRY = None  # type: ignore

_ENABLED = False

REQUESTS_TOTAL = None
LATENCY_SECONDS = None
FP_SPIKE_TOTAL = None
FP_SPIKE_TOTAL_BY_PROGRAM = None
AUTH_FAILURES_TOTAL = None
AUTH_RETRIES_TOTAL = None
ACTIVE_SESSIONS = None
HTTP_403_429_TOTAL = None
CANDIDATES_TOTAL = None
POC_VALID_TOTAL = None
ERRORS_TOTAL = None
TARGETS_PROCESSED_TOTAL = None
TASK_QUEUE_DEPTH = None
TASKS_TOTAL = None
CACHE_HIT_TOTAL = None
CACHE_MISS_TOTAL = None
PLUGIN_LATENCY_SECONDS = None
SCOPE_BLOCKED_TOTAL = None
SCOPE_BLOCKED_PATH_TOTAL = None
PROGRAM_BUDGET_BLOCKED_TOTAL = None


def enable_metrics(port: int = 9108) -> None:
    global _ENABLED
    global REQUESTS_TOTAL
    global LATENCY_SECONDS
    global FP_SPIKE_TOTAL
    global FP_SPIKE_TOTAL_BY_PROGRAM
    global AUTH_FAILURES_TOTAL
    global AUTH_RETRIES_TOTAL
    global ACTIVE_SESSIONS
    global HTTP_403_429_TOTAL
    global CANDIDATES_TOTAL
    global POC_VALID_TOTAL
    global ERRORS_TOTAL
    global TARGETS_PROCESSED_TOTAL
    global BASELINE_SCORE
    global TASK_QUEUE_DEPTH
    global TASKS_TOTAL
    global CACHE_HIT_TOTAL
    global CACHE_MISS_TOTAL
    global PLUGIN_LATENCY_SECONDS
    global SCOPE_BLOCKED_TOTAL
    global SCOPE_BLOCKED_PATH_TOTAL
    global PROGRAM_BUDGET_BLOCKED_TOTAL
    if Counter is None or start_http_server is None:
        return
    if _ENABLED:
        return
    REQUESTS_TOTAL = Counter("app_requests_total", "Total HTTP requests", ["status"])
    LATENCY_SECONDS = Histogram("app_latency_seconds", "HTTP request latency", ["endpoint"])
    FP_SPIKE_TOTAL = Counter("app_false_positive_spike_total", "False positive spike events")
    FP_SPIKE_TOTAL_BY_PROGRAM = Counter("app_false_positive_spike_by_program_total", "False positive spikes by program", ["program"])
    AUTH_FAILURES_TOTAL = Counter("app_auth_failures_total", "Auth failures", ["session"])
    AUTH_RETRIES_TOTAL = Counter("app_auth_retries_total", "Auth retries", ["session"])
    ACTIVE_SESSIONS = Gauge("app_active_session_count", "Active session count")
    HTTP_403_429_TOTAL = Counter("app_403_429_total", "403/429 responses", ["status"])
    CANDIDATES_TOTAL = Counter("app_candidates_total", "Candidate findings", ["module"])
    POC_VALID_TOTAL = Counter("app_poc_valid_total", "Validated PoCs", ["module"])
    ERRORS_TOTAL = Counter("app_errors_total", "Module errors", ["module"])
    TARGETS_PROCESSED_TOTAL = Counter("app_targets_processed_total", "Targets processed")
    BASELINE_SCORE = Histogram("app_baseline_score", "Baseline divergence score", ["program"])
    TASK_QUEUE_DEPTH = Gauge("app_task_queue_depth", "Task queue depth")
    TASKS_TOTAL = Counter("app_tasks_total", "Tasks processed", ["status"])
    CACHE_HIT_TOTAL = Counter("app_endpoint_cache_hit_total", "Endpoint cache hits")
    CACHE_MISS_TOTAL = Counter("app_endpoint_cache_miss_total", "Endpoint cache misses")
    PLUGIN_LATENCY_SECONDS = Histogram("app_plugin_latency_seconds", "Plugin latency", ["plugin"])
    SCOPE_BLOCKED_TOTAL = Counter("app_scope_blocked_total", "Requests blocked by scope")
    SCOPE_BLOCKED_PATH_TOTAL = Counter("app_scope_blocked_path_total", "Requests blocked by blocked paths")
    PROGRAM_BUDGET_BLOCKED_TOTAL = Counter("app_program_budget_blocked_total", "Requests blocked by program budget", ["program"])
    start_http_server(int(port))
    _ENABLED = True


def metrics_enabled() -> bool:
    return _ENABLED and REQUESTS_TOTAL is not None


def write_metrics_snapshot(path: str | Path) -> bool:
    if not metrics_enabled() or generate_latest is None or REGISTRY is None:
        return False
    try:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(generate_latest(REGISTRY))
        return True
    except Exception:
        return False


def inc_request(status: int) -> None:
    if not metrics_enabled():
        return
    REQUESTS_TOTAL.labels(status=str(int(status or 0))).inc()
    if int(status or 0) in {403, 429}:
        HTTP_403_429_TOTAL.labels(status=str(int(status or 0))).inc()


def observe_latency(endpoint: str, seconds: float) -> None:
    if not metrics_enabled():
        return
    LATENCY_SECONDS.labels(endpoint=endpoint).observe(float(seconds))


def inc_fp_spike(program: str | None = None) -> None:
    if not metrics_enabled():
        return
    FP_SPIKE_TOTAL.inc()
    if program is not None:
        FP_SPIKE_TOTAL_BY_PROGRAM.labels(program=str(program)).inc()


def inc_auth_failure(session: str) -> None:
    if not metrics_enabled():
        return
    AUTH_FAILURES_TOTAL.labels(session=session).inc()


def inc_auth_retry(session: str) -> None:
    if not metrics_enabled():
        return
    AUTH_RETRIES_TOTAL.labels(session=session).inc()


def set_active_sessions(count: int) -> None:
    if not metrics_enabled():
        return
    ACTIVE_SESSIONS.set(int(count))


def inc_candidate(module: str) -> None:
    if not metrics_enabled():
        return
    CANDIDATES_TOTAL.labels(module=module).inc()


def inc_poc_valid(module: str) -> None:
    if not metrics_enabled():
        return
    POC_VALID_TOTAL.labels(module=module).inc()


def inc_error(module: str) -> None:
    if not metrics_enabled():
        return
    ERRORS_TOTAL.labels(module=module).inc()


def inc_target_processed() -> None:
    if not metrics_enabled():
        return
    TARGETS_PROCESSED_TOTAL.inc()


def set_task_queue_depth(depth: int) -> None:
    if not metrics_enabled():
        return
    TASK_QUEUE_DEPTH.set(int(depth))


def inc_task(status: str) -> None:
    if not metrics_enabled():
        return
    TASKS_TOTAL.labels(status=str(status)).inc()


def inc_cache_hit() -> None:
    if not metrics_enabled():
        return
    CACHE_HIT_TOTAL.inc()


def inc_cache_miss() -> None:
    if not metrics_enabled():
        return
    CACHE_MISS_TOTAL.inc()


def observe_plugin_latency(plugin: str, seconds: float) -> None:
    if not metrics_enabled():
        return
    PLUGIN_LATENCY_SECONDS.labels(plugin=str(plugin)).observe(float(seconds))


def inc_scope_blocked() -> None:
    if not metrics_enabled():
        return
    SCOPE_BLOCKED_TOTAL.inc()


def inc_scope_blocked_path() -> None:
    if not metrics_enabled():
        return
    SCOPE_BLOCKED_PATH_TOTAL.inc()


def inc_program_budget_blocked(program: str | None = None) -> None:
    if not metrics_enabled():
        return
    PROGRAM_BUDGET_BLOCKED_TOTAL.labels(program=str(program or "unknown")).inc()


def dump_metrics_snapshot() -> dict[str, Any]:
    return {"enabled": metrics_enabled()}


def observe_baseline_score(program: str, score: float) -> None:
    if not metrics_enabled():
        return
    BASELINE_SCORE.labels(program=str(program or "unknown")).observe(float(score))
