from __future__ import annotations

import asyncio
import fnmatch
import json
import logging
import os
import random
import re
import time
from datetime import datetime
from zoneinfo import ZoneInfo
from typing import Any

from hunterops.async_runtime import install_uvloop_if_available
from hunterops.plugin_base import Plugin
from hunterops.rate_limit import AsyncRateLimiter
from hunterops.redaction import redact_findings
from hunterops.retry import retry_async
from hunterops.endpoint_cache import EndpointCache
from hunterops.intelligence import dedupe_findings, serialize_findings
from hunterops.metrics import inc_error, inc_task, set_task_queue_depth, observe_plugin_latency
from hunterops.task_store import compute_task_id, BaseTaskStore
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - typing-only imports
    from hunterops.program_registry import ProgramPolicy
from hunterops.types import Finding, Task
from hunterops.url_utils import normalize_endpoint, normalize_host

SENSITIVE_PRIORITY_KEYWORDS = ("admin", "internal", "v1/debug", "config", "staging", "export", "graphiql")


def _normalize_endpoint_key(raw: str) -> str:
    return normalize_endpoint(raw)


def _endpoint_is_noisy(path: str, patterns: list[str]) -> bool:
    if not patterns:
        return False
    value = str(path or "").strip().lower()
    if not value:
        return False
    for raw in patterns:
        pat = str(raw or "").strip().lower()
        if not pat:
            continue
        if pat.startswith("re:"):
            try:
                if re.search(pat[3:], value, re.IGNORECASE):
                    return True
            except Exception:
                continue
        elif "*" in pat or "?" in pat:
            if fnmatch.fnmatch(value, pat):
                return True
        else:
            if pat in value:
                return True
    return False


def _parse_time_window(raw: str) -> tuple[int, int] | None:
    text = str(raw or "").strip()
    if not text or "-" not in text:
        return None
    start_raw, end_raw = text.split("-", 1)
    try:
        sh, sm = [int(x) for x in start_raw.split(":")]
        eh, em = [int(x) for x in end_raw.split(":")]
    except Exception:
        return None
    if not (0 <= sh < 24 and 0 <= eh < 24 and 0 <= sm < 60 and 0 <= em < 60):
        return None
    return sh * 60 + sm, eh * 60 + em


def _allowed_now(windows: list[str], timezone: str) -> tuple[bool, int]:
    if not windows:
        return True, 0
    tz_name = str(timezone or "UTC").strip() or "UTC"
    try:
        tz = ZoneInfo(tz_name)
    except Exception:
        tz = ZoneInfo("UTC")
    now = datetime.now(tz)
    now_min = now.hour * 60 + now.minute
    parsed: list[tuple[int, int]] = []
    for w in windows:
        slot = _parse_time_window(w)
        if slot:
            parsed.append(slot)
    if not parsed:
        return True, 0
    for start, end in parsed:
        if start <= end:
            if start <= now_min < end:
                return True, 0
        else:
            if now_min >= start or now_min < end:
                return True, 0
    deltas: list[int] = []
    for start, end in parsed:
        if start <= end:
            if now_min < start:
                deltas.append(start - now_min)
            else:
                deltas.append((1440 - now_min) + start)
        else:
            if now_min < start and now_min >= end:
                deltas.append(start - now_min)
            else:
                deltas.append(0)
    wait_minutes = min([d for d in deltas if d > 0], default=0)
    return False, int(wait_minutes * 60)


def _task_endpoints(task: Task) -> list[str]:
    payload = task.payload if isinstance(task.payload, dict) else {}
    eps = payload.get("seed_paths") or payload.get("paths") or payload.get("endpoints") or payload.get("known_endpoints")
    if isinstance(eps, list):
        out: list[str] = []
        for e in eps:
            if not isinstance(e, str) or not e.strip():
                continue
            out.append(_normalize_endpoint_key(e))
        return sorted(list(set(out)))
    endpoint = payload.get("endpoint")
    if isinstance(endpoint, str) and endpoint.strip():
        return [_normalize_endpoint_key(endpoint)]
    return []


class TaskExecutor:
    def __init__(
        self,
        plugins: dict[str, Plugin],
        context: dict[str, Any],
        logger: logging.Logger,
        *,
        endpoint_cache: EndpointCache | None = None,
        storage: Any | None = None,
        run_id: str = "",
        feedback: dict[str, Any] | None = None,
        task_store: BaseTaskStore | None = None,
    ) -> None:
        install_uvloop_if_available(logger=logger)
        self.plugins = plugins
        self.context = context
        self.logger = logger
        runtime = context["runtime"]
        self.queue: asyncio.PriorityQueue[tuple[int, int, Task]] = asyncio.PriorityQueue(maxsize=runtime["task_queue_size"])
        self.results: list[Finding] = []
        self.rate_limiter = AsyncRateLimiter(runtime["rate_limit_per_sec"])
        cpu_workers = max(2, (os.cpu_count() or 1) * 2)
        configured_workers = int(runtime.get("concurrency", 0) or 0)
        self.concurrency = max(1, configured_workers, cpu_workers)
        self.max_retries = runtime["max_retries"]
        self.backoff = runtime["backoff_base_seconds"]
        self.enable_recursive_tasks = bool(runtime.get("enable_recursive_tasks", True))
        self.recursion_max_depth = int(runtime.get("recursion_max_depth", 2))
        self.recursion_max_tasks = int(runtime.get("recursion_max_tasks", 500))
        self.recursion_max_tasks_step = int(runtime.get("recursion_max_tasks_step", 150))
        self.recursion_max_tasks_cap = int(runtime.get("recursion_max_tasks_cap", 5000))
        self.spawned_tasks = 0
        self.spawn_signatures: set[str] = set()
        self._spawn_lock = asyncio.Lock()
        self.metrics: dict[str, dict[str, float]] = {}
        self._task_counter = 0
        self.endpoint_cache = endpoint_cache or context.get("endpoint_cache")
        self.storage = storage or context.get("storage")
        self.run_id = str(run_id or context.get("run_id", ""))
        self.feedback = feedback or context.get("feedback") or {}
        self.task_store = task_store or context.get("task_store")
        self.program_policies: dict[str, "ProgramPolicy"] = context.get("program_policies", {}) or {}
        self.allowed_hours_sleep_cap = int(runtime.get("allowed_hours_sleep_cap_seconds", 300) or 300)
        self.endpoint_noise_patterns = runtime.get("endpoint_noise_patterns", []) if isinstance(runtime.get("endpoint_noise_patterns", []), list) else []
        self.priority_patterns = runtime.get("priority_endpoint_patterns", []) if isinstance(runtime.get("priority_endpoint_patterns", []), list) else []
        self.priority_boost = float(runtime.get("priority_endpoint_boost", 0.0) or 0.0)
        self.roi_patterns = runtime.get("roi_endpoint_patterns", []) if isinstance(runtime.get("roi_endpoint_patterns", []), list) else []
        self.roi_boost = float(runtime.get("roi_endpoint_boost", 0.0) or 0.0)
        self.roi_plugin_boosts = {
            str(k).strip().lower(): float(v)
            for k, v in (runtime.get("roi_plugin_boosts", {}) if isinstance(runtime.get("roi_plugin_boosts", {}), dict) else {}).items()
            if str(k).strip()
        }
        self.roi_boost_cap = float(runtime.get("roi_boost_cap", 0.0) or 0.0)
        self.auto_mute_enabled = bool(runtime.get("auto_mute_enabled", True))
        self.auto_mute_window_seconds = int(runtime.get("auto_mute_window_seconds", 120) or 120)
        self.auto_mute_event_threshold = int(runtime.get("auto_mute_event_threshold", 6) or 6)
        self.auto_mute_seconds = int(runtime.get("auto_mute_seconds", 900) or 900)
        self._auto_mute_events: dict[str, list[float]] = {}
        self._auto_mute_until: dict[str, float] = {}
        self.per_target_inflight = max(1, int(runtime.get("per_target_inflight", 2) or 2))
        self.per_target_jitter_ms = max(0, int(runtime.get("per_target_jitter_ms", 0) or 0))
        self._target_semaphores: dict[str, asyncio.Semaphore] = {}
        self._target_sem_lock = asyncio.Lock()
        self._target_next_allowed: dict[str, float] = {}
        self._target_lock = asyncio.Lock()
        self.findings_flush_every = max(0, int(runtime.get("findings_flush_every", 0) or 0))
        self._flushed_any = False
        self._tasks_by_target: dict[str, int] = {}
        self.max_tasks_per_target = int(runtime.get("max_tasks_per_target", 0) or 0)
        self._hours_wait_log: dict[str, float] = {}

    def _priority_boost_for_endpoint(self, endpoint: str) -> float:
        if not self.priority_patterns or self.priority_boost <= 0:
            return 0.0
        if _endpoint_is_noisy(endpoint, self.priority_patterns):
            return self.priority_boost
        return 0.0

    def _roi_boost_for_task(self, endpoint: str, plugin: str) -> float:
        boost = 0.0
        if self.roi_patterns and self.roi_boost > 0 and _endpoint_is_noisy(endpoint, self.roi_patterns):
            boost += self.roi_boost
        if self.roi_plugin_boosts:
            boost += float(self.roi_plugin_boosts.get(str(plugin).strip().lower(), 0.0) or 0.0)
        if self.roi_boost_cap > 0:
            boost = min(boost, self.roi_boost_cap)
        return boost

    def _task_priority(self, task: Task) -> int:
        payload = task.payload if isinstance(task.payload, dict) else {}
        base = int(payload.get("priority", payload.get("priority_score", 0)) or 0)
        endpoint_hints = _task_endpoints(task)
        endpoint = _normalize_endpoint_key(endpoint_hints[0] if endpoint_hints else "/")
        joined = " ".join([task.target] + endpoint_hints).lower()
        if any(k in joined for k in SENSITIVE_PRIORITY_KEYWORDS):
            base = max(base, 100)
        if self.endpoint_noise_patterns and _endpoint_is_noisy(endpoint, self.endpoint_noise_patterns):
            base = max(0, int(base * 0.1))
        boost = self._priority_boost_for_endpoint(endpoint)
        boost += self._roi_boost_for_task(endpoint, task.plugin)
        return max(0, int(base + boost))

    async def _enqueue(self, task: Task) -> Task | None:
        filtered = self._filter_task(task)
        if filtered is None:
            if task.task_id and self.task_store and self.run_id:
                try:
                    self.task_store.mark_skipped(self.run_id, task.task_id, reason="filtered")
                except Exception:
                    pass
            inc_task("skipped")
            return None
        if self.max_tasks_per_target > 0:
            current = int(self._tasks_by_target.get(filtered.target, 0) or 0)
            if current >= self.max_tasks_per_target:
                if filtered.task_id and self.task_store and self.run_id:
                    try:
                        self.task_store.mark_skipped(self.run_id, filtered.task_id, reason="target_task_cap")
                    except Exception:
                        pass
                inc_task("skipped")
                return None
            self._tasks_by_target[filtered.target] = current + 1
        if not filtered.task_id:
            filtered.task_id = compute_task_id(filtered)
        priority = self._task_priority(filtered)
        # Lower numeric priority comes first in PriorityQueue.
        item = (-priority, self._task_counter, filtered)
        self._task_counter += 1
        await self.queue.put(item)
        set_task_queue_depth(self.queue.qsize())
        inc_task("queued")
        return filtered

    async def add_tasks(self, tasks: list[Task]) -> None:
        enqueued: list[Task] = []
        for t in tasks:
            task = await self._enqueue(t)
            if task is not None:
                enqueued.append(task)
        if enqueued and self.task_store and self.run_id:
            try:
                self.task_store.enqueue_tasks(self.run_id, enqueued)
            except Exception:
                pass

    def _filter_task(self, task: Task) -> Task | None:
        endpoints = _task_endpoints(task)
        if not endpoints:
            return task
        remaining: list[str] = []
        for ep in endpoints:
            normalized = _normalize_endpoint_key(ep)
            if self.endpoint_noise_patterns and _endpoint_is_noisy(normalized, self.endpoint_noise_patterns):
                continue
            cache = self.endpoint_cache
            if isinstance(cache, EndpointCache) and cache.was_seen(plugin=task.plugin, target=task.target, endpoint=normalized):
                continue
            remaining.append(ep)
        if not remaining:
            return None
        if len(remaining) != len(endpoints):
            payload = task.payload.copy() if isinstance(task.payload, dict) else {}
            payload["seed_paths"] = remaining
            return Task(plugin=task.plugin, target=task.target, payload=payload)
        return task

    async def _wait_target_budget(self, target: str) -> None:
        if not target:
            return
        async with self._target_lock:
            policy = self.program_policies.get(target) or self.program_policies.get(normalize_host(target))
            if policy and policy.scope.allowed_hours:
                allowed, wait_s = _allowed_now(policy.scope.allowed_hours, policy.scope.timezone)
                while not allowed and wait_s > 0:
                    now = time.monotonic()
                    last_log = float(self._hours_wait_log.get(target, 0.0))
                    if now - last_log > 60:
                        self.logger.info(
                            f"target_paused_outside_allowed_hours target={target} wait_seconds={wait_s} tz={policy.scope.timezone}"
                        )
                        self._hours_wait_log[target] = now
                    await asyncio.sleep(min(wait_s, self.allowed_hours_sleep_cap))
                    allowed, wait_s = _allowed_now(policy.scope.allowed_hours, policy.scope.timezone)
            now = time.monotonic()
            if self.auto_mute_enabled:
                mute_until = float(self._auto_mute_until.get(target, 0.0))
                if mute_until > now:
                    await asyncio.sleep(max(0.0, mute_until - now))
                    now = time.monotonic()
            if self.per_target_jitter_ms > 0:
                await asyncio.sleep(random.uniform(0.0, float(self.per_target_jitter_ms) / 1000.0))
            next_allowed = float(self._target_next_allowed.get(target, now))
            if next_allowed > now:
                await asyncio.sleep(next_allowed - now)
                now = time.monotonic()
            self._target_next_allowed[target] = now

    async def _get_target_semaphore(self, target: str) -> asyncio.Semaphore:
        async with self._target_sem_lock:
            sem = self._target_semaphores.get(target)
            if sem is None:
                sem = asyncio.Semaphore(self.per_target_inflight)
                self._target_semaphores[target] = sem
            return sem

    @staticmethod
    def _collect_status_codes(value: Any, out: set[int], depth: int = 0) -> None:
        if depth > 4:
            return
        if isinstance(value, dict):
            for key, child in value.items():
                lk = str(key).lower()
                if lk in {"status", "status_code"}:
                    try:
                        status = int(child or 0)
                    except Exception:
                        status = 0
                    if status > 0:
                        out.add(status)
                TaskExecutor._collect_status_codes(child, out, depth + 1)
        elif isinstance(value, list):
            for item in value[:80]:
                TaskExecutor._collect_status_codes(item, out, depth + 1)

    def _feedback_statuses(self, findings: list[Finding]) -> set[int]:
        tracked = {403, 429}
        statuses: set[int] = set()
        for finding in findings:
            self._collect_status_codes(finding.evidence if isinstance(finding.evidence, dict) else {}, statuses)
            self._collect_status_codes(finding.metadata if isinstance(finding.metadata, dict) else {}, statuses)
        return {status for status in statuses if status in tracked}

    def register_feedback(self, target: str, status_code: int) -> None:
        if int(status_code) not in {403, 429}:
            self.clear_feedback(target)
            return
        if not self.auto_mute_enabled:
            return
        now = time.monotonic()
        bucket = self._auto_mute_events.setdefault(target, [])
        bucket.append(now)
        window = max(10.0, float(self.auto_mute_window_seconds))
        self._auto_mute_events[target] = [ts for ts in bucket if (now - ts) <= window]
        if len(self._auto_mute_events[target]) >= max(1, int(self.auto_mute_event_threshold)):
            self._auto_mute_until[target] = now + max(30.0, float(self.auto_mute_seconds))

    def clear_feedback(self, target: str) -> None:
        if not target:
            return
        self._auto_mute_events[target] = []

    def _mark_task_endpoints(self, task: Task) -> None:
        cache = self.endpoint_cache
        if not isinstance(cache, EndpointCache):
            return
        endpoints = _task_endpoints(task)
        if endpoints:
            cache.mark_many(plugin=task.plugin, target=task.target, endpoints=endpoints)

    async def _maybe_flush(self) -> None:
        if self.findings_flush_every <= 0:
            return
        if not self.storage or not self.run_id:
            return
        if len(self.results) < self.findings_flush_every:
            return
        try:
            rows = serialize_findings(self.results, feedback=self.feedback)
            self.storage.write_findings(self.run_id, rows)
            self.results = []
            self._flushed_any = True
        except Exception as err:
            self.logger.warning(f"findings_flush_failed err={err}")

    async def worker(self, idx: int) -> None:
        while True:
            _priority, _seq, task = await self.queue.get()
            if task.plugin == "__stop__":
                self.queue.task_done()
                return
            try:
                start = time.perf_counter()
                if task.task_id and self.task_store and self.run_id:
                    try:
                        self.task_store.mark_started(self.run_id, task.task_id)
                    except Exception:
                        pass
                inc_task("started")
                await self._wait_target_budget(task.target)
                sem = await self._get_target_semaphore(task.target)
                async with sem:
                    await self.rate_limiter.wait()
                    pack = task.payload.get("program_pack", {}) if isinstance(task.payload, dict) else {}
                    blocked = {str(x) for x in pack.get("blocked_checks", [])} if isinstance(pack, dict) else set()
                    allowed = {str(x) for x in pack.get("allowed_checks", [])} if isinstance(pack, dict) else set()
                    if blocked and task.plugin in blocked:
                        if task.task_id and self.task_store and self.run_id:
                            try:
                                self.task_store.mark_skipped(self.run_id, task.task_id, reason="blocked_by_pack")
                            except Exception:
                                pass
                        inc_task("skipped")
                        continue
                    if allowed and task.plugin not in allowed and task.plugin != "platform_sync":
                        if task.task_id and self.task_store and self.run_id:
                            try:
                                self.task_store.mark_skipped(self.run_id, task.task_id, reason="not_allowed_by_pack")
                            except Exception:
                                pass
                        inc_task("skipped")
                        continue
                    plugin = self.plugins[task.plugin]

                    async def invoke() -> list[Finding]:
                        try:
                            return await plugin.run(task, self.context)
                        except Exception as err:
                            self.logger.exception(f"plugin_run_failed plugin={task.plugin} target={task.target} err={err}")
                            inc_error(task.plugin)
                            return []

                    findings = await retry_async(invoke, retries=self.max_retries, base_delay=self.backoff)
                    findings = plugin.normalize_findings(findings, task)
                    if findings:
                        await self._spawn_from_findings(task, findings)
                    self._mark_task_endpoints(task)
                    statuses = self._feedback_statuses(findings)
                    if statuses:
                        for status in statuses:
                            self.register_feedback(task.target, status)
                    else:
                        self.clear_feedback(task.target)
                    findings = redact_findings(findings)
                    findings = dedupe_findings(findings)
                    if findings:
                        self.results.extend(findings)
                        await self._maybe_flush()
                    elapsed = time.perf_counter() - start
                    m = self.metrics.setdefault(task.plugin, {"runs": 0.0, "errors": 0.0, "latency_sum": 0.0, "findings": 0.0})
                    m["runs"] += 1
                    m["latency_sum"] += elapsed
                    m["findings"] += float(len(findings or []))
                    observe_plugin_latency(task.plugin, elapsed)
                    if task.task_id and self.task_store and self.run_id:
                        try:
                            self.task_store.mark_done(self.run_id, task.task_id)
                        except Exception:
                            pass
                    inc_task("done")
            except Exception as err:
                self.logger.exception(f"worker_failed worker={idx} plugin={task.plugin} target={task.target} err={err}")
                m = self.metrics.setdefault(task.plugin, {"runs": 0.0, "errors": 0.0, "latency_sum": 0.0, "findings": 0.0})
                m["runs"] += 1
                m["errors"] += 1
                inc_error(task.plugin)
                if task.task_id and self.task_store and self.run_id:
                    try:
                        self.task_store.mark_failed(self.run_id, task.task_id, error=str(err))
                    except Exception:
                        pass
                inc_task("failed")
            finally:
                self.queue.task_done()
                set_task_queue_depth(self.queue.qsize())

    async def run(self, tasks: list[Task]) -> list[Finding]:
        await self.add_tasks(tasks)
        workers = [asyncio.create_task(self.worker(i)) for i in range(self.concurrency)]
        await self.queue.join()
        for _ in workers:
            await self._enqueue(Task(plugin="__stop__", target="", payload={"priority": 1000}))
        await asyncio.gather(*workers)
        return self.results

    @property
    def flushed_any(self) -> bool:
        return bool(self._flushed_any)

    @staticmethod
    def _finding_is_anomaly(finding: Finding) -> bool:
        cat = str(finding.category).lower()
        sev = str(finding.severity).lower()
        if sev in {"critical", "high"}:
            return True
        if any(k in cat for k in ("anomaly", "idor", "leak", "auth_bypass", "behavior")):
            return True
        ev = finding.evidence if isinstance(finding.evidence, dict) else {}
        diff = ev.get("diff_map", ev.get("response_diff", ev.get("base_vs_variant_diff", {})))
        if isinstance(diff, dict):
            if float(diff.get("structure_similarity_pct", 0) or 0) >= 90 and int(diff.get("status_other", 0) or 0) == 200:
                return True
            if int(diff.get("anomaly_score", 0) or 0) >= 60:
                return True
        return False

    def _extract_endpoints_from_finding(self, finding: Finding) -> list[str]:
        endpoints: list[str] = []
        for source in (finding.evidence if isinstance(finding.evidence, dict) else {}, finding.metadata if isinstance(finding.metadata, dict) else {}):
            for key in ("endpoints", "known_endpoints", "seed_paths", "paths"):
                vals = source.get(key, [])
                if isinstance(vals, list):
                    endpoints.extend([str(v) for v in vals if isinstance(v, str)])
            req = source.get("request", {}) if isinstance(source.get("request"), dict) else {}
            req_url = req.get("url")
            if isinstance(req_url, str) and req_url.strip():
                endpoints.append(req_url)
            for key in ("endpoint", "path", "url", "base_url", "modified_url"):
                raw = source.get(key)
                if isinstance(raw, str) and raw.strip():
                    endpoints.append(raw)
        normalized: list[str] = []
        seen: set[str] = set()
        for ep in endpoints:
            norm = _normalize_endpoint_key(ep)
            if not norm or norm in seen:
                continue
            seen.add(norm)
            normalized.append(norm)
        return sorted(normalized)

    async def _spawn_from_findings(self, parent: Task, findings: list[Finding]) -> None:
        if not self.enable_recursive_tasks:
            return
        depth = 0
        if isinstance(parent.payload, dict):
            try:
                depth = int(parent.payload.get("_depth", 0))
            except Exception:
                depth = 0
        if depth >= self.recursion_max_depth:
            return
        if any(self._finding_is_anomaly(f) for f in findings):
            self.recursion_max_tasks = min(
                self.recursion_max_tasks + self.recursion_max_tasks_step,
                self.recursion_max_tasks_cap,
            )
        for f in findings:
            meta = f.metadata if isinstance(f.metadata, dict) else {}
            spawn = meta.get("spawn_tasks", [])
            spawn_list: list[dict[str, Any]] = spawn if isinstance(spawn, list) else []
            if (
                str(self.context.get("runtime", {}).get("attack_chain_seed_enabled", "1")).strip().lower() in {"1", "true", "yes"}
                and str(f.plugin).strip().lower() != "attack_chain_seed"
            ):
                endpoints = self._extract_endpoints_from_finding(f)
                max_seed = int(self.context.get("runtime", {}).get("attack_chain_seed_max_endpoints", 80) or 80)
                if endpoints:
                    spawn_list.append(
                        {
                            "plugin": "attack_chain_seed",
                            "target": parent.target,
                            "payload": {
                                "endpoints": endpoints[:max_seed],
                                "program_id": meta.get("program", meta.get("program_id", "")),
                            },
                        }
                    )
            if not spawn_list:
                continue
            for raw in spawn_list:
                if not isinstance(raw, dict):
                    continue
                plugin = str(raw.get("plugin", "")).strip()
                target = str(raw.get("target", parent.target)).strip() or parent.target
                if not plugin:
                    continue
                if plugin not in self.plugins:
                    continue
                payload = raw.get("payload", {})
                if not isinstance(payload, dict):
                    payload = {}
                payload = payload.copy()
                payload["_depth"] = depth + 1
                if isinstance(parent.payload, dict) and "program_pack" in parent.payload and "program_pack" not in payload:
                    payload["program_pack"] = parent.payload.get("program_pack", {})
                sig = f"{plugin}|{target}|{json.dumps(payload, sort_keys=True, ensure_ascii=True)}"
                async with self._spawn_lock:
                    if self.spawned_tasks >= self.recursion_max_tasks:
                        return
                    if sig in self.spawn_signatures:
                        continue
                    self.spawn_signatures.add(sig)
                    self.spawned_tasks += 1
                spawned = await self._enqueue(Task(plugin=plugin, target=target, payload=payload))
                if spawned is not None and self.task_store and self.run_id:
                    try:
                        self.task_store.enqueue_tasks(self.run_id, [spawned])
                    except Exception:
                        pass

    def summarize_metrics(self) -> dict[str, dict[str, float]]:
        out: dict[str, dict[str, float]] = {}
        for plugin, m in self.metrics.items():
            runs = max(1.0, m.get("runs", 1.0))
            out[plugin] = {
                "runs": m.get("runs", 0.0),
                "errors": m.get("errors", 0.0),
                "error_rate": round((m.get("errors", 0.0) / runs) * 100, 2),
                "avg_latency_sec": round(m.get("latency_sum", 0.0) / runs, 4),
                "findings": m.get("findings", 0.0),
            }
        return out
