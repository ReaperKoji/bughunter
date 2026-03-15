from __future__ import annotations

import asyncio
import hashlib
import json
import random
import re
import time
from datetime import datetime
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
import os
from zoneinfo import ZoneInfo

from hunterops.attack_chain.config import resolve_path_from_cfg
from hunterops.attack_chain.baseline import BaselineComparer
from hunterops.attack_chain.modules import ModuleContext, build_modules
from hunterops.attack_chain.politeness import PolitenessConfig, PolitenessManager
from hunterops.attack_chain.scope import ScopePolicy, collect_scope, in_scope, kyc_okay, load_programs
from hunterops.attack_chain.types import HistoryEntry, ModuleResult, Target, Verdict, ValidationDecision
from hunterops.attack_chain.validator import PoCValidator
from hunterops.alert_router import AlertRouter
from hunterops.http_client import apply_runtime_session_headers, configure_global_http_limits, request_http_async
from hunterops.logging_utils import setup_logging
from hunterops.metrics import (
    enable_metrics,
    inc_fp_spike,
    inc_candidate,
    inc_error,
    inc_poc_valid,
    inc_target_processed,
    observe_baseline_score,
)
from hunterops.policy import EndpointPolicyEngine
from hunterops.go_no_go import GoNoGoChecklist
from hunterops.runbook import RunbookManager
from hunterops.runtime_paths import ensure_directory, resolve_path
from hunterops.scope_authorization import authorize_targets, load_authorized_scope
from hunterops.session_guardian import SessionGuardian
from hunterops.session_profiles import load_sessions
from hunterops.storage import PostgresStorage
from hunterops.types import Finding
from hunterops.rules_engine import check_automation_allowed
from hunterops.redaction import redact_value


@dataclass
class CircuitBreakerConfig:
    failure_threshold: int = 5
    half_open_after_s: int = 300


class HostCircuitBreaker:
    def __init__(self, cfg: CircuitBreakerConfig) -> None:
        self.cfg = cfg
        self._streaks: dict[str, int] = {}
        self._cooldown_until: dict[str, float] = {}

    def _now(self) -> float:
        return time.monotonic()

    def is_open(self, host: str) -> tuple[bool, float]:
        until = float(self._cooldown_until.get(host, 0.0))
        remaining = max(0.0, until - self._now())
        return remaining > 0.0, remaining

    def record(self, host: str, status: str) -> None:
        if not host:
            return
        if status in {"timeout", "error"}:
            streak = self._streaks.get(host, 0) + 1
            self._streaks[host] = streak
            if streak >= self.cfg.failure_threshold:
                self._cooldown_until[host] = self._now() + float(self.cfg.half_open_after_s)
                self._streaks[host] = 0
            return
        self._streaks[host] = 0
        if host in self._cooldown_until and self._cooldown_until[host] <= self._now():
            self._cooldown_until.pop(host, None)


class EventWriter:
    def __init__(self, path: Path) -> None:
        self.path = path
        ensure_directory(self.path.parent)

    def write(self, payload: dict[str, Any]) -> None:
        line = json.dumps(payload, ensure_ascii=True)
        with self.path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")


class ChainOrchestrator:
    def __init__(self, pipeline_cfg: dict[str, Any]) -> None:
        self.cfg = pipeline_cfg
        self.real_mode = bool(self.cfg.get("real_mode", False)) or str(os.getenv("HUNTEROPS_REAL_MODE", "")).strip().lower() in {"1", "true", "yes"}
        globals_cfg = self.cfg.get("globals", {}) if isinstance(self.cfg.get("globals"), dict) else {}
        timeouts = globals_cfg.get("timeouts", {}) if isinstance(globals_cfg.get("timeouts"), dict) else {}
        politeness_cfg = globals_cfg.get("politeness", {}) if isinstance(globals_cfg.get("politeness"), dict) else {}
        retry_cfg = globals_cfg.get("retry", {}) if isinstance(globals_cfg.get("retry"), dict) else {}
        cb_cfg = globals_cfg.get("circuit_breaker", {}) if isinstance(globals_cfg.get("circuit_breaker"), dict) else {}
        validator_cfg = globals_cfg.get("validator", {}) if isinstance(globals_cfg.get("validator"), dict) else {}
        http_limits_cfg = globals_cfg.get("http_limits", {}) if isinstance(globals_cfg.get("http_limits"), dict) else {}
        baseline_cfg = globals_cfg.get("baseline", {}) if isinstance(globals_cfg.get("baseline"), dict) else {}

        self.timeouts = timeouts
        self.retry_cfg = {
            "max_attempts": int(retry_cfg.get("max_attempts", 1) or 1),
            "backoff_base_s": float(retry_cfg.get("backoff_base_s", 1.0) or 1.0),
            "backoff_max_s": float(retry_cfg.get("backoff_max_s", 30.0) or 30.0),
            "jitter": float(retry_cfg.get("jitter", 0.2) or 0.2),
        }
        rate_cap = 10.0
        configured_rate = float(http_limits_cfg.get("rate_per_sec", rate_cap) or rate_cap)
        configure_global_http_limits(
            rate_per_sec=min(rate_cap, configured_rate),
            max_inflight=int(http_limits_cfg.get("max_inflight", 10) or 10),
        )
        self.politeness = PolitenessManager(
            PolitenessConfig(
                per_host_rpm=int(politeness_cfg.get("per_host_rpm", 60) or 60),
                per_target_rpm=int(politeness_cfg.get("per_target_rpm", 30) or 30),
                jitter_ms_min=int((politeness_cfg.get("jitter_ms", [200, 800]) or [200, 800])[0]),
                jitter_ms_max=int((politeness_cfg.get("jitter_ms", [200, 800]) or [200, 800])[1]),
                concurrency_per_host=int(politeness_cfg.get("concurrency_per_host", 2) or 2),
            )
        )
        self.validator = PoCValidator(validator_cfg)
        self.modules = build_modules()
        self.baseline_cfg = baseline_cfg
        self.baseline_enabled = bool(baseline_cfg.get("enabled", True))
        default_methods = [
            {"method": "GET"},
            {"method": "POST", "body": {"ping": "1"}},
            {"method": "PUT", "body": {"ping": "1"}},
        ]
        baseline_methods = baseline_cfg.get("methods", default_methods) if isinstance(baseline_cfg.get("methods", default_methods), list) else default_methods
        self.baseline = BaselineComparer(methods=baseline_methods, timeout_s=int(baseline_cfg.get("timeout_s", self.timeouts.get("total_s", 20)) or 20))

        cb = CircuitBreakerConfig(
            failure_threshold=int(cb_cfg.get("failure_threshold", 5) or 5),
            half_open_after_s=int(cb_cfg.get("half_open_after_s", 300) or 300),
        )
        self.circuit = HostCircuitBreaker(cb)

        outputs = self.cfg.get("outputs", {}) if isinstance(self.cfg.get("outputs"), dict) else {}
        self.events_path = resolve_path_from_cfg(outputs.get("events_path", "data/events/events.ndjson"))
        self.evidence_path = resolve_path_from_cfg(outputs.get("evidence_path", "data/evidence"))
        self.reports_path = resolve_path_from_cfg(outputs.get("reports_path", "reports"))
        self.metrics_path = resolve_path_from_cfg(outputs.get("metrics_path", "data/metrics"))
        ensure_directory(self.evidence_path)
        ensure_directory(self.reports_path)
        ensure_directory(self.metrics_path)

        self.event_writer = EventWriter(self.events_path)
        log_file = resolve_path("data/attack_chain.log")
        self.logger = setup_logging(log_file, verbose=False)

        self.user_agents = list(politeness_cfg.get("user_agents", []) or [])
        self.stealth_mode = bool(politeness_cfg.get("stealth_mode", True))
        raw_proxies = os.environ.get("HUNTEROPS_PROXIES", "")
        self.proxies = [x.strip() for x in raw_proxies.split(",") if x.strip()]
        self.tool_timeout_s = int(timeouts.get("tool_s", timeouts.get("total_s", 60)) or 60)
        self.hot_reload_cfg = self.cfg.get("hot_reload", {}) if isinstance(self.cfg.get("hot_reload", {}), dict) else {}
        self._hot_reload_state: dict[str, float] = {}
        self._hot_reload_next_check = 0.0
        self._hot_reload_interval = float(self.hot_reload_cfg.get("poll_interval_s", 300) or 300)
        self.metrics_cfg = self.cfg.get("metrics", {}) if isinstance(self.cfg.get("metrics", {}), dict) else {}
        self.governance_cfg = self.cfg.get("governance", {}) if isinstance(self.cfg.get("governance", {}), dict) else {}
        self.endpoint_policy = EndpointPolicyEngine(self.cfg)
        self.go_no_go = GoNoGoChecklist(self.cfg.get("go_no_go", {}))
        self.runbook = RunbookManager(self.cfg.get("runbook", {}))
        self._host_status_counts: dict[str, dict[int, int]] = {}
        self._metrics: dict[str, Any] = {
            "targets_total": 0,
            "targets_skipped": 0,
            "targets_processed": 0,
            "poc_valid": 0,
            "no_poc": 0,
            "candidates": 0,
            "false_positive": 0,
            "inconclusive": 0,
            "errors": 0,
            "module_runs": 0,
            "module_errors": 0,
            "module_timeouts": 0,
            "per_module": {},
        }
        self.blocked_path_keywords = [
            "checkout",
            "payment",
            "kyc",
            "pci",
            "billing",
            "invoice",
        ]
        self.policy_defaults = self.cfg.get("policy_defaults", {}) if isinstance(self.cfg.get("policy_defaults", {}), dict) else {}
        self.run_id = f"attack-chain-{int(time.time())}"

        alert_cfg = self.cfg.get("alerting", {}) if isinstance(self.cfg.get("alerting", {}), dict) else {}
        self.alert_router = AlertRouter(alert_cfg, logger=self.logger)

        if bool(self.metrics_cfg.get("enabled", False)):
            enable_metrics(int(self.metrics_cfg.get("port", 9108) or 9108))

        storage_cfg = self.cfg.get("storage", {}) if isinstance(self.cfg.get("storage", {}), dict) else {}
        dsn_env = str(storage_cfg.get("dsn_env", "HUNTEROPS_POSTGRES_DSN")).strip() or "HUNTEROPS_POSTGRES_DSN"
        dsn = os.getenv(dsn_env, "").strip()
        storage_enabled = bool(storage_cfg.get("enabled", True)) and bool(dsn)
        self.storage = PostgresStorage(dsn, enabled=storage_enabled) if storage_enabled else None

        replay_cfg = validator_cfg.get("replay", {}) if isinstance(validator_cfg.get("replay", {}), dict) else {}
        self.replay_attempts = int(replay_cfg.get("attempts", 1) or 1)
        self.replay_require_signal_match = bool(replay_cfg.get("require_signal_match", True))

        sg_cfg = self.cfg.get("session_guardian", {}) if isinstance(self.cfg.get("session_guardian", {}), dict) else {}
        self.session_guardian = SessionGuardian(
            cfg=sg_cfg,
            runtime={"timeout_seconds": int(self.timeouts.get("total_s", 30) or 30)},
            logger=self.logger,
            storage=self.storage,
        )

        impact_cfg = self.cfg.get("impact_validator", {}) if isinstance(self.cfg.get("impact_validator", {}), dict) else {}
        self.impact_cfg = impact_cfg
        self.impact_enabled = bool(impact_cfg.get("enabled", False))
        self.impact_modules = {str(x).strip() for x in impact_cfg.get("modules", []) if str(x).strip()}
        self.impact_require_auth = bool(impact_cfg.get("require_auth_session", False))
        self.impact_max_body_diff_ratio = float(impact_cfg.get("max_body_diff_ratio", 0.25) or 0.25)
        self.impact_auth_status = {int(x) for x in impact_cfg.get("auth_status", [200]) if str(x).strip()} or {200}
        self.impact_anon_status = {int(x) for x in impact_cfg.get("anon_status", [200]) if str(x).strip()} or {200}
        self.impact_sensitive_markers = [
            str(x).strip().lower()
            for x in impact_cfg.get(
                "sensitive_markers",
                ["email", "phone", "iban", "account", "wallet", "balance", "transaction", "order", "portfolio"],
            )
            if str(x).strip()
        ]

    def _preflight_check(self, targets: list[Target]) -> bool:
        scope = load_authorized_scope()
        ok, unauthorized = authorize_targets([t.url for t in targets], scope)
        if not ok:
            self.event_writer.write({
                "event": "preflight_failed",
                "reason": "unauthorized_targets",
                "unauthorized": unauthorized,
            })
            return False

        if self.politeness.cfg.per_host_rpm <= 0 or self.politeness.cfg.per_target_rpm <= 0:
            self.event_writer.write({
                "event": "preflight_failed",
                "reason": "rate_limit_missing",
                "per_host_rpm": self.politeness.cfg.per_host_rpm,
                "per_target_rpm": self.politeness.cfg.per_target_rpm,
            })
            return False

        auth_required = False
        modules_cfg = self.cfg.get("modules", {}) if isinstance(self.cfg.get("modules", {}), dict) else {}
        for cfg in modules_cfg.values():
            if not isinstance(cfg, dict):
                continue
            if cfg.get("requires_auth") or cfg.get("use_auth") or cfg.get("auth_session"):
                auth_required = True
                break
        sessions = {}
        if auth_required or self.session_guardian.enabled:
            sessions = load_sessions(self.session_guardian.sessions_file)
            if not sessions:
                self.event_writer.write({
                    "event": "preflight_failed",
                    "reason": "authorized_accounts_missing",
                    "sessions_file": str(self.session_guardian.sessions_file),
                })
                return False

        programs = load_programs("config/programs.yaml")
        for target in targets:
            policy = collect_scope(programs, target.program_id or "all")
            decision = check_automation_allowed(policy.rules_of_engagement)
            if decision.manual_only:
                self.event_writer.write({
                    "event": "preflight_failed",
                    "reason": "automation_not_allowed",
                    "program": target.program_id,
                    "details": {"automation_allowed": decision.automation_allowed, "reason": decision.reason},
                })
                return False

        go_no_go = self.go_no_go.evaluate(
            targets=[t.url for t in targets],
            scope=scope,
            programs=programs.get("programs", []) if isinstance(programs, dict) else [],
            auth_required=bool(auth_required or self.session_guardian.enabled),
            sessions_present=bool(sessions),
            real_mode=self.real_mode,
        )
        self.go_no_go.write_report(go_no_go)
        self.event_writer.write({"event": "go_no_go", "result": go_no_go.to_dict()})
        if not go_no_go.ok:
            self.event_writer.write({"event": "preflight_failed", "reason": "go_no_go_failed"})
            return False

        self.event_writer.write({"event": "preflight_ok"})
        return True

    def load_targets(self) -> list[Target]:
        targets: list[Target] = []
        sources = self.cfg.get("target_sources", []) if isinstance(self.cfg.get("target_sources"), list) else []
        for src in sources:
            if not isinstance(src, dict):
                continue
            if src.get("type") != "file":
                continue
            path = resolve_path_from_cfg(src.get("path", "data/targets/in_scope.txt"))
            if not path.exists():
                continue
            lines = [x.strip() for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]
            for idx, line in enumerate(lines):
                program_id = str(src.get("program", "all"))
                raw_line = line
                if "::" in line:
                    left, right = line.split("::", 1)
                    if left.strip() and right.strip():
                        program_id = left.strip()
                        raw_line = right.strip()
                url = self._normalize_target(raw_line)
                targets.append(Target(target_id=f"t{idx:04d}", url=url, program_id=program_id))
        return targets

    def _normalize_target(self, raw: str) -> str:
        if raw.startswith("http://") or raw.startswith("https://"):
            return raw
        return f"https://{raw}"

    def _host_from_url(self, url: str) -> str:
        try:
            return str(urlsplit(url).hostname or "").strip().lower()
        except Exception:
            return ""

    def _blocked_by_path(self, program: str, url: str, policy: ScopePolicy, method: str = "GET") -> tuple[bool, str]:
        path = str(urlsplit(url).path or "").lower()
        blocked = list(self.blocked_path_keywords)
        blocked.extend(self.policy_defaults.get("blocked_paths", []) or [])
        blocked.extend(policy.blocked_paths or [])
        if any(keyword in path for keyword in blocked):
            return True, "blocked_keyword"
        engine_blocked, reason = self.endpoint_policy.is_blocked(program, path, method)
        return bool(engine_blocked), reason

    def _owasp_coverage(self, enabled_modules: list[str]) -> dict[str, Any]:
        default_relevant = [
            "A01:2021",
            "A02:2021",
            "A03:2021",
            "A04:2021",
            "A05:2021",
            "A06:2021",
            "A07:2021",
            "A08:2021",
            "A09:2021",
            "A10:2021",
        ]
        owasp_cfg = self.cfg.get("owasp", {}) if isinstance(self.cfg.get("owasp", {}), dict) else {}
        relevant = set(str(x) for x in owasp_cfg.get("relevant", default_relevant) if str(x).strip())
        mapping = {}
        for name in enabled_modules:
            entry = self.cfg.get("modules", {}).get(name, {}) if isinstance(self.cfg.get("modules", {}), dict) else {}
            cats = entry.get("owasp", []) if isinstance(entry.get("owasp", []), list) else []
            mapping[name] = cats
        covered = {c for cats in mapping.values() for c in cats}
        score = 0.0
        if relevant:
            score = round(len(covered & relevant) / len(relevant), 2)
        return {"modules": mapping, "covered": sorted(covered), "relevant": sorted(relevant), "score": score}

    def _merge_policy(self, policy: ScopePolicy) -> dict[str, Any]:
        merged = dict(self.policy_defaults)
        if policy.per_host_rpm is not None and policy.per_host_rpm > 0:
            merged["per_host_rpm"] = policy.per_host_rpm
        if policy.per_target_rpm is not None and policy.per_target_rpm > 0:
            merged["per_target_rpm"] = policy.per_target_rpm
        if policy.concurrency_per_host is not None and policy.concurrency_per_host > 0:
            merged["concurrency_per_host"] = policy.concurrency_per_host
        if isinstance(policy.required_headers, dict) and policy.required_headers:
            merged_headers = {}
            if isinstance(merged.get("required_headers"), dict):
                merged_headers.update(merged.get("required_headers") or {})
            merged_headers.update(policy.required_headers)
            merged["required_headers"] = merged_headers
        return self.runbook.apply_policy(merged)

    def _module_allowed(self, module_name: str, policy: ScopePolicy) -> bool:
        allowed = {str(x).strip() for x in (policy.allowed_modules or []) if str(x).strip()}
        blocked = {str(x).strip() for x in (policy.blocked_modules or []) if str(x).strip()}
        global_allowed = {
            str(x).strip()
            for x in (self.governance_cfg.get("allowed_modules", []) if isinstance(self.governance_cfg.get("allowed_modules", []), list) else [])
            if str(x).strip()
        }
        global_blocked = {
            str(x).strip()
            for x in (self.governance_cfg.get("blocked_modules", []) if isinstance(self.governance_cfg.get("blocked_modules", []), list) else [])
            if str(x).strip()
        }
        if global_allowed and module_name not in global_allowed:
            return False
        if module_name in global_blocked:
            return False
        if allowed and module_name not in allowed:
            return False
        if blocked and module_name in blocked:
            return False
        if self.real_mode and module_name == "rce":
            return False
        return True

    def _policy_allows_now(self, policy: ScopePolicy) -> bool:
        windows = policy.allowed_hours or self.policy_defaults.get("allowed_hours", []) or []
        if not windows:
            return True
        tz = policy.timezone or str(self.policy_defaults.get("timezone", "UTC"))
        try:
            now = datetime.now(ZoneInfo(tz))
        except Exception:
            now = datetime.now(ZoneInfo("UTC"))
        current = now.time()
        for window in windows:
            raw = str(window or "").strip()
            if "-" not in raw:
                continue
            start_s, end_s = [x.strip() for x in raw.split("-", 1)]
            try:
                start_h, start_m = [int(x) for x in start_s.split(":", 1)]
                end_h, end_m = [int(x) for x in end_s.split(":", 1)]
            except Exception:
                continue
            start = current.replace(hour=start_h, minute=start_m, second=0, microsecond=0)
            end = current.replace(hour=end_h, minute=end_m, second=0, microsecond=0)
            if start <= end:
                if start <= current <= end:
                    return True
            else:
                if current >= start or current <= end:
                    return True
        return False

    def _body_diff_ratio(self, a: str, b: str) -> float:
        la = len(a or "")
        lb = len(b or "")
        if la == 0 and lb == 0:
            return 0.0
        return abs(la - lb) / max(1, max(la, lb))

    async def _impact_check(
        self,
        *,
        module_name: str,
        target: Target,
        ctx: ModuleContext,
        evidence: dict[str, Any],
    ) -> tuple[bool, str]:
        if not self.impact_enabled:
            return True, "impact_validator_disabled"
        if self.impact_modules and module_name not in self.impact_modules:
            return True, "impact_validator_skipped"

        url = str(
            evidence.get("variant_url")
            or evidence.get("request_url")
            or evidence.get("base_url")
            or target.url
        ).strip()
        if not url:
            return False, "impact_no_url"

        host = self._host_from_url(url)
        policy = ctx.policy or {}
        safe_methods = {
            str(x).strip().upper()
            for x in self.impact_cfg.get("safe_methods", ["GET", "HEAD"])
            if str(x).strip()
        } or {"GET", "HEAD"}
        req_meta = evidence.get("request", {}) if isinstance(evidence.get("request"), dict) else {}
        method = str(req_meta.get("method", "GET")).upper()
        if method not in safe_methods:
            method = "GET"
        body = None

        async def _fetch_with_headers(headers: dict[str, str]) -> dict[str, Any]:
            async with ctx.politeness.guard(
                host,
                target.target_id,
                per_host_rpm=policy.get("per_host_rpm"),
                per_target_rpm=policy.get("per_target_rpm"),
                concurrency_per_host=policy.get("concurrency_per_host"),
            ):
                return await request_http_async(
                    method,
                    url,
                    headers=headers,
                    body=body,
                    timeout=int(self.timeouts.get("total_s", 20) or 20),
                )

        auth_headers = {}
        if ctx.session_name and (ctx.use_auth or not self.impact_require_auth):
            auth_headers = apply_runtime_session_headers(ctx.session_name, ctx.required_headers or {})
        anon_headers = dict(ctx.required_headers or {})

        auth_resp = await _fetch_with_headers(auth_headers if auth_headers else anon_headers)
        anon_resp = await _fetch_with_headers(anon_headers)

        auth_status = int(auth_resp.get("status", 0) or 0)
        anon_status = int(anon_resp.get("status", 0) or 0)
        if auth_status not in self.impact_auth_status:
            return False, f"impact_auth_status_{auth_status}"
        if anon_status not in self.impact_anon_status:
            return False, f"impact_anon_status_{anon_status}"

        auth_text = str(auth_resp.get("text", "") or "")
        anon_text = str(anon_resp.get("text", "") or "")
        diff_ratio = self._body_diff_ratio(auth_text, anon_text)
        marker_hit = False
        sample = anon_text[:12000].lower()
        for marker in self.impact_sensitive_markers:
            if marker and marker in sample:
                marker_hit = True
                break

        if diff_ratio <= self.impact_max_body_diff_ratio or marker_hit:
            evidence["impact_confirmed"] = True
            evidence["impact_reason"] = "anon_similarity" if diff_ratio <= self.impact_max_body_diff_ratio else "anon_sensitive_marker"
            evidence["impact_auth_status"] = auth_status
            evidence["impact_anon_status"] = anon_status
            evidence["impact_body_diff_ratio"] = round(diff_ratio, 4)
            return True, "impact_confirmed"

        evidence["impact_confirmed"] = False
        evidence["impact_reason"] = "anon_diff_high"
        evidence["impact_body_diff_ratio"] = round(diff_ratio, 4)
        return False, "impact_not_confirmed"

    def _seed_for_target(self, target: Target, rotate_on: str) -> int:
        raw = str(rotate_on or "").strip().lower()
        parts = [p.strip() for p in raw.split("+") if p.strip()] if raw else []
        if not parts:
            parts = ["target"]
        tokens: list[str] = []
        for part in parts:
            if part == "run":
                tokens.append(self.run_id)
            elif part == "host":
                tokens.append(self._host_from_url(target.url))
            elif part == "target":
                tokens.append(target.url)
            elif part == "program":
                tokens.append(target.program_id or "all")
            else:
                tokens.append(part)
        seed_text = "|".join(tokens) or target.url
        return int(hashlib.sha256(seed_text.encode("utf-8", errors="ignore")).hexdigest()[:8], 16)

    def _select_order_for_target(self, target: Target, base_order: list[str], policy: ScopePolicy) -> list[str]:
        chain_cfg = self.cfg.get("chain", {}) if isinstance(self.cfg.get("chain", {}), dict) else {}
        strategy = str(chain_cfg.get("strategy", "sequential") or "sequential").strip().lower()
        rotate_on = str(chain_cfg.get("rotate_on", "target") or "target").strip().lower()
        adaptive_min_score = float(chain_cfg.get("adaptive_min_score", 0.15) or 0.15)
        max_modules = int(chain_cfg.get("max_modules_per_target", 0) or 0)
        shuffle_ties = bool(chain_cfg.get("shuffle_ties", True))

        use_adaptive = "adaptive" in strategy
        use_shuffle = "shuffle" in strategy and not use_adaptive
        use_rotate = "rotate" in strategy or bool(chain_cfg.get("rotate", False))

        order = [
            m for m in base_order
            if m in self.modules and self.cfg.get("modules", {}).get(m, {}).get("enabled", True)
        ]
        if not order:
            return []

        ordered = list(order)
        if use_adaptive:
            seed = self._seed_for_target(target, rotate_on)
            rng = random.Random(seed)
            scored: list[tuple[float, str, float]] = []
            for name in order:
                module = self.modules.get(name)
                if not module:
                    continue
                try:
                    score = float(module.score_target(target))
                except Exception:
                    score = 0.0
                if score < adaptive_min_score:
                    continue
                tie = rng.random() if shuffle_ties else 0.0
                scored.append((score, name, tie))
            if scored:
                scored.sort(key=lambda x: (-x[0], x[2]))
                ordered = [name for _score, name, _tie in scored]
        elif use_shuffle:
            seed = self._seed_for_target(target, rotate_on)
            rng = random.Random(seed)
            rng.shuffle(ordered)

        if use_rotate and len(ordered) > 1:
            seed = self._seed_for_target(target, rotate_on)
            shift = seed % len(ordered)
            ordered = ordered[shift:] + ordered[:shift]

        if max_modules > 0:
            ordered = ordered[:max_modules]

        return ordered

    async def run(self) -> None:
        targets = self.load_targets()
        if not targets:
            self.logger.error("attack_chain_no_targets")
            return
        await self.run_targets(targets)

    async def run_targets(self, targets: list[Target]) -> None:
        start_ts = time.monotonic()
        self._metrics["targets_total"] = len(targets)
        if not self._preflight_check(targets):
            self.logger.error("attack_chain_preflight_failed")
            return
        order = self.cfg.get("chain", {}).get("order", []) if isinstance(self.cfg.get("chain", {}), dict) else []
        order = [str(x) for x in order if str(x).strip()]
        enabled_modules = [m for m in order if self.cfg.get("modules", {}).get(m, {}).get("enabled", True)]
        coverage = self._owasp_coverage(enabled_modules)
        self.event_writer.write({"event": "owasp_coverage", "coverage": coverage})

        programs = load_programs("config/programs.yaml")
        policy_cache: dict[str, ScopePolicy] = {}

        if self.session_guardian.enabled:
            try:
                await self.session_guardian.warmup()
            except Exception as err:
                self.logger.warning(f"session_guardian_warmup_failed err={type(err).__name__}")

        if self.real_mode and any(t.program_id in {"", "all"} for t in targets):
            self.logger.error("real_mode_requires_program_id")
            return

        for target in targets:
            paused, pause_reason = self.runbook.is_paused()
            if paused:
                self.event_writer.write({
                    "event": "target_skipped",
                    "target": target.url,
                    "reason": "runbook_paused",
                    "details": pause_reason,
                })
                self._metrics["targets_skipped"] += 1
                break
            program_id = target.program_id or "all"
            if program_id not in policy_cache:
                policy_cache[program_id] = collect_scope(programs, program_id)
            policy = policy_cache[program_id]
            if self.real_mode and not policy.include:
                self.logger.error(f"real_mode_missing_scope program={program_id}")
                return
            if not kyc_okay(policy):
                self.logger.error("kyc_required_but_not_verified")
                return
            if not policy.include:
                self.event_writer.write({
                    "event": "target_skipped",
                    "target": target.url,
                    "reason": "no_in_scope_patterns",
                    "program": program_id,
                })
                self._metrics["targets_skipped"] += 1
                continue
            if not self._policy_allows_now(policy):
                self.event_writer.write({
                    "event": "target_skipped",
                    "target": target.url,
                    "reason": "outside_allowed_hours",
                    "program": program_id,
                })
                self._metrics["targets_skipped"] += 1
                continue

            policy_cfg = self._merge_policy(policy)
            ctx = ModuleContext(
                timeouts=self.timeouts,
                politeness=self.politeness,
                user_agents=self.user_agents,
                logger=self.logger,
                stealth_mode=self.stealth_mode,
                proxies=self.proxies,
                tool_timeout_s=self.tool_timeout_s,
                policy=policy_cfg,
                required_headers=policy_cfg.get("required_headers", {}),
                safe_payloads_only=False,
                baseline_score=0.0,
                baseline_notes=[],
                baseline_methods=[],
            )
            self._check_hot_reload()
            await self._run_target(target, order, policy, ctx)

        duration_s = max(0.1, time.monotonic() - start_ts)
        self._write_metrics(duration_s)

    async def _run_target(self, target: Target, order: list[str], policy: ScopePolicy, ctx: ModuleContext) -> None:
        if not in_scope(target.url, policy):
            self.event_writer.write({
                "event": "target_skipped",
                "target": target.url,
                "reason": "out_of_scope",
            })
            self._metrics["targets_skipped"] += 1
            return
        blocked, reason = self._blocked_by_path(target.program_id or "all", target.url, policy, "GET")
        if blocked:
            self.event_writer.write({
                "event": "target_skipped",
                "target": target.url,
                "reason": "blocked_path",
                "block_reason": reason,
            })
            self._metrics["targets_skipped"] += 1
            return
        if reason == "manual_override":
            self.event_writer.write({
                "event": "governance_override",
                "target": target.url,
                "method": "GET",
                "program": target.program_id,
            })

        host = self._host_from_url(target.url)
        if self.runbook.is_host_blocked(host):
            self.event_writer.write({
                "event": "target_skipped",
                "target": target.url,
                "reason": "runbook_blocked_host",
                "host": host,
            })
            self._metrics["targets_skipped"] += 1
            return
        is_open, remaining = self.circuit.is_open(host)
        if is_open:
            self.event_writer.write({
                "event": "target_skipped",
                "target": target.url,
                "reason": "circuit_open",
                "cooldown_remaining": round(remaining, 2),
            })
            self._metrics["targets_skipped"] += 1
            return

        if self.session_guardian.enabled:
            try:
                events = await self.session_guardian.ensure_target_health(target=target.url, run_id=self.run_id)
                for ev in events:
                    self.event_writer.write({"event": "session_guardian_event", "data": ev, "target": target.url})
            except Exception as err:
                self.logger.warning(f"session_guardian_error target={target.url} err={type(err).__name__}")

        baseline_score = 0.0
        baseline_notes: list[str] = []
        baseline_methods: list[str] = []
        if self.baseline_enabled:
            try:
                ua = random.choice(self.user_agents) if self.user_agents else "Mozilla/5.0 (HunterOps/AttackChain)"
                base_headers = {"User-Agent": ua}
                if isinstance(ctx.required_headers, dict):
                    base_headers.update(ctx.required_headers)
                baseline = await self.baseline.measure(
                    target.url,
                    headers=base_headers,
                    target_id=target.target_id,
                    politeness=ctx.politeness,
                    policy=ctx.policy,
                )
                baseline_score = float(baseline.get("baseline_score", 0.0) or 0.0)
                baseline_notes = list(baseline.get("notes", []) or [])
                baseline_methods = list(baseline.get("methods", []) or [])
                observe_baseline_score(target.program_id or "all", baseline_score)
                self.event_writer.write({
                    "event": "baseline_score",
                    "target": target.url,
                    "program": target.program_id,
                    "baseline_score": baseline_score,
                    "baseline_methods": baseline_methods,
                    "baseline_notes": baseline_notes,
                })
            except Exception as err:
                self.logger.warning(f"baseline_measure_failed target={target.url} err={type(err).__name__}")
        ctx.baseline_score = baseline_score
        ctx.baseline_notes = baseline_notes
        ctx.baseline_methods = baseline_methods

        order_for_target = self._select_order_for_target(target, order, policy)
        if not order_for_target:
            self.event_writer.write({
                "event": "target_skipped",
                "target": target.url,
                "reason": "no_modules_selected",
            })
            self._metrics["targets_skipped"] += 1
            return
        chain_cfg = self.cfg.get("chain", {}) if isinstance(self.cfg.get("chain", {}), dict) else {}
        self.event_writer.write({
            "event": "module_order",
            "target": target.url,
            "order": order_for_target,
            "strategy": str(chain_cfg.get("strategy", "sequential")),
        })

        history: list[HistoryEntry] = []
        for module_name in order_for_target:
            if not self._module_allowed(module_name, policy):
                history.append(HistoryEntry(module_name, Verdict.ABORTED, "module_blocked_by_policy", time.time(), {}))
                continue
            module_cfg = self.cfg.get("modules", {}).get(module_name, {}) if isinstance(self.cfg.get("modules", {}), dict) else {}
            if not module_cfg.get("enabled", True):
                continue
            module = self.modules.get(module_name)
            if not module:
                history.append(HistoryEntry(module_name, Verdict.ERROR, "module_missing", time.time(), {}))
                continue
            module_method = str(module_cfg.get("method", "GET")).upper()
            blocked, reason = self._blocked_by_path(target.program_id or "all", target.url, policy, module_method)
            if blocked:
                history.append(HistoryEntry(module_name, Verdict.ABORTED, f"blocked_path:{reason}", time.time(), {}))
                self.event_writer.write({
                    "event": "module_blocked",
                    "target": target.url,
                    "module": module_name,
                    "method": module_method,
                    "reason": reason,
                })
                continue
            if reason == "manual_override":
                self.event_writer.write({
                    "event": "governance_override",
                    "target": target.url,
                    "module": module_name,
                    "method": module_method,
                    "program": target.program_id,
                })
            auth_session = str(module_cfg.get("auth_session", "")).strip() or str((ctx.policy or {}).get("auth_session", "")).strip()
            requires_auth = bool(module_cfg.get("requires_auth", False))
            use_auth = bool(module_cfg.get("use_auth", False) or requires_auth)
            if use_auth and not auth_session:
                use_auth = False

            module_ctx = ModuleContext(
                timeouts=ctx.timeouts,
                politeness=ctx.politeness,
                user_agents=ctx.user_agents,
                logger=ctx.logger,
                stealth_mode=ctx.stealth_mode,
                proxies=ctx.proxies,
                tool_timeout_s=ctx.tool_timeout_s,
                policy=ctx.policy,
                module_cfg=module_cfg,
                session_name=auth_session,
                use_auth=use_auth,
                required_headers=ctx.required_headers,
                safe_payloads_only=bool(module_cfg.get("safe_payloads_only", False)),
                baseline_score=ctx.baseline_score,
                baseline_notes=ctx.baseline_notes,
                baseline_methods=ctx.baseline_methods,
            )

            self._metrics["module_runs"] += 1
            self._metrics["per_module"].setdefault(module_name, {"runs": 0, "errors": 0, "timeouts": 0, "poc_valid": 0})
            self._metrics["per_module"][module_name]["runs"] += 1
            result = await self._run_with_retry(module, target, module_ctx)
            if isinstance(result.evidence, dict):
                result.evidence.setdefault("baseline_score", module_ctx.baseline_score)
                result.evidence.setdefault("baseline_notes", module_ctx.baseline_notes or [])
                result.evidence.setdefault("baseline_methods", module_ctx.baseline_methods or [])
            safe_evidence = redact_value(result.evidence) if isinstance(result.evidence, dict) else result.evidence
            self.event_writer.write({
                "event": "module_result",
                "target": target.url,
                "module": module_name,
                "status": result.status,
                "evidence": safe_evidence,
            })
            if isinstance(result.evidence, dict):
                req_meta = result.evidence.get("request", {}) if isinstance(result.evidence.get("request"), dict) else {}
                method = str(req_meta.get("method", "GET")).upper()
                url = str(req_meta.get("url", target.url))
                endpoint = str(urlsplit(url).path or "/")
                status_val = result.evidence.get("status_variant", result.evidence.get("status"))
                if status_val is not None:
                    self._record_status(host, int(status_val))
                self.event_writer.write({
                    "event": "observation",
                    "timestamp": datetime.now(ZoneInfo("UTC")).isoformat().replace("+00:00", "Z"),
                    "program": target.program_id,
                    "target": target.url,
                    "endpoint": endpoint,
                    "method": method,
                    "status": status_val,
                    "sensitivity_score": result.evidence.get("sensitivity_score"),
                    "baseline_score": result.evidence.get("baseline_score"),
                    "note": result.status,
                })
            if result.status in {"error", "timeout"}:
                self.circuit.record(host, result.status)
                history.append(HistoryEntry(module_name, Verdict.ERROR, result.status, time.time(), result.metadata))
                self._metrics["errors"] += 1
                inc_error(module_name)
                if result.status == "timeout":
                    self._metrics["module_timeouts"] += 1
                    self._metrics["per_module"][module_name]["timeouts"] += 1
                else:
                    self._metrics["module_errors"] += 1
                    self._metrics["per_module"][module_name]["errors"] += 1
                continue
            self.circuit.record(host, result.status)

            if result.status == "no_poc":
                history.append(HistoryEntry(module_name, Verdict.NO_POC, "no_poc", time.time(), result.metadata))
                self._metrics["no_poc"] += 1
                continue

            self._metrics["candidates"] += 1
            inc_candidate(module_name)
            impact_ok, impact_reason = await self._impact_check(
                module_name=module_name,
                target=target,
                ctx=module_ctx,
                evidence=result.evidence,
            )
            if not impact_ok:
                decision = ValidationDecision(Verdict.INCONCLUSIVE, 0.45, impact_reason, [])
                history.append(HistoryEntry(module_name, decision.verdict, decision.rationale, time.time(), result.metadata))
                self._metrics["inconclusive"] += 1
                await self._persist_finding(target, module_name, result, decision, None)
                continue
            if self.replay_attempts > 0:
                base_signals = self.validator.heuristic_signals(result.evidence)
                replay_ok = await self._replay_confirm(module, target, module_ctx, base_signals)
                if not replay_ok:
                    decision = ValidationDecision(Verdict.INCONCLUSIVE, 0.4, "replay_failed", base_signals)
                    self.event_writer.write({
                        "event": "replay_failed",
                        "target": target.url,
                        "module": module_name,
                        "signals": base_signals,
                    })
                else:
                    decision = await self.validator.validate(result.evidence, module_name, target.url)
            else:
                decision = await self.validator.validate(result.evidence, module_name, target.url)
            history.append(HistoryEntry(module_name, decision.verdict, decision.rationale, time.time(), result.metadata))
            if decision.verdict == Verdict.FALSE_POSITIVE:
                self._metrics["false_positive"] += 1
                inc_fp_spike(target.program_id or "all")
            elif decision.verdict == Verdict.INCONCLUSIVE:
                self._metrics["inconclusive"] += 1

            if decision.verdict == Verdict.POC_VALID:
                self._metrics["poc_valid"] += 1
                self._metrics["per_module"][module_name]["poc_valid"] += 1
                inc_poc_valid(module_name)
                report_path = self._emit_report(target, module_name, result, decision)
                await self._persist_finding(target, module_name, result, decision, report_path)
                self.event_writer.write({
                    "event": "poc_valid",
                    "target": target.url,
                    "module": module_name,
                    "report_path": str(report_path),
                    "rationale": decision.rationale,
                })
                self._metrics["targets_processed"] += 1
                inc_target_processed()
                return
            await self._persist_finding(target, module_name, result, decision, None)

        self._metrics["targets_processed"] += 1
        inc_target_processed()
        self.event_writer.write({
            "event": "no_poc",
            "target": target.url,
            "history": [h.__dict__ for h in history],
        })

    def _check_hot_reload(self) -> None:
        now = time.monotonic()
        if now < self._hot_reload_next_check:
            return
        self._hot_reload_next_check = now + max(5.0, float(self._hot_reload_interval))
        templates_path = self.hot_reload_cfg.get("nuclei_templates_path")
        wordlists_path = self.hot_reload_cfg.get("wordlists_path")
        for label, path in {"nuclei_templates": templates_path, "wordlists": wordlists_path}.items():
            if not path:
                continue
            resolved = resolve_path_from_cfg(path)
            if not resolved.exists():
                continue
            latest = max((p.stat().st_mtime for p in resolved.rglob("*") if p.is_file()), default=0.0)
            previous = self._hot_reload_state.get(label, 0.0)
            if latest > previous:
                self._hot_reload_state[label] = latest
                self.event_writer.write({
                    "event": "hot_reload",
                    "asset": label,
                    "path": str(resolved),
                    "mtime": latest,
                })

    def _write_metrics(self, duration_s: float) -> None:
        throughput_tph = round(self._metrics["targets_processed"] / max(1e-6, duration_s / 3600.0), 2)
        candidates = max(1, int(self._metrics["candidates"]))
        signal_rate = round(self._metrics["poc_valid"] / candidates, 4)
        error_rate = round(self._metrics["errors"] / max(1, int(self._metrics["module_runs"])), 4)
        fp_rate = round(self._metrics["false_positive"] / candidates, 4)
        baseline_tph = float(self.metrics_cfg.get("throughput_baseline_tph", 60) or 60)
        throughput_score = min(1.0, throughput_tph / max(1.0, baseline_tph))
        efficiency_score = round((0.5 * signal_rate) + (0.3 * throughput_score) + (0.2 * (1.0 - error_rate)), 4)

        summary = {
            "duration_s": round(duration_s, 2),
            "throughput_tph": throughput_tph,
            "signal_rate": signal_rate,
            "error_rate": error_rate,
            "false_positive_rate": fp_rate,
            "efficiency_score": efficiency_score,
            "metrics": self._metrics,
        }
        out_path = self.metrics_path / "attack_chain_summary.json"
        out_path.write_text(json.dumps(summary, ensure_ascii=True, indent=2), encoding="utf-8")
        self.event_writer.write({"event": "metrics_summary", "summary": summary, "path": str(out_path)})

        if self.alert_router.available:
            fp_threshold = float(self.metrics_cfg.get("fp_alert_threshold", 0.4) or 0.4)
            err_threshold = float(self.metrics_cfg.get("error_alert_threshold", 0.2) or 0.2)
            if fp_rate >= fp_threshold:
                inc_fp_spike("all")
                self.alert_router.enqueue_critical_log(
                    message=f"attack_chain_fp_rate_high rate={fp_rate} threshold={fp_threshold}",
                    run_id=self.run_id,
                )
            if error_rate >= err_threshold:
                self.alert_router.enqueue_critical_log(
                    message=f"attack_chain_error_rate_high rate={error_rate} threshold={err_threshold}",
                    run_id=self.run_id,
                )
        if self.runbook.enabled:
            actions = self.runbook.auto_actions(fp_rate=fp_rate, error_rate=error_rate)
            if actions:
                self.event_writer.write({
                    "event": "runbook_actions",
                    "actions": actions,
                    "fp_rate": fp_rate,
                    "error_rate": error_rate,
                })

    def _record_status(self, host: str, status: int) -> None:
        if not host:
            return
        counts = self._host_status_counts.setdefault(host, {})
        counts[status] = counts.get(status, 0) + 1
        if status in {403, 429} and self.runbook.enabled:
            threshold = int(self.runbook.auto_blacklist_403_429_threshold or 0)
            if threshold > 0 and counts[status] >= threshold:
                self.runbook.block_host(host, minutes=self.runbook.blacklist_minutes, reason=f"auto_block_status_{status}")
                self.event_writer.write({
                    "event": "runbook_block_host",
                    "host": host,
                    "status": status,
                    "count": counts[status],
                })

    async def _run_with_retry(self, module: Any, target: Target, ctx: ModuleContext) -> ModuleResult:
        max_attempts = max(1, int(self.retry_cfg.get("max_attempts", 1)))
        base = float(self.retry_cfg.get("backoff_base_s", 1.0))
        max_backoff = float(self.retry_cfg.get("backoff_max_s", 30.0))
        jitter = float(self.retry_cfg.get("jitter", 0.2))

        last_result: ModuleResult | None = None
        for attempt in range(max_attempts):
            try:
                last_result = await module.run(target, ctx)
                return last_result
            except asyncio.TimeoutError:
                last_result = ModuleResult(module.name, "timeout", {"reason": "timeout"}, "", {})
            except Exception as exc:
                last_result = ModuleResult(module.name, "error", {"reason": str(exc)}, "", {})

            backoff = min(max_backoff, base * (2**attempt))
            if jitter > 0:
                backoff = backoff * max(0.1, 1.0 + random.uniform(-jitter, jitter))
            await asyncio.sleep(backoff)

        return last_result or ModuleResult(module.name, "error", {"reason": "unknown"}, "", {})

    async def _replay_confirm(
        self,
        module: Any,
        target: Target,
        ctx: ModuleContext,
        base_signals: list[str],
    ) -> bool:
        if self.replay_attempts <= 0:
            return True
        base_set = set(base_signals or [])
        for _ in range(self.replay_attempts):
            try:
                replay = await module.run(target, ctx)
            except Exception:
                continue
            if replay.status != "candidate":
                continue
            replay_signals = self.validator.heuristic_signals(replay.evidence)
            if not replay_signals:
                continue
            if not self.replay_require_signal_match:
                return True
            if base_set & set(replay_signals):
                return True
        return False

    def _emit_report(self, target: Target, module: str, result: ModuleResult, decision: Any) -> Path:
        safe_name = target.target_id.replace("/", "_")
        report_path = self.reports_path / f"poc_{safe_name}_{module}.md"
        safe_evidence = redact_value(result.evidence) if isinstance(result.evidence, dict) else result.evidence
        content = (
            "# PoC Report\n\n"
            f"## Summary\n- Module: {module}\n- Target: {target.url}\n\n"
            "## Steps to Reproduce\n"
            f"1. Access {target.url}\n"
            f"2. Apply payload: {result.candidate_poc}\n"
            "3. Observe the response changes noted in evidence.\n\n"
            "## Evidence\n"
            f"- Evidence: {json.dumps(safe_evidence, ensure_ascii=True)}\n\n"
            "## LLM Triage\n"
            f"- Verdict: {decision.verdict.value}\n"
            f"- Confidence: {decision.confidence}\n"
            f"- Rationale: {decision.rationale}\n"
        )
        report_path.write_text(content, encoding="utf-8")
        return report_path

    async def _persist_finding(
        self,
        target: Target,
        module: str,
        result: ModuleResult,
        decision: Any,
        report_path: Path | None,
    ) -> None:
        severity = "medium" if decision.verdict == Verdict.POC_VALID else "low"
        evidence = dict(redact_value(result.evidence) if isinstance(result.evidence, dict) else (result.evidence or {}))
        evidence["url"] = target.url
        evidence["endpoint"] = urlsplit(target.url).path or "/"
        if report_path:
            evidence["report_path"] = str(report_path)
        metadata = {
            "source": "attack_chain",
            "confidence_score": float(decision.confidence or 0),
            "validator_note": decision.rationale,
        }
        finding = Finding(
            plugin=module,
            target=target.url,
            category=module,
            severity=severity,
            title=f"{module.upper()} candidate",
            evidence=evidence,
            metadata=metadata,
        )

        if self.storage is not None:
            try:
                self.storage.write_findings(self.run_id, [finding.__dict__])
                status = "actionable" if decision.verdict == Verdict.POC_VALID else (
                    "review" if decision.verdict == Verdict.INCONCLUSIVE else "rejected"
                )
                self.storage.upsert_triage_queue_rows(
                    run_id=self.run_id,
                    rows=[finding.__dict__],
                    status=status,
                )
                if decision.verdict == Verdict.POC_VALID:
                    self.storage.upsert_verified_finding(
                        run_id=self.run_id,
                        target=target.url,
                        plugin=module,
                        category=module,
                        severity=severity,
                        title=f"{module.upper()} candidate",
                        confidence_score=float(decision.confidence or 0),
                        impact_analysis=decision.rationale,
                        endpoint=str(evidence.get("endpoint", evidence.get("url", ""))),
                        parameter_name=str(evidence.get("param", "")),
                        poc_path=str(report_path) if report_path else "",
                        curl_command="",
                        metadata=metadata,
                        evidence=evidence,
                    )
            except Exception as err:
                self.logger.warning(f"attack_chain_storage_failed err={err}")

        if self.alert_router.available and decision.verdict == Verdict.POC_VALID:
            try:
                await self.alert_router.send_finding(finding, run_id=self.run_id, source="attack_chain")
            except Exception as err:
                self.logger.warning(f"attack_chain_alert_failed err={err}")
