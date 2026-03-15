#!/usr/bin/env python3
"""Autonomous research pipeline for HunterOps (incremental, non-core orchestration)."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import fnmatch
import hashlib
import json
import logging
import os
import re
import random
import sys
import time
import traceback
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from zoneinfo import ZoneInfo
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hunterops.config import get_runtime, load_config
from hunterops.ade_brain import PluginImpl as ADEBrainPlugin
from hunterops.alert_router import AlertRouter
from hunterops.discord_notifier import DiscordDispatch
from hunterops.env_utils import evaluate_runtime_dependencies, filter_enabled_plugins
from hunterops.evidence_generator import generate_research_artifacts
from hunterops.hackerone_manager import HackerOneManager
from hunterops.hackerone_sync_engine import HackerOneSyncEngine
from hunterops.http_client import (
    close_async_http_client,
    configure_global_http_limits,
    configure_http_pool,
    json_keys,
    request_http_async,
)
from hunterops.intelligence import dedupe_findings, serialize_findings, to_jsonl
from hunterops.intigriti_manager import IntigritiManager
from hunterops.logging_utils import attach_alert_router, setup_logging
from hunterops.metrics import enable_metrics, write_metrics_snapshot
from hunterops.oob_engine import OOBEngine
from hunterops.plugin_loader import load_plugins
from hunterops.program_packs import load_program_packs, resolve_pack
from hunterops.report_engine import ReportEngine
from hunterops.rate_limit import AsyncRateLimiter
from hunterops.reporting import export_csv, export_dashboard, export_html, export_json, export_markdown
from hunterops.retry import retry_async
from hunterops.shannon_adapter import ShannonAdapter, ShannonResult
from hunterops.async_runtime import install_uvloop_if_available
from hunterops.impact_validator import ImpactValidator
from hunterops.runtime_paths import ensure_directory, resolve_path
from hunterops.session_guardian import SessionGuardian
from hunterops.session_profiles import auth_header, load_sessions
from hunterops.storage import PostgresStorage
from hunterops.types import Finding, Task
from hunterops.scope_authorization import authorize_targets, load_authorized_scope
from hunterops.target_governance import apply_target_governance
from hunterops.attack_chain.scope import ScopePolicy, collect_scope, in_scope, load_programs
from hunterops.rules_engine import check_automation_allowed

EMAIL_RE = re.compile(r"""[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}""")
UUID_RE = re.compile(r"""\b[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}\b""")
NUMERIC_ID_RE = re.compile(r"""\b[1-9][0-9]{2,18}\b""")
SENSITIVE_PRIORITY_KEYWORDS = ("admin", "internal", "v1/debug", "config", "staging", "export", "graphiql")
DEFAULT_PIPELINE_LOG = "data/pipeline.log"



def _env_truthy(name: str, default: bool = False) -> bool:
    raw = os.getenv(name, "").strip().lower()
    if not raw:
        return default
    return raw in {"1", "true", "yes", "y", "on"}


def _policy_allows_now(policy: ScopePolicy) -> bool:
    windows = policy.allowed_hours or []
    if not windows:
        return True
    tz = policy.timezone or "UTC"
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


def _missing_required_headers(policy: ScopePolicy) -> list[str]:
    missing: list[str] = []
    if not isinstance(policy.required_headers, dict):
        return missing
    for key, value in policy.required_headers.items():
        val = str(value or "").strip()
        if not val:
            missing.append(str(key))
            continue
        if val.startswith("${") and val.endswith("}"):
            missing.append(str(key))
    return missing


def _policy_rps(policy: ScopePolicy) -> float:
    rps: list[float] = []
    if policy.per_host_rpm is not None and policy.per_host_rpm > 0:
        rps.append(float(policy.per_host_rpm) / 60.0)
    if policy.per_target_rpm is not None and policy.per_target_rpm > 0:
        rps.append(float(policy.per_target_rpm) / 60.0)
    if not rps:
        return 0.0
    return max(0.0, min(rps))


def _warn_scope_expiry(scope_doc: dict[str, Any], logger: logging.Logger) -> None:
    raw = str(scope_doc.get("valid_to", "")).strip()
    if not raw:
        return
    try:
        warn_days = float(os.getenv("HUNTEROPS_SCOPE_EXPIRY_WARN_DAYS", "0") or 0)
    except Exception:
        warn_days = 0.0
    if warn_days <= 0:
        return
    try:
        end = datetime.fromisoformat(raw.replace("Z", "+00:00")).astimezone(UTC)
    except Exception:
        return
    remaining_days = (end - datetime.now(UTC)).total_seconds() / 86400.0
    if remaining_days <= warn_days:
        end_text = end.isoformat().replace("+00:00", "Z")
        logger.warning(f"scope_expiring_soon days_remaining={remaining_days:.2f} valid_to={end_text}")


def _finding_from_row(row: dict[str, Any]) -> Finding | None:
    if not isinstance(row, dict):
        return None
    evidence = row.get("evidence", {})
    if not isinstance(evidence, dict):
        try:
            evidence = json.loads(str(evidence))
        except Exception:
            evidence = {}
    metadata = row.get("metadata", {})
    if not isinstance(metadata, dict):
        try:
            metadata = json.loads(str(metadata))
        except Exception:
            metadata = {}
    plugin = str(row.get("plugin", "") or "")
    if not plugin:
        plugin = str(metadata.get("plugin_source", "") or "")
    target = str(row.get("target", "") or "")
    category = str(row.get("category", "") or "")
    severity = str(row.get("severity", "") or "")
    if not severity:
        severity = str(metadata.get("severity", "info") or "info")
    title = str(row.get("title", "") or "")
    if not title:
        title = str(metadata.get("title", category or "finding") or "finding")
    return Finding(
        plugin=plugin,
        target=target,
        category=category,
        severity=severity,
        title=title,
        evidence=evidence,
        metadata=metadata,
    )


def _reload_findings_from_storage(
    storage: PostgresStorage,
    *,
    run_id: str,
    current: list[Finding],
    logger: logging.Logger,
) -> tuple[list[Finding], bool]:
    try:
        in_memory_before = len(current)
        stored_rows = storage.fetch_run_findings_all(run_id)
        reloaded: list[Finding] = []
        for row in stored_rows:
            item = _finding_from_row(row)
            if item:
                reloaded.append(item)
        if current:
            reloaded.extend(current)
        logger.info(
            "research_findings_reload "
            f"storage_rows={len(stored_rows)} in_memory_before={in_memory_before} merged_total={len(reloaded)}"
        )
        return reloaded, True
    except Exception as err:
        logger.error(f"research_findings_reload_failed err={err}")
        return current, False


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="HunterOps autonomous research pipeline")
    parser.add_argument("--config", default="config/engine.yaml")
    parser.add_argument("--targets-file", default="data/targets/in_scope_hosts.txt")
    parser.add_argument("--target", default="")
    parser.add_argument("--plugins", default="")
    parser.add_argument("--run-id", default="")
    parser.add_argument("--out-dir", default="data/reports/research")
    parser.add_argument(
        "--alert-dry-run",
        action="store_true",
        help="Bypass scan flow and dispatch synthetic critical/research alerts to Discord and Slack",
    )
    parser.add_argument("--verbose", action="store_true")
    return parser.parse_args()


def _force_stdio_unbuffered() -> None:
    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        if stream is None:
            continue
        try:
            stream.reconfigure(line_buffering=True, write_through=True)
        except Exception:
            with contextlib.suppress(Exception):
                stream.flush()


def _stderr_echo(message: str) -> None:
    ts = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    line = f"[{ts}] {message}"
    try:
        print(line, file=sys.stderr, flush=True)
    except Exception:
        return


def _build_fallback_logger(log_file: Path, *, verbose: bool) -> logging.Logger:
    logger = logging.getLogger("hunterops")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.propagate = False
    logger.handlers.clear()

    formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    console = logging.StreamHandler(stream=sys.stderr)
    console.setLevel(logging.DEBUG if verbose else logging.INFO)
    console.setFormatter(formatter)
    logger.addHandler(console)

    try:
        ensure_directory(log_file.parent, mode=0o755)
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    except Exception:
        _stderr_echo(f"fallback_logger_file_attach_failed path={log_file}")
    return logger


def _init_bootstrap_logger(log_file: Path, *, verbose: bool) -> logging.Logger:
    try:
        ensure_directory(log_file.parent, mode=0o755)
        return setup_logging(log_file, verbose=verbose)
    except Exception as err:
        _stderr_echo(f"logger_init_failed path={log_file} err={type(err).__name__}: {err}")
        return _build_fallback_logger(log_file, verbose=verbose)


def _attach_json_file_handler(logger: Any, log_file: Path) -> None:
    if not isinstance(logger, logging.Logger):
        return
    ensure_directory(log_file.parent, mode=0o755)
    target = log_file.resolve()
    for handler in logger.handlers:
        if isinstance(handler, logging.FileHandler):
            base = Path(getattr(handler, "baseFilename", "")).resolve()
            if base == target:
                return

    formatter: logging.Formatter | None = None
    for handler in logger.handlers:
        if isinstance(handler, logging.FileHandler) and handler.formatter is not None:
            formatter = handler.formatter
            break
    if formatter is None:
        for handler in logger.handlers:
            if handler.formatter is not None:
                formatter = handler.formatter
                break
    if formatter is None:
        formatter = logging.Formatter("%(message)s")

    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)


def _assert_writable_directory(path: Path, *, label: str) -> Path:
    if path.exists() and not path.is_dir():
        raise NotADirectoryError(f"{label} is not a directory: {path}")
    ensure_directory(path, mode=0o755)
    probe = path / f".hunterops_write_probe_{os.getpid()}_{int(time.time() * 1000)}"
    try:
        probe.write_text("ok\n", encoding="utf-8")
    except Exception as err:
        raise PermissionError(f"{label} is not writable: {path} ({type(err).__name__}: {err})") from err
    finally:
        with contextlib.suppress(Exception):
            probe.unlink(missing_ok=True)
    return path


def _cfg_get(cfg: dict[str, Any], dotted_path: str) -> tuple[Any, bool]:
    node: Any = cfg
    for part in dotted_path.split("."):
        if not isinstance(node, dict) or part not in node:
            return None, False
        node = node[part]
    return node, True


def _validate_config_structure(cfg: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    required: list[tuple[str, type[Any]]] = [
        ("runtime", dict),
        ("modules", dict),
        ("storage", dict),
        ("storage.postgres", dict),
        ("storage.postgres.enabled", bool),
        ("storage.postgres.dsn_env", str),
        ("storage.postgres.required", bool),
        ("storage.redis", dict),
        ("storage.redis.enabled", bool),
        ("storage.redis.required", bool),
    ]
    for dotted_path, expected_type in required:
        value, found = _cfg_get(cfg, dotted_path)
        if not found:
            errors.append(f"missing_config_key path={dotted_path}")
            continue
        if not isinstance(value, expected_type):
            errors.append(
                f"invalid_config_type path={dotted_path} expected={expected_type.__name__} got={type(value).__name__}"
            )
            continue
        if expected_type is str and not str(value).strip():
            errors.append(f"empty_config_value path={dotted_path}")

    modules, modules_found = _cfg_get(cfg, "modules")
    if modules_found and isinstance(modules, dict):
        h1_manager = modules.get("hackerone_manager", {})
        if isinstance(h1_manager, dict) and bool(h1_manager.get("enabled", False)):
            for key in ("api_user_env", "api_token_env"):
                raw = str(h1_manager.get(key, "")).strip()
                if not raw:
                    errors.append(f"missing_config_key path=modules.hackerone_manager.{key}")

        intigriti_manager = modules.get("intigriti_manager", {})
        if isinstance(intigriti_manager, dict) and bool(intigriti_manager.get("enabled", False)):
            for key in ("api_token_env",):
                raw = str(intigriti_manager.get(key, "")).strip()
                if not raw:
                    errors.append(f"missing_config_key path=modules.intigriti_manager.{key}")
            for key in ("include_hosts", "exclude_hosts", "program_handles"):
                raw_list = intigriti_manager.get(key, [])
                if raw_list is None:
                    continue
                if not isinstance(raw_list, list):
                    errors.append(f"invalid_config_type path=modules.intigriti_manager.{key} expected=list")

        report_engine = modules.get("report_engine", {})
        if isinstance(report_engine, dict) and bool(report_engine.get("auto_submit_h1_draft", False)):
            for key in ("identifier_env", "token_env"):
                raw = str(report_engine.get(key, "")).strip()
                if not raw:
                    errors.append(f"missing_config_key path=modules.report_engine.{key}")

        shannon_validator = modules.get("shannon_validator", {})
        if isinstance(shannon_validator, dict) and bool(shannon_validator.get("enabled", False)):
            binary_path = str(shannon_validator.get("binary_path", "")).strip()
            if not binary_path:
                errors.append("missing_config_key path=modules.shannon_validator.binary_path")
            thresholds = shannon_validator.get("thresholds", {})
            if not isinstance(thresholds, dict):
                errors.append("invalid_config_type path=modules.shannon_validator.thresholds expected=dict")
            else:
                min_severity = str(thresholds.get("min_severity", "")).strip().lower()
                if min_severity not in {"low", "medium", "high", "critical"}:
                    errors.append("invalid_config_value path=modules.shannon_validator.thresholds.min_severity expected=low|medium|high|critical")
                for key in ("min_confidence", "min_impact"):
                    with contextlib.suppress(Exception):
                        float(thresholds.get(key, 0))
                        continue
                    errors.append(f"invalid_config_value path=modules.shannon_validator.thresholds.{key} expected=float")
            for key in ("timeout_seconds", "max_candidates_per_run"):
                with contextlib.suppress(Exception):
                    int(shannon_validator.get(key, 0))
                    continue
                errors.append(f"invalid_config_value path=modules.shannon_validator.{key} expected=int")

    return errors


def _validate_config_env(cfg: dict[str, Any]) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []

    pg_cfg = cfg.get("storage", {}).get("postgres", {}) if isinstance(cfg.get("storage"), dict) else {}
    pg_enabled = bool(pg_cfg.get("enabled", False))
    pg_required = bool(pg_cfg.get("required", True))
    dsn_env = str(pg_cfg.get("dsn_env", "HUNTEROPS_POSTGRES_DSN")).strip()
    dsn_value = str(os.getenv(dsn_env, "")).strip() if dsn_env else ""
    if pg_enabled and pg_required and not dsn_value:
        errors.append(f"missing_required_env env={dsn_env} reason=postgres_enabled")
    elif pg_enabled and not dsn_value:
        warnings.append(f"missing_optional_env env={dsn_env} reason=postgres_enabled_but_optional")

    modules = cfg.get("modules", {}) if isinstance(cfg.get("modules"), dict) else {}
    h1_sync_cfg = modules.get("hackerone_sync_engine", {})
    if isinstance(h1_sync_cfg, dict) and bool(h1_sync_cfg.get("enabled", False)):
        for env_name in ("H1_API_IDENTIFIER", "H1_API_TOKEN"):
            if not str(os.getenv(env_name, "")).strip():
                errors.append(f"missing_required_env env={env_name} reason=hackerone_sync_engine_enabled")

    h1_manager_cfg = modules.get("hackerone_manager", {})
    if isinstance(h1_manager_cfg, dict) and bool(h1_manager_cfg.get("enabled", False)):
        user_env = str(h1_manager_cfg.get("api_user_env", "HACKERONE_API_USER")).strip()
        token_env = str(h1_manager_cfg.get("api_token_env", "HACKERONE_API_TOKEN")).strip()
        if user_env and not str(os.getenv(user_env, "")).strip():
            errors.append(f"missing_required_env env={user_env} reason=hackerone_manager_enabled")
        if token_env and not str(os.getenv(token_env, "")).strip():
            errors.append(f"missing_required_env env={token_env} reason=hackerone_manager_enabled")
        handles = h1_manager_cfg.get("program_handles", [])
        has_handles = isinstance(handles, list) and any(str(item).strip() for item in handles)
        has_single = bool(str(os.getenv("HACKERONE_PROGRAM_HANDLE", "")).strip())
        if not has_handles and not has_single:
            errors.append("missing_required_value path=modules.hackerone_manager.program_handles_or_env:HACKERONE_PROGRAM_HANDLE")

    intigriti_manager_cfg = modules.get("intigriti_manager", {})
    if isinstance(intigriti_manager_cfg, dict) and bool(intigriti_manager_cfg.get("enabled", False)):
        token_env = str(intigriti_manager_cfg.get("api_token_env", "INTIGRITI_API_TOKEN")).strip() or "INTIGRITI_API_TOKEN"
        if not str(os.getenv(token_env, "")).strip():
            errors.append(f"missing_required_env env={token_env} reason=intigriti_manager_enabled")

    report_engine_cfg = modules.get("report_engine", {})
    if isinstance(report_engine_cfg, dict) and bool(report_engine_cfg.get("auto_submit_h1_draft", False)):
        id_env = str(report_engine_cfg.get("identifier_env", "H1_API_IDENTIFIER")).strip()
        token_env = str(report_engine_cfg.get("token_env", "H1_API_TOKEN")).strip()
        if id_env and not str(os.getenv(id_env, "")).strip():
            errors.append(f"missing_required_env env={id_env} reason=report_engine_auto_submit_enabled")
        if token_env and not str(os.getenv(token_env, "")).strip():
            errors.append(f"missing_required_env env={token_env} reason=report_engine_auto_submit_enabled")

    oob_cfg = modules.get("oob_engine", {})
    if isinstance(oob_cfg, dict) and bool(oob_cfg.get("enabled", False)):
        callback_env = str(oob_cfg.get("callback_domain_env", "HUNTEROPS_OOB_CALLBACK_DOMAIN")).strip()
        poll_env = str(oob_cfg.get("poll_url_env", "HUNTEROPS_OOB_POLL_URL")).strip()
        callback = str(os.getenv(callback_env, str(oob_cfg.get("callback_domain", "")))).strip()
        poll_url = str(os.getenv(poll_env, str(oob_cfg.get("poll_url", "")))).strip()
        if not callback:
            errors.append(f"missing_required_value path=modules.oob_engine.callback_domain_or_env:{callback_env}")
        if not poll_url:
            errors.append(f"missing_required_value path=modules.oob_engine.poll_url_or_env:{poll_env}")

    bug_bounty_username = str(
        os.getenv("HUNTEROPS_BUG_BOUNTY_USERNAME", os.getenv("BUG_BOUNTY_USERNAME", os.getenv("H1_API_IDENTIFIER", "")))
    ).strip()
    test_account_email = str(
        os.getenv("HUNTEROPS_TEST_ACCOUNT_EMAIL", os.getenv("BUG_BOUNTY_TEST_ACCOUNT_EMAIL", ""))
    ).strip()
    if not bug_bounty_username:
        warnings.append("missing_recommended_env env=HUNTEROPS_BUG_BOUNTY_USERNAME reason=program_submission_header")
    if not test_account_email:
        warnings.append("missing_recommended_env env=HUNTEROPS_TEST_ACCOUNT_EMAIL reason=program_submission_header")

    return errors, warnings


def _resolve_redis_target(redis_cfg: dict[str, Any]) -> tuple[str, int, float]:
    timeout = float(redis_cfg.get("connect_timeout_seconds", 2.0) or 2.0)
    url_env = str(redis_cfg.get("url_env", "HUNTEROPS_REDIS_URL")).strip()
    redis_url = str(os.getenv(url_env, "")).strip() if url_env else ""
    if redis_url:
        parsed = urlparse(redis_url)
        host = str(parsed.hostname or "").strip()
        if not host:
            raise RuntimeError(f"invalid_redis_url env={url_env} value={redis_url}")
        return host, int(parsed.port or 6379), timeout

    host_env = str(redis_cfg.get("host_env", "REDIS_HOST")).strip()
    port_env = str(redis_cfg.get("port_env", "REDIS_PORT")).strip()
    host = str(os.getenv(host_env, "")).strip() if host_env else ""
    if not host:
        host = str(redis_cfg.get("host", "redis")).strip() or "redis"
    port_raw = str(os.getenv(port_env, "")).strip() if port_env else ""
    if not port_raw:
        port_raw = str(redis_cfg.get("port", 6379)).strip() or "6379"
    try:
        port = int(port_raw)
    except Exception as err:
        raise RuntimeError(f"invalid_redis_port source={port_env or 'storage.redis.port'} value={port_raw}") from err
    return host, port, timeout


async def _ping_redis(host: str, port: int, timeout: float) -> str:
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    reader, writer = await asyncio.wait_for(asyncio.open_connection(host=host, port=port), timeout=timeout)
    try:
        writer.write(b"*1\r\n$4\r\nPING\r\n")
        await writer.drain()
        raw = await asyncio.wait_for(reader.readline(), timeout=timeout)
        reply = raw.decode("utf-8", errors="ignore").strip()
        if reply.startswith("+PONG") or reply.startswith("-NOAUTH"):
            return reply or "PONG"
        if reply.startswith("-"):
            raise RuntimeError(reply)
        return reply or "unknown_reply"
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


async def _validate_redis_connectivity(cfg: dict[str, Any], logger: Any) -> None:
    storage_cfg = cfg.get("storage", {}) if isinstance(cfg.get("storage"), dict) else {}
    redis_cfg = storage_cfg.get("redis", {}) if isinstance(storage_cfg.get("redis"), dict) else {}
    enabled = bool(redis_cfg.get("enabled", False))
    required = bool(redis_cfg.get("required", True))
    if not enabled:
        try:
            logger.info("redis_startup_check skipped=disabled")
        except Exception:
            _stderr_echo("redis_startup_check skipped=disabled")
        return

    host, port, timeout = _resolve_redis_target(redis_cfg)
    try:
        reply = await _ping_redis(host=host, port=port, timeout=timeout)
        logger.info(f"redis_startup_check_ok host={host} port={port} reply={reply}")
    except Exception as err:
        message = f"redis_connection_failed host={host} port={port} timeout={timeout} err={type(err).__name__}: {err}"
        if required:
            raise RuntimeError(message) from err
        logger.warning(message)


def collect_targets(args: argparse.Namespace) -> list[str]:
    if args.target:
        return [args.target.strip()]
    p = resolve_path(args.targets_file)
    if not p.exists():
        return []
    return [x.strip() for x in p.read_text(encoding="utf-8").splitlines() if x.strip()]


def _task_endpoints(task: Task) -> list[str]:
    if not isinstance(task.payload, dict):
        return ["/"]
    eps = task.payload.get("seed_paths") or task.payload.get("paths") or task.payload.get("endpoints") or task.payload.get("known_endpoints")
    if isinstance(eps, list):
        out = []
        for e in eps:
            if not isinstance(e, str) or not e.strip():
                continue
            if e.startswith("http://") or e.startswith("https://"):
                out.append(urlparse(e).path or "/")
            else:
                out.append(e if e.startswith("/") else f"/{e}")
        return sorted(list(set(out))) or ["/"]
    return ["/"]


def _iter_strings(value: Any, max_depth: int = 4, _depth: int = 0) -> list[str]:
    if _depth > max_depth:
        return []
    if isinstance(value, str):
        if value.strip():
            return [value]
        return []
    out: list[str] = []
    if isinstance(value, dict):
        for k, v in value.items():
            if isinstance(k, str) and k.strip():
                out.append(k)
            out.extend(_iter_strings(v, max_depth=max_depth, _depth=_depth + 1))
    elif isinstance(value, list):
        for item in value:
            out.extend(_iter_strings(item, max_depth=max_depth, _depth=_depth + 1))
    return out


def _detect_entities_from_text(text: str) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    for hit in EMAIL_RE.findall(text):
        found.append(("email", hit.strip()))
    for hit in UUID_RE.findall(text):
        found.append(("uuid", hit.strip()))
    for hit in NUMERIC_ID_RE.findall(text):
        found.append(("numeric_id", hit.strip()))
    return found


def _finding_source_endpoint(finding: Finding) -> str:
    ev = finding.evidence if isinstance(finding.evidence, dict) else {}
    req = ev.get("request", {}) if isinstance(ev.get("request"), dict) else {}
    req_url = req.get("url")
    if isinstance(req_url, str) and req_url.strip():
        return urlparse(req_url).path or "/"
    for key in ("endpoint", "path", "base_url", "modified_url", "url"):
        raw = ev.get(key)
        if isinstance(raw, str) and raw.strip():
            if raw.startswith("http://") or raw.startswith("https://"):
                return urlparse(raw).path or "/"
            return raw if raw.startswith("/") else f"/{raw}"
    return "/"


def extract_entity_rows(findings: list[Finding], target: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    dedupe: set[str] = set()
    for f in findings:
        ev = f.evidence if isinstance(f.evidence, dict) else {}
        md = f.metadata if isinstance(f.metadata, dict) else {}
        source_endpoint = _finding_source_endpoint(f)
        confidence = float(md.get("confidence_score", md.get("confidence", 65)) or 65)

        explicit = ev.get("discovered_entities", [])
        if isinstance(explicit, list):
            for item in explicit:
                if not isinstance(item, dict):
                    continue
                etype = str(item.get("entity_type", "")).strip().lower()
                evalue = str(item.get("entity_value", "")).strip()
                if not etype or not evalue:
                    continue
                sig = f"{target}|{etype}|{evalue.lower()}|{f.plugin}|{source_endpoint}"
                if sig in dedupe:
                    continue
                dedupe.add(sig)
                rows.append(
                    {
                        "entity_type": etype,
                        "entity_value": evalue,
                        "source_plugin": f.plugin,
                        "source_endpoint": str(item.get("source_endpoint", source_endpoint)),
                        "confidence_score": float(item.get("confidence_score", confidence) or confidence),
                        "metadata": {
                            "finding_category": f.category,
                            "finding_title": f.title,
                            "origin": "explicit_discovered_entities",
                            "source_target": target,
                        },
                    }
                )

        for key in ("leaked_identifiers", "object_identifiers"):
            values = ev.get(key, [])
            if isinstance(values, list):
                for raw in values:
                    if not isinstance(raw, str):
                        continue
                    for etype, evalue in _detect_entities_from_text(raw):
                        sig = f"{target}|{etype}|{evalue.lower()}|{f.plugin}|{source_endpoint}"
                        if sig in dedupe:
                            continue
                        dedupe.add(sig)
                        rows.append(
                            {
                                "entity_type": etype,
                                "entity_value": evalue,
                                "source_plugin": f.plugin,
                                "source_endpoint": source_endpoint,
                                "confidence_score": confidence,
                                "metadata": {
                                    "finding_category": f.category,
                                    "finding_title": f.title,
                                    "origin": key,
                                    "source_target": target,
                                },
                            }
                        )

        # Fallback: lightweight regex extraction over structured evidence/metadata strings.
        for blob in _iter_strings({"evidence": ev, "metadata": md}, max_depth=3):
            for etype, evalue in _detect_entities_from_text(blob):
                sig = f"{target}|{etype}|{evalue.lower()}|{f.plugin}|{source_endpoint}"
                if sig in dedupe:
                    continue
                dedupe.add(sig)
                rows.append(
                    {
                        "entity_type": etype,
                        "entity_value": evalue,
                        "source_plugin": f.plugin,
                        "source_endpoint": source_endpoint,
                        "confidence_score": max(45.0, confidence - 18.0),
                        "metadata": {
                            "finding_category": f.category,
                            "finding_title": f.title,
                            "origin": "regex_fallback",
                            "source_target": target,
                        },
                    }
                )
    return rows


def _set_query(url: str, key: str, value: str) -> str:
    parsed = urlparse(url)
    query_items = parse_qsl(parsed.query, keep_blank_values=True)
    query_items = [item for item in query_items if item[0] != key]
    query_items.append((key, value))
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(query_items), parsed.fragment))


def _json_structure_tokens(value: Any, prefix: str = "") -> set[str]:
    tokens: set[str] = set()
    if isinstance(value, dict):
        for key, child in value.items():
            key_s = str(key)
            path = f"{prefix}.{key_s}" if prefix else key_s
            tokens.add(path)
            tokens |= _json_structure_tokens(child, path)
    elif isinstance(value, list):
        for item in value[:5]:
            path = f"{prefix}[]" if prefix else "[]"
            tokens.add(path)
            tokens |= _json_structure_tokens(item, path)
    return tokens


def _semantic_structure_similarity(text_a: str, text_b: str) -> float:
    try:
        obj_a = json.loads(text_a)
        obj_b = json.loads(text_b)
    except Exception:
        tokens_a = set(re.split(r"[^a-z0-9]+", text_a.lower()))
        tokens_b = set(re.split(r"[^a-z0-9]+", text_b.lower()))
        tokens_a = {t for t in tokens_a if t}
        tokens_b = {t for t in tokens_b if t}
        if not tokens_a and not tokens_b:
            return 100.0
        return round((len(tokens_a & tokens_b) / max(1, len(tokens_a | tokens_b))) * 100.0, 2)
    ta = _json_structure_tokens(obj_a)
    tb = _json_structure_tokens(obj_b)
    if not ta and not tb:
        return 100.0
    return round((len(ta & tb) / max(1, len(ta | tb))) * 100.0, 2)


def _extract_endpoints_from_finding(finding: Finding) -> list[str]:
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


def _spawn_tasks_from_findings(
    findings: list[Finding],
    *,
    max_depth: int = 2,
    attack_chain_seed_enabled: bool = False,
    attack_chain_seed_available: bool = False,
    attack_chain_seed_max_endpoints: int = 80,
) -> list[Task]:
    spawned: list[Task] = []
    dedupe: set[str] = set()
    seed_groups: dict[tuple[str, str], list[str]] = {}
    for f in findings:
        meta = f.metadata if isinstance(f.metadata, dict) else {}
        raw = meta.get("spawn_tasks", [])
        if not isinstance(raw, list):
            raw = []
        for item in raw:
            if not isinstance(item, dict):
                continue
            plugin = str(item.get("plugin", "")).strip()
            target = str(item.get("target", f.target)).strip() or f.target
            payload = item.get("payload", {})
            if not plugin:
                continue
            payload_dict = payload if isinstance(payload, dict) else {}
            depth = int(payload_dict.get("_depth", 0) or 0)
            if depth > max_depth:
                continue
            sig = f"{plugin}|{target}|{json.dumps(payload_dict, sort_keys=True, ensure_ascii=True)}"
            if sig in dedupe:
                continue
            dedupe.add(sig)
            spawned.append(Task(plugin=plugin, target=target, payload=payload_dict))
        if attack_chain_seed_enabled and attack_chain_seed_available:
            endpoints = _extract_endpoints_from_finding(f)
            if endpoints:
                program_id = str(meta.get("program", meta.get("program_id", "")) or "").strip()
                key = (str(f.target), program_id)
                seed_groups.setdefault(key, []).extend(endpoints)
    if attack_chain_seed_enabled and attack_chain_seed_available and seed_groups:
        max_seed = max(1, int(attack_chain_seed_max_endpoints))
        for (target, program_id), endpoints in seed_groups.items():
            uniq: list[str] = []
            seen_ep: set[str] = set()
            for ep in endpoints:
                norm = _normalize_endpoint_key(ep)
                if not norm or norm in seen_ep:
                    continue
                seen_ep.add(norm)
                uniq.append(norm)
                if len(uniq) >= max_seed:
                    break
            if not uniq:
                continue
            payload_dict = {"endpoints": uniq[:max_seed], "program_id": program_id}
            sig = f"attack_chain_seed|{target}|{json.dumps(payload_dict, sort_keys=True, ensure_ascii=True)}"
            if sig in dedupe:
                continue
            dedupe.add(sig)
            spawned.append(Task(plugin="attack_chain_seed", target=target, payload=payload_dict))
    return spawned


def _dynamic_recursion_depth_for_round(*, base_depth: int, target: str, findings: list[Finding]) -> int:
    depth = max(1, int(base_depth))
    max_extra = max(1, int(base_depth)) + 3
    max_conf = 0.0
    critical_signal = False
    for finding in findings:
        max_conf = max(max_conf, _finding_confidence_value(finding))
        cat = str(finding.category or "").strip().lower()
        if cat in {
            "confirmed_idor_bac",
            "critical_public_data_exposure",
            "critical_financial_idor_bac",
        }:
            critical_signal = True
    target_l = str(target or "").strip().lower()
    if target_l.endswith("backend-capital.com"):
        if max_conf >= 95.0:
            depth += 2
        elif max_conf >= 85.0:
            depth += 1
    if critical_signal:
        depth += 1
    return max(1, min(depth, max_extra))


async def _run_report_engine_if_high_critical(
    *,
    report_engine: ReportEngine,
    target: str,
    run_id: str,
    round_findings: list[Finding],
    logger: Any,
) -> list[Finding]:
    if not any(str(f.severity).strip().lower() in {"high", "critical"} for f in round_findings):
        return []
    try:
        return await report_engine.process_round(target=target, run_id=run_id, round_findings=round_findings)
    except Exception as err:
        logger.error(f"report_engine_round_failed target={target} err={err}")
        return []


SEVERITY_RANK: dict[str, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def _severity_rank(severity: str) -> int:
    return int(SEVERITY_RANK.get(str(severity or "").strip().lower(), 0))


def _finding_confidence_value(finding: Finding) -> float:
    metadata = finding.metadata if isinstance(finding.metadata, dict) else {}
    evidence = finding.evidence if isinstance(finding.evidence, dict) else {}
    try:
        return float(
            metadata.get(
                "confidence_score",
                metadata.get(
                    "confidence",
                    evidence.get("confidence_score", evidence.get("confidence", 0.0)),
                ),
            )
            or 0.0
        )
    except Exception:
        return 0.0


def _finding_impact_value(finding: Finding) -> float:
    metadata = finding.metadata if isinstance(finding.metadata, dict) else {}
    evidence = finding.evidence if isinstance(finding.evidence, dict) else {}
    raw = metadata.get("impact", evidence.get("impact_score", evidence.get("impact", 0.0)))
    try:
        return float(raw or 0.0)
    except Exception:
        return 0.0


def _is_unknown_endpoint(endpoint: str) -> bool:
    normalized = str(endpoint or "").strip().lower()
    return normalized in {"unknown", "/unknown", ""}


def _is_root_endpoint(endpoint: str) -> bool:
    normalized = str(endpoint or "").strip().lower()
    return normalized == "/"


def _has_concrete_endpoint(items: Any) -> bool:
    if not isinstance(items, list):
        return False
    for raw in items:
        value = str(raw or "").strip()
        if not value:
            continue
        if value.startswith("http://") or value.startswith("https://"):
            value = urlparse(value).path or "/"
        value = value.strip()
        if value and value.lower() not in {"/", "/unknown", "unknown"}:
            return True
    return False


def _is_low_quality_js_leak_finding(finding: Finding) -> bool:
    plugin = str(finding.plugin or "").strip().lower()
    category = str(finding.category or "").strip().lower()
    title = str(finding.title or "").strip().lower()
    evidence = finding.evidence if isinstance(finding.evidence, dict) else {}
    metadata = finding.metadata if isinstance(finding.metadata, dict) else {}

    if plugin == "deep_js_intelligence" and category == "js_information_leak":
        if "across 0 endpoints" in title:
            return True
        endpoints = evidence.get("endpoints", [])
        if _has_concrete_endpoint(endpoints):
            return False
        req_samples = evidence.get("request_response_sample", [])
        if isinstance(req_samples, list):
            for sample in req_samples:
                if not isinstance(sample, dict):
                    continue
                request = sample.get("request", {})
                if not isinstance(request, dict):
                    continue
                url = str(request.get("url", "")).strip()
                if not url:
                    continue
                parsed = urlparse(url)
                path = (parsed.path or "/").strip()
                if path.lower() not in {"", "/", "/unknown", "unknown"}:
                    return False
        return True

    if plugin == "report_synthesis":
        source_plugin = str(metadata.get("plugin_source", "")).strip().lower()
        endpoint = _finding_source_endpoint(finding)
        if source_plugin == "deep_js_intelligence" and endpoint in {"/", "/unknown", "unknown", ""}:
            return True

    return False


def _is_finding_actionable_for_triage(
    finding: Finding,
    triage_cfg: dict[str, Any] | None = None,
) -> bool:
    if _is_low_quality_js_leak_finding(finding):
        return False
    cfg = triage_cfg if isinstance(triage_cfg, dict) else {}
    min_severity = str(cfg.get("actionable_min_severity", "high")).strip().lower() or "high"
    min_confidence = float(cfg.get("actionable_min_confidence", 80.0) or 80.0)
    min_impact = float(cfg.get("actionable_min_impact", 70.0) or 70.0)
    require_known_endpoint = bool(cfg.get("actionable_require_known_endpoint", True))
    disallow_root_endpoint = bool(cfg.get("actionable_disallow_root_endpoint", False))
    allow_correlation_submission = bool(cfg.get("allow_correlation_submission", False))
    fastlane_low_medium = bool(cfg.get("fastlane_low_medium", True))
    fastlane_categories = [
        str(x).strip().lower()
        for x in cfg.get(
            "fastlane_categories",
            [
                "information_disclosure",
                "info_leak",
                "open_redirect",
                "cors",
                "misconfiguration",
                "source_map",
                "path_disclosure",
                "idor_response_discrepancy",
            ],
        )
        if str(x).strip()
    ]

    endpoint = _finding_source_endpoint(finding)
    confidence = _finding_confidence_value(finding)
    impact = _finding_impact_value(finding)
    severity_ok = _severity_rank(finding.severity) >= _severity_rank(min_severity)
    confidence_ok = confidence >= min_confidence
    impact_ok = impact >= min_impact
    endpoint_ok = (not require_known_endpoint) or (not _is_unknown_endpoint(endpoint))
    if disallow_root_endpoint and _is_root_endpoint(endpoint):
        endpoint_ok = False
    correlation_ok = allow_correlation_submission or finding.plugin != "vulnerability_correlation_engine"

    if fastlane_low_medium and endpoint_ok and correlation_ok:
        category_text = f"{str(finding.category or '').lower()} {str(finding.title or '').lower()}"
        if _severity_rank(finding.severity) >= _severity_rank("low") and any(marker in category_text for marker in fastlane_categories):
            return True

    return bool(severity_ok and confidence_ok and impact_ok and endpoint_ok and correlation_ok)


def _should_alert_router_dispatch(finding: Finding, triage_cfg: dict[str, Any] | None = None) -> bool:
    cfg = triage_cfg if isinstance(triage_cfg, dict) else {}
    require_actionable = bool(cfg.get("alert_require_actionable", False))
    min_severity = str(cfg.get("alert_min_severity", cfg.get("actionable_min_severity", "high"))).strip().lower() or "high"
    min_confidence = float(cfg.get("alert_min_confidence", cfg.get("actionable_min_confidence", 80.0)) or 80.0)
    require_known_endpoint = bool(cfg.get("alert_require_known_endpoint", True))
    disallow_root_endpoint = bool(cfg.get("alert_disallow_root_endpoint", False))
    allow_correlation_alerts = bool(cfg.get("allow_correlation_alerts", False))
    correlation_min_confidence = float(cfg.get("correlation_min_confidence", max(85.0, min_confidence)) or max(85.0, min_confidence))

    sev_rank = _severity_rank(finding.severity)
    if sev_rank < _severity_rank(min_severity):
        return False

    confidence = _finding_confidence_value(finding)
    if confidence < min_confidence:
        metadata = finding.metadata if isinstance(finding.metadata, dict) else {}
        evidence = finding.evidence if isinstance(finding.evidence, dict) else {}
        has_explicit_confidence = any(
            key in metadata or key in evidence
            for key in ("confidence_score", "confidence")
        )
        # Keep alert routing resilient for critical findings without explicit confidence metadata.
        if not (sev_rank >= _severity_rank("critical") and not has_explicit_confidence):
            return False

    endpoint = _finding_source_endpoint(finding)
    if require_known_endpoint and _is_unknown_endpoint(endpoint):
        return False
    if disallow_root_endpoint and _is_root_endpoint(endpoint):
        return False

    if finding.plugin == "vulnerability_correlation_engine":
        if not allow_correlation_alerts:
            return False
        if confidence < correlation_min_confidence:
            return False

    if require_actionable and not _is_finding_actionable_for_triage(finding, triage_cfg=cfg):
        return False

    return True


def split_findings_for_triage(
    findings: list[Finding],
    triage_cfg: dict[str, Any] | None = None,
) -> tuple[list[Finding], list[Finding]]:
    cfg = triage_cfg if isinstance(triage_cfg, dict) else {}
    actionable: list[Finding] = []
    review_queue: list[Finding] = []

    for finding in findings:
        if _is_finding_actionable_for_triage(finding, triage_cfg=cfg):
            actionable.append(finding)
        else:
            review_queue.append(finding)
    return actionable, review_queue


def _triage_row_key(row: dict[str, Any]) -> str:
    evidence = row.get("evidence", {}) if isinstance(row.get("evidence"), dict) else {}
    metadata = row.get("metadata", {}) if isinstance(row.get("metadata"), dict) else {}
    endpoint = str(
        row.get("endpoint", "")
        or evidence.get("endpoint", "")
        or evidence.get("path", "")
        or evidence.get("url", "")
        or ""
    ).strip()
    if endpoint.startswith("http://") or endpoint.startswith("https://"):
        endpoint = urlparse(endpoint).path or "/"
    elif endpoint and not endpoint.startswith("/"):
        endpoint = f"/{endpoint}"
    parameter_name = str(
        row.get("parameter_name", "")
        or metadata.get("parameter_name", metadata.get("parameter", ""))
        or evidence.get("tested_parameter", "")
    ).strip()
    raw = "|".join(
        [
            str(row.get("plugin", "")).strip().lower(),
            str(row.get("target", "")).strip().lower(),
            str(row.get("category", "")).strip().lower(),
            str(row.get("title", "")).strip().lower(),
            endpoint.lower(),
            parameter_name.lower(),
        ]
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def persist_validated_candidates_outputs(
    out_dir: Path,
    *,
    run_id: str,
    rows: list[dict[str, Any]],
) -> None:
    triage_dir = ensure_directory(out_dir / "triage", mode=0o755)
    export_json(triage_dir / "validated_candidates.json", rows)
    (triage_dir / "validated_candidates.jsonl").write_text(to_jsonl(rows), encoding="utf-8")
    export_markdown(triage_dir / "validated_candidates.md", rows, f"{run_id}-validated-candidates")


async def _run_shannon_validation_stage(
    *,
    run_id: str,
    cfg: dict[str, Any],
    storage: PostgresStorage | None,
    logger: Any,
    out_dir: Path,
    actionable_rows: list[dict[str, Any]],
    review_rows: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    modules_cfg = cfg.get("modules", {}) if isinstance(cfg.get("modules"), dict) else {}
    shannon_cfg = modules_cfg.get("shannon_validator", {}) if isinstance(modules_cfg.get("shannon_validator"), dict) else {}
    enabled = bool(shannon_cfg.get("enabled", False))
    if not enabled:
        persist_validated_candidates_outputs(out_dir, run_id=run_id, rows=[])
        return actionable_rows, review_rows, []

    if storage is None:
        logger.warning("shannon_validation_skipped reason=storage_unavailable")
        persist_validated_candidates_outputs(out_dir, run_id=run_id, rows=[])
        return actionable_rows, review_rows, []

    binary_path = str(shannon_cfg.get("binary_path", "/opt/shannon_ref/shannon")).strip()
    timeout_seconds = float(shannon_cfg.get("timeout_seconds", 30) or 30)
    max_candidates = max(1, int(shannon_cfg.get("max_candidates_per_run", 5) or 5))
    thresholds = shannon_cfg.get("thresholds", {}) if isinstance(shannon_cfg.get("thresholds"), dict) else {}
    min_confidence = float(thresholds.get("min_confidence", 75) or 75)
    min_impact = float(thresholds.get("min_impact", 70) or 70)
    min_severity = str(thresholds.get("min_severity", "medium")).strip().lower() or "medium"

    adapter = ShannonAdapter(binary_path=binary_path, timeout_seconds=timeout_seconds)
    try:
        storage.upsert_triage_queue_rows(run_id=run_id, rows=actionable_rows, status="actionable")
        storage.upsert_triage_queue_rows(run_id=run_id, rows=review_rows, status="review")
        candidates = storage.list_triage_review_candidates(
            run_id=run_id,
            min_confidence=min_confidence,
            min_impact=min_impact,
            min_severity=min_severity,
            limit=max_candidates,
        )
    except Exception as err:
        logger.error(f"shannon_validation_failed stage=select_candidates err={err}")
        persist_validated_candidates_outputs(out_dir, run_id=run_id, rows=[])
        return actionable_rows, review_rows, []

    if not candidates:
        logger.info(
            "shannon_validation_candidates_none "
            f"min_severity={min_severity} min_confidence={min_confidence} min_impact={min_impact}"
        )
        persist_validated_candidates_outputs(out_dir, run_id=run_id, rows=[])
        return actionable_rows, review_rows, []

    promoted_keys: set[str] = set()
    promoted_review_keys: set[str] = set()
    promoted_rows: list[dict[str, Any]] = []
    validated_rows: list[dict[str, Any]] = []

    for item in candidates:
        payload = item.get("payload", {}) if isinstance(item.get("payload"), dict) else {}
        finding_key = str(item.get("finding_key", "")).strip()
        target = str(item.get("target", payload.get("target", ""))).strip()
        endpoint = str(item.get("endpoint", "")).strip()
        if not endpoint:
            evidence = payload.get("evidence", {}) if isinstance(payload.get("evidence"), dict) else {}
            endpoint = str(evidence.get("endpoint", evidence.get("path", "/")) or "/").strip()
        if endpoint.startswith("http://") or endpoint.startswith("https://"):
            endpoint = urlparse(endpoint).path or "/"
        elif endpoint and not endpoint.startswith("/"):
            endpoint = f"/{endpoint}"
        logger.info(f"shannon_validation_start target={target} endpoint={endpoint} finding_key={finding_key}")

        result: ShannonResult = await adapter.validate(
            {
                "target": target,
                "endpoint": endpoint,
                "metadata": payload.get("metadata", {}) if isinstance(payload.get("metadata"), dict) else {},
            }
        )
        exit_code = int(result.exit_code) if isinstance(result.exit_code, int) else -1
        if result.validated:
            try:
                promoted = storage.promote_triage_candidate_with_validation(
                    run_id=run_id,
                    finding_key=finding_key,
                    confidence_delta=float(result.confidence_delta or 0.0),
                    evidence_path=str(result.evidence_path or ""),
                    validator_note=str(result.error or ""),
                )
            except Exception as err:
                promoted = False
                result.error = f"promotion_error type={type(err).__name__} err={err}"
            if promoted:
                promoted_keys.add(finding_key)
                promoted_payload = payload.copy()
                md = promoted_payload.get("metadata", {}) if isinstance(promoted_payload.get("metadata"), dict) else {}
                ev = promoted_payload.get("evidence", {}) if isinstance(promoted_payload.get("evidence"), dict) else {}
                md = md.copy()
                ev = ev.copy()
                md["source"] = "shannon_validation"
                md["confidence_delta"] = float(result.confidence_delta or 0.0)
                if result.error:
                    md["validator_note"] = str(result.error)
                ev["evidence_path"] = str(result.evidence_path or "")
                promoted_payload["metadata"] = md
                promoted_payload["evidence"] = ev
                promoted_rows.append(promoted_payload)
                promoted_review_keys.add(_triage_row_key(promoted_payload))
                validated_rows.append(
                    {
                        "plugin": str(promoted_payload.get("plugin", "")),
                        "target": target,
                        "category": str(promoted_payload.get("category", "")),
                        "severity": str(promoted_payload.get("severity", "")),
                        "title": str(promoted_payload.get("title", "")),
                        "risk_score": float(promoted_payload.get("risk_score", 0) or 0),
                        "evidence": {
                            "endpoint": endpoint,
                            "evidence_path": str(result.evidence_path or ""),
                            "finding_key": finding_key,
                            "confidence_delta": float(result.confidence_delta or 0.0),
                            "exit_code": exit_code,
                        },
                    }
                )
                logger.info(f"shannon_validation_success target={target} endpoint={endpoint} finding_key={finding_key}")
                continue

        note = str(result.error or "validator_not_validated").strip() or "validator_not_validated"
        with contextlib.suppress(Exception):
            storage.mark_triage_candidate_validation_failed(
                run_id=run_id,
                finding_key=finding_key,
                note=note,
            )
        logger.error(
            f"shannon_validation_failed target={target} endpoint={endpoint} finding_key={finding_key} "
            f"exit_code={exit_code} err={note}"
        )

    if promoted_rows:
        existing_actionable_keys = {_triage_row_key(row) for row in actionable_rows if isinstance(row, dict)}
        for row in promoted_rows:
            key = _triage_row_key(row)
            if key in existing_actionable_keys:
                continue
            actionable_rows.append(row)
            existing_actionable_keys.add(key)
        review_rows = [row for row in review_rows if _triage_row_key(row) not in promoted_review_keys]

    persist_validated_candidates_outputs(out_dir, run_id=run_id, rows=validated_rows)
    return actionable_rows, review_rows, validated_rows


async def _route_alerts_from_batch(
    *,
    alert_router: AlertRouter,
    batch: list[Finding],
    run_id: str,
    logger: Any,
    source: str,
    triage_cfg: dict[str, Any] | None = None,
) -> None:
    if not alert_router.available or not batch:
        return
    for finding in batch:
        if not _should_alert_router_dispatch(finding, triage_cfg=triage_cfg):
            continue
        try:
            await alert_router.send_finding(finding, run_id=run_id, source=source)
        except Exception as err:
            logger.error(f"alert_router_dispatch_failed plugin={finding.plugin} target={finding.target} err={err}")


def _write_alert_dry_run_poc(*, out_dir: Path, run_id: str) -> Path:
    dry_dir = ensure_directory(out_dir / "alert_dry_run", mode=0o755)
    out_file = dry_dir / f"dry_run_poc_{run_id}.md"
    if out_file.exists():
        return out_file
    lines = [
        "# Alert Dry Run Evidence",
        "",
        "## Scenario",
        "Synthetic critical finding used to validate Discord/Slack routing and attachment uploads.",
        "",
        "## URL Afetada",
        "`https://dry-run.hunterops.local/api/v2/transactions/transfer?amount=-9999&currency=USD`",
        "",
        "## Parametro Vulneravel",
        "`amount`",
        "",
        "## Requisicao (CURL)",
        "```bash",
        "curl -i -X POST \"https://dry-run.hunterops.local/api/v2/transactions/transfer?amount=-9999&currency=USD\" "
        "-H \"Content-Type: application/json\" -d '{\"from_account_id\":\"1001\",\"to_account_id\":\"1002\",\"amount\":-9999,\"currency\":\"USD\"}'",
        "```",
        "",
        "## Prova de Vazamento (Impacto)",
        "Simulated response returns HTTP 200 with cross-account transfer confirmation despite invalid negative amount.",
        "",
        "## Payload Expansion",
    ]
    for idx in range(1, 90):
        lines.append(f"- sample_{idx:03d}: unauthorized_record=true transaction_ref=TXN-{idx:05d}")
    out_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out_file


async def _run_alert_dry_run(
    *,
    alert_router: AlertRouter,
    out_dir: Path,
    run_id: str,
    logger: Any,
) -> int:
    if not alert_router.available:
        logger.error("alert_dry_run_unavailable reason=no_webhook_configured")
        return 7

    has_discord = bool(
        str(getattr(alert_router, "discord_research_webhook", "")).strip()
        or str(getattr(alert_router, "discord_critical_webhook", "")).strip()
    )
    has_slack = bool(
        str(getattr(alert_router, "slack_research_webhook", "")).strip()
        or str(getattr(alert_router, "slack_critical_webhook", "")).strip()
    )
    if not has_discord and not has_slack:
        logger.error("alert_dry_run_missing_channels discord=0 slack=0")
        return 7
    if not has_discord:
        logger.warning("alert_dry_run_warning discord_channels_missing=1")
    if not has_slack:
        logger.warning("alert_dry_run_warning slack_channels_missing=1")

    poc_path = _write_alert_dry_run_poc(out_dir=out_dir, run_id=run_id)
    identifier = str(os.getenv("H1_API_IDENTIFIER", "")).strip() or "reaperk0ji"

    critical_finding = Finding(
        plugin="business_logic_sniper",
        target="dry-run.hunterops.local",
        category="financial_tampering_indicator",
        severity="critical",
        title="Test Critical Finding - Financial Logic Tampering",
        evidence={
            "endpoint": "/api/v2/transactions/transfer?amount=-9999&currency=USD",
            "tested_parameter": "amount",
            "poc_path": str(poc_path),
            "request": {
                "method": "POST",
                "url": "https://dry-run.hunterops.local/api/v2/transactions/transfer?amount=-9999&currency=USD",
                "headers": {
                    "Content-Type": "application/json",
                    "X-H1-Client-Identifier": identifier,
                },
                "body": {
                    "from_account_id": "1001",
                    "to_account_id": "1002",
                    "amount": -9999,
                    "currency": "USD",
                },
            },
            "impact": "Dry-run signal: negative transfer accepted with HTTP 200 and cross-account context.",
        },
        metadata={
            "impact": 98.0,
            "confidence_score": 99.0,
            "dry_run": True,
            "discovery_source": "alert_dry_run",
        },
    )
    research_log = Finding(
        plugin="vulnerability_correlation_engine",
        target="dry-run.hunterops.local",
        category="research_log_heartbeat",
        severity="medium",
        title="Test Research Log - Pipeline Heartbeat",
        evidence={
            "endpoint": "/api/health/research-log",
            "tested_parameter": "trace_id",
            "request": {
                "method": "GET",
                "url": "https://dry-run.hunterops.local/api/health/research-log?trace_id=hb-001",
                "headers": {
                    "Accept": "application/json",
                    "X-H1-Client-Identifier": identifier,
                },
            },
            "evidence_snippet": "Dry-run heartbeat for low/medium research stream validation.",
        },
        metadata={
            "impact": 45.0,
            "confidence_score": 76.0,
            "dry_run": True,
            "discovery_source": "alert_dry_run",
        },
    )

    critical_sent = await alert_router.send_finding(critical_finding, run_id=run_id, source="alert_dry_run")
    research_sent = await alert_router.send_finding(research_log, run_id=run_id, source="alert_dry_run")
    await alert_router.send_critical_log(message="Alert dry-run completed: critical and research signals dispatched.", run_id=run_id)
    logger.info(
        "alert_dry_run_completed "
        f"critical_sent={critical_sent} "
        f"research_sent={research_sent} "
        f"poc_attachment={poc_path}"
    )
    return 0 if (critical_sent and research_sent) else 7


def _delta_score(delta: dict[str, Any]) -> float:
    new_endpoints = len(delta.get("new_endpoints", [])) if isinstance(delta.get("new_endpoints"), list) else 0
    changed_js = len(delta.get("changed_js", [])) if isinstance(delta.get("changed_js"), list) else 0
    new_parameters = len(delta.get("new_parameters", [])) if isinstance(delta.get("new_parameters"), list) else 0
    return round(min(100.0, (new_endpoints * 22.0) + (changed_js * 16.0) + (new_parameters * 12.0)), 2)


def _delta_has_high_value(delta: dict[str, Any], patterns: list[str]) -> bool:
    if not patterns:
        return False
    endpoints = [str(x) for x in delta.get("new_endpoints", []) if isinstance(x, str)]
    endpoints.extend([str(x) for x in delta.get("new_parameters", []) if isinstance(x, str)])
    endpoints.extend([str(x) for x in delta.get("changed_js", []) if isinstance(x, str)])
    for ep in endpoints:
        if _endpoint_matches_any(_normalize_endpoint_key(ep), patterns):
            return True
    return False


def _semantic_key(finding: Finding) -> tuple[str, str, str, str]:
    target = str(finding.target or "").strip().lower()
    category = str(finding.category or "").strip().lower()
    title = str(finding.title or "").strip().lower()
    endpoint = _normalize_endpoint_key(_finding_source_endpoint(finding)).lower()
    return (target, category, title, endpoint)


def _finding_confidence(finding: Finding) -> float:
    md = finding.metadata if isinstance(finding.metadata, dict) else {}
    return float(md.get("confidence_score", md.get("confidence", 0)) or 0)


def _is_logic_prover_confirmed(finding: Finding) -> bool:
    if finding.plugin != "logic_prover":
        return False
    if finding.category not in {"Potential_IDOR_Signal", "Broken_Object_Level_Authorization"}:
        return False
    return _finding_confidence(finding) > 50.0


def _finding_impact(finding: Finding) -> str:
    category = str(finding.category).lower()
    if "broken_object_level_authorization" in category or "idor" in category:
        return "Critical: Unauthorized PII/object access confirmed across authentication boundaries."
    if "auth" in category:
        return "High: Access-control inconsistency may allow unauthorized account/resource operations."
    return "Medium: Logic discrepancy with potential business impact requires triage."


def _estimated_payout_for_severity(severity: str) -> str:
    sev = str(severity or "").strip().lower()
    if sev == "critical":
        return "USD 1200-5000"
    if sev == "high":
        return "USD 400-1500"
    if sev == "medium":
        return "USD 100-500"
    if sev == "low":
        return "USD 25-150"
    return "N/A"


def _finding_evidence_snippet(finding: Finding) -> str:
    evidence = finding.evidence if isinstance(finding.evidence, dict) else {}
    parameter = str(evidence.get("tested_parameter", evidence.get("parameter", ""))).strip()
    leaked = evidence.get("leaked_entities", []) if isinstance(evidence.get("leaked_entities"), list) else []
    leaked_preview = []
    for item in leaked[:4]:
        if isinstance(item, dict):
            leaked_preview.append(str(item.get("entity_value", "")).strip())
    leaked_sample = ", ".join([x for x in leaked_preview if x]) or "n/a"
    response_a = evidence.get("response_auth_a", {}) if isinstance(evidence.get("response_auth_a"), dict) else {}
    response_b = evidence.get("response_auth_b", {}) if isinstance(evidence.get("response_auth_b"), dict) else {}
    return (
        f"param={parameter or 'id'} "
        f"statusA={int(response_a.get('status', 0) or 0)} "
        f"statusB={int(response_b.get('status', 0) or 0)} "
        f"leaks={len(leaked)} sample=[{leaked_sample}]"
    )


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
            _collect_status_codes(child, out, depth + 1)
    elif isinstance(value, list):
        for item in value[:80]:
            _collect_status_codes(item, out, depth + 1)


def _feedback_status_by_target(findings: list[Finding]) -> dict[str, set[int]]:
    tracked = {403, 429}
    out: dict[str, set[int]] = {}
    for finding in findings:
        statuses: set[int] = set()
        _collect_status_codes(finding.evidence if isinstance(finding.evidence, dict) else {}, statuses)
        _collect_status_codes(finding.metadata if isinstance(finding.metadata, dict) else {}, statuses)
        hits = {status for status in statuses if status in tracked}
        if not hits:
            continue
        out.setdefault(finding.target, set()).update(hits)
    return out


def _feedback_status_by_target_window(findings: list[Finding], *, window_seconds: int = 120) -> dict[str, set[int]]:
    tracked = {403, 429}
    out: dict[str, set[int]] = {}
    now = time.time()
    for finding in findings:
        evidence = finding.evidence if isinstance(finding.evidence, dict) else {}
        ts = evidence.get("timestamp") or evidence.get("ts") or evidence.get("time")
        ts_val = None
        try:
            if ts is not None:
                ts_val = float(ts)
        except Exception:
            ts_val = None
        if ts_val is not None and (now - ts_val) > window_seconds:
            continue
        statuses: set[int] = set()
        _collect_status_codes(finding.evidence if isinstance(finding.evidence, dict) else {}, statuses)
        _collect_status_codes(finding.metadata if isinstance(finding.metadata, dict) else {}, statuses)
        hits = {status for status in statuses if status in tracked}
        if not hits:
            continue
        out.setdefault(finding.target, set()).update(hits)
    return out


def _build_feedback_retry_tasks(
    *,
    current_wave: list[Task],
    feedback: dict[str, set[int]],
    scheduler: Any,
    run_id: str,
    max_depth: int,
) -> list[Task]:
    if not feedback:
        return []
    out: list[Task] = []
    dedupe: set[str] = set()
    for task in current_wave:
        statuses = feedback.get(task.target, set())
        if not statuses:
            continue
        payload = task.payload if isinstance(task.payload, dict) else {}
        retry_count = int(payload.get("_feedback_retry", 0) or 0)
        if retry_count >= int(getattr(scheduler, "feedback_max_retries", 2)):
            continue
        dominant_status = 429 if 429 in statuses else 403
        rotated_ua = scheduler.next_user_agent(task.target)
        rotated_proxy = scheduler.next_proxy(task.target)
        merged = payload.copy()
        merged["run_id"] = str(merged.get("run_id", run_id) or run_id)
        merged["_feedback_retry"] = retry_count + 1
        merged["_depth"] = min(int(merged.get("_depth", 0) or 0), max_depth)
        merged["trigger"] = f"feedback_retry_{dominant_status}"
        merged["feedback_status"] = dominant_status
        merged["request_delay_seconds"] = round(float(scheduler.target_delay_remaining(task.target)), 3)
        if rotated_ua:
            merged["user_agent"] = rotated_ua
        if rotated_proxy:
            merged["proxy"] = rotated_proxy
        base_prio = float(merged.get("priority_score", merged.get("priority", 0)) or 0)
        merged["priority_score"] = max(base_prio, 97.0 if dominant_status == 429 else 94.0)

        sig = f"{task.plugin}|{task.target}|{json.dumps(merged, sort_keys=True, ensure_ascii=True)}"
        if sig in dedupe:
            continue
        dedupe.add(sig)
        out.append(Task(plugin=task.plugin, target=task.target, payload=merged))
    return out


def _normalize_endpoint_key(raw: str) -> str:
    value = str(raw or "").strip()
    if not value:
        return "/"
    if value.startswith("http://") or value.startswith("https://"):
        parsed = urlparse(value)
        return parsed.path or "/"
    parsed = urlparse(value)
    path = parsed.path or value
    if not path.startswith("/"):
        path = f"/{path}"
    return path or "/"


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


def _endpoint_is_blocked(path: str, blocked: list[str]) -> bool:
    if not blocked:
        return False
    value = str(path or "").strip().lower()
    if not value:
        return False
    for raw in blocked:
        token = str(raw or "").strip().lower()
        if not token:
            continue
        if token in value:
            return True
    return False


def _annotate_program_metadata(
    findings: list[Finding],
    program_by_target: dict[str, str],
    programs_by_target: dict[str, list[str]],
) -> None:
    if not findings:
        return
    for finding in findings:
        target = str(finding.target or "").strip()
        if not target:
            continue
        program = program_by_target.get(target, "")
        programs = programs_by_target.get(target, [])
        if not program and not programs:
            continue
        meta = finding.metadata if isinstance(finding.metadata, dict) else {}
        if program and not str(meta.get("program", "")).strip():
            meta["program"] = program
        if programs and not isinstance(meta.get("programs"), list):
            meta["programs"] = programs
        finding.metadata = meta


def _endpoint_matches_any(path: str, patterns: list[str]) -> bool:
    return _endpoint_is_noisy(path, patterns)


def _auth_weight_from_finding(finding: Finding) -> float:
    evidence = finding.evidence if isinstance(finding.evidence, dict) else {}
    ra = evidence.get("response_auth_a", {}) if isinstance(evidence.get("response_auth_a"), dict) else {}
    rb = evidence.get("response_auth_b", {}) if isinstance(evidence.get("response_auth_b"), dict) else {}
    rc = evidence.get("response_unauthenticated", {}) if isinstance(evidence.get("response_unauthenticated"), dict) else {}
    status_a = int(ra.get("status", 0) or 0)
    status_b = int(rb.get("status", 0) or 0)
    status_c = int(rc.get("status", 0) or 0)
    if status_a in {200, 201} and status_b in {200, 201} and status_c in {401, 403}:
        return 2.0
    if status_a in {200, 201} and status_b in {200, 201} and status_c in {200, 201}:
        return 1.4
    return 1.0


class HighValuePriorityQueue:
    """Ranks recursive tasks by Delta-first and entity cross-pollination confidence."""

    def __init__(
        self,
        max_size: int = 4000,
        priority_patterns: list[str] | None = None,
        priority_boost: float = 0.0,
        roi_patterns: list[str] | None = None,
        roi_boost: float = 0.0,
        roi_plugin_boosts: dict[str, float] | None = None,
        roi_boost_cap: float = 0.0,
    ) -> None:
        self.max_size = max(50, int(max_size))
        self.priority_patterns = [str(x).strip() for x in (priority_patterns or []) if str(x).strip()]
        self.priority_boost = float(priority_boost or 0.0)
        self.roi_patterns = [str(x).strip() for x in (roi_patterns or []) if str(x).strip()]
        self.roi_boost = float(roi_boost or 0.0)
        self.roi_plugin_boosts = {
            str(k).strip().lower(): float(v)
            for k, v in (roi_plugin_boosts or {}).items()
            if str(k).strip()
        }
        self.roi_boost_cap = float(roi_boost_cap or 0.0)

    def _priority_boost_for_endpoint(self, endpoint: str) -> float:
        if not self.priority_patterns or self.priority_boost <= 0:
            return 0.0
        if _endpoint_matches_any(endpoint, self.priority_patterns):
            return self.priority_boost
        return 0.0

    def _roi_boost_for_task(self, endpoint: str, plugin: str) -> float:
        boost = 0.0
        if self.roi_patterns and self.roi_boost > 0 and _endpoint_matches_any(endpoint, self.roi_patterns):
            boost += self.roi_boost
        if self.roi_plugin_boosts:
            boost += float(self.roi_plugin_boosts.get(str(plugin).strip().lower(), 0.0) or 0.0)
        if self.roi_boost_cap > 0:
            boost = min(boost, self.roi_boost_cap)
        return boost

    @staticmethod
    def confidence_formula(delta_struct: float, auth_weight: float, leaked_entities: int, probes: int) -> float:
        # C = ((Delta_struct * W_auth) + (E_leaked * 20)) / N_probes
        return round(((max(0.0, delta_struct) * max(1.0, auth_weight)) + (max(0, leaked_entities) * 20.0)) / max(1.0, float(probes)), 2)

    def _build_signal_map(self, findings: list[Finding]) -> dict[str, dict[str, float]]:
        endpoint_signals: dict[str, dict[str, float]] = {}
        for finding in findings:
            evidence = finding.evidence if isinstance(finding.evidence, dict) else {}
            metadata = finding.metadata if isinstance(finding.metadata, dict) else {}
            endpoint = _normalize_endpoint_key(_finding_source_endpoint(finding))

            struct_similarity = evidence.get("structure_similarity_pct", metadata.get("structure_similarity_pct"))
            if struct_similarity is None and isinstance(evidence.get("diff_map"), dict):
                struct_similarity = evidence["diff_map"].get("structure_similarity_pct")
            try:
                similarity = float(struct_similarity if struct_similarity is not None else 100.0)
            except Exception:
                similarity = 100.0
            delta_struct = max(0.0, 100.0 - similarity)

            leaked = 0
            if isinstance(evidence.get("leaked_entities"), list):
                leaked += len(evidence["leaked_entities"])
            if isinstance(evidence.get("sensitive_field_indicators"), list):
                leaked += len(evidence["sensitive_field_indicators"])
            if isinstance(evidence.get("diff_map"), dict):
                hits = evidence["diff_map"].get("sensitive_object_hits", [])
                if isinstance(hits, list):
                    leaked += len(hits)

            probes = int(metadata.get("probe_count", 1) or 1)
            auth_weight = _auth_weight_from_finding(finding)
            confidence = self.confidence_formula(delta_struct=delta_struct, auth_weight=auth_weight, leaked_entities=leaked, probes=probes)

            prev = endpoint_signals.get(endpoint, {"confidence": 0.0, "delta_struct": 0.0, "leaked_entities": 0.0, "probes": 1.0})
            if confidence >= float(prev.get("confidence", 0.0)):
                endpoint_signals[endpoint] = {
                    "confidence": confidence,
                    "delta_struct": delta_struct,
                    "leaked_entities": float(leaked),
                    "probes": float(probes),
                }
        return endpoint_signals

    @staticmethod
    def _priority_class(task: Task) -> int:
        payload = task.payload if isinstance(task.payload, dict) else {}
        trigger = str(payload.get("trigger", "")).strip().lower()
        if trigger in {"delta_change_monitor", "delta_detected"} or bool(payload.get("delta_detected", False)):
            return 0
        if task.plugin == "entity_cross_pollinator" or trigger in {"entity_cross_pollinator", "entity_pool_update"}:
            return 1
        if bool(payload.get("entity_substitution")) or bool(payload.get("recursive_object_probe", False)):
            return 1
        return 2

    def rank(self, tasks: list[Task], findings: list[Finding]) -> list[Task]:
        if not tasks:
            return []
        signal_map = self._build_signal_map(findings=findings)
        ranked: list[tuple[int, float, float, str, Task]] = []
        dedupe: set[str] = set()

        for task in tasks:
            payload = task.payload.copy() if isinstance(task.payload, dict) else {}
            endpoints = _task_endpoints(task)
            endpoint = _normalize_endpoint_key(endpoints[0] if endpoints else "/")
            signal = signal_map.get(endpoint, {})
            payload_priority = float(payload.get("priority_score", payload.get("priority", 0)) or 0.0)

            if signal:
                queue_confidence = float(signal.get("confidence", 0.0))
            else:
                leaked = int(payload.get("leaked_entities", 0) or 0)
                delta_struct = float(payload.get("delta_struct", 0.0) or 0.0)
                auth_weight = float(payload.get("auth_weight", 1.0) or 1.0)
                probes = int(payload.get("probe_count", 1) or 1)
                queue_confidence = self.confidence_formula(delta_struct=delta_struct, auth_weight=auth_weight, leaked_entities=leaked, probes=probes)

            priority_class = self._priority_class(task)
            if priority_class == 0 and queue_confidence < 100.0:
                queue_confidence = 100.0
            if priority_class == 1 and queue_confidence < 90.0:
                queue_confidence = 90.0

            boost = self._priority_boost_for_endpoint(endpoint)
            boost += self._roi_boost_for_task(endpoint, task.plugin)
            payload["priority_class"] = priority_class
            payload["queue_confidence"] = queue_confidence
            payload["priority_boost"] = boost
            payload["priority_score"] = max(payload_priority, queue_confidence) + boost

            ranked_task = Task(plugin=task.plugin, target=task.target, payload=payload)
            signature = f"{ranked_task.plugin}|{ranked_task.target}|{json.dumps(ranked_task.payload, sort_keys=True, ensure_ascii=True)}"
            if signature in dedupe:
                continue
            dedupe.add(signature)
            ranked.append((priority_class, -queue_confidence, -payload["priority_score"], ranked_task.plugin, ranked_task))

        ranked.sort(key=lambda row: (row[0], row[1], row[2], row[3]))
        return [row[4] for row in ranked[: self.max_size]]


@dataclass
class ResearchState:
    run_id: str
    storage: PostgresStorage | None
    endpoint_cache_enabled: bool = False
    endpoint_cache_ttl_seconds: int = 0
    endpoint_noise_patterns: list[str] = None  # type: ignore[assignment]
    blocked_paths_by_target: dict[str, list[str]] = None  # type: ignore[assignment]
    allowed_plugins_by_target: dict[str, list[str]] = None  # type: ignore[assignment]
    blocked_plugins_by_target: dict[str, list[str]] = None  # type: ignore[assignment]
    endpoint_cache_max_entries: int = 0
    endpoint_cache_local: dict[tuple[str, str, str], float] = None  # type: ignore[assignment]

    def was_scanned(self, plugin: str, target: str, endpoint: str) -> bool:
        if not self.storage:
            return False
        try:
            return self.storage.was_endpoint_scanned(self.run_id, plugin, target, endpoint)
        except Exception:
            return False

    def was_recently_scanned(self, plugin: str, target: str, endpoint: str) -> bool:
        if not self.storage:
            return False
        if not self.endpoint_cache_enabled or self.endpoint_cache_ttl_seconds <= 0:
            return False
        try:
            return self.storage.endpoint_seen_recently(
                plugin=plugin,
                target=target,
                endpoint=endpoint,
                ttl_seconds=self.endpoint_cache_ttl_seconds,
            )
        except Exception:
            return False

    def _local_cache_key(self, plugin: str, target: str, endpoint: str) -> tuple[str, str, str]:
        return (str(plugin), str(target), _normalize_endpoint_key(endpoint))

    def _local_cache_prune(self, now: float) -> None:
        if not self.endpoint_cache_local:
            return
        ttl = max(0, int(self.endpoint_cache_ttl_seconds))
        if ttl > 0:
            for key, ts in list(self.endpoint_cache_local.items()):
                if (now - float(ts)) > ttl:
                    self.endpoint_cache_local.pop(key, None)
        if self.endpoint_cache_max_entries > 0 and len(self.endpoint_cache_local) > self.endpoint_cache_max_entries:
            items = sorted(self.endpoint_cache_local.items(), key=lambda row: row[1])
            for key, _ in items[: max(0, len(items) - self.endpoint_cache_max_entries)]:
                self.endpoint_cache_local.pop(key, None)

    def was_recently_scanned_local(self, plugin: str, target: str, endpoint: str) -> bool:
        if not self.endpoint_cache_enabled or self.endpoint_cache_ttl_seconds <= 0:
            return False
        if not self.endpoint_cache_local:
            return False
        now = time.time()
        self._local_cache_prune(now)
        key = self._local_cache_key(plugin, target, endpoint)
        ts = self.endpoint_cache_local.get(key)
        if ts is None:
            return False
        return (now - float(ts)) <= self.endpoint_cache_ttl_seconds

    def mark_scanned_local(self, plugin: str, target: str, endpoint: str) -> None:
        if not self.endpoint_cache_enabled or self.endpoint_cache_ttl_seconds <= 0:
            return
        if self.endpoint_cache_local is None:
            self.endpoint_cache_local = {}
        now = time.time()
        self._local_cache_prune(now)
        key = self._local_cache_key(plugin, target, endpoint)
        self.endpoint_cache_local[key] = now

    def mark_scanned(self, plugin: str, target: str, endpoint: str) -> None:
        if not self.storage:
            return
        try:
            self.storage.mark_endpoint_scanned(self.run_id, plugin, target, endpoint)
            if self.endpoint_cache_enabled and self.endpoint_cache_ttl_seconds > 0:
                self.storage.mark_endpoint_seen(plugin=plugin, target=target, endpoint=endpoint)
                self.mark_scanned_local(plugin, target, endpoint)
        except Exception:
            return

    def filter_task(self, task: Task) -> Task | None:
        plugin_name = str(task.plugin).strip().lower()
        allow_map = self.allowed_plugins_by_target or {}
        block_map = self.blocked_plugins_by_target or {}
        allow_list = {str(x).strip().lower() for x in (allow_map.get(task.target, []) or []) if str(x).strip()}
        block_list = {str(x).strip().lower() for x in (block_map.get(task.target, []) or []) if str(x).strip()}
        if allow_list and plugin_name not in allow_list:
            return None
        if block_list and plugin_name in block_list:
            return None
        endpoints = _task_endpoints(task)
        patterns = self.endpoint_noise_patterns or []
        blocked_paths = (self.blocked_paths_by_target or {}).get(task.target, []) or []
        remaining: list[str] = []
        for ep in endpoints:
            normalized = _normalize_endpoint_key(ep)
            if _endpoint_is_noisy(normalized, patterns):
                continue
            if _endpoint_is_blocked(normalized, blocked_paths):
                continue
            if self.was_scanned(task.plugin, task.target, ep):
                continue
            if self.was_recently_scanned_local(task.plugin, task.target, ep):
                continue
            if self.was_recently_scanned(task.plugin, task.target, ep):
                continue
            remaining.append(ep)
        if not remaining:
            return None
        payload = task.payload.copy() if isinstance(task.payload, dict) else {}
        if len(remaining) != len(endpoints):
            payload["seed_paths"] = remaining
        return Task(plugin=task.plugin, target=task.target, payload=payload)


class ReactionLogic:
    """Turns discovery findings into follow-up tasks."""

    def __init__(self, max_seed_paths: int = 80) -> None:
        self.max_seed_paths = max_seed_paths

    @staticmethod
    def _priority(seed_paths: list[str]) -> int:
        merged = " ".join(seed_paths).lower()
        if any(k in merged for k in SENSITIVE_PRIORITY_KEYWORDS):
            return 100
        return 70

    def tasks_from_saved_findings(
        self,
        findings: list[Finding],
        run_id: str,
        pack: dict[str, Any] | None,
        available_plugins: set[str] | None = None,
    ) -> list[Task]:
        derived: list[Task] = []
        enabled = available_plugins if isinstance(available_plugins, set) else set()
        has_filter = bool(enabled)
        by_target: dict[str, set[str]] = {}
        for f in findings:
            if f.category != "js_discovery":
                continue
            eps = set()
            if isinstance(f.evidence, dict):
                raw = f.evidence.get("endpoints", [])
                if isinstance(raw, list):
                    eps |= {str(x) for x in raw if isinstance(x, str)}
            if isinstance(f.metadata, dict):
                rawm = f.metadata.get("endpoints", [])
                if isinstance(rawm, list):
                    eps |= {str(x) for x in rawm if isinstance(x, str)}
            if not eps:
                continue
            normalized = set()
            for ep in eps:
                if ep.startswith("http"):
                    normalized.add(urlparse(ep).path or "/")
                else:
                    normalized.add(ep if ep.startswith("/") else f"/{ep}")
            by_target.setdefault(f.target, set()).update(normalized)

        for target, eps in by_target.items():
            seed_paths = sorted(list(eps))[: self.max_seed_paths]
            prio = self._priority(seed_paths)
            if (not has_filter) or ("parameter_intelligence" in enabled):
                derived.append(
                    Task(
                        plugin="parameter_intelligence",
                        target=target,
                        payload={
                            "seed_paths": seed_paths,
                            "trigger": "js_discovery",
                            "run_id": run_id,
                            "priority": prio,
                            "priority_score": prio,
                            "program_pack": pack or {},
                        },
                    )
                )
            if (not has_filter) or ("differential_auth_prover" in enabled):
                derived.append(
                    Task(
                        plugin="differential_auth_prover",
                        target=target,
                        payload={
                            "seed_paths": seed_paths,
                            "trigger": "js_discovery",
                            "run_id": run_id,
                            "priority": prio,
                            "priority_score": prio,
                            "program_pack": pack or {},
                        },
                    )
                )
        return derived


class DeltaMonitor:
    """Compares current results with previous run and prioritizes deep probes."""

    def __init__(self, storage: PostgresStorage | None) -> None:
        self.storage = storage

    @staticmethod
    def _extract_js_discovery(findings: list[Finding]) -> tuple[set[str], dict[str, str]]:
        endpoints: set[str] = set()
        js_hashes: dict[str, str] = {}
        for f in findings:
            if f.category != "js_discovery":
                continue
            if isinstance(f.evidence, dict):
                for e in f.evidence.get("endpoints", []) if isinstance(f.evidence.get("endpoints"), list) else []:
                    if isinstance(e, str):
                        endpoints.add(e if e.startswith("/") else urlparse(e).path or "/")
                artifacts = f.evidence.get("javascript_artifacts", [])
                if isinstance(artifacts, list):
                    for a in artifacts:
                        if not isinstance(a, dict):
                            continue
                        u = str(a.get("url", ""))
                        h = str(a.get("sha256", ""))
                        if u and h:
                            js_hashes[u] = h
        return endpoints, js_hashes

    @staticmethod
    def _extract_parameter_keys(findings: list[Finding]) -> set[str]:
        out: set[str] = set()
        for finding in findings:
            if finding.category != "parameter_intelligence":
                continue
            evidence = finding.evidence if isinstance(finding.evidence, dict) else {}
            sample = evidence.get("parameter_map_sample", [])
            if isinstance(sample, list):
                for item in sample:
                    if not isinstance(item, dict):
                        continue
                    endpoint = _normalize_endpoint_key(str(item.get("endpoint", "")))
                    parameter = str(item.get("parameter", "")).strip()
                    if endpoint and parameter:
                        out.add(f"{endpoint}:{parameter}")
            tested = str(evidence.get("tested_parameter", "")).strip()
            if tested:
                endpoint = _normalize_endpoint_key(_finding_source_endpoint(finding))
                out.add(f"{endpoint}:{tested}")
        return out

    def compare(self, target: str, run_id: str, current_findings: list[Finding]) -> dict[str, Any]:
        if not self.storage:
            return {"new_endpoints": [], "changed_js": [], "new_parameters": []}
        try:
            prev_run = self.storage.get_previous_run_id(target=target, current_run_id=run_id)
            if not prev_run:
                return {"new_endpoints": [], "changed_js": [], "new_parameters": []}
            prev_rows = self.storage.fetch_run_findings(run_id=prev_run, target=target)
        except Exception:
            return {"new_endpoints": [], "changed_js": [], "new_parameters": []}

        curr_eps, curr_js = self._extract_js_discovery(current_findings)
        prev_findings = []
        for r in prev_rows:
            prev_findings.append(
                Finding(
                    plugin=str(r.get("plugin", "")),
                    target=str(r.get("target", target)),
                    category=str(r.get("category", "")),
                    severity=str(r.get("severity", "info")),
                    title=str(r.get("title", "")),
                    evidence=r.get("evidence", {}) if isinstance(r.get("evidence"), dict) else {},
                    metadata=r.get("metadata", {}) if isinstance(r.get("metadata"), dict) else {},
                )
            )
        prev_eps, prev_js = self._extract_js_discovery(prev_findings)
        curr_params = self._extract_parameter_keys(current_findings)
        prev_params = self._extract_parameter_keys(prev_findings)

        new_eps = sorted(list(curr_eps - prev_eps))
        changed_js = sorted([u for u, h in curr_js.items() if u in prev_js and prev_js[u] != h])
        new_parameters = sorted(list(curr_params - prev_params))
        return {"new_endpoints": new_eps, "changed_js": changed_js, "new_parameters": new_parameters}

    def build_priority_tasks(
        self,
        target: str,
        run_id: str,
        pack: dict[str, Any] | None,
        current_findings: list[Finding],
        available_plugins: set[str],
        precomputed_delta: dict[str, Any] | None = None,
    ) -> list[Task]:
        delta = precomputed_delta if isinstance(precomputed_delta, dict) else self.compare(target=target, run_id=run_id, current_findings=current_findings)
        if not delta.get("new_endpoints") and not delta.get("changed_js") and not delta.get("new_parameters"):
            return []
        deep_paths: set[str] = set(delta.get("new_endpoints", []))
        for jsu in delta.get("changed_js", []):
            deep_paths.add(urlparse(jsu).path or "/")
        for key in delta.get("new_parameters", []):
            if not isinstance(key, str) or ":" not in key:
                continue
            endpoint, _ = key.split(":", 1)
            deep_paths.add(_normalize_endpoint_key(endpoint))

        tasks: list[Task] = []
        if "parameter_intelligence" in available_plugins:
            tasks.append(
                Task(
                    plugin="parameter_intelligence",
                    target=target,
                    payload={
                        "seed_paths": sorted(list(deep_paths))[:120],
                        "priority_score": 100,
                        "trigger": "delta_change_monitor",
                        "program_pack": pack or {},
                        "run_id": run_id,
                    },
                )
            )
        if "behavioral_diff_engine" in available_plugins:
            tasks.append(
                Task(
                    plugin="behavioral_diff_engine",
                    target=target,
                    payload={
                        "paths": sorted(list(deep_paths))[:60],
                        "priority_score": 100,
                        "trigger": "delta_change_monitor",
                        "program_pack": pack or {},
                        "run_id": run_id,
                    },
                )
            )
        return tasks


class LogicChainingEngine:
    """Chains high-value logic leads into auth/account flow probes (safe, non-destructive)."""

    def __init__(self, auth_paths: list[str] | None = None) -> None:
        self.auth_paths = auth_paths or [
            "/api/password/recover",
            "/api/password/reset",
            "/api/account/update",
            "/api/profile/update",
        ]

    def build_tasks(
        self,
        findings: list[Finding],
        run_id: str,
        pack: dict[str, Any] | None,
        available_plugins: set[str],
    ) -> list[Task]:
        leaks_by_target: dict[str, set[str]] = {}
        for f in findings:
            if f.category not in {"idor_logic_signal", "idor_inconsistency_indicator", "idor_behavior_indicator"}:
                continue
            if not isinstance(f.evidence, dict):
                continue
            leaks = f.evidence.get("leaked_identifiers", [])
            if not isinstance(leaks, list):
                continue
            for lk in leaks:
                if isinstance(lk, str) and lk.strip():
                    leaks_by_target.setdefault(f.target, set()).add(lk.strip())

        tasks: list[Task] = []
        for target, leaks in leaks_by_target.items():
            if not leaks:
                continue
            payload_base = {
                "paths": self.auth_paths,
                "leaked_indicators": sorted(list(leaks))[:30],
                "trigger": "logic_chaining",
                "priority_score": 100,
                "program_pack": pack or {},
                "run_id": run_id,
            }
            if "behavioral_diff_engine" in available_plugins:
                tasks.append(Task(plugin="behavioral_diff_engine", target=target, payload=payload_base.copy()))
            if "context_aware_fuzzing_engine" in available_plugins:
                tasks.append(Task(plugin="context_aware_fuzzing_engine", target=target, payload=payload_base.copy()))
        return tasks


class DifferentialAuthProver:
    """Runs multi-session differential checks for high-risk object access patterns."""

    def __init__(self, cfg: dict[str, Any], runtime: dict[str, Any]) -> None:
        self.cfg = cfg
        self.timeout = int(runtime.get("timeout_seconds", 25))
        self.min_similarity = float(cfg.get("min_structure_similarity_pct", 90.0))
        self.max_candidates = int(cfg.get("max_candidates", 80))
        self.max_entities = int(cfg.get("max_entities", 120))
        self.auth_context_a = str(cfg.get("auth_context_a", "user")).strip() or "user"
        self.auth_context_b = str(cfg.get("auth_context_b", "user_b")).strip() or "user_b"
        self.sessions_file = Path(str(cfg.get("sessions_file", "data/sessions.yaml")))
        # Stealth-concurrency hard cap for non-disruptive operation.
        self.semaphore = asyncio.Semaphore(min(10, max(1, int(runtime.get("concurrency", 10)))))
        self.risk_types = {str(x).strip().lower() for x in cfg.get("high_risk_param_types", ["numeric_id", "identifier", "uuid", "token"])}
        self.risk_types.discard("")

    @staticmethod
    def _infer_param_type(param_name: str) -> str:
        name = param_name.lower()
        if "email" in name or "mail" in name:
            return "email"
        if any(k in name for k in ("token", "jwt", "auth", "api_key", "key", "secret")):
            return "token"
        if any(k in name for k in ("id", "uid", "account_id", "user_id", "order_id", "invoice_id", "profile_id")):
            return "numeric_id"
        return "string"

    @staticmethod
    def _normalize_endpoint(raw: str) -> str:
        value = str(raw or "").strip()
        if not value:
            return ""
        if value.startswith("http://") or value.startswith("https://"):
            p = urlparse(value)
            return p.path or "/"
        return value if value.startswith("/") else f"/{value}"

    def _candidate_rows(
        self,
        findings: list[Finding],
        storage: PostgresStorage | None,
        run_id: str,
    ) -> list[dict[str, str]]:
        rows: list[dict[str, str]] = []
        seen: set[str] = set()

        for f in findings:
            if f.category not in {"parameter_intelligence", "idor_logic_signal", "idor_inconsistency_indicator", "idor_behavior_indicator"}:
                continue
            ev = f.evidence if isinstance(f.evidence, dict) else {}
            samples = ev.get("parameter_map_sample", [])
            if isinstance(samples, list):
                for item in samples:
                    if not isinstance(item, dict):
                        continue
                    endpoint = self._normalize_endpoint(str(item.get("endpoint", "")))
                    param = str(item.get("parameter", "")).strip()
                    ptype = str(item.get("type", self._infer_param_type(param))).strip().lower()
                    if not endpoint or not param:
                        continue
                    if ptype not in self.risk_types:
                        continue
                    sig = f"{endpoint}|{param}"
                    if sig in seen:
                        continue
                    seen.add(sig)
                    rows.append({"endpoint": endpoint, "parameter": param, "param_type": ptype})

            if isinstance(ev.get("tested_parameter"), str):
                endpoint = self._normalize_endpoint(str(ev.get("base_url", ev.get("modified_url", ""))))
                param = str(ev.get("tested_parameter", "")).strip()
                if endpoint and param:
                    ptype = self._infer_param_type(param)
                    if ptype in self.risk_types:
                        sig = f"{endpoint}|{param}"
                        if sig not in seen:
                            seen.add(sig)
                            rows.append({"endpoint": endpoint, "parameter": param, "param_type": ptype})

        if not rows and storage:
            try:
                for item in storage.list_endpoint_parameters(run_id=run_id, limit=self.max_candidates * 8):
                    endpoint = self._normalize_endpoint(str(item.get("endpoint", "")))
                    param = str(item.get("param_name", "")).strip()
                    ptype = str(item.get("param_type", self._infer_param_type(param))).strip().lower()
                    if not endpoint or not param or ptype not in self.risk_types:
                        continue
                    sig = f"{endpoint}|{param}"
                    if sig in seen:
                        continue
                    seen.add(sig)
                    rows.append({"endpoint": endpoint, "parameter": param, "param_type": ptype})
                    if len(rows) >= self.max_candidates:
                        break
            except Exception:
                pass

        return rows[: self.max_candidates]

    @staticmethod
    def _entity_buckets(entities: list[dict[str, Any]]) -> dict[str, list[str]]:
        buckets: dict[str, list[str]] = {}
        for ent in entities:
            et = str(ent.get("entity_type", "")).strip().lower()
            ev = str(ent.get("entity_value", "")).strip()
            if not et or not ev:
                continue
            buckets.setdefault(et, [])
            if ev not in buckets[et]:
                buckets[et].append(ev)
        return buckets

    def _pick_value(self, param_type: str, buckets: dict[str, list[str]]) -> str:
        if param_type in buckets and buckets[param_type]:
            return buckets[param_type][0]
        if param_type in {"identifier", "numeric_id"}:
            for key in ("uuid", "numeric_id", "identifier"):
                if buckets.get(key):
                    return buckets[key][0]
            return "2"
        if param_type == "email":
            if buckets.get("email"):
                return buckets["email"][0]
            return "user@example.com"
        if param_type == "token":
            if buckets.get("token"):
                return buckets["token"][0]
            return "invalid-token"
        for key in ("uuid", "numeric_id", "email", "token", "identifier"):
            if buckets.get(key):
                return buckets[key][0]
        return "1"

    async def _probe_candidate(self, target: str, endpoint: str, parameter: str, param_type: str, value: str, headers_a: dict[str, str], headers_b: dict[str, str]) -> Finding | None:
        base_url = endpoint if endpoint.startswith("http://") or endpoint.startswith("https://") else f"https://{target}{endpoint}"
        probe_url = _set_query(base_url, parameter, value)
        async with self.semaphore:
            response_a = await request_http_async("GET", probe_url, headers=headers_a, timeout=self.timeout)
            response_b = await request_http_async("GET", probe_url, headers=headers_b, timeout=self.timeout)

        status_a = int(response_a.get("status", 0) or 0)
        status_b = int(response_b.get("status", 0) or 0)
        text_a = str(response_a.get("text", ""))
        text_b = str(response_b.get("text", ""))
        struct_similarity = _semantic_structure_similarity(text_a, text_b)
        if status_a != status_b or struct_similarity < self.min_similarity:
            return None
        if status_a not in {200, 201, 202, 204}:
            return None

        keys_a = json_keys(text_a)
        keys_b = json_keys(text_b)
        sensitive_markers = []
        lower_payload = f"{text_a}\n{text_b}".lower()
        for marker in ("email", "cpf", "phone", "address", "account", "wallet", "invoice"):
            if marker in lower_payload:
                sensitive_markers.append(marker)

        body_hash_a = hashlib.sha256(text_a.encode("utf-8", errors="ignore")).hexdigest()
        body_hash_b = hashlib.sha256(text_b.encode("utf-8", errors="ignore")).hexdigest()
        diff_map = {
            "status_a": status_a,
            "status_b": status_b,
            "status_equal": status_a == status_b,
            "length_a": int(response_a.get("length", 0) or 0),
            "length_b": int(response_b.get("length", 0) or 0),
            "length_delta": abs(int(response_a.get("length", 0) or 0) - int(response_b.get("length", 0) or 0)),
            "json_keys_a": keys_a,
            "json_keys_b": keys_b,
            "json_key_overlap": len(set(keys_a) & set(keys_b)),
            "structure_similarity_pct": struct_similarity,
            "body_hash_a": body_hash_a,
            "body_hash_b": body_hash_b,
            "body_equal": body_hash_a == body_hash_b,
        }

        confidence = 92.0 if sensitive_markers else 88.0
        return Finding(
            plugin="differential_auth_prover",
            target=target,
            category="critical_idor_vulnerability",
            severity="critical",
            title=f"Cross-context access consistency anomaly on {endpoint} ({parameter})",
            evidence={
                "request_auth_a": {"method": "GET", "url": probe_url, "headers": headers_a},
                "response_auth_a": {
                    "status": status_a,
                    "length": int(response_a.get("length", 0) or 0),
                    "headers": response_a.get("headers", {}),
                    "body": text_a,
                },
                "request_auth_b": {"method": "GET", "url": probe_url, "headers": headers_b},
                "response_auth_b": {
                    "status": status_b,
                    "length": int(response_b.get("length", 0) or 0),
                    "headers": response_b.get("headers", {}),
                    "body": text_b,
                },
                "diff_map": diff_map,
                "tested_parameter": parameter,
                "tested_value": value,
                "param_type": param_type,
                "sensitive_field_indicators": sorted(set(sensitive_markers)),
                "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                "discovery_source": "differential_auth_prover",
            },
            metadata={
                "novelty": 93,
                "confidence": confidence,
                "confidence_score": confidence,
                "impact": 95,
                "discovery_source": "differential_auth_prover",
                "auth_context_a": self.auth_context_a,
                "auth_context_b": self.auth_context_b,
                "structure_similarity_pct": struct_similarity,
                "status_match": True,
            },
        )

    async def run(self, target: str, run_id: str, findings: list[Finding], storage: PostgresStorage | None) -> list[Finding]:
        sessions = load_sessions(self.sessions_file)
        session_a = sessions.get(self.auth_context_a, {})
        session_b = sessions.get(self.auth_context_b, {})
        headers_a = auth_header(session_a) if session_a else {}
        headers_b = auth_header(session_b) if session_b else {}
        if not headers_a or not headers_b:
            return []

        candidates = self._candidate_rows(findings=findings, storage=storage, run_id=run_id)
        if not candidates:
            return []

        entities = storage.list_recent_entities(target=target, limit=self.max_entities) if storage else []
        buckets = self._entity_buckets(entities)
        probes = []
        for cand in candidates[: self.max_candidates]:
            endpoint = str(cand.get("endpoint", ""))
            parameter = str(cand.get("parameter", ""))
            param_type = str(cand.get("param_type", self._infer_param_type(parameter)))
            if not endpoint or not parameter:
                continue
            val = self._pick_value(param_type=param_type, buckets=buckets)
            probes.append(
                self._probe_candidate(
                    target=target,
                    endpoint=endpoint,
                    parameter=parameter,
                    param_type=param_type,
                    value=val,
                    headers_a=headers_a,
                    headers_b=headers_b,
                )
            )
        if not probes:
            return []
        results = await asyncio.gather(*probes, return_exceptions=False)
        out: list[Finding] = []
        for item in results:
            if isinstance(item, Finding):
                out.append(item)
        return out


class ResearchScheduler:
    def __init__(self, plugins: dict[str, Any], context: dict[str, Any], state: ResearchState) -> None:
        self.plugins = plugins
        self.context = context
        self.state = state
        runtime = context["runtime"]
        self.rate = AsyncRateLimiter(float(runtime["rate_limit_per_sec"]))
        self._base_concurrency = max(1, int(runtime["concurrency"]))
        self._active_concurrency = self._base_concurrency
        self.semaphore = asyncio.Semaphore(self._active_concurrency)
        self.max_retries = int(runtime["max_retries"])
        self.backoff = float(runtime["backoff_base_seconds"])
        self.logger = context["logger"]
        self.target_rps: dict[str, float] = context.get("target_rps", {}) if isinstance(context.get("target_rps"), dict) else {}
        self._target_next_allowed: dict[str, float] = {}
        self._target_penalty_until: dict[str, float] = {}
        self._target_lock = asyncio.Lock()
        self.feedback_base_delay = float(runtime.get("feedback_base_delay_seconds", 1.2))
        self.feedback_max_delay = float(runtime.get("feedback_max_delay_seconds", 25.0))
        self.feedback_max_retries = int(runtime.get("feedback_max_retries", 2))
        self._feedback_counts: dict[str, int] = {}
        self._feedback_streak: dict[str, int] = {}
        self._feedback_events_total = 0
        self._feedback_events_by_target: dict[str, int] = {}
        self._task_timeouts_total = 0
        self._task_timeouts_by_target: dict[str, int] = {}
        self.feedback_streak_threshold = int(runtime.get("feedback_streak_threshold", 3))
        self.feedback_hard_pause_seconds = float(runtime.get("feedback_hard_pause_seconds", 60.0))
        self.auto_mute_enabled = bool(runtime.get("auto_mute_enabled", True))
        self.auto_mute_window_seconds = int(runtime.get("auto_mute_window_seconds", 120))
        self.auto_mute_event_threshold = int(runtime.get("auto_mute_event_threshold", 6))
        self.auto_mute_seconds = int(runtime.get("auto_mute_seconds", 900))
        self._auto_mute_events: dict[str, list[float]] = {}
        self._auto_mute_until: dict[str, float] = {}
        self.per_target_inflight = max(1, int(runtime.get("per_target_inflight", 2) or 2))
        self.per_target_jitter_ms = max(0, int(runtime.get("per_target_jitter_ms", 0) or 0))
        self._target_semaphores: dict[str, asyncio.Semaphore] = {}
        self._target_sem_lock = asyncio.Lock()
        self.metrics_enabled = bool(runtime.get("plugin_metrics_enabled", True))
        self._plugin_stats: dict[str, dict[str, float]] = defaultdict(lambda: {"calls": 0.0, "errors": 0.0, "latency_sum": 0.0})
        user_agents = runtime.get("user_agents", [])
        if not isinstance(user_agents, list) or not user_agents:
            user_agents = [
                "Mozilla/5.0 (compatible; Pinguinho/1.0; +https://hunterops.local)",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Firefox/121.0",
            ]
        self.user_agents = [str(x).strip() for x in user_agents if str(x).strip()]
        self.proxies = [str(x).strip() for x in runtime.get("proxies", [])] if isinstance(runtime.get("proxies"), list) else []
        self._ua_idx: dict[str, int] = {}
        self._proxy_idx: dict[str, int] = {}
        try:
            base_timeout_seconds = float(runtime.get("timeout_seconds", 30) or 30)
        except Exception:
            base_timeout_seconds = 30.0
        try:
            configured_task_timeout = float(runtime.get("task_timeout_seconds", base_timeout_seconds * 4) or (base_timeout_seconds * 4))
        except Exception:
            configured_task_timeout = base_timeout_seconds * 4
        try:
            configured_heartbeat = float(runtime.get("batch_heartbeat_seconds", 15.0) or 15.0)
        except Exception:
            configured_heartbeat = 15.0
        self.task_timeout_seconds = max(30.0, configured_task_timeout)
        self.batch_heartbeat_seconds = max(5.0, configured_heartbeat)

    async def _wait_target_budget(self, target: str) -> None:
        rps = float(self.target_rps.get(target, 0) or 0)
        interval = 0.0 if rps <= 0 else 1.0 / max(0.1, rps)
        async with self._target_lock:
            now = time.monotonic()
            if self.auto_mute_enabled:
                mute_until = float(self._auto_mute_until.get(target, 0.0))
                if mute_until > now:
                    await asyncio.sleep(max(0.0, mute_until - now))
                    now = time.monotonic()
            if self.per_target_jitter_ms > 0:
                await asyncio.sleep(random.uniform(0.0, float(self.per_target_jitter_ms) / 1000.0))
            next_allowed = float(self._target_next_allowed.get(target, now + interval))
            penalty_until = float(self._target_penalty_until.get(target, now))
            if penalty_until > next_allowed:
                next_allowed = penalty_until
            if next_allowed > now:
                await asyncio.sleep(next_allowed - now)
                now = time.monotonic()
            self._target_next_allowed[target] = now + interval

    async def _get_target_semaphore(self, target: str) -> asyncio.Semaphore:
        async with self._target_sem_lock:
            sem = self._target_semaphores.get(target)
            if sem is None:
                sem = asyncio.Semaphore(self.per_target_inflight)
                self._target_semaphores[target] = sem
            return sem

    def register_feedback(self, target: str, status_code: int) -> None:
        if int(status_code) not in {403, 429}:
            self.clear_feedback(target)
            return
        if self.auto_mute_enabled:
            now = time.monotonic()
            bucket = self._auto_mute_events.setdefault(target, [])
            bucket.append(now)
            window = max(10.0, float(self.auto_mute_window_seconds))
            self._auto_mute_events[target] = [ts for ts in bucket if (now - ts) <= window]
            if len(self._auto_mute_events[target]) >= max(1, int(self.auto_mute_event_threshold)):
                self._auto_mute_until[target] = now + max(30.0, float(self.auto_mute_seconds))
        self._feedback_events_total += 1
        self._feedback_events_by_target[target] = int(self._feedback_events_by_target.get(target, 0) or 0) + 1
        count = int(self._feedback_counts.get(target, 0) or 0) + 1
        self._feedback_counts[target] = count
        streak = int(self._feedback_streak.get(target, 0) or 0) + 1
        self._feedback_streak[target] = streak
        status_factor = 2.0 if int(status_code) == 429 else 1.3
        cooldown = min(self.feedback_max_delay, self.feedback_base_delay * status_factor * max(1.0, float(count)))
        until = time.monotonic() + cooldown
        prev = float(self._target_penalty_until.get(target, 0.0))
        penalty_until = max(prev, until)
        if streak > self.feedback_streak_threshold:
            penalty_until = max(penalty_until, time.monotonic() + self.feedback_hard_pause_seconds)
            new_concurrency = max(1, int(self._active_concurrency / 2))
            if new_concurrency < self._active_concurrency:
                self._active_concurrency = new_concurrency
                self.semaphore = asyncio.Semaphore(self._active_concurrency)
                self.logger.warning(
                    f"adaptive_concurrency_reduced target={target} active={self._active_concurrency} hard_pause={int(self.feedback_hard_pause_seconds)}s"
                )
        self._target_penalty_until[target] = penalty_until
        self.logger.warning(f"adaptive_backoff_applied target={target} status={status_code} cooldown={round(cooldown, 2)}")

    def clear_feedback(self, target: str) -> None:
        self._feedback_counts[target] = 0
        self._feedback_streak[target] = 0

    def target_delay_remaining(self, target: str) -> float:
        now = time.monotonic()
        return max(0.0, float(self._target_penalty_until.get(target, now)) - now)

    def timeout_count(self, target: str | None = None) -> int:
        if target is None:
            return int(self._task_timeouts_total)
        return int(self._task_timeouts_by_target.get(target, 0) or 0)

    def feedback_event_count(self, target: str | None = None) -> int:
        if target is None:
            return int(self._feedback_events_total)
        return int(self._feedback_events_by_target.get(target, 0) or 0)

    def next_user_agent(self, target: str) -> str:
        if not self.user_agents:
            return ""
        idx = int(self._ua_idx.get(target, 0) or 0)
        value = self.user_agents[idx % len(self.user_agents)]
        self._ua_idx[target] = (idx + 1) % len(self.user_agents)
        return value

    def next_proxy(self, target: str) -> str:
        if not self.proxies:
            return ""
        idx = int(self._proxy_idx.get(target, 0) or 0)
        value = self.proxies[idx % len(self.proxies)]
        self._proxy_idx[target] = (idx + 1) % len(self.proxies)
        return value

    async def run_task(self, task: Task) -> list[Finding]:
        filtered = self.state.filter_task(task)
        if filtered is None:
            return []
        if filtered.plugin not in self.plugins:
            self.logger.warning(f"plugin_not_loaded={filtered.plugin}")
            return []
        plugin = self.plugins[filtered.plugin]
        target_sem = await self._get_target_semaphore(filtered.target)
        async with target_sem:
            await self.rate.wait()
            await self._wait_target_budget(filtered.target)
            async with self.semaphore:
                async def invoke() -> list[Finding]:
                    return await plugin.run(filtered, self.context)

                started_at = time.monotonic()
                try:
                    findings = await asyncio.wait_for(
                        retry_async(invoke, retries=self.max_retries, base_delay=self.backoff),
                        timeout=self.task_timeout_seconds,
                    )
                    findings = plugin.normalize_findings(findings, filtered)
                except asyncio.TimeoutError:
                    elapsed = round(time.monotonic() - started_at, 2)
                    self._task_timeouts_total += 1
                    self._task_timeouts_by_target[filtered.target] = int(self._task_timeouts_by_target.get(filtered.target, 0) or 0) + 1
                    self.logger.error(
                        f"pipeline_task_timeout plugin={filtered.plugin} target={filtered.target} "
                        f"timeout={self.task_timeout_seconds}s elapsed={elapsed}s"
                    )
                    if self.metrics_enabled:
                        stats = self._plugin_stats[filtered.plugin]
                        stats["calls"] += 1.0
                        stats["errors"] += 1.0
                        stats["latency_sum"] += float(elapsed)
                    return []
                except Exception as err:
                    self.logger.error(f"pipeline_task_failed plugin={filtered.plugin} target={filtered.target} err={err}")
                    if self.metrics_enabled:
                        elapsed = round(time.monotonic() - started_at, 2)
                        stats = self._plugin_stats[filtered.plugin]
                        stats["calls"] += 1.0
                        stats["errors"] += 1.0
                        stats["latency_sum"] += float(elapsed)
                    return []
                elapsed = round(time.monotonic() - started_at, 2)
                if elapsed >= self.batch_heartbeat_seconds:
                    self.logger.info(
                        f"pipeline_task_slow_complete plugin={filtered.plugin} target={filtered.target} elapsed={elapsed}s findings={len(findings)}"
                    )
                if self.metrics_enabled:
                    stats = self._plugin_stats[filtered.plugin]
                    stats["calls"] += 1.0
                    stats["latency_sum"] += float(elapsed)
                for ep in _task_endpoints(filtered):
                    self.state.mark_scanned(filtered.plugin, filtered.target, ep)
                return findings

    async def run_batch(self, tasks: list[Task]) -> list[Finding]:
        if not tasks:
            return []
        out: list[Finding] = []
        pending: dict[asyncio.Task[list[Finding]], Task] = {
            asyncio.create_task(self.run_task(work_item)): work_item for work_item in tasks
        }
        batch_started = time.monotonic()
        while pending:
            done, _ = await asyncio.wait(
                set(pending.keys()),
                timeout=self.batch_heartbeat_seconds,
                return_when=asyncio.FIRST_COMPLETED,
            )
            if not done:
                elapsed = round(time.monotonic() - batch_started, 1)
                sample = [f"{work.plugin}@{work.target}" for work in list(pending.values())[:3]]
                sample_raw = ";".join(sample) if sample else "none"
                self.logger.info(
                    f"batch_heartbeat pending_tasks={len(pending)} elapsed={elapsed}s sample={sample_raw}"
                )
                continue
            for completed in done:
                work_item = pending.pop(completed, None)
                if work_item is None:
                    continue
                try:
                    out.extend(completed.result())
                except Exception as err:
                    self.logger.error(
                        f"pipeline_batch_task_failed plugin={work_item.plugin} target={work_item.target} err={err}"
                    )
        if self.metrics_enabled and self._plugin_stats:
            for name, stats in sorted(self._plugin_stats.items()):
                calls = int(stats.get("calls", 0) or 0)
                errors = int(stats.get("errors", 0) or 0)
                latency_sum = float(stats.get("latency_sum", 0.0) or 0.0)
                if calls <= 0:
                    continue
                avg = latency_sum / max(1, calls)
                self.logger.info(
                    "plugin_metrics "
                    f"plugin={name} calls={calls} errors={errors} avg_latency={avg:.2f}s"
                )
        return out


def persist_outputs(out_dir: Path, target_label: str, rows: list[dict[str, Any]]) -> None:
    export_json(out_dir / "findings.json", rows)
    export_csv(out_dir / "findings.csv", rows)
    export_markdown(out_dir / "findings.md", rows, target_label)
    export_html(out_dir / "findings.html", rows, target_label)
    export_dashboard(out_dir / "dashboard.html", rows)
    (out_dir / "findings.jsonl").write_text(to_jsonl(rows), encoding="utf-8")


def persist_triage_outputs(
    out_dir: Path,
    *,
    run_id: str,
    actionable_rows: list[dict[str, Any]],
    review_rows: list[dict[str, Any]],
) -> None:
    def _write_triage(dir_path: Path) -> None:
        triage_dir = ensure_directory(dir_path, mode=0o755)
        export_json(triage_dir / "actionable_findings.json", actionable_rows)
        export_json(triage_dir / "review_queue.json", review_rows)
        (triage_dir / "actionable_findings.jsonl").write_text(to_jsonl(actionable_rows), encoding="utf-8")
        (triage_dir / "review_queue.jsonl").write_text(to_jsonl(review_rows), encoding="utf-8")
        export_markdown(triage_dir / "actionable_findings.md", actionable_rows, f"{run_id}-actionable")
        export_markdown(triage_dir / "review_queue.md", review_rows, f"{run_id}-review-queue")
        (triage_dir / "summary.json").write_text(
            json.dumps(
                {
                    "run_id": run_id,
                    "actionable_count": len(actionable_rows),
                    "review_count": len(review_rows),
                },
                ensure_ascii=True,
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

    _write_triage(out_dir / "triage")
    _write_triage(out_dir / "runs" / str(run_id) / "triage")


def print_research_summary_table(rows: list[dict[str, Any]]) -> None:
    if not rows:
        return
    headers = ["Severity", "Plugin", "Endpoint", "Confidence", "Report_Path"]
    try:
        from rich.console import Console
        from rich.table import Table

        table = Table(title="HunterOps Research Summary")
        for h in headers:
            table.add_column(h)
        for row in rows:
            table.add_row(
                str(row.get("severity", "")),
                str(row.get("plugin", "")),
                str(row.get("endpoint", "")),
                str(row.get("confidence", "")),
                str(row.get("report_path", "")),
            )
        Console().print(table)
        return
    except Exception:
        pass
    try:
        from tabulate import tabulate

        lines = [
            [
                str(row.get("severity", "")),
                str(row.get("plugin", "")),
                str(row.get("endpoint", "")),
                str(row.get("confidence", "")),
                str(row.get("report_path", "")),
            ]
            for row in rows
        ]
        print(tabulate(lines, headers=headers, tablefmt="github"))
        return
    except Exception:
        pass

    # Fallback plain table.
    col_sizes = {
        "Severity": max(len("Severity"), max(len(str(r.get("severity", ""))) for r in rows)),
        "Plugin": max(len("Plugin"), max(len(str(r.get("plugin", ""))) for r in rows)),
        "Endpoint": max(len("Endpoint"), max(len(str(r.get("endpoint", ""))) for r in rows)),
        "Confidence": max(len("Confidence"), max(len(str(r.get("confidence", ""))) for r in rows)),
        "Report_Path": max(len("Report_Path"), max(len(str(r.get("report_path", ""))) for r in rows)),
    }
    sep = " | "
    header_line = sep.join([h.ljust(col_sizes[h]) for h in headers])
    rule = "-+-".join(["-" * col_sizes[h] for h in headers])
    print(header_line)
    print(rule)
    for row in rows:
        print(
            sep.join(
                [
                    str(row.get("severity", "")).ljust(col_sizes["Severity"]),
                    str(row.get("plugin", "")).ljust(col_sizes["Plugin"]),
                    str(row.get("endpoint", "")).ljust(col_sizes["Endpoint"]),
                    str(row.get("confidence", "")).ljust(col_sizes["Confidence"]),
                    str(row.get("report_path", "")).ljust(col_sizes["Report_Path"]),
                ]
            )
        )


def generate_auto_poc(out_dir: Path, findings: list[Finding], min_confidence: float = 80.0) -> None:
    poc_dir = out_dir / "auto_poc"
    poc_dir.mkdir(parents=True, exist_ok=True)
    index: list[dict[str, Any]] = []
    for i, f in enumerate(findings, start=1):
        meta = f.metadata if isinstance(f.metadata, dict) else {}
        conf = float(meta.get("confidence_score", meta.get("confidence", 0)) or 0)
        if conf < min_confidence:
            continue
        ev = f.evidence if isinstance(f.evidence, dict) else {}
        req = ev.get("request", {}) if isinstance(ev.get("request"), dict) else {}
        req_a = ev.get("request_auth_a", {}) if isinstance(ev.get("request_auth_a"), dict) else {}
        req_b = ev.get("request_auth_b", {}) if isinstance(ev.get("request_auth_b"), dict) else {}
        cat = f.category.lower()
        if "payment" in cat or "wallet" in cat or "invoice" in cat:
            impact = "Unauthorized Financial Transaction risk through broken business logic."
        elif "idor" in cat or "access" in cat:
            impact = "Massive Data Breach risk through unauthorized cross-account data access."
        elif "auth" in cat or "password" in cat or "session" in cat:
            impact = "Potential Account Takeover risk affecting user account integrity."
        else:
            impact = "Unauthorized Data Exposure risk with potential regulatory and trust impact."

        commands: list[str] = []
        md = [f"# PoC - {f.title}", "", f"- Target: {f.target}", f"- Category: {f.category}", f"- Confidence: {conf}", f"- Discovery Source: {meta.get('discovery_source', '')}", f"- Impact: {impact}", ""]
        if req_a and req_b:
            method_a = str(req_a.get("method", "GET")).upper()
            url_a = str(req_a.get("url", ""))
            headers_a = req_a.get("headers", {}) if isinstance(req_a.get("headers"), dict) else {}
            method_b = str(req_b.get("method", "GET")).upper()
            url_b = str(req_b.get("url", ""))
            headers_b = req_b.get("headers", {}) if isinstance(req_b.get("headers"), dict) else {}
            curl_a = f"curl -i -X {method_a} \"{url_a}\""
            curl_b = f"curl -i -X {method_b} \"{url_b}\""
            for hk, hv in headers_a.items():
                curl_a += f" -H \"{hk}: {hv}\""
            for hk, hv in headers_b.items():
                curl_b += f" -H \"{hk}: {hv}\""
            commands = [curl_a, curl_b]
            md.extend(
                [
                    "## Reproduction",
                    f"1. Execute request using Auth Context A: `{curl_a}`",
                    f"2. Replay the same request using Auth Context B: `{curl_b}`",
                    "3. Compare status/structure and confirm unauthorized cross-context consistency.",
                    "",
                ]
            )
        else:
            method = str(req.get("method", "GET")).upper()
            url = str(req.get("url", ev.get("modified_url", ev.get("base_url", ev.get("url", "")))))
            headers = req.get("headers", {}) if isinstance(req.get("headers"), dict) else {}
            curl = f"curl -i -X {method} \"{url}\""
            for hk, hv in headers.items():
                curl += f" -H \"{hk}: {hv}\""
            commands = [curl]
            md.extend(
                [
                    "## Reproduction",
                    f"1. Execute: `{curl}`",
                    "2. Observe response differences and sensitive indicators in evidence.",
                    "",
                ]
            )
        md_file = poc_dir / f"poc_{i:03d}.md"
        curl_file = poc_dir / f"poc_{i:03d}.sh"
        md_file.write_text("\n".join(md), encoding="utf-8")
        curl_file.write_text("\n".join(commands) + "\n", encoding="utf-8")
        index.append({"title": f.title, "target": f.target, "confidence": conf, "impact": impact, "markdown": str(md_file), "curl": str(curl_file), "commands": len(commands)})
    (poc_dir / "index.json").write_text(json.dumps({"count": len(index), "items": index}, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")


async def run_async(args: argparse.Namespace) -> int:
    ts = args.run_id.strip() or datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    data_dir = _assert_writable_directory(resolve_path("data", prefer_existing=False), label="data directory")
    out_dir = _assert_writable_directory(resolve_path(args.out_dir, prefer_existing=False), label="output directory")
    pipeline_log_path = resolve_path(DEFAULT_PIPELINE_LOG, prefer_existing=False)
    _assert_writable_directory(pipeline_log_path.parent, label="pipeline log directory")
    logger = _init_bootstrap_logger(pipeline_log_path, verbose=args.verbose)
    _attach_json_file_handler(logger, out_dir / f"research_{ts}.jsonl")

    running_loop = asyncio.get_running_loop()
    logger.info(
        "bootstrap_started "
        f"run_id={ts} "
        f"config={resolve_path(args.config)} "
        f"data_dir={data_dir} "
        f"out_dir={out_dir} "
        f"event_loop={type(running_loop).__name__} "
        f"policy={type(asyncio.get_event_loop_policy()).__name__}"
    )

    cfg = load_config(resolve_path(args.config))
    structure_errors = _validate_config_structure(cfg)
    if structure_errors:
        raise RuntimeError("config_validation_failed " + " | ".join(structure_errors))
    env_errors, env_warnings = _validate_config_env(cfg)
    for warning in env_warnings:
        logger.warning(warning)
    if env_errors:
        raise RuntimeError("config_env_validation_failed " + " | ".join(env_errors))

    bootstrap_cfg = cfg.get("bootstrap", {}) if isinstance(cfg.get("bootstrap"), dict) else {}
    if bool(bootstrap_cfg.get("force_stdio_flush", True)):
        _force_stdio_unbuffered()
    startup_check_dir = str(bootstrap_cfg.get("startup_write_check_dir", "data")).strip() or "data"
    startup_writable = _assert_writable_directory(resolve_path(startup_check_dir, prefer_existing=False), label="startup write-check directory")
    logger.info(f"startup_write_check_ok path={startup_writable}")

    configured_pipeline_log = resolve_path(str(bootstrap_cfg.get("pipeline_log_file", DEFAULT_PIPELINE_LOG)), prefer_existing=False)
    if configured_pipeline_log.resolve() != pipeline_log_path.resolve():
        _assert_writable_directory(configured_pipeline_log.parent, label="configured pipeline log directory")
        _attach_json_file_handler(logger, configured_pipeline_log)
        logger.info(f"configured_pipeline_log_attached path={configured_pipeline_log}")

    runtime = get_runtime(cfg)
    metrics_cfg = cfg.get("metrics", {}) if isinstance(cfg.get("metrics", {}), dict) else {}
    metrics_enabled = bool(metrics_cfg.get("enabled", False))
    metrics_port = int(metrics_cfg.get("port", int(os.getenv("HUNTEROPS_METRICS_PORT", "9108") or 9108)) or 9108)
    if metrics_enabled or os.getenv("HUNTEROPS_METRICS_PORT"):
        enable_metrics(metrics_port)
        logger.info(f"metrics_enabled port={metrics_port}")
    triage_cfg = cfg.get("triage", {}) if isinstance(cfg.get("triage"), dict) else {}
    logger.info(
        "triage_policy "
        f"actionable_min_severity={str(triage_cfg.get('actionable_min_severity', 'high')).strip().lower() or 'high'} "
        f"actionable_min_confidence={float(triage_cfg.get('actionable_min_confidence', 80.0) or 80.0)} "
        f"actionable_min_impact={float(triage_cfg.get('actionable_min_impact', 70.0) or 70.0)} "
        f"alert_min_severity={str(triage_cfg.get('alert_min_severity', triage_cfg.get('actionable_min_severity', 'high'))).strip().lower() or 'high'} "
        f"alert_min_confidence={float(triage_cfg.get('alert_min_confidence', triage_cfg.get('actionable_min_confidence', 80.0)) or 80.0)} "
        f"alert_require_actionable={int(bool(triage_cfg.get('alert_require_actionable', False)))} "
        f"allow_correlation_alerts={int(bool(triage_cfg.get('allow_correlation_alerts', False)))}"
    )
    pool_cfg = cfg.get("http_pool", {}) if isinstance(cfg.get("http_pool"), dict) else {}
    configure_http_pool(
        max_connections=int(pool_cfg.get("max_connections", max(50, int(runtime.get("concurrency", 10)) * 12))),
        max_keepalive_connections=int(pool_cfg.get("max_keepalive_connections", max(20, int(runtime.get("concurrency", 10)) * 4))),
        keepalive_expiry=float(pool_cfg.get("keepalive_expiry", 10.0)),
        verify_ssl=bool(pool_cfg.get("verify_ssl", True)),
        http2=bool(pool_cfg.get("http2", False)),
        retries=int(pool_cfg.get("retries", 0)),
        linux_socket_tuning=bool(pool_cfg.get("linux_socket_tuning", True)),
    )
    configure_global_http_limits(
        rate_per_sec=float(runtime.get("global_http_rate_limit_per_sec", 10.0)),
        max_inflight=int(runtime.get("global_http_max_inflight", 10)),
    )
    logger.info(
        "startup_http_pool_configured "
        f"max_connections={int(pool_cfg.get('max_connections', max(50, int(runtime.get('concurrency', 10)) * 12)))} "
        f"keepalive={int(pool_cfg.get('max_keepalive_connections', max(20, int(runtime.get('concurrency', 10)) * 4)))}"
    )
    logger.info(
        "startup_http_global_limit_configured "
        f"rps={float(runtime.get('global_http_rate_limit_per_sec', 10.0))} "
        f"max_inflight={int(runtime.get('global_http_max_inflight', 10))}"
    )
    discord = DiscordDispatch(cfg=cfg.get("modules", {}).get("discord_notifier", {}), logger=logger)
    alert_router = AlertRouter(cfg=cfg.get("modules", {}).get("alert_router", {}), logger=logger)
    attach_alert_router(logger, alert_router)

    async def _shutdown_clients() -> None:
        await discord.close()
        await alert_router.close()
        await close_async_http_client()

    if args.alert_dry_run:
        rc = await _run_alert_dry_run(
            alert_router=alert_router,
            out_dir=out_dir,
            run_id=ts,
            logger=logger,
        )
        await _shutdown_clients()
        return rc

    # Optional DB-backed state + persistence.
    storage: PostgresStorage | None = None
    pg_cfg = cfg.get("storage", {}).get("postgres", {})
    pg_enabled = bool(pg_cfg.get("enabled", False))
    pg_required = bool(pg_cfg.get("required", True))
    dsn_env = str(pg_cfg.get("dsn_env", "HUNTEROPS_POSTGRES_DSN")).strip() or "HUNTEROPS_POSTGRES_DSN"
    dsn = str(os.getenv(dsn_env, "")).strip()
    if pg_enabled and pg_required and not dsn:
        raise RuntimeError(f"postgres_config_error enabled=true required=true missing_env={dsn_env}")
    if pg_enabled and dsn:
        try:
            storage = PostgresStorage(dsn=dsn, enabled=True)
            storage.ensure_research_schema()
            logger.info(f"research_storage_ready backend=postgres env={dsn_env}")
        except Exception as err:
            raise RuntimeError(f"postgres_connection_failed env={dsn_env} err={type(err).__name__}: {err}") from err
    elif pg_enabled and not dsn:
        logger.warning(f"research_storage_disabled reason=missing_env env={dsn_env} required=false")

    await _validate_redis_connectivity(cfg=cfg, logger=logger)

    h1_sync_engine = HackerOneSyncEngine(
        cfg=cfg.get("modules", {}).get("hackerone_sync_engine", {}),
        logger=logger,
        storage=storage,
        targets_file=args.targets_file,
    )
    if h1_sync_engine.enabled:
        try:
            preflight = h1_sync_engine.sync(run_id=ts, timeout=int(runtime.get("timeout_seconds", 25)))
            if preflight.get("enabled", False):
                targets_added = ((preflight.get("targets_file", {}) or {}).get("added_count", 0))
                logger.info(
                    "h1_preflight_sync "
                    f"api_called={preflight.get('api_called', False)} "
                    f"cache={preflight.get('used_cache', False)} "
                    f"domains={preflight.get('domains_total', 0)} "
                    f"added_targets={targets_added}"
                )
            else:
                logger.warning(f"h1_preflight_sync_skipped reason={preflight.get('reason', 'unknown')}")
                if h1_sync_engine.strict_sync:
                    await _shutdown_clients()
                    return 5
        except Exception as err:
            logger.error(f"h1_preflight_sync_failed err={err}")
            if h1_sync_engine.strict_sync:
                await _shutdown_clients()
                return 5

    h1_manager = HackerOneManager(cfg=cfg.get("modules", {}).get("hackerone_manager", {}), logger=logger)
    intigriti_manager = IntigritiManager(cfg=cfg.get("modules", {}).get("intigriti_manager", {}), logger=logger)
    scope_manager: Any | None = None
    scope_provider = "none"
    if intigriti_manager.enabled and h1_manager.enabled:
        logger.warning("scope_provider_conflict intigriti=enabled hackerone=enabled selected=intigriti")
    if intigriti_manager.enabled:
        scope_manager = intigriti_manager
        scope_provider = "intigriti"
    elif h1_manager.enabled:
        scope_manager = h1_manager
        scope_provider = "hackerone"

    targets = collect_targets(args)
    if not targets and not (scope_manager and bool(getattr(scope_manager, "enabled", False))):
        logger.error("no_targets_provided")
        await _shutdown_clients()
        return 2
    if not targets and scope_manager and bool(getattr(scope_manager, "enabled", False)):
        logger.info(f"targets_seed_empty provider={scope_provider} mode=scope_sync_only")

    scope_added: set[str] = set()
    if scope_manager and bool(getattr(scope_manager, "enabled", False)):
        try:
            scope_state = scope_manager.watch_scope_updates(timeout=int(runtime.get("timeout_seconds", 25)))
            if not bool(scope_state.get("enabled", False)):
                logger.warning(
                    "scope_sync_unavailable "
                    f"provider={scope_provider} "
                    f"reason={scope_state.get('reason', 'unknown')}"
                )
                if bool(getattr(scope_manager, "strict_scope", False)):
                    await _shutdown_clients()
                    return 5
            else:
                scope_hosts = sorted(list(scope_manager.current_scope_hosts()))
                if scope_hosts:
                    targets = sorted(list(set(targets) | set(scope_hosts)))
                targets = scope_manager.filter_targets(targets)
                scope_added = {str(x).strip().lower() for x in scope_state.get("added_hosts", []) if str(x).strip()}
                logger.info(
                    "scope_sync "
                    f"provider={scope_provider} "
                    f"enabled={scope_state.get('enabled', False)} "
                    f"targets={len(targets)} "
                    f"added={len(scope_added)}"
                )
        except Exception as err:
            logger.error(f"scope_sync_failed provider={scope_provider} err={err}")
            if bool(getattr(scope_manager, "strict_scope", False)):
                await _shutdown_clients()
                return 5
    if not targets:
        logger.error("no_in_scope_targets_after_scope_sync")
        await _shutdown_clients()
        return 2

    targets = apply_target_governance(
        targets,
        allow_patterns=runtime.get("target_allowlist_patterns", []) if isinstance(runtime.get("target_allowlist_patterns", []), list) else [],
        deny_patterns=runtime.get("target_denylist_patterns", []) if isinstance(runtime.get("target_denylist_patterns", []), list) else [],
        priority_patterns=runtime.get("target_priority_patterns", []) if isinstance(runtime.get("target_priority_patterns", []), list) else [],
        logger=logger,
    )

    program_target_rps: dict[str, float] = {}
    program_limit_rps: float = 0.0
    program_blocked_paths: dict[str, list[str]] = {}
    program_by_target: dict[str, str] = {}
    programs_by_target: dict[str, list[str]] = {}
    target_policies: dict[str, list[ScopePolicy]] = {}
    programs_doc = load_programs(resolve_path("config/programs.yaml"))
    program_entries = programs_doc.get("programs", []) if isinstance(programs_doc, dict) else []
    require_program_match = _env_truthy("HUNTEROPS_REQUIRE_PROGRAM_MATCH", default=True)
    if require_program_match and (not isinstance(program_entries, list) or not program_entries):
        logger.error("program_config_missing action=abort reason=empty_programs_yaml")
        return
    if isinstance(program_entries, list) and program_entries:
        enforce_allowed_hours = _env_truthy("HUNTEROPS_ENFORCE_ALLOWED_HOURS", default=True)
        require_program_headers = _env_truthy("HUNTEROPS_REQUIRE_PROGRAM_HEADERS", default=True)
        program_names = sorted(
            {
                str(entry.get("name", "")).strip()
                for entry in program_entries
                if isinstance(entry, dict) and str(entry.get("name", "")).strip()
            }
        )
        program_policies = {name: collect_scope(programs_doc, name) for name in program_names}
        filtered_targets: list[str] = []
        policy_rps_values: list[float] = []
        for target in targets:
            matched: list[tuple[str, ScopePolicy]] = []
            for name, policy in program_policies.items():
                if in_scope(target, policy):
                    matched.append((name, policy))
            if not matched:
                if require_program_match:
                    logger.error(f"program_scope_missing target={target} action=drop")
                    continue
                filtered_targets.append(target)
                continue
            blocked = False
            matched_names: list[str] = []
            for name, policy in matched:
                matched_names.append(name)
                decision = check_automation_allowed(policy.rules_of_engagement)
                if decision.manual_only:
                    logger.error(
                        "automation_not_allowed "
                        f"program={name} target={target} reason={decision.reason} action=drop"
                    )
                    blocked = True
                    break
                if enforce_allowed_hours and not _policy_allows_now(policy):
                    logger.warning(
                        "outside_allowed_hours "
                        f"program={name} target={target} action=skip"
                    )
                    blocked = True
                    break
                if require_program_headers:
                    missing = _missing_required_headers(policy)
                    if missing:
                        logger.error(
                            "required_headers_missing "
                            f"program={name} target={target} headers={','.join(missing)} action=drop"
                        )
                        blocked = True
                        break
            if blocked:
                continue
            filtered_targets.append(target)
            if matched_names:
                program_by_target[target] = matched_names[0]
                programs_by_target[target] = matched_names
            target_policies[target] = [policy for _, policy in matched]
            blocked_paths: list[str] = []
            for _, policy in matched:
                blocked_paths.extend(policy.blocked_paths or [])
            if blocked_paths:
                program_blocked_paths[target] = sorted({str(x).strip() for x in blocked_paths if str(x).strip()})
            per_target_rps: list[float] = []
            for _, policy in matched:
                rps = _policy_rps(policy)
                if rps > 0:
                    per_target_rps.append(rps)
            if per_target_rps:
                program_target_rps[target] = min(per_target_rps)
                policy_rps_values.append(program_target_rps[target])

        if len(filtered_targets) != len(targets):
            logger.warning(
                "program_scope_filter_applied "
                f"input={len(targets)} output={len(filtered_targets)} "
                f"require_match={int(require_program_match)} "
                f"enforce_hours={int(enforce_allowed_hours)} "
                f"require_headers={int(require_program_headers)}"
            )
        targets = filtered_targets
        if policy_rps_values:
            program_limit_rps = min(policy_rps_values)
            current = float(runtime.get("rate_limit_per_sec", 10.0))
            if program_limit_rps > 0 and current > program_limit_rps:
                runtime["rate_limit_per_sec"] = program_limit_rps
                global_rps = float(runtime.get("global_http_rate_limit_per_sec", program_limit_rps))
                runtime["global_http_rate_limit_per_sec"] = min(global_rps, program_limit_rps)
                configure_global_http_limits(
                    rate_per_sec=float(runtime.get("global_http_rate_limit_per_sec", program_limit_rps)),
                    max_inflight=int(runtime.get("global_http_max_inflight", 10)),
                )
                logger.warning(
                    "rate_limit_clamped_by_program_policy "
                    f"global_rps={float(runtime.get('global_http_rate_limit_per_sec', program_limit_rps))} "
                    f"runtime_rps={float(runtime.get('rate_limit_per_sec', program_limit_rps))}"
                )

    scope_doc = load_authorized_scope()
    if scope_doc:
        _warn_scope_expiry(scope_doc, logger)
    ok, unauthorized = authorize_targets(targets, scope_doc)
    if not ok:
        logger.error(f"scope_authorization_failed unauthorized={unauthorized}")
        return
    if not targets:
        logger.error("no_targets_after_governance_filter")
        await _shutdown_clients()
        return 2

    if args.plugins.strip():
        plugin_names = [x.strip().lower() for x in args.plugins.split(",") if x.strip()]
    else:
        plugin_profile = str(runtime.get("plugin_profile", "safe")).strip().lower() or "safe"
        if plugin_profile == "full":
            plugin_names = [
                "asset_discovery_engine",
                "recon_engine",
                "surface_massive",
                "crawler_intelligent",
                "intelligent_crawler",
                "deep_js_intelligence",
                "deep_js_analyzer",
                "javascript_deep_analysis",
                "hidden_route_discovery",
                "hidden_route_detector",
                "surface_expansion",
                "parameter_enum",
                "js_route_mapper",
                "surface_mapper",
                "undocumented_api",
                "graphql_scan",
                "cors",
                "takeover",
                "parameter_intelligence",
                "differential_auth_prover",
                "business_logic_sniper",
                "vulnerability_correlation_engine",
                "report_synthesis",
                "security_report_builder",
                "evidence_packager",
            ]
            for extra in ("logic_prover", "auth_matrix_engine", "entity_cross_pollinator", "race_condition_turbo"):
                if extra not in plugin_names:
                    plugin_names.append(extra)
        elif plugin_profile in {"capital_idor_focus", "capital_closed_loop"}:
            plugin_names = [
                "deep_js_intelligence",
                "parameter_intelligence",
                "business_logic_sniper",
                "differential_auth_prover",
                "auth_matrix_engine",
                "logic_prover",
                "entity_cross_pollinator",
                "vulnerability_correlation_engine",
                "report_synthesis",
                "evidence_packager",
                "security_report_builder",
            ]
            logger.info(f"plugin_profile_selected profile={plugin_profile} mode=capital_closed_loop")
        elif plugin_profile in {"low_medium", "low_medium_hunt", "profit_low_medium"}:
            plugin_names = [
                "asset_discovery_engine",
                "recon_engine",
                "surface_massive",
                "crawler_intelligent",
                "intelligent_crawler",
                "deep_js_intelligence",
                "deep_js_analyzer",
                "javascript_deep_analysis",
                "hidden_route_discovery",
                "hidden_route_detector",
                "surface_expansion",
                "parameter_enum",
                "js_route_mapper",
                "surface_mapper",
                "undocumented_api",
                "graphql_scan",
                "cors",
                "takeover",
                "parameter_intelligence",
                "differential_auth_prover",
                "business_logic_sniper",
                "vulnerability_correlation_engine",
                "report_synthesis",
                "security_report_builder",
                "evidence_packager",
            ]
            logger.info(f"plugin_profile_selected profile={plugin_profile} mode=low_medium_hunt")
        else:
            plugin_names = [
                "deep_js_intelligence",
                "parameter_intelligence",
                "business_logic_sniper",
                "race_condition_turbo",
                "vulnerability_correlation_engine",
                "report_synthesis",
                "evidence_packager",
            ]
            logger.info(f"plugin_profile_selected profile={plugin_profile} mode=safe")
    if bool(runtime.get("attack_chain_seed_enabled", True)) and "attack_chain_seed" not in plugin_names:
        plugin_names.append("attack_chain_seed")
    allowed_plugins = runtime.get("allowed_plugins", []) if isinstance(runtime.get("allowed_plugins", []), list) else []
    blocked_plugins = runtime.get("blocked_plugins", []) if isinstance(runtime.get("blocked_plugins", []), list) else []
    if allowed_plugins:
        allowed_set = {str(x).strip().lower() for x in allowed_plugins if str(x).strip()}
        plugin_names = [p for p in plugin_names if p in allowed_set]
    if blocked_plugins:
        blocked_set = {str(x).strip().lower() for x in blocked_plugins if str(x).strip()}
        plugin_names = [p for p in plugin_names if p not in blocked_set]
    dep_report = evaluate_runtime_dependencies(cfg, plugin_names)
    for msg in dep_report["critical_warnings"]:
        logger.critical(msg)
    plugin_names = filter_enabled_plugins(plugin_names, dep_report["disabled_plugins"])
    if not plugin_names:
        logger.error("no_runnable_plugins_after_dependency_checks")
        await _shutdown_clients()
        return 6
    program_allowed_plugins: dict[str, list[str]] = {}
    program_blocked_plugins: dict[str, list[str]] = {}
    if target_policies:
        plugin_set = {str(p).strip().lower() for p in plugin_names if str(p).strip()}
        for target, policies in target_policies.items():
            allowed_explicit: set[str] = set()
            blocked_explicit: set[str] = set()
            allowed_tokens: set[str] = set()
            blocked_tokens: set[str] = set()
            for policy in policies:
                allowed_explicit |= {
                    str(x).strip().lower()
                    for x in (getattr(policy, "allowed_plugins", []) or [])
                    if str(x).strip()
                }
                blocked_explicit |= {
                    str(x).strip().lower()
                    for x in (getattr(policy, "blocked_plugins", []) or [])
                    if str(x).strip()
                }
                allowed_tokens |= {
                    str(x).strip().lower()
                    for x in (policy.allowed_modules or [])
                    if str(x).strip() and len(str(x).strip()) >= 2
                }
                blocked_tokens |= {
                    str(x).strip().lower()
                    for x in (policy.blocked_modules or [])
                    if str(x).strip() and len(str(x).strip()) >= 2
                }
            allowed_effective: set[str] = set()
            if allowed_explicit:
                allowed_effective |= {p for p in plugin_set if p in allowed_explicit}
            if allowed_tokens:
                allowed_effective |= {p for p in plugin_set if any(tok in p for tok in allowed_tokens)}
            if allowed_explicit or allowed_tokens:
                if allowed_effective:
                    program_allowed_plugins[target] = sorted(allowed_effective)
                else:
                    logger.warning(
                        "program_allowed_plugins_unmatched "
                        f"target={target} allowed_plugins={','.join(sorted(allowed_explicit)) or 'none'} "
                        f"allowed_modules={','.join(sorted(allowed_tokens)) or 'none'}"
                    )
            blocked_effective: set[str] = set()
            if blocked_explicit:
                blocked_effective |= {p for p in plugin_set if p in blocked_explicit}
            if blocked_tokens:
                blocked_effective |= {p for p in plugin_set if any(tok in p for tok in blocked_tokens)}
            if blocked_effective:
                program_blocked_plugins[target] = sorted(blocked_effective)
    sessions_path = resolve_path(
        str(
            (
                cfg.get("modules", {}).get("auth_matrix_engine", {}) if isinstance(cfg.get("modules"), dict) else {}
            ).get("sessions_file", "data/sessions.yaml")
        )
    )
    configured_sessions = load_sessions(sessions_path)
    populated_sessions = sorted(
        [name for name, session in configured_sessions.items() if auth_header(session)],
    )
    if not populated_sessions:
        logger.warning(
            "auth_sessions_not_configured "
            f"path={sessions_path} "
            "impact=restricted_authenticated_coverage"
        )
    else:
        logger.info(
            "auth_sessions_loaded "
            f"path={sessions_path} "
            f"profiles={','.join(populated_sessions)}"
        )
        if "user" not in populated_sessions or "user_b" not in populated_sessions:
            logger.warning("auth_sessions_partial profiles_expected=user,user_b impact=idor_and_auth_diff_reduced")

    session_guardian = SessionGuardian(
        cfg=cfg.get("modules", {}).get("session_guardian", {}),
        runtime=runtime,
        logger=logger,
        storage=storage,
        sessions_file=sessions_path,
    )
    await session_guardian.warmup()
    impact_validator = ImpactValidator(
        cfg=cfg.get("modules", {}).get("impact_validator", {}),
        runtime=runtime,
        logger=logger,
    )
    logger.info(
        "validation_modules "
        f"session_guardian_enabled={int(session_guardian.enabled)} "
        f"impact_validator_enabled={int(impact_validator.enabled)}"
    )

    logger.info(
        "startup_phase_notifier_check begin=true "
        f"discord_available={int(discord.available)} "
        f"targets={len(targets)} "
        f"plugins={len(plugin_names)}"
    )
    await discord.send_system_online(run_id=ts, targets_count=len(targets), plugins_count=len(plugin_names))
    logger.info("startup_phase_notifier_check completed=true")
    plugins = load_plugins(plugin_names)
    target_rps_map: dict[str, float] = {}
    if program_target_rps:
        target_rps_map.update(program_target_rps)
    if scope_manager and bool(getattr(scope_manager, "enabled", False)):
        for target in targets:
            scope_rps = float(scope_manager.target_rps(target))
            policy_rps = float(program_target_rps.get(target, 0.0) or 0.0)
            if scope_rps > 0 and policy_rps > 0:
                target_rps_map[target] = min(scope_rps, policy_rps)
            elif scope_rps > 0:
                target_rps_map[target] = scope_rps
            elif policy_rps > 0:
                target_rps_map[target] = policy_rps
    context = {
        "config": cfg,
        "runtime": runtime,
        "logger": logger,
        "target_rps": target_rps_map,
        "session_guardian": session_guardian,
        "storage": storage,
    }
    ade_brain = ADEBrainPlugin()
    report_engine = ReportEngine(
        cfg=cfg.get("modules", {}).get("report_engine", {}),
        logger=logger,
        storage=storage,
    )

    endpoint_cache_enabled = bool(runtime.get("endpoint_cache_enabled", True)) and not _env_truthy("HUNTEROPS_DISABLE_ENDPOINT_CACHE", False)
    try:
        endpoint_cache_ttl_hours = float(runtime.get("endpoint_cache_ttl_hours", 24.0) or 0)
    except Exception:
        endpoint_cache_ttl_hours = 24.0
    endpoint_cache_ttl_seconds = max(0, int(endpoint_cache_ttl_hours * 3600))
    endpoint_cache_max_entries = int(runtime.get("endpoint_cache_max_entries", 50000) or 50000)
    noise_patterns = runtime.get("endpoint_noise_patterns", [])
    if not isinstance(noise_patterns, list):
        noise_patterns = []
    state = ResearchState(
        run_id=ts,
        storage=storage,
        endpoint_cache_enabled=endpoint_cache_enabled,
        endpoint_cache_ttl_seconds=endpoint_cache_ttl_seconds,
        endpoint_cache_max_entries=endpoint_cache_max_entries,
        endpoint_cache_local={},
        endpoint_noise_patterns=[str(x) for x in noise_patterns if str(x).strip()],
        blocked_paths_by_target=program_blocked_paths,
        allowed_plugins_by_target=program_allowed_plugins,
        blocked_plugins_by_target=program_blocked_plugins,
    )
    scheduler = ResearchScheduler(plugins=plugins, context=context, state=state)
    packs = load_program_packs(resolve_path(cfg.get("program_packs", {}).get("file", "config/program_packs.yaml")))
    reactions = ReactionLogic()
    delta_monitor = DeltaMonitor(storage=storage)
    logic_chaining = LogicChainingEngine()
    oob_engine = OOBEngine(cfg=cfg.get("modules", {}).get("oob_engine", {}), runtime=runtime, logger=logger)
    available_plugins = set(plugins.keys())
    recursion_max_depth = int(runtime.get("recursion_max_depth", 2))
    max_tasks_per_target = max(20, int(runtime.get("max_tasks_per_target", 1200)))
    priority_patterns = runtime.get("priority_endpoint_patterns", [])
    if not isinstance(priority_patterns, list) or not priority_patterns:
        priority_patterns = list(SENSITIVE_PRIORITY_KEYWORDS)
    try:
        priority_boost = float(runtime.get("priority_endpoint_boost", 12.0) or 12.0)
    except Exception:
        priority_boost = 12.0
    roi_patterns = runtime.get("roi_endpoint_patterns", [])
    if not isinstance(roi_patterns, list):
        roi_patterns = []
    try:
        roi_boost = float(runtime.get("roi_endpoint_boost", 18.0) or 18.0)
    except Exception:
        roi_boost = 18.0
    roi_plugin_boosts = runtime.get("roi_plugin_boosts", {})
    if not isinstance(roi_plugin_boosts, dict):
        roi_plugin_boosts = {}
    try:
        roi_boost_cap = float(runtime.get("roi_boost_cap", 30.0) or 30.0)
    except Exception:
        roi_boost_cap = 30.0
    queue_engine = HighValuePriorityQueue(
        max_size=int(runtime.get("task_queue_size", 4000)),
        priority_patterns=priority_patterns,
        priority_boost=priority_boost,
        roi_patterns=roi_patterns,
        roi_boost=roi_boost,
        roi_plugin_boosts=roi_plugin_boosts,
        roi_boost_cap=roi_boost_cap,
    )
    wave_size = max(1, int(runtime.get("concurrency", 10)) * 2)
    adaptive_levels_cfg = runtime.get("adaptive_levels", {}) if isinstance(runtime.get("adaptive_levels"), dict) else {}
    adaptive_levels_enabled = bool(adaptive_levels_cfg.get("enabled", True))
    try:
        adaptive_level_min = max(1, int(adaptive_levels_cfg.get("min_level", 1) or 1))
    except Exception:
        adaptive_level_min = 1
    try:
        adaptive_level_max = max(adaptive_level_min, int(adaptive_levels_cfg.get("max_level", 3) or 3))
    except Exception:
        adaptive_level_max = max(adaptive_level_min, 3)
    try:
        adaptive_level_start = min(
            adaptive_level_max,
            max(adaptive_level_min, int(adaptive_levels_cfg.get("start_level", adaptive_level_min) or adaptive_level_min)),
        )
    except Exception:
        adaptive_level_start = adaptive_level_min
    try:
        adaptive_escalate_after_clean_rounds = max(1, int(adaptive_levels_cfg.get("escalate_after_clean_rounds", 1) or 1))
    except Exception:
        adaptive_escalate_after_clean_rounds = 1
    adaptive_demote_on_feedback = bool(adaptive_levels_cfg.get("demote_on_feedback", True))

    delta_priority_min_score = float(runtime.get("delta_priority_min_score", 35.0) or 35.0)
    delta_priority_window_seconds = int(runtime.get("delta_priority_window_seconds", 900) or 900)
    roi_patterns_for_delta = runtime.get("roi_endpoint_patterns", [])
    if not isinstance(roi_patterns_for_delta, list):
        roi_patterns_for_delta = []
    try:
        findings_flush_every = int(runtime.get("findings_flush_every", 200) or 200)
    except Exception:
        findings_flush_every = 200
    adaptive_demote_on_timeout = bool(adaptive_levels_cfg.get("demote_on_timeout", True))
    logger.info(
        "adaptive_levels "
        f"enabled={int(adaptive_levels_enabled)} "
        f"min_level={adaptive_level_min} "
        f"max_level={adaptive_level_max} "
        f"start_level={adaptive_level_start} "
        f"escalate_after_clean_rounds={adaptive_escalate_after_clean_rounds}"
    )

    all_findings: list[Finding] = []
    flushed_findings = False
    findings_storage_failed = False
    notified_logic_signals: set[str] = set()
    notified_report_paths: set[str] = set()
    processed_tasks_total = 0
    for target in targets:
        logger.info(f"target_scan_start target={target}")
        if scope_manager and bool(getattr(scope_manager, "enabled", False)) and not scope_manager.in_scope(target):
            logger.warning(f"skip_out_of_scope_target target={target}")
            continue
        try:
            guardian_events = await session_guardian.ensure_target_health(target=target, run_id=ts)
        except Exception as err:
            logger.error(f"session_guardian_target_health_failed target={target} err={type(err).__name__}")
            guardian_events = []
        for event in guardian_events:
            logger.warning(
                "session_guardian_event "
                f"target={event.get('target', target)} "
                f"session={event.get('session_name', '')} "
                f"status={event.get('status', '')} "
                f"reason={event.get('reason', '')} "
                f"refresh_ok={int(bool(event.get('refresh_ok', False)))}"
            )
        pack = resolve_pack(target, packs)
        initial_priority = 100 if str(target).strip().lower() in scope_added else 70
        seed_plugins_cfg = runtime.get("seed_plugins", [])
        if not isinstance(seed_plugins_cfg, list):
            seed_plugins_cfg = []
        seed_plugins = [str(p).strip().lower() for p in seed_plugins_cfg if str(p).strip()]
        if not seed_plugins:
            seed_plugins = ["deep_js_intelligence"]
        seed_plugins = [p for p in seed_plugins if p in available_plugins]
        if not seed_plugins:
            seed_plugins = ["deep_js_intelligence"] if "deep_js_intelligence" in available_plugins else sorted(list(available_plugins))[:1]
        pending: list[Task] = []
        for plugin_name in seed_plugins:
            pending.append(
                Task(
                    plugin=plugin_name,
                    target=target,
                    payload={
                        "run_id": ts,
                        "program_pack": pack or {},
                        "_depth": 0,
                        "priority": initial_priority,
                        "priority_score": initial_priority,
                        "trigger": f"{scope_provider}_scope_update" if initial_priority == 100 else f"initial_seed:{plugin_name}",
                    },
                )
            )
        pending = queue_engine.rank(pending, findings=[])
        target_history: list[Finding] = []
        rounds = 0
        processed_tasks = 0
        target_adaptive_level = adaptive_level_start
        target_clean_round_streak = 0
        max_rounds = max(4, int(runtime.get("max_rounds_per_target", 6)))
        while pending and rounds < max_rounds and processed_tasks < max_tasks_per_target:
            rounds += 1
            try:
                round_guardian_events = await session_guardian.ensure_target_health(target=target, run_id=ts)
            except Exception as err:
                logger.error(f"session_guardian_round_health_failed target={target} round={rounds} err={type(err).__name__}")
                round_guardian_events = []
            for event in round_guardian_events:
                logger.warning(
                    "session_guardian_round_event "
                    f"target={event.get('target', target)} "
                    f"session={event.get('session_name', '')} "
                    f"status={event.get('status', '')} "
                    f"reason={event.get('reason', '')} "
                    f"refresh_ok={int(bool(event.get('refresh_ok', False)))}"
                )
            budget_left = max_tasks_per_target - processed_tasks
            if budget_left <= 0:
                break
            round_timeout_before = scheduler.timeout_count(target)
            level_multiplier = target_adaptive_level if adaptive_levels_enabled else 1
            dynamic_wave_size = max(1, wave_size * max(1, level_multiplier))
            wave_take = min(dynamic_wave_size, budget_left)
            current_wave = pending[:wave_take]
            pending = pending[wave_take:]
            processed_tasks += len(current_wave)
            logger.info(
                f"target_round_start target={target} "
                f"round={rounds} "
                f"level={target_adaptive_level} "
                f"wave_tasks={len(current_wave)} "
                f"pending_after_pop={len(pending)} "
                f"processed_tasks={processed_tasks}"
            )
            batch = await scheduler.run_batch(current_wave)
            if oob_engine.available and batch:
                try:
                    await oob_engine.inject_from_findings(
                        target=target,
                        run_id=ts,
                        findings=batch,
                        rate_limiter=scheduler.rate,
                        target_waiter=scheduler._wait_target_budget,
                    )
                    oob_hits = await oob_engine.poll_and_correlate()
                    if oob_hits:
                        batch.extend([x for x in oob_hits if x.target == target])
                except Exception as err:
                    logger.error(f"oob_engine_cycle_failed target={target} round={rounds} err={err}")
            batch = dedupe_findings(batch)
            try:
                ade_task = Task(
                    plugin="ade_brain",
                    target=target,
                    payload={
                        "run_id": ts,
                        "_depth": 0,
                        "round_findings": serialize_findings(batch),
                    },
                )
                ade_findings = await ade_brain.run(ade_task, context)
                ade_findings = ade_brain.normalize_findings(ade_findings, ade_task)
                if ade_findings:
                    batch.extend(ade_findings)
                    batch = dedupe_findings(batch)
            except Exception as err:
                logger.error(f"ade_brain_round_failed target={target} round={rounds} err={err}")
            if "vulnerability_correlation_engine" in plugins and batch:
                try:
                    corr_plugin = plugins["vulnerability_correlation_engine"]
                    corr_task = Task(
                        plugin="vulnerability_correlation_engine",
                        target=target,
                        payload={
                            "run_id": ts,
                            "findings": serialize_findings(batch),
                        },
                    )
                    corr_findings = await corr_plugin.run(corr_task, context)
                    corr_findings = corr_plugin.normalize_findings(corr_findings, corr_task)
                    if corr_findings:
                        batch.extend(corr_findings)
                        batch = dedupe_findings(batch)
                except Exception as err:
                    logger.error(f"vulnerability_correlation_round_failed target={target} round={rounds} err={err}")
            if impact_validator.enabled and batch:
                try:
                    batch = await impact_validator.validate_batch(
                        target=target,
                        run_id=ts,
                        findings=batch,
                    )
                    batch = dedupe_findings(batch)
                except Exception as err:
                    logger.error(f"impact_validator_round_failed target={target} round={rounds} err={err}")
            report_findings = await _run_report_engine_if_high_critical(
                report_engine=report_engine,
                target=target,
                run_id=ts,
                round_findings=batch,
                logger=logger,
            )
            if report_findings:
                batch.extend(report_findings)
                batch = dedupe_findings(batch)
            _annotate_program_metadata(batch, program_by_target, programs_by_target)
            all_findings.extend(batch)
            if findings_flush_every > 0 and len(all_findings) >= findings_flush_every:
                if storage and not findings_storage_failed:
                    flushed_findings = True
                    logger.info(
                        f"research_findings_flush target={target} round={rounds} in_memory={len(all_findings)}"
                    )
                    all_findings = []
            await _route_alerts_from_batch(
                alert_router=alert_router,
                batch=batch,
                run_id=ts,
                logger=logger,
                source="scan_round",
                triage_cfg=triage_cfg,
            )
            target_history.extend(batch)
            if len(target_history) > 1200:
                target_history = target_history[-1200:]
            feedback = _feedback_status_by_target_window(
                batch,
                window_seconds=int(runtime.get("auto_mute_window_seconds", 120) or 120),
            )
            if feedback:
                for fb_target, statuses in feedback.items():
                    for status_code in statuses:
                        scheduler.register_feedback(fb_target, int(status_code))
            wave_targets = {str(t.target).strip() for t in current_wave if str(t.target).strip()}
            for wave_target in wave_targets:
                if wave_target not in feedback:
                    scheduler.clear_feedback(wave_target)
            round_recursion_depth = _dynamic_recursion_depth_for_round(
                base_depth=recursion_max_depth,
                target=target,
                findings=batch,
            )
            feedback_retry_tasks = _build_feedback_retry_tasks(
                current_wave=current_wave,
                feedback=feedback,
                scheduler=scheduler,
                run_id=ts,
                max_depth=round_recursion_depth,
            )
            feedback_events_this_round = sum(len(statuses) for statuses in feedback.values())
            timeouts_this_round = max(0, scheduler.timeout_count(target) - round_timeout_before)
            if discord.available and batch:
                for finding in batch:
                    if not _is_logic_prover_confirmed(finding):
                        continue
                    meta = finding.metadata if isinstance(finding.metadata, dict) else {}
                    sig = str(meta.get("structural_hash", "")).strip() or f"{finding.target}|{finding.category}|{finding.title}"
                    if sig in notified_logic_signals:
                        continue
                    notified_logic_signals.add(sig)
                    dedupe_key = str(meta.get("structural_hash", "")).strip()
                    if not dedupe_key:
                        dedupe_key = f"{finding.target}|{_finding_source_endpoint(finding)}|{finding.category}|{finding.title}|{finding.severity}"
                    discord.route_finding_confirmed(
                        target=finding.target,
                        title=finding.title,
                        impact=_finding_impact(finding),
                        confidence=_finding_confidence(finding),
                        endpoint=_finding_source_endpoint(finding),
                        evidence_snippet=_finding_evidence_snippet(finding),
                        report_path=str(meta.get("report_path", "pending_generation")),
                        severity_level=str(finding.severity),
                        estimated_payout=_estimated_payout_for_severity(str(finding.severity)),
                        dedupe_key=dedupe_key,
                    )
            entity_rows: list[dict[str, Any]] = []
            if storage and batch:
                try:
                    entity_rows = extract_entity_rows(batch, target=target)
                    if entity_rows:
                        storage.upsert_discovered_entities(run_id=ts, target=target, rows=entity_rows)
                except Exception as err:
                    logger.error(f"research_entity_pool_upsert_failed target={target} round={rounds} err={err}")
            if storage and batch:
                try:
                    storage.write_findings(run_id=ts, rows=serialize_findings(batch))
                except Exception as err:
                    findings_storage_failed = True
                    logger.error(f"research_write_batch_failed target={target} round={rounds} err={err}")

            delta = delta_monitor.compare(target=target, run_id=ts, current_findings=batch)
            if discord.available and (
                delta.get("new_endpoints")
                or delta.get("changed_js")
                or delta.get("new_parameters")
            ):
                discord.route_recon_delta(
                    target=target,
                    delta_score=_delta_score(delta),
                    new_endpoints=[str(x) for x in delta.get("new_endpoints", []) if isinstance(x, str)],
                    changed_js=[str(x) for x in delta.get("changed_js", []) if isinstance(x, str)],
                    new_parameters=[str(x) for x in delta.get("new_parameters", []) if isinstance(x, str)],
                )

            delta_score = _delta_score(delta)
            delta_has_roi = _delta_has_high_value(delta, roi_patterns_for_delta)
            next_tasks: list[Task] = []
            # Delta-first: prioritize recon deltas before any other follow-ups.
            if (delta_score >= delta_priority_min_score) or delta_has_roi:
                next_tasks.extend(
                    delta_monitor.build_priority_tasks(
                        target=target,
                        run_id=ts,
                        pack=pack,
                        current_findings=batch,
                        available_plugins=available_plugins,
                        precomputed_delta=delta,
                    )
                )
            next_tasks.extend(
                reactions.tasks_from_saved_findings(
                    batch,
                    run_id=ts,
                    pack=pack,
                    available_plugins=available_plugins,
                )
            )
            next_tasks.extend(logic_chaining.build_tasks(batch, run_id=ts, pack=pack, available_plugins=available_plugins))
            next_tasks.extend(feedback_retry_tasks)
            next_tasks.extend(
                _spawn_tasks_from_findings(
                    batch,
                    max_depth=round_recursion_depth,
                    attack_chain_seed_enabled=bool(runtime.get("attack_chain_seed_enabled", True)),
                    attack_chain_seed_available=("attack_chain_seed" in available_plugins),
                    attack_chain_seed_max_endpoints=int(runtime.get("attack_chain_seed_max_endpoints", 80) or 80),
                )
            )
            if "logic_prover" in available_plugins:
                logic_paths: set[str] = set()
                for finding in batch:
                    if finding.category in {
                        "js_discovery",
                        "parameter_intelligence",
                        "object_leakage_indicator",
                        "critical_idor_vulnerability",
                        "Potential_IDOR_Signal",
                        "Broken_Object_Level_Authorization",
                    }:
                        logic_paths.add(_normalize_endpoint_key(_finding_source_endpoint(finding)))
                if logic_paths:
                    next_tasks.append(
                        Task(
                            plugin="logic_prover",
                            target=target,
                            payload={
                                "run_id": ts,
                                "seed_paths": sorted(list(logic_paths))[:120],
                                "_depth": 0,
                                "trigger": "decision_brain",
                                "priority": 95,
                                "priority_score": 95,
                            },
                        )
                    )
            if "auth_matrix_engine" in available_plugins:
                matrix_paths: set[str] = set()
                for finding in batch:
                    if finding.category in {
                        "js_discovery",
                        "parameter_intelligence",
                        "object_leakage_indicator",
                        "Potential_IDOR_Signal",
                        "Broken_Object_Level_Authorization",
                        "broken_access_control_matrix_signal",
                    }:
                        matrix_paths.add(_normalize_endpoint_key(_finding_source_endpoint(finding)))
                if matrix_paths:
                    next_tasks.append(
                        Task(
                            plugin="auth_matrix_engine",
                            target=target,
                            payload={
                                "run_id": ts,
                                "seed_paths": sorted(list(matrix_paths))[:140],
                                "_depth": 0,
                                "trigger": "auth_matrix_expand",
                                "priority": 98,
                                "priority_score": 98,
                            },
                        )
                    )
            if entity_rows and "entity_cross_pollinator" in available_plugins:
                next_tasks.append(
                    Task(
                        plugin="entity_cross_pollinator",
                        target=target,
                        payload={
                            "run_id": ts,
                            "trigger": "entity_pool_update",
                            "_depth": 0,
                            "seed_paths": [f"/__entity_pool_round_{rounds}"],
                        },
                    )
                )
            # de-duplicate follow-up tasks
            seen: set[str] = set()
            deduped: list[Task] = []
            for t in next_tasks:
                sig = f"{t.plugin}|{t.target}|{json.dumps(t.payload, sort_keys=True, ensure_ascii=True) if isinstance(t.payload, dict) else ''}"
                if sig in seen:
                    continue
                seen.add(sig)
                deduped.append(t)
            pending = queue_engine.rank(pending + deduped, findings=target_history)
            if adaptive_levels_enabled:
                prev_level = target_adaptive_level
                demote_reasons: list[str] = []
                if adaptive_demote_on_timeout and timeouts_this_round > 0:
                    demote_reasons.append(f"timeouts={timeouts_this_round}")
                if adaptive_demote_on_feedback and feedback_events_this_round > 0:
                    demote_reasons.append(f"feedback={feedback_events_this_round}")
                if demote_reasons:
                    target_adaptive_level = max(adaptive_level_min, target_adaptive_level - 1)
                    target_clean_round_streak = 0
                    reason = ",".join(demote_reasons)
                else:
                    target_clean_round_streak += 1
                    reason = "clean_round"
                    if (
                        target_clean_round_streak >= adaptive_escalate_after_clean_rounds
                        and target_adaptive_level < adaptive_level_max
                    ):
                        target_adaptive_level += 1
                        target_clean_round_streak = 0
                        reason = f"clean_rounds={adaptive_escalate_after_clean_rounds}"
                if target_adaptive_level != prev_level:
                    logger.info(
                        f"adaptive_level_change target={target} round={rounds} "
                        f"from={prev_level} to={target_adaptive_level} reason={reason}"
                    )
            logger.info(
                f"target_round_end target={target} "
                f"round={rounds} "
                f"level={target_adaptive_level} "
                f"recursion_depth={round_recursion_depth} "
                f"round_findings={len(batch)} "
                f"round_feedback_events={feedback_events_this_round} "
                f"round_timeouts={timeouts_this_round} "
                f"pending_next={len(pending)} "
                f"target_findings_total={len(target_history)}"
            )
        if processed_tasks >= max_tasks_per_target:
            logger.warning(
                f"target_task_budget_reached target={target} processed_tasks={processed_tasks} limit={max_tasks_per_target}"
            )
        logger.info(
            f"target_scan_completed target={target} "
            f"rounds={rounds} "
            f"processed_tasks={processed_tasks} "
            f"target_findings={len(target_history)}"
        )
        processed_tasks_total += processed_tasks

    if flushed_findings and storage:
        all_findings, reloaded_ok = _reload_findings_from_storage(
            storage,
            run_id=ts,
            current=all_findings,
            logger=logger,
        )
        if reloaded_ok:
            flushed_findings = False

    all_findings = dedupe_findings(all_findings)

    synthesized_findings: list[Finding] = []
    if "report_synthesis" in plugins:
        synth_plugin = plugins["report_synthesis"]
        serialized = serialize_findings(all_findings)
        if scope_manager and bool(getattr(scope_manager, "enabled", False)):
            try:
                known_endpoints = scope_manager.fetch_known_report_endpoints(timeout=int(runtime.get("timeout_seconds", 25)))
                serialized = scope_manager.suppress_probable_duplicates(serialized, known_endpoints)
            except Exception as err:
                logger.error(f"scope_duplicate_prevention_failed provider={scope_provider} err={err}")
        synth_jobs = []
        for target in targets:
            target_rows = [row for row in serialized if str(row.get("target", "")) == target]
            synth_jobs.append(
                synth_plugin.run(
                    Task(
                        plugin="report_synthesis",
                        target=target,
                        payload={
                            "run_id": ts,
                            "findings": target_rows,
                        },
                    ),
                    context,
                )
            )
        synth_groups = await asyncio.gather(*synth_jobs, return_exceptions=False)
        for grp in synth_groups:
            synthesized_findings.extend(grp)
        synthesized_findings = dedupe_findings(synthesized_findings)
        if synthesized_findings:
            all_findings.extend(synthesized_findings)
            await _route_alerts_from_batch(
                alert_router=alert_router,
                batch=synthesized_findings,
                run_id=ts,
                logger=logger,
                source="report_synthesis",
                triage_cfg=triage_cfg,
            )
            if storage:
                try:
                    storage.write_findings(run_id=ts, rows=serialize_findings(synthesized_findings))
                except Exception as err:
                    findings_storage_failed = True
                    logger.error(f"research_write_synthesized_findings_failed err={err}")

    packaged_findings: list[Finding] = []
    if "evidence_packager" in plugins:
        packager_plugin = plugins["evidence_packager"]
        package_jobs = []
        serialized_all = serialize_findings(all_findings)
        for target in targets:
            target_rows = [row for row in serialized_all if str(row.get("target", "")) == target]
            package_jobs.append(
                packager_plugin.run(
                    Task(
                        plugin="evidence_packager",
                        target=target,
                        payload={
                            "run_id": ts,
                            "findings": target_rows,
                        },
                    ),
                    context,
                )
            )
        package_groups = await asyncio.gather(*package_jobs, return_exceptions=False)
        for group in package_groups:
            packaged_findings.extend(group)
        packaged_findings = dedupe_findings(packaged_findings)
        if packaged_findings:
            _annotate_program_metadata(packaged_findings, program_by_target, programs_by_target)
            all_findings.extend(packaged_findings)
            if findings_flush_every > 0 and len(all_findings) >= findings_flush_every:
                if storage and not findings_storage_failed:
                    flushed_findings = True
                    logger.info(
                        f"research_findings_flush phase=packaged in_memory={len(all_findings)}"
                    )
                    all_findings = []
            await _route_alerts_from_batch(
                alert_router=alert_router,
                batch=packaged_findings,
                run_id=ts,
                logger=logger,
                source="evidence_packager",
                triage_cfg=triage_cfg,
            )
            if storage:
                try:
                    storage.write_findings(run_id=ts, rows=serialize_findings(packaged_findings))
                except Exception as err:
                    findings_storage_failed = True
                    logger.error(f"research_write_packaged_findings_failed err={err}")
            if discord.available:
                for finding in packaged_findings:
                    evidence = finding.evidence if isinstance(finding.evidence, dict) else {}
                    source_category = str(evidence.get("category", "")).strip()
                    confidence = float(evidence.get("confidence_score", 0) or 0)
                    report_path = str(evidence.get("report_path", "")).strip()
                    if source_category not in {"Potential_IDOR_Signal", "Broken_Object_Level_Authorization"}:
                        continue
                    if confidence <= 50:
                        continue
                    if report_path and report_path in notified_report_paths:
                        continue
                    if report_path:
                        notified_report_paths.add(report_path)
                    dedupe_key = report_path or f"{finding.target}|{source_category}|{finding.title}|{finding.severity}"
                    discord.route_finding_confirmed(
                        target=finding.target,
                        title=str(finding.title),
                        impact=str(evidence.get("impact", _finding_impact(finding))),
                        confidence=confidence,
                        endpoint=str(evidence.get("endpoint", "/")),
                        evidence_snippet=f"bundle={source_category} confidence={confidence}",
                        report_path=report_path or "pending_generation",
                        severity_level=str(finding.severity),
                        estimated_payout=_estimated_payout_for_severity(str(finding.severity)),
                        dedupe_key=dedupe_key,
                    )

    security_report_findings: list[Finding] = []
    if "security_report_builder" in plugins:
        report_plugin = plugins["security_report_builder"]
        report_jobs = []
        serialized_all = serialize_findings(all_findings)
        for target in targets:
            target_rows = [row for row in serialized_all if str(row.get("target", "")).strip() == str(target).strip()]
            report_jobs.append(
                report_plugin.run(
                    Task(
                        plugin="security_report_builder",
                        target=target,
                        payload={
                            "run_id": ts,
                            "findings": target_rows,
                        },
                    ),
                    context,
                )
            )
        report_groups = await asyncio.gather(*report_jobs, return_exceptions=False)
        for group in report_groups:
            security_report_findings.extend(group)
        security_report_findings = dedupe_findings(security_report_findings)
        if security_report_findings:
            all_findings.extend(security_report_findings)
            await _route_alerts_from_batch(
                alert_router=alert_router,
                batch=security_report_findings,
                run_id=ts,
                logger=logger,
                source="security_report_builder",
                triage_cfg=triage_cfg,
            )
            if storage:
                try:
                    storage.write_findings(run_id=ts, rows=serialize_findings(security_report_findings))
                except Exception as err:
                    findings_storage_failed = True
                    logger.error(f"research_write_security_report_findings_failed err={err}")

    if flushed_findings and storage:
        all_findings, reloaded_ok = _reload_findings_from_storage(
            storage,
            run_id=ts,
            current=all_findings,
            logger=logger,
        )
        if reloaded_ok:
            flushed_findings = False

    all_findings = dedupe_findings(all_findings)
    actionable_findings, review_findings = split_findings_for_triage(all_findings, triage_cfg=triage_cfg)
    rows = serialize_findings(all_findings)
    actionable_rows = serialize_findings(actionable_findings)
    review_rows = serialize_findings(review_findings)
    actionable_rows, review_rows, _validated_rows = await _run_shannon_validation_stage(
        run_id=ts,
        cfg=cfg,
        storage=storage,
        logger=logger,
        out_dir=out_dir,
        actionable_rows=actionable_rows,
        review_rows=review_rows,
    )
    persist_outputs(out_dir, f"{len(targets)}-targets", rows)
    persist_triage_outputs(
        out_dir,
        run_id=ts,
        actionable_rows=actionable_rows,
        review_rows=review_rows,
    )
    run_stats_dir = ensure_directory(out_dir / "runs" / ts, mode=0o755)
    (run_stats_dir / "run_stats.json").write_text(
        json.dumps(
            {
                "run_id": ts,
                "targets": targets,
                "processed_tasks": processed_tasks_total,
                "findings_total": len(rows),
                "actionable": len(actionable_rows),
                "review": len(review_rows),
                "validated": len(_validated_rows),
            },
            ensure_ascii=True,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    metrics_snapshot_path = run_stats_dir / "metrics" / f"metrics_{ts}.txt"
    if write_metrics_snapshot(metrics_snapshot_path):
        logger.info(f"metrics_snapshot_written path={metrics_snapshot_path}")
    generate_auto_poc(out_dir=out_dir, findings=all_findings, min_confidence=80.0)
    generate_research_artifacts(
        findings=all_findings,
        out_root=resolve_path("data/reports"),
        run_id=ts,
        min_confidence=85.0,
    )

    summary_rows: list[dict[str, Any]] = []
    for f in synthesized_findings + packaged_findings:
        meta = f.metadata if isinstance(f.metadata, dict) else {}
        ev = f.evidence if isinstance(f.evidence, dict) else {}
        report_path = str(meta.get("report_path", ev.get("report_path", "")))
        if not report_path:
            continue
        summary_rows.append(
            {
                "severity": f.severity,
                "plugin": str(meta.get("plugin_source", f.plugin)),
                "endpoint": str(meta.get("endpoint", ev.get("endpoint", ""))),
                "confidence": float(meta.get("confidence_score", meta.get("confidence", 0)) or 0),
                "report_path": report_path,
            }
        )
    if summary_rows:
        print_research_summary_table(summary_rows)

    logger.info(
        f"research_pipeline_completed run_id={ts} "
        f"findings={len(rows)} "
        f"actionable={len(actionable_rows)} "
        f"review_queue={len(review_rows)} "
        f"validated={len(_validated_rows)}"
    )
    await _shutdown_clients()
    return 0


def main() -> int:
    _force_stdio_unbuffered()
    args = parse_args()
    _stderr_echo(f"research_pipeline_starting config={args.config} out_dir={args.out_dir}")
    uvloop_enabled = install_uvloop_if_available()
    _stderr_echo(
        f"uvloop_install_result enabled={int(uvloop_enabled)} policy={type(asyncio.get_event_loop_policy()).__name__}"
    )
    try:
        return asyncio.run(run_async(args))
    except KeyboardInterrupt:
        _stderr_echo("research_pipeline_interrupted signal=KeyboardInterrupt")
        return 130
    except Exception as err:
        _stderr_echo(f"fatal_startup_or_runtime_error type={type(err).__name__} err={err}")
        traceback.print_exc(file=sys.stderr)
        with contextlib.suppress(Exception):
            sys.stderr.flush()
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
