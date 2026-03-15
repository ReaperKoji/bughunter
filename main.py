#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import hashlib
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from hunterops.config import get_runtime, load_config
from hunterops.async_runtime import install_uvloop_if_available
from hunterops.env_utils import evaluate_runtime_dependencies, filter_enabled_plugins
from hunterops.executor import TaskExecutor
from hunterops.http_client import (
    close_async_http_client,
    configure_http_pool,
    configure_global_http_limits,
    configure_host_policies,
    configure_scope_guard,
)
from hunterops.endpoint_cache import EndpointCache
from hunterops.intelligence import dedupe_findings, http_diff_score, load_feedback, serialize_findings, to_jsonl
from hunterops.logging_utils import setup_logging
from hunterops.plugin_loader import enabled_plugins, load_plugins
from hunterops.program_packs import load_program_packs, resolve_pack
from hunterops.program_registry import build_host_policies, load_program_data, map_targets_to_programs, resolve_program_for_target
from hunterops.reporting import export_csv, export_dashboard, export_html, export_json, export_markdown, write_json
from hunterops.retention import cleanup_old_files
from hunterops.runtime_paths import ensure_directory, resolve_path
from hunterops.storage import PostgresStorage
from hunterops.task_store import PostgresTaskStore, SQLiteTaskStore
from hunterops.types import Finding, Task
from hunterops.metrics import enable_metrics, write_metrics_snapshot
from hunterops.target_governance import apply_target_governance
from hunterops.config_validation import validate_attack_pipeline_modules, validate_findings_schema
from hunterops.scope_authorization import load_authorized_scope, validate_scope_signature
from hunterops.url_utils import normalize_host


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="HunterOps Professional CLI")
    parser.add_argument("--config", default="config/engine.yaml")
    parser.add_argument("--target", default="")
    parser.add_argument("--targets-file", default="data/targets/in_scope_hosts.txt")
    parser.add_argument("--full-scan", action="store_true")
    parser.add_argument("--plugins", default="")
    parser.add_argument("--out-dir", default="data/reports/engine")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--resume-run", default="")
    parser.add_argument("--run-id", default="")
    return parser.parse_args()


def collect_targets(args: argparse.Namespace) -> list[str]:
    if args.target:
        return [args.target.strip()]
    path = resolve_path(args.targets_file)
    if not path.exists():
        return []
    return [x.strip() for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]


def env_truthy(name: str, default: bool = False) -> bool:
    raw = os.getenv(name, "").strip().lower()
    if not raw:
        return default
    return raw in {"1", "true", "yes", "y", "on"}


def resolve_plugins(config: dict[str, Any], runtime: dict[str, Any], args: argparse.Namespace) -> list[str]:
    if args.plugins:
        return [x.strip().lower() for x in args.plugins.split(",") if x.strip()]
    names = enabled_plugins(config)
    if args.full_scan:
        return names
    plugin_profile = str(runtime.get("plugin_profile", "")).strip().lower()
    plugin_names: list[str]
    if plugin_profile:
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
    else:
        default_plugins = runtime.get("default_plugins", []) if isinstance(runtime.get("default_plugins", []), list) else []
        if default_plugins:
            allow = {str(x).strip().lower() for x in default_plugins if str(x).strip()}
            plugin_names = [n for n in names if n in allow]
        else:
            default_set = {
                "recon",
                "fingerprint",
                "scan",
                "cors",
                "takeover",
                "playwright_capture",
                "business_logic_sniper",
                "race_condition_turbo",
            }
            plugin_names = [n for n in names if n in default_set]
    if not plugin_names:
        plugin_names = names
    if bool(runtime.get("attack_chain_seed_enabled", True)) and "attack_chain_seed" not in plugin_names:
        plugin_names.append("attack_chain_seed")
    return plugin_names


def build_tasks(
    targets: list[str], plugin_names: list[str], include_platform_sync: bool, packs: list[dict[str, Any]]
) -> list[Task]:
    tasks: list[Task] = []
    for t in targets:
        pack = resolve_pack(t, packs)
        for p in plugin_names:
            if p == "attack_chain_seed":
                continue
            tasks.append(Task(plugin=p, target=t, payload={"program_pack": pack or {}}))
    if include_platform_sync and "platform_sync" in plugin_names:
        tasks.append(Task(plugin="platform_sync", target="__platforms__"))
    return tasks


def baseline_compare(rows: list[dict[str, Any]], baseline_path: Path) -> dict[str, Any]:
    if not baseline_path.exists():
        return {"baseline_exists": False, "diffs": []}
    import json

    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    old = baseline.get("findings", [])
    old_map = {f"{x.get('plugin')}|{x.get('target')}|{x.get('title')}": x for x in old}
    diffs: list[dict[str, Any]] = []
    for row in rows:
        key = f"{row.get('plugin')}|{row.get('target')}|{row.get('title')}"
        old_row = old_map.get(key)
        if not old_row:
            diffs.append({"type": "new", "key": key})
            continue
        baseline_resp = {
            "status": old_row.get("metadata", {}).get("status", 0),
            "length": old_row.get("metadata", {}).get("length", 0),
            "json_keys": old_row.get("metadata", {}).get("json_keys", []),
        }
        current_resp = {
            "status": row.get("metadata", {}).get("status", 0),
            "length": row.get("metadata", {}).get("length", 0),
            "json_keys": row.get("metadata", {}).get("json_keys", []),
        }
        diff = http_diff_score(baseline_resp, current_resp)
        if diff["anomaly_score"] > 0:
            diffs.append({"type": "changed", "key": key, "diff": diff})
    return {"baseline_exists": True, "diffs": diffs}


async def run_async(args: argparse.Namespace) -> int:
    config_path = resolve_path(args.config)
    config = load_config(config_path)
    runtime = get_runtime(config)
    pool_cfg = config.get("http_pool", {}) if isinstance(config.get("http_pool"), dict) else {}
    configure_http_pool(
        max_connections=int(pool_cfg.get("max_connections", max(50, int(runtime.get("concurrency", 8)) * 12))),
        max_keepalive_connections=int(pool_cfg.get("max_keepalive_connections", max(20, int(runtime.get("concurrency", 8)) * 4))),
        keepalive_expiry=float(pool_cfg.get("keepalive_expiry", 10.0)),
        verify_ssl=bool(pool_cfg.get("verify_ssl", True)),
        http2=bool(pool_cfg.get("http2", False)),
        retries=int(pool_cfg.get("retries", 0)),
        linux_socket_tuning=bool(pool_cfg.get("linux_socket_tuning", True)),
    )
    configure_global_http_limits(
        rate_per_sec=float(runtime.get("global_http_rate_limit_per_sec", runtime.get("rate_limit_per_sec", 10.0)) or 10.0),
        max_inflight=int(runtime.get("global_http_max_inflight", max(4, int(runtime.get("concurrency", 8)) * 2)) or 10),
    )
    ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    resume_run = str(args.resume_run or "").strip()
    run_id = resume_run or str(args.run_id or "").strip() or ts
    out_dir = ensure_directory(resolve_path(args.out_dir), mode=0o755)
    logger = setup_logging(out_dir / f"engine_{run_id}.jsonl", verbose=args.verbose)
    config_hash = hashlib.sha256(config_path.read_bytes()).hexdigest() if config_path.exists() else ""
    metrics_cfg = config.get("metrics", {}) if isinstance(config.get("metrics", {}), dict) else {}
    metrics_enabled = bool(metrics_cfg.get("enabled", False))
    metrics_port = int(metrics_cfg.get("port", int(os.getenv("HUNTEROPS_METRICS_PORT", "9108") or 9108)) or 9108)
    if metrics_enabled or os.getenv("HUNTEROPS_METRICS_PORT"):
        enable_metrics(metrics_port)

    if bool(runtime.get("config_validation_enabled", True)):
        attack_cfg_path = resolve_path(str(runtime.get("attack_chain_config", "attack_pipeline.yaml")))
        spec_path = resolve_path(str(runtime.get("modules_spec_path", "modules_spec.json")))
        validation_errors = validate_attack_pipeline_modules(attack_cfg_path, spec_path)
        for err in validation_errors:
            logger.warning(f"config_validation_warning {err}")
        if validation_errors and bool(runtime.get("config_validation_strict", False)):
            logger.error("config_validation_failed")
            await close_async_http_client()
            return 6

    targets = collect_targets(args)
    if not targets:
        logger.error("No targets provided.")
        await close_async_http_client()
        return 2
    targets = apply_target_governance(
        targets,
        allow_patterns=runtime.get("target_allowlist_patterns", []) if isinstance(runtime.get("target_allowlist_patterns", []), list) else [],
        deny_patterns=runtime.get("target_denylist_patterns", []) if isinstance(runtime.get("target_denylist_patterns", []), list) else [],
        priority_patterns=runtime.get("target_priority_patterns", []) if isinstance(runtime.get("target_priority_patterns", []), list) else [],
        logger=logger,
    )
    if not targets:
        logger.error("No targets after governance filter.")
        await close_async_http_client()
        return 2

    programs_path = resolve_path(str(runtime.get("programs_file", "config/programs.yaml")))
    programs_data = load_program_data(programs_path) if programs_path.exists() else {}
    program_policy_map = map_targets_to_programs(targets, programs_data)
    host_policies = build_host_policies(programs_data)
    configure_host_policies(host_policies)
    if program_policy_map:
        policy_rps_values: list[float] = []
        for policy in program_policy_map.values():
            scope = getattr(policy, "scope", None)
            per_host_rpm = getattr(scope, "per_host_rpm", None) if scope else None
            per_target_rpm = getattr(scope, "per_target_rpm", None) if scope else None
            for rpm in (per_host_rpm, per_target_rpm):
                try:
                    rpm_val = float(rpm) if rpm is not None else 0.0
                except Exception:
                    rpm_val = 0.0
                if rpm_val > 0:
                    policy_rps_values.append(rpm_val / 60.0)
        if policy_rps_values:
            program_limit_rps = min(policy_rps_values)
            current_rps = float(runtime.get("rate_limit_per_sec", 10.0) or 10.0)
            if current_rps > program_limit_rps:
                runtime["rate_limit_per_sec"] = program_limit_rps
            global_rps = float(runtime.get("global_http_rate_limit_per_sec", program_limit_rps) or program_limit_rps)
            if global_rps > program_limit_rps:
                runtime["global_http_rate_limit_per_sec"] = program_limit_rps
                configure_global_http_limits(
                    rate_per_sec=float(runtime.get("global_http_rate_limit_per_sec", program_limit_rps)),
                    max_inflight=int(runtime.get("global_http_max_inflight", max(4, int(runtime.get("concurrency", 8)) * 2)) or 10),
                )
                logger.warning(
                    "rate_limit_clamped_by_program_policy "
                    f"global_rps={float(runtime.get('global_http_rate_limit_per_sec', program_limit_rps))} "
                    f"runtime_rps={float(runtime.get('rate_limit_per_sec', program_limit_rps))}"
                )
    scope_patterns: set[str] = set()
    scope_doc = load_authorized_scope()
    if scope_doc and validate_scope_signature(scope_doc):
        scope_patterns.update([str(x).strip() for x in scope_doc.get("targets", []) if str(x).strip()])
    auth_env = os.getenv("AUTHORIZED_TARGETS", "").strip()
    if auth_env:
        scope_patterns.update([x.strip() for x in auth_env.split(",") if x.strip()])
    allowlist_patterns = runtime.get("scope_allowlist_patterns", []) if isinstance(runtime.get("scope_allowlist_patterns", []), list) else []
    denylist_patterns = runtime.get("target_denylist_patterns", []) if isinstance(runtime.get("target_denylist_patterns", []), list) else []
    scope_patterns.update([str(x).strip() for x in runtime.get("target_allowlist_patterns", []) if str(x).strip()])
    for policy in host_policies:
        scope_patterns.add(str(policy.get("pattern", "")).strip())
    for t in targets:
        host = normalize_host(t)
        if host:
            scope_patterns.add(host)
    configure_scope_guard(
        enabled=bool(runtime.get("scope_enforce_http", True)),
        patterns=sorted([p for p in scope_patterns if p]),
        allowlist=[str(p).strip() for p in allowlist_patterns if str(p).strip()],
        denylist=[str(p).strip() for p in denylist_patterns if str(p).strip()],
    )
    if bool(runtime.get("scope_enforce_http", True)) and not scope_patterns:
        logger.warning("scope_guard_enabled_but_no_patterns")

    plugin_names = resolve_plugins(config, runtime, args)
    allowed_plugins = runtime.get("allowed_plugins", []) if isinstance(runtime.get("allowed_plugins", []), list) else []
    blocked_plugins = runtime.get("blocked_plugins", []) if isinstance(runtime.get("blocked_plugins", []), list) else []
    if allowed_plugins:
        allowed_set = {str(x).strip().lower() for x in allowed_plugins if str(x).strip()}
        plugin_names = [p for p in plugin_names if p in allowed_set]
    if blocked_plugins:
        blocked_set = {str(x).strip().lower() for x in blocked_plugins if str(x).strip()}
        plugin_names = [p for p in plugin_names if p not in blocked_set]
    dep_report = evaluate_runtime_dependencies(config, plugin_names)
    for msg in dep_report["critical_warnings"]:
        logger.critical(msg)
    plugin_names = filter_enabled_plugins(plugin_names, dep_report["disabled_plugins"])
    if not plugin_names:
        logger.error("No runnable plugins after dependency checks.")
        await close_async_http_client()
        return 5
    plugins = load_plugins(plugin_names)
    packs = load_program_packs(resolve_path(config.get("program_packs", {}).get("file", "config/program_packs.yaml")))
    feedback = load_feedback(resolve_path(config.get("feedback", {}).get("file", "data/processed/feedback_weights.json")))
    pg_cfg = config.get("storage", {}).get("postgres", {})
    pg_enabled = bool(pg_cfg.get("enabled", False))
    dsn_env = str(pg_cfg.get("dsn_env", "HUNTEROPS_POSTGRES_DSN"))
    dsn = os.getenv(dsn_env, "")
    db_optional = os.getenv("HUNTEROPS_DB_OPTIONAL", "0") == "1"
    if pg_enabled and not dsn and not db_optional:
        logger.error(f"postgres enabled but missing env {dsn_env}")
        await close_async_http_client()
        return 3
    storage = PostgresStorage(dsn=dsn, enabled=bool(pg_enabled and dsn)) if dsn else None
    findings_retention_hours = int(runtime.get("findings_retention_hours", 0) or 0)
    if storage and findings_retention_hours > 0:
        try:
            removed = storage.purge_findings_older_than(findings_retention_hours)
            if removed:
                logger.info(f"findings_retention_cleanup removed={removed}")
        except Exception as err:
            logger.warning(f"findings_retention_cleanup_failed err={err}")
    evidence_retention_hours = int(runtime.get("evidence_retention_hours", 0) or 0)
    if evidence_retention_hours > 0:
        cleanup_old_files(resolve_path("data/evidence"), evidence_retention_hours * 3600, logger.info)
    reports_retention_hours = int(runtime.get("reports_retention_hours", 0) or 0)
    if reports_retention_hours > 0:
        cleanup_old_files(resolve_path("data/reports"), reports_retention_hours * 3600, logger.info)
    persist_tasks = bool(runtime.get("persist_tasks", True))
    task_store_backend = str(runtime.get("task_store_backend", "auto")).strip().lower()
    task_store_path = resolve_path(str(runtime.get("task_store_path", "data/processed/task_queue.db")))
    task_store = None
    if persist_tasks:
        if task_store_backend in {"postgres", "auto"} and storage and bool(storage.enabled):
            task_store = PostgresTaskStore(storage)
        elif task_store_backend in {"sqlite", "auto"}:
            task_store = SQLiteTaskStore(task_store_path)
        else:
            logger.warning("task_store_disabled_no_backend")
            task_store = None
    endpoint_cache_enabled = bool(runtime.get("endpoint_cache_enabled", True)) and not env_truthy("HUNTEROPS_DISABLE_ENDPOINT_CACHE", False)
    endpoint_cache_ttl_hours = float(runtime.get("endpoint_cache_ttl_hours", 24.0) or 0.0)
    endpoint_cache_ttl_seconds = max(0, int(endpoint_cache_ttl_hours * 3600))
    endpoint_cache_max_entries = int(runtime.get("endpoint_cache_max_entries", 50000) or 50000)
    if storage and endpoint_cache_enabled and endpoint_cache_ttl_seconds > 0:
        try:
            storage.ensure_research_schema()
        except Exception:
            logger.warning("endpoint_cache_schema_init_failed")
    endpoint_cache = EndpointCache(
        storage=storage,
        enabled=endpoint_cache_enabled,
        ttl_seconds=endpoint_cache_ttl_seconds,
        max_entries=endpoint_cache_max_entries,
    )
    context = {
        "config": config,
        "runtime": runtime,
        "logger": logger,
        "storage": storage,
        "endpoint_cache": endpoint_cache,
        "run_id": run_id,
        "feedback": feedback,
        "task_store": task_store,
        "program_policies": program_policy_map,
    }

    tasks: list[Task] = []
    if resume_run:
        if not task_store:
            logger.error("resume_requested_but_task_store_unavailable")
            await close_async_http_client()
            return 7
        task_store.reset_in_progress(run_id)
        tasks = task_store.list_pending_tasks(run_id)
        if tasks:
            tasks = [t for t in tasks if t.plugin in plugin_names]
        logger.info(f"resuming execution run_id={run_id} pending_tasks={len(tasks)} plugins={len(plugin_names)}")
    else:
        tasks = build_tasks(targets, plugin_names, include_platform_sync=True, packs=packs)
        logger.info(f"starting execution targets={len(targets)} plugins={len(plugin_names)} tasks={len(tasks)}")
    if resume_run and not tasks:
        logger.warning(f"resume_requested_but_no_pending_tasks run_id={run_id}")
        await close_async_http_client()
        return 0
    for task in tasks:
        if task.target not in program_policy_map:
            policy = resolve_program_for_target(task.target, programs_data)
            if policy is not None:
                program_policy_map[task.target] = policy
    write_json(
        out_dir / "run_audit.json",
        {
            "run_id": run_id,
            "started_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "config_file": args.config,
            "config_hash_sha256": config_hash,
            "targets_count": len(targets),
            "plugins": plugin_names,
            "resume": bool(resume_run),
        },
    )

    if args.dry_run:
        logger.info(f"dry_run enabled run_id={run_id} targets={len(targets)} plugins={len(plugin_names)} tasks={len(tasks)}")
        await close_async_http_client()
        return 0

    executor = TaskExecutor(
        plugins=plugins,
        context=context,
        logger=logger,
        endpoint_cache=endpoint_cache,
        storage=storage,
        run_id=run_id,
        feedback=feedback,
        task_store=task_store,
    )
    findings = await executor.run(tasks)
    if executor.flushed_any and storage:
        if findings:
            rows_remaining = serialize_findings(findings, feedback=feedback)
            storage.write_findings(run_id=run_id, rows=rows_remaining)
        stored_rows = storage.list_findings(run_id=run_id)
        findings = [
            Finding(
                plugin=row.get("plugin", ""),
                target=row.get("target", ""),
                category=row.get("category", ""),
                severity=row.get("severity", ""),
                title=row.get("title", ""),
                evidence=row.get("evidence", {}) if isinstance(row.get("evidence", {}), dict) else {},
                metadata=row.get("metadata", {}) if isinstance(row.get("metadata", {}), dict) else {},
            )
            for row in stored_rows
            if isinstance(row, dict)
        ]
    findings = dedupe_findings(findings)
    rows = serialize_findings(findings, feedback=feedback)

    if bool(runtime.get("config_validation_enabled", True)):
        schema_path = resolve_path(str(runtime.get("findings_schema_path", "findings.schema.json")))
        schema_errors = validate_findings_schema(rows, schema_path)
        for err in schema_errors:
            logger.warning(f"findings_schema_warning {err}")
        if schema_errors and bool(runtime.get("findings_validation_strict", runtime.get("config_validation_strict", False))):
            logger.error("findings_schema_validation_failed")
            await close_async_http_client()
            return 8

    label = args.target if args.target else f"{len(targets)}-targets"
    export_json(out_dir / "findings.json", rows)
    export_csv(out_dir / "findings.csv", rows)
    export_markdown(out_dir / "findings.md", rows, label)
    export_html(out_dir / "findings.html", rows, label)
    export_dashboard(out_dir / "dashboard.html", rows)
    (out_dir / "findings.jsonl").write_text(to_jsonl(rows), encoding="utf-8")

    if storage and not executor.flushed_any:
        try:
            storage.write_findings(run_id=run_id, rows=rows)
            logger.info("postgres_write=ok")
        except Exception as err:
            logger.error(f"postgres_write=failed err={err}")
            if not db_optional:
                await close_async_http_client()
                return 4

    baseline = baseline_compare(rows, out_dir / "baseline.json")
    write_json(out_dir / "baseline_diff.json", baseline)
    write_json(out_dir / "baseline.json", {"generated_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z"), "findings": rows})
    write_json(out_dir / "metrics.json", {"plugin_metrics": executor.summarize_metrics()})
    metrics_snapshot_path = out_dir / "metrics" / f"metrics_{run_id}.txt"
    if write_metrics_snapshot(metrics_snapshot_path):
        logger.info(f"metrics_snapshot_written path={metrics_snapshot_path}")

    logger.info(f"completed findings={len(rows)}")
    if baseline.get("diffs"):
        logger.info(f"baseline_diffs={len(baseline['diffs'])}")
    write_json(
        out_dir / "run_audit.json",
        {
            "run_id": run_id,
            "completed_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "config_file": args.config,
            "config_hash_sha256": config_hash,
            "targets_count": len(targets),
            "plugins": plugin_names,
            "findings_count": len(rows),
        },
    )
    await close_async_http_client()
    return 0


def main() -> int:
    install_uvloop_if_available()
    args = parse_args()
    try:
        return asyncio.run(run_async(args))
    except KeyboardInterrupt:
        return 130
    except Exception as err:
        # global fail-safe
        print(f"[fatal] unhandled exception: {err}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
