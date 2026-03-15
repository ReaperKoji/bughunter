from __future__ import annotations

import asyncio
from typing import Any
from urllib.parse import urlparse

from hunterops.attack_chain import ChainOrchestrator, Target, load_attack_pipeline
from hunterops.attack_chain.scope import collect_scope, in_scope, load_programs
from hunterops.plugin_base import Plugin
from hunterops.runtime_paths import ensure_directory, resolve_path
from hunterops.rules_engine import check_automation_allowed
from hunterops.scope_authorization import authorize_targets, load_authorized_scope
from hunterops.types import Finding, Task
from hunterops.url_utils import normalize_url

_FILE_LOCK = asyncio.Lock()


def _normalize_url(raw: str, target: str) -> str:
    value = str(raw or "").strip()
    if not value:
        return ""
    if value.startswith("http://") or value.startswith("https://"):
        return normalize_url(value)
    if value.startswith("/"):
        return normalize_url(f"https://{target}{value}")
    return normalize_url(f"https://{target}/{value}")


def _resolve_program_for_target(target: str) -> str:
    programs = load_programs("config/programs.yaml")
    host = str(urlparse(f"https://{target}").hostname or target).strip().lower()
    for entry in programs.get("programs", []) if isinstance(programs.get("programs", []), list) else []:
        name = str(entry.get("name", "")).strip()
        if not name:
            continue
        policy = collect_scope(programs, name)
        if in_scope(host, policy):
            return name
    return ""


class PluginImpl(Plugin):
    name = "attack_chain_seed"

    async def run(self, task: Task, context: dict[str, Any]) -> list[Finding]:
        cfg = context.get("config", {}).get("modules", {}).get(self.name, {})
        payload = task.payload if isinstance(task.payload, dict) else {}
        raw_eps = (
            payload.get("endpoints")
            or payload.get("seed_paths")
            or payload.get("known_endpoints")
            or payload.get("paths")
            or []
        )
        if not isinstance(raw_eps, list) or not raw_eps:
            return []
        max_endpoints = int(cfg.get("max_endpoints", 120) or 120)
        program_id = str(payload.get("program_id", "") or payload.get("program", "")).strip()
        if not program_id:
            program_id = _resolve_program_for_target(task.target)

        urls: list[str] = []
        seen: set[str] = set()
        for ep in raw_eps:
            url = _normalize_url(str(ep), task.target)
            if not url or url in seen:
                continue
            seen.add(url)
            urls.append(url)
            if len(urls) >= max_endpoints:
                break
        if not urls:
            return []

        output_file = str(cfg.get("output_file", "data/targets/attack_chain_discovered.txt")).strip()
        path = resolve_path(output_file, prefer_existing=False)
        ensure_directory(path.parent)
        lines = [(f"{program_id}::{url}" if program_id else url) for url in urls]

        async with _FILE_LOCK:
            existing: set[str] = set()
            if path.exists():
                try:
                    existing = {x.strip() for x in path.read_text(encoding="utf-8").splitlines() if x.strip()}
                except Exception:
                    existing = set()
            new_lines = [line for line in lines if line not in existing]
            if new_lines:
                with path.open("a", encoding="utf-8") as f:
                    for line in new_lines:
                        f.write(line + "\n")

        auto_run = bool(cfg.get("auto_run", False)) or str(context.get("runtime", {}).get("attack_chain_auto_run", "")).strip().lower() in {"1", "true", "yes"}
        max_auto = int(cfg.get("max_auto_run", 0) or 0)
        auto_run_reason = ""
        ran = 0
        auto_requested = bool(auto_run and max_auto > 0)
        auto_run_config = ""
        if auto_requested:
            chain_cfg_path = str(
                cfg.get("attack_chain_config")
                or context.get("runtime", {}).get("attack_chain_config", "attack_pipeline.yaml")
                or "attack_pipeline.yaml"
            ).strip()
            auto_run_config = chain_cfg_path
            require_scope = bool(cfg.get("auto_run_require_scope", True))
            require_program = bool(cfg.get("auto_run_require_program", True))
            if require_scope:
                scope_doc = load_authorized_scope()
                ok, unauthorized = authorize_targets(urls[:max_auto], scope_doc)
                if not ok:
                    auto_run_reason = "unauthorized_targets"
            if not auto_run_reason and require_program and not program_id:
                auto_run_reason = "missing_program_id"
            if not auto_run_reason and program_id:
                programs = load_programs("config/programs.yaml")
                policy = collect_scope(programs, program_id)
                decision = check_automation_allowed(policy.rules_of_engagement)
                if decision.manual_only:
                    auto_run_reason = "automation_not_allowed"
            if not auto_run_reason:
                try:
                    chain_cfg = load_attack_pipeline(chain_cfg_path)
                    orchestrator = ChainOrchestrator(chain_cfg)
                    if require_program and orchestrator.real_mode and not program_id:
                        auto_run_reason = "missing_program_id"
                    else:
                        targets = [
                            Target(target_id=f"seed-{idx:04d}", url=url, program_id=program_id or "all")
                            for idx, url in enumerate(urls[:max_auto])
                        ]
                        await orchestrator.run_targets(targets)
                        ran = len(targets)
                except Exception as exc:
                    auto_run_reason = f"auto_run_failed:{type(exc).__name__}"

        return [
            Finding(
                plugin=self.name,
                target=task.target,
                category="attack_chain_seed",
                severity="info",
                title=f"Seeded {len(urls)} endpoints for attack_chain",
                evidence={
                    "seed_file": str(path),
                    "seeded": len(urls),
                    "auto_run_requested": auto_requested,
                    "auto_run": ran,
                    "auto_run_reason": auto_run_reason,
                    "auto_run_config": auto_run_config,
                },
                metadata={"novelty": 60, "confidence": 70, "impact": 35, "program": program_id},
            )
        ]
