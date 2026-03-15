from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from hunterops.attack_chain.scope import ScopePolicy, collect_scope, in_scope, load_programs
from hunterops.url_utils import normalize_host


@dataclass
class ProgramPolicy:
    program_id: str
    scope: ScopePolicy


def load_program_data(path: str | Path) -> dict[str, Any]:
    return load_programs(path)


def resolve_program_for_target(target: str, programs_data: dict[str, Any]) -> ProgramPolicy | None:
    host = normalize_host(target)
    if not host:
        return None
    for entry in programs_data.get("programs", []) if isinstance(programs_data.get("programs", []), list) else []:
        name = str(entry.get("name", "")).strip()
        if not name:
            continue
        policy = collect_scope(programs_data, name)
        if in_scope(host, policy):
            return ProgramPolicy(program_id=name, scope=policy)
    return None


def build_host_policies(programs_data: dict[str, Any]) -> list[dict[str, Any]]:
    policies: list[dict[str, Any]] = []
    for entry in programs_data.get("programs", []) if isinstance(programs_data.get("programs", []), list) else []:
        name = str(entry.get("name", "")).strip()
        if not name:
            continue
        policy = collect_scope(programs_data, name)
        per_host_rpm = policy.per_host_rpm if policy.per_host_rpm is not None else 0
        per_target_rpm = policy.per_target_rpm if policy.per_target_rpm is not None else 0
        rate_candidates = [r for r in (per_host_rpm, per_target_rpm) if isinstance(r, int) and r > 0]
        rate_per_sec = min(rate_candidates) / 60.0 if rate_candidates else 0.0
        try:
            request_budget = int(entry.get("request_budget") or 0)
        except Exception:
            request_budget = 0
        max_inflight = int(policy.concurrency_per_host or 0)
        for pattern in policy.include or []:
            pat = str(pattern).strip().lower()
            if not pat:
                continue
            policies.append(
                {
                    "pattern": pat,
                    "program_id": name,
                    "rate_per_sec": rate_per_sec,
                    "max_inflight": max_inflight,
                    "blocked_paths": policy.blocked_paths or [],
                    "required_headers": policy.required_headers or {},
                    "request_budget": request_budget,
                }
            )
    return policies


def map_targets_to_programs(targets: list[str], programs_data: dict[str, Any]) -> dict[str, ProgramPolicy]:
    mapping: dict[str, ProgramPolicy] = {}
    for target in targets or []:
        policy = resolve_program_for_target(target, programs_data)
        if policy is None:
            continue
        mapping[str(target)] = policy
    return mapping
