from __future__ import annotations

import fnmatch
import ipaddress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml
from hunterops.runtime_paths import resolve_path
from hunterops.secrets import read_secret


@dataclass
class ScopePolicy:
    include: list[str]
    exclude: list[str]
    kyc_required: bool = False
    notes: str = ""
    per_host_rpm: int | None = None
    per_target_rpm: int | None = None
    concurrency_per_host: int | None = None
    blocked_paths: list[str] = None  # type: ignore[assignment]
    allowed_hours: list[str] = None  # type: ignore[assignment]
    timezone: str = "UTC"
    allow_internal: bool = False
    allowed_modules: list[str] = None  # type: ignore[assignment]
    blocked_modules: list[str] = None  # type: ignore[assignment]
    allowed_plugins: list[str] = None  # type: ignore[assignment]
    blocked_plugins: list[str] = None  # type: ignore[assignment]
    required_headers: dict[str, str] = field(default_factory=dict)
    rules_of_engagement: str = ""


def _host_from_target(target: str) -> str:
    raw = str(target or "").strip()
    if not raw:
        return ""
    if "://" in raw:
        try:
            return str(urlparse(raw).hostname or "").strip().lower()
        except Exception:
            return ""
    return raw.lower()


def load_programs(path: str | Path) -> dict[str, Any]:
    resolved = resolve_path(path)
    if not resolved.exists():
        return {}
    return yaml.safe_load(resolved.read_text(encoding="utf-8")) or {}


def collect_scope(programs_data: dict[str, Any], program: str) -> ScopePolicy:
    include: list[str] = []
    exclude: list[str] = []
    kyc_required = False
    notes = ""
    per_host_rpm: int | None = None
    per_target_rpm: int | None = None
    concurrency_per_host: int | None = None
    blocked_paths: list[str] = []
    allowed_hours: list[str] = []
    timezone = "UTC"
    allow_internal = False
    allowed_modules: list[str] = []
    blocked_modules: list[str] = []
    allowed_plugins: list[str] = []
    blocked_plugins: list[str] = []
    required_headers: dict[str, str] = {}
    rules_of_engagement = ""

    for entry in programs_data.get("programs", []) or []:
        if program != "all" and entry.get("name") != program:
            continue
        include.extend(entry.get("in_scope", []) or [])
        exclude.extend(entry.get("out_of_scope", []) or [])
        if bool(entry.get("kyc_required", False)):
            kyc_required = True
        if entry.get("notes"):
            notes = str(entry.get("notes"))
        if entry.get("per_host_rpm") is not None:
            per_host_rpm = int(entry.get("per_host_rpm") or 0)
        if entry.get("per_target_rpm") is not None:
            per_target_rpm = int(entry.get("per_target_rpm") or 0)
        if entry.get("concurrency_per_host") is not None:
            concurrency_per_host = int(entry.get("concurrency_per_host") or 0)
        blocked_paths.extend(entry.get("blocked_paths", []) or [])
        allowed_hours.extend(entry.get("allowed_hours", []) or [])
        if entry.get("timezone"):
            timezone = str(entry.get("timezone")).strip() or timezone
        if entry.get("allow_internal") is not None:
            allow_internal = bool(entry.get("allow_internal"))
        allowed_modules.extend(entry.get("allowed_modules", []) or [])
        blocked_modules.extend(entry.get("blocked_modules", []) or [])
        allowed_plugins.extend(entry.get("allowed_plugins", []) or [])
        blocked_plugins.extend(entry.get("blocked_plugins", []) or [])
        if isinstance(entry.get("required_headers"), dict):
            for hk, hv in entry.get("required_headers", {}).items():
                key = str(hk).strip()
                if not key:
                    continue
                val = str(hv)
                if val.startswith("${") and val.endswith("}"):
                    env_key = val[2:-1].strip()
                    if env_key:
                        secret_val = read_secret(env_key)
                        if secret_val:
                            val = secret_val
                required_headers[key] = str(val)
        if entry.get("rules_of_engagement"):
            rules_of_engagement = str(entry.get("rules_of_engagement", "")).strip()

    return ScopePolicy(
        include=include,
        exclude=exclude,
        kyc_required=kyc_required,
        notes=notes,
        per_host_rpm=per_host_rpm,
        per_target_rpm=per_target_rpm,
        concurrency_per_host=concurrency_per_host,
        blocked_paths=blocked_paths,
        allowed_hours=allowed_hours,
        timezone=timezone,
        allow_internal=allow_internal,
        allowed_modules=allowed_modules,
        blocked_modules=blocked_modules,
        allowed_plugins=allowed_plugins,
        blocked_plugins=blocked_plugins,
        required_headers=required_headers,
        rules_of_engagement=rules_of_engagement,
    )


def in_scope(target: str, policy: ScopePolicy) -> bool:
    host = _host_from_target(target)
    if not host:
        return False
    if not policy.allow_internal and _is_internal_host(host):
        return False
    if not policy.include:
        return False
    included = any(fnmatch.fnmatch(host, pattern.lower()) for pattern in policy.include)
    excluded = any(fnmatch.fnmatch(host, pattern.lower()) for pattern in policy.exclude)
    return included and not excluded


def kyc_okay(policy: ScopePolicy) -> bool:
    if not policy.kyc_required:
        return True
    return str(__import__("os").environ.get("HUNTEROPS_KYC_VERIFIED", "")).strip() in {"1", "true", "yes"}


def _is_internal_host(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local
    except Exception:
        return host in {"localhost"} or host.endswith(".local")
