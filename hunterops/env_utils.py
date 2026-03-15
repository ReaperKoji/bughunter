from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Any

LINUX_BIN_DIR = Path("/usr/local/bin")
REQUIRED_BINARIES = ("interactsh-client", "subfinder", "httpx", "naabu", "nuclei")

# Static dependency hints for plugins that do not declare shell commands directly.
STATIC_PLUGIN_DEPENDENCIES: dict[str, set[str]] = {
    "oob_engine": {"interactsh-client"},
    "recon": {"subfinder"},
    "scan": {"nuclei"},
    "surface_massive": {"subfinder", "naabu"},
}


def _command_tool(command: str) -> str:
    raw = str(command or "").strip()
    if not raw:
        return ""
    return raw.split()[0].strip()


def resolve_binary(tool: str) -> str | None:
    name = str(tool or "").strip()
    if not name:
        return None
    preferred = LINUX_BIN_DIR / name
    if preferred.exists() and os.access(preferred, os.X_OK):
        return str(preferred)
    return shutil.which(name)


def resolve_binary_for_plugin(tool: str) -> str | None:
    name = str(tool or "").strip()
    if not name:
        return None
    return shutil.which(name)


def collect_plugin_binary_dependencies(config: dict[str, Any]) -> dict[str, set[str]]:
    deps: dict[str, set[str]] = {k: set(v) for k, v in STATIC_PLUGIN_DEPENDENCIES.items()}
    modules = config.get("modules", {}) if isinstance(config.get("modules"), dict) else {}
    for module_name, module_cfg in modules.items():
        module_key = str(module_name).strip().lower()
        if not isinstance(module_cfg, dict):
            continue
        commands = module_cfg.get("commands", [])
        if not isinstance(commands, list):
            continue
        for cmd in commands:
            tool = _command_tool(str(cmd))
            if tool:
                deps.setdefault(module_key, set()).add(tool)
    return deps


def check_binaries(binaries: list[str] | tuple[str, ...] | set[str]) -> dict[str, bool]:
    return {str(b): bool(resolve_binary_for_plugin(str(b))) for b in binaries}


def evaluate_runtime_dependencies(config: dict[str, Any], requested_plugins: list[str]) -> dict[str, Any]:
    requested = [str(x).strip().lower() for x in requested_plugins if str(x).strip()]
    plugin_deps = collect_plugin_binary_dependencies(config)
    disabled: list[str] = []
    plugin_missing: dict[str, list[str]] = {}

    for plugin in requested:
        needs = sorted(list(plugin_deps.get(plugin, set())))
        if not needs:
            continue
        missing = [tool for tool in needs if not resolve_binary_for_plugin(tool)]
        if missing:
            disabled.append(plugin)
            plugin_missing[plugin] = missing

    required_status = check_binaries(REQUIRED_BINARIES)
    required_missing = sorted([tool for tool, ok in required_status.items() if not ok])

    critical_warnings: list[str] = []
    for tool in required_missing:
        critical_warnings.append(f"missing_required_binary tool={tool} expected={LINUX_BIN_DIR / tool}")
    for plugin, missing in plugin_missing.items():
        critical_warnings.append(f"plugin_disabled_missing_dependency plugin={plugin} missing={','.join(missing)}")

    return {
        "required_status": required_status,
        "required_missing": required_missing,
        "disabled_plugins": sorted(list(set(disabled))),
        "plugin_missing": plugin_missing,
        "critical_warnings": critical_warnings,
    }


def filter_enabled_plugins(requested_plugins: list[str], disabled_plugins: list[str]) -> list[str]:
    disabled = {str(x).strip().lower() for x in disabled_plugins if str(x).strip()}
    return [str(p).strip().lower() for p in requested_plugins if str(p).strip().lower() not in disabled]
