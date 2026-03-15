#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import yaml
from hunterops.env_utils import resolve_binary
from hunterops.runtime_paths import resolve_path
from hunterops.secrets import read_secret

REQUIRED_ENV = [
    "HUNTEROPS_USER_TOKEN",
    "HUNTEROPS_USER_COOKIE",
    "HUNTEROPS_USER_B_TOKEN",
    "HUNTEROPS_USER_B_COOKIE",
    "HUNTEROPS_ADMIN_TOKEN",
    "HUNTEROPS_ADMIN_COOKIE",
    "HUNTEROPS_POSTGRES_DSN",
]

REQUIRED_BINARIES = [
    "subfinder",
    "naabu",
    "nuclei",
    "interactsh-client",
    "amass",
    "assetfinder",
    "gau",
    "waybackurls",
    "katana",
    "hakrawler",
    "gospider",
    "ffuf",
    "httpx",
]



def _load_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}



def _load_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [x.strip() for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]



def _is_example_scope(host: str) -> bool:
    low = host.lower()
    return "example.com" in low or "replace" in low or "todo" in low



def main() -> None:
    parser = argparse.ArgumentParser(description="HunterOps production preflight check")
    parser.add_argument("--programs", default="config/programs.yaml")
    parser.add_argument("--targets", default="data/targets/in_scope_hosts.txt")
    parser.add_argument("--sessions", default="data/sessions.yaml")
    parser.add_argument("--submissions", default="data/findings/submissions.jsonl")
    parser.add_argument("--out", default="data/reports/preflight_real_setup.json")
    args = parser.parse_args()

    programs_cfg = _load_yaml(resolve_path(args.programs))
    sessions_cfg = _load_yaml(resolve_path(args.sessions))
    targets = _load_lines(resolve_path(args.targets))
    submissions = _load_lines(resolve_path(args.submissions))

    issues: list[str] = []
    warnings: list[str] = []

    programs = programs_cfg.get("programs", []) if isinstance(programs_cfg.get("programs", []), list) else []
    if not programs:
        issues.append("No programs configured in config/programs.yaml")
    else:
        for p in programs:
            in_scope = p.get("in_scope", []) if isinstance(p, dict) else []
            if not in_scope:
                issues.append(f"Program {p.get('name', 'unknown')} has empty in_scope")
                continue
            if any(_is_example_scope(str(x)) for x in in_scope):
                warnings.append(f"Program {p.get('name', 'unknown')} still uses example/TODO scope values")

    if not targets:
        issues.append("No targets in data/targets/in_scope_hosts.txt")
    elif any(_is_example_scope(x) for x in targets):
        warnings.append("Target list still contains example/TODO hosts")

    sessions = sessions_cfg.get("sessions", []) if isinstance(sessions_cfg.get("sessions", []), list) else []
    if len(sessions) < 2:
        warnings.append("Less than 2 sessions configured; multi-account coverage is weak")

    missing_env = [k for k in REQUIRED_ENV if not read_secret(k)]
    if missing_env:
        issues.append(f"Missing required env vars: {', '.join(missing_env)}")

    missing_bins = [b for b in REQUIRED_BINARIES if not resolve_binary(b)]
    if missing_bins:
        issues.append(f"Missing binaries: {', '.join(missing_bins)}")

    if not submissions:
        warnings.append("No submissions history found; feedback loop/calibration will be generic")

    status = "ok" if not issues else "blocked"
    result = {
        "status": status,
        "issues": issues,
        "warnings": warnings,
        "counts": {
            "programs": len(programs),
            "targets": len(targets),
            "sessions": len(sessions),
            "submissions": len(submissions),
            "missing_env": len(missing_env),
            "missing_binaries": len(missing_bins),
        },
    }

    out = resolve_path(args.out, prefer_existing=False)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")

    print(f"[preflight] status={status} out={out}")
    for i in issues:
        print(f"[issue] {i}")
    for w in warnings:
        print(f"[warn] {w}")

    raise SystemExit(0 if status == "ok" else 2)


if __name__ == "__main__":
    main()
