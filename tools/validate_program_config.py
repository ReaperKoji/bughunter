#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Any

import yaml

from hunterops.rules_engine import check_automation_allowed
from hunterops.secrets import read_secret

_TIME_WINDOW = re.compile(r"^\d{2}:\d{2}-\d{2}:\d{2}$")


def _warn(msg: str) -> None:
    print(f"WARN: {msg}")


def _error(msg: str) -> None:
    print(f"ERROR: {msg}")


def _is_positive_int(value: Any) -> bool:
    try:
        return int(value) > 0
    except Exception:
        return False


def _validate_headers(program: dict[str, Any], errors: list[str], warnings: list[str]) -> None:
    headers = program.get("required_headers")
    if headers is None:
        return
    if not isinstance(headers, dict):
        errors.append(f"{program.get('name','<unknown>')}: required_headers must be a mapping")
        return
    for key, value in headers.items():
        if not key or not str(key).strip():
            errors.append(f"{program.get('name','<unknown>')}: header key empty")
        if value is None or str(value).strip() == "":
            errors.append(f"{program.get('name','<unknown>')}: header '{key}' value empty")
            continue
        raw = str(value)
        if raw.startswith("${") and raw.endswith("}"):
            env_name = raw[2:-1]
            if not read_secret(env_name):
                warnings.append(f"{program.get('name','<unknown>')}: env var '{env_name}' for header '{key}' not set")


def _validate_hours(program: dict[str, Any], errors: list[str]) -> None:
    hours = program.get("allowed_hours")
    if hours is None:
        return
    if not isinstance(hours, list):
        errors.append(f"{program.get('name','<unknown>')}: allowed_hours must be list")
        return
    for item in hours:
        if not isinstance(item, str) or not _TIME_WINDOW.match(item):
            errors.append(f"{program.get('name','<unknown>')}: invalid allowed_hours entry '{item}'")


def _validate_rules(program: dict[str, Any], warnings: list[str]) -> None:
    roe = program.get("rules_of_engagement") or program.get("rules_text") or ""
    if not roe:
        warnings.append(f"{program.get('name','<unknown>')}: rules_of_engagement missing (RoE not validated)")
    decision = check_automation_allowed(str(roe))
    if decision.manual_only:
        warnings.append(f"{program.get('name','<unknown>')}: automation not allowed by RoE ({decision.reason})")


def validate_programs(path: Path) -> int:
    errors: list[str] = []
    warnings: list[str] = []
    data = yaml.safe_load(path.read_text(encoding="utf-8")) if path.exists() else {}
    programs = data.get("programs", []) if isinstance(data, dict) else []
    if not isinstance(programs, list) or not programs:
        errors.append("programs list missing or empty")
    for program in programs:
        if not isinstance(program, dict):
            errors.append("program entry must be mapping")
            continue
        name = program.get("name")
        if not name:
            errors.append("program missing name")
        if not program.get("in_scope"):
            warnings.append(f"{name}: in_scope missing or empty")
        if program.get("per_host_rpm") is not None and not _is_positive_int(program.get("per_host_rpm")):
            errors.append(f"{name}: per_host_rpm must be positive")
        if program.get("per_target_rpm") is not None and not _is_positive_int(program.get("per_target_rpm")):
            errors.append(f"{name}: per_target_rpm must be positive")
        if program.get("concurrency_per_host") is not None and not _is_positive_int(program.get("concurrency_per_host")):
            errors.append(f"{name}: concurrency_per_host must be positive")
        _validate_headers(program, errors, warnings)
        _validate_hours(program, errors)
        _validate_rules(program, warnings)

    for msg in warnings:
        _warn(msg)
    for msg in errors:
        _error(msg)
    return 1 if errors else 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate programs.yaml for required headers and policies")
    parser.add_argument("path", nargs="?", default="config/programs.yaml")
    args = parser.parse_args()
    return validate_programs(Path(args.path))


if __name__ == "__main__":
    raise SystemExit(main())
