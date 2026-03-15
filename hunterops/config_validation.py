from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml


def validate_attack_pipeline_modules(pipeline_path: Path, modules_spec_path: Path) -> list[str]:
    errors: list[str] = []
    if not pipeline_path.exists() or not modules_spec_path.exists():
        return errors
    try:
        pipeline = yaml.safe_load(pipeline_path.read_text(encoding="utf-8")) or {}
    except Exception:
        return ["attack_pipeline_load_failed"]
    try:
        spec = json.loads(modules_spec_path.read_text(encoding="utf-8"))
    except Exception:
        return ["modules_spec_load_failed"]
    spec_names = {str(entry.get("name", "")).strip() for entry in spec if isinstance(entry, dict)}
    spec_names.discard("")
    module_cfg = pipeline.get("pipeline", {}).get("modules", {}) if isinstance(pipeline.get("pipeline", {}), dict) else {}
    if isinstance(module_cfg, dict):
        for key, cfg in module_cfg.items():
            module_name = str(cfg.get("module", key)).strip()
            if module_name and module_name not in spec_names:
                errors.append(f"unknown_attack_module name={module_name}")
    chain_order = pipeline.get("pipeline", {}).get("chain", {}).get("order", []) if isinstance(pipeline.get("pipeline", {}), dict) else []
    if isinstance(chain_order, list):
        for name in chain_order:
            module_name = str(name).strip()
            if module_name and module_name not in spec_names:
                errors.append(f"chain_module_missing_in_spec name={module_name}")
    return errors


def validate_findings_schema(rows: list[dict[str, Any]], schema_path: Path) -> list[str]:
    errors: list[str] = []
    if not rows or not schema_path.exists():
        return errors
    schema = {}
    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
    except Exception:
        return ["findings_schema_load_failed"]
    try:
        from jsonschema import Draft7Validator  # type: ignore

        validator = Draft7Validator(schema)
        for idx, row in enumerate(rows):
            for err in validator.iter_errors(row):
                errors.append(f"finding[{idx}] {err.message}")
        return errors
    except Exception:
        pass
    required = schema.get("required", []) if isinstance(schema, dict) else []
    properties = schema.get("properties", {}) if isinstance(schema, dict) else {}
    for idx, row in enumerate(rows):
        if not isinstance(row, dict):
            errors.append(f"finding[{idx}] not_object")
            continue
        for key in required:
            if key not in row:
                errors.append(f"finding[{idx}] missing_required {key}")
        for key, spec in properties.items():
            if key not in row:
                continue
            expected = spec.get("type") if isinstance(spec, dict) else None
            if expected == "string" and not isinstance(row[key], str):
                errors.append(f"finding[{idx}] {key} not_string")
            if expected == "number" and not isinstance(row[key], (int, float)):
                errors.append(f"finding[{idx}] {key} not_number")
            if expected == "object" and not isinstance(row[key], dict):
                errors.append(f"finding[{idx}] {key} not_object")
            if expected == "array" and not isinstance(row[key], list):
                errors.append(f"finding[{idx}] {key} not_array")
    return errors
