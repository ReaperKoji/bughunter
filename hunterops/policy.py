from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any


@dataclass
class EndpointRule:
    prefix: str
    methods: list[str]


class EndpointPolicyEngine:
    def __init__(self, cfg: dict[str, Any]) -> None:
        self.cfg = cfg if isinstance(cfg, dict) else {}
        self.manual_override = str(os.getenv("HUNTEROPS_MANUAL_OVERRIDE", "")).strip().lower() in {"1", "true", "yes"}

    def _load_rules(self, program: str) -> dict[str, list[EndpointRule]]:
        rules_cfg = self.cfg.get("endpoint_policies", {}) if isinstance(self.cfg.get("endpoint_policies", {}), dict) else {}
        default = rules_cfg.get("default", {}) if isinstance(rules_cfg.get("default", {}), dict) else {}
        programs = rules_cfg.get("programs", {}) if isinstance(rules_cfg.get("programs", {}), dict) else {}
        program_cfg = programs.get(program, {}) if isinstance(programs.get(program, {}), dict) else {}
        block = list(default.get("block", []) or []) + list(program_cfg.get("block", []) or [])
        allow = list(default.get("allow", []) or []) + list(program_cfg.get("allow", []) or [])
        return {
            "block": self._parse_rules(block),
            "allow": self._parse_rules(allow),
        }

    def _parse_rules(self, rows: list[dict[str, Any]]) -> list[EndpointRule]:
        parsed: list[EndpointRule] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            prefix = str(row.get("prefix", "")).strip()
            if not prefix:
                continue
            methods = [str(x).strip().upper() for x in (row.get("methods", []) or []) if str(x).strip()]
            parsed.append(EndpointRule(prefix=prefix, methods=methods))
        return parsed

    def is_blocked(self, program: str, path: str, method: str) -> tuple[bool, str]:
        if self.manual_override:
            return False, "manual_override"
        rules = self._load_rules(program)
        method_u = str(method or "GET").upper()
        path_n = str(path or "/").strip()
        if not path_n.startswith("/"):
            path_n = "/" + path_n

        for rule in rules.get("allow", []):
            if path_n.startswith(rule.prefix) and (not rule.methods or method_u in rule.methods):
                return False, "allowed_by_rule"

        for rule in rules.get("block", []):
            if path_n.startswith(rule.prefix) and (not rule.methods or method_u in rule.methods):
                return True, "blocked_by_rule"

        return False, "not_blocked"

