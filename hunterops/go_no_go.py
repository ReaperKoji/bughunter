from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from hunterops.rules_engine import check_automation_allowed
from hunterops.runtime_paths import resolve_path
from hunterops.scope_authorization import validate_scope_signature


@dataclass
class GoNoGoResult:
    ok: bool
    reasons: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "reasons": list(self.reasons),
            "warnings": list(self.warnings),
            "details": self.details,
        }


class GoNoGoChecklist:
    def __init__(self, cfg: dict[str, Any] | None = None) -> None:
        settings = cfg if isinstance(cfg, dict) else {}
        self.require_signed_scope = bool(settings.get("require_signed_scope", True))
        self.allow_env_targets = bool(settings.get("allow_env_targets", True))
        self.require_roe = bool(settings.get("require_roe", True))
        self.require_authorized_by = bool(settings.get("require_authorized_by", True))
        self.require_sessions_if_auth = bool(settings.get("require_sessions_if_auth", True))
        self.report_path = resolve_path(settings.get("report_path", "reports/go_no_go.json"), prefer_existing=False)
        self.report_md_path = resolve_path(settings.get("report_md_path", "reports/go_no_go.md"), prefer_existing=False)

    def evaluate(
        self,
        *,
        targets: list[str],
        scope: dict[str, Any],
        programs: list[dict[str, Any]],
        auth_required: bool,
        sessions_present: bool,
        real_mode: bool,
    ) -> GoNoGoResult:
        reasons: list[str] = []
        warnings: list[str] = []
        details: dict[str, Any] = {}

        scope_present = bool(scope)
        scope_valid = validate_scope_signature(scope) if scope_present else False
        details["scope_present"] = scope_present
        details["scope_valid"] = scope_valid
        details["authorized_by"] = str(scope.get("authorized_by", "")).strip() if scope_present else ""

        if self.require_signed_scope and real_mode:
            if not scope_present:
                reasons.append("missing_signed_scope")
            elif not scope_valid:
                reasons.append("invalid_scope_signature")
        if scope_present and self.require_authorized_by and not str(scope.get("authorized_by", "")).strip():
            reasons.append("authorized_by_missing")

        env_targets = os.getenv("AUTHORIZED_TARGETS", "").strip()
        if not scope_present and not env_targets and self.allow_env_targets:
            reasons.append("authorized_targets_env_missing")

        program_rules: dict[str, str] = {}
        for program in programs:
            name = str(program.get("name", "")).strip()
            if not name:
                continue
            rules = str(program.get("rules_of_engagement", "") or program.get("rules_text", "") or "").strip()
            program_rules[name] = rules
            if self.require_roe and not rules:
                reasons.append(f"roe_missing:{name}")
                continue
            decision = check_automation_allowed(rules)
            if decision.manual_only:
                reasons.append(f"automation_not_allowed:{name}:{decision.reason}")

        details["program_rules"] = program_rules

        if auth_required and self.require_sessions_if_auth and not sessions_present:
            reasons.append("sessions_required_missing")

        ok = len(reasons) == 0
        return GoNoGoResult(ok=ok, reasons=reasons, warnings=warnings, details=details)

    def write_report(self, result: GoNoGoResult) -> None:
        payload = result.to_dict()
        payload["generated_at"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        self.report_path.parent.mkdir(parents=True, exist_ok=True)
        self.report_path.write_text(json.dumps(payload, ensure_ascii=True, indent=2), encoding="utf-8")

        lines = [
            "# Go/No-Go Checklist",
            "",
            f"Generated: {payload['generated_at']}",
            "",
            f"Status: {'GO' if result.ok else 'NO-GO'}",
            "",
            "## Reasons",
        ]
        if result.reasons:
            lines.extend([f"- {r}" for r in result.reasons])
        else:
            lines.append("- None")
        lines.append("")
        lines.append("## Warnings")
        if result.warnings:
            lines.extend([f"- {w}" for w in result.warnings])
        else:
            lines.append("- None")
        lines.append("")
        lines.append("## Details")
        lines.append("```json")
        lines.append(json.dumps(result.details, ensure_ascii=True, indent=2))
        lines.append("```")
        self.report_md_path.parent.mkdir(parents=True, exist_ok=True)
        self.report_md_path.write_text("\n".join(lines), encoding="utf-8")
