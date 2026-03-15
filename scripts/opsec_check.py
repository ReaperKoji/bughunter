#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import yaml
from hunterops.secrets import read_secret


def main() -> None:
    parser = argparse.ArgumentParser(description="OPSEC and security hardening checks")
    parser.add_argument("--sessions", default="data/sessions.yaml")
    parser.add_argument("--programs", default="config/programs.yaml")
    parser.add_argument("--out", default="data/reports/opsec_check.json")
    parser.add_argument("--strict-secrets", action="store_true")
    args = parser.parse_args()

    sessions_cfg = yaml.safe_load(Path(args.sessions).read_text(encoding="utf-8")) if Path(args.sessions).exists() else {}
    programs_cfg = yaml.safe_load(Path(args.programs).read_text(encoding="utf-8")) if Path(args.programs).exists() else {}

    issues: list[str] = []
    warnings: list[str] = []

    sessions = sessions_cfg.get("sessions", [])
    if not sessions:
        issues.append("No sessions configured for multi-account testing.")

    for s in sessions:
        if s.get("token") and not s.get("token_env"):
            warnings.append(f"Session {s.get('name')} has inline token; prefer token_env for secret management.")
        if s.get("cookie") and not s.get("cookie_env"):
            warnings.append(f"Session {s.get('name')} has inline cookie; prefer cookie_env for secret management.")
        if s.get("token_env") and not read_secret(str(s.get("token_env"))):
            msg = f"Missing env token for session {s.get('name')}: {s.get('token_env')}"
            if args.strict_secrets:
                issues.append(msg)
            else:
                warnings.append(msg)

    programs = programs_cfg.get("programs", [])
    if not programs:
        issues.append("No programs configured in config/programs.yaml.")
    for p in programs:
        if not p.get("in_scope"):
            issues.append(f"Program {p.get('name')} has empty in_scope.")

    payload = {"issues": issues, "warnings": warnings, "ok": not issues}
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    print(f"[opsec-check] out={args.out} ok={payload['ok']} strict_secrets={args.strict_secrets}")
    raise SystemExit(0 if payload["ok"] else 2)


if __name__ == "__main__":
    main()
