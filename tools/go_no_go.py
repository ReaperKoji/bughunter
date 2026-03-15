#!/usr/bin/env python3
from __future__ import annotations

import argparse

from hunterops.attack_chain.config import load_attack_pipeline
from hunterops.attack_chain.scope import load_programs
from hunterops.attack_chain.types import Target
from hunterops.go_no_go import GoNoGoChecklist
from hunterops.scope_authorization import load_authorized_scope
from hunterops.session_profiles import load_sessions


def main() -> int:
    parser = argparse.ArgumentParser(description="Go/No-Go checklist for safe execution")
    parser.add_argument("--config", default="attack_pipeline.yaml")
    args = parser.parse_args()

    cfg = load_attack_pipeline(args.config)
    pipeline = cfg if isinstance(cfg, dict) else {}

    targets = []
    sources = pipeline.get("target_sources", []) if isinstance(pipeline.get("target_sources", []), list) else []
    for src in sources:
        if not isinstance(src, dict) or src.get("type") != "file":
            continue
        path = src.get("path")
        if not path:
            continue
        try:
            lines = [x.strip() for x in open(path, "r", encoding="utf-8").read().splitlines() if x.strip()]
        except Exception:
            lines = []
        for idx, line in enumerate(lines):
            program_id = str(src.get("program", "all"))
            raw_line = line
            if "::" in line:
                left, right = line.split("::", 1)
                if left.strip() and right.strip():
                    program_id = left.strip()
                    raw_line = right.strip()
            url = raw_line if raw_line.startswith("http") else f"https://{raw_line}"
            targets.append(Target(target_id=f"t{idx:04d}", url=url, program_id=program_id))

    go_no_go = GoNoGoChecklist(pipeline.get("go_no_go", {}))
    scope = load_authorized_scope()
    programs = load_programs("config/programs.yaml")

    modules_cfg = pipeline.get("modules", {}) if isinstance(pipeline.get("modules", {}), dict) else {}
    auth_required = any(
        isinstance(cfg, dict) and (cfg.get("requires_auth") or cfg.get("use_auth") or cfg.get("auth_session"))
        for cfg in modules_cfg.values()
    )
    sessions_present = bool(load_sessions("data/sessions.yaml"))

    result = go_no_go.evaluate(
        targets=[t.url for t in targets],
        scope=scope,
        programs=programs.get("programs", []) if isinstance(programs, dict) else [],
        auth_required=auth_required,
        sessions_present=sessions_present,
        real_mode=bool(pipeline.get("real_mode", False)),
    )
    go_no_go.write_report(result)
    print("go_no_go:", result.to_dict())
    return 0 if result.ok else 2


if __name__ == "__main__":
    raise SystemExit(main())
