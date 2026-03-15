#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path


def load_events(path: Path) -> list[dict]:
    if not path.exists():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except Exception:
            continue
    return rows


def summarize(events: list[dict]) -> dict:
    summary = {
        "poc_valid": 0,
        "no_poc": 0,
        "module_result": 0,
        "target_skipped": 0,
        "hot_reload": 0,
        "by_module": {},
    }
    for ev in events:
        et = ev.get("event")
        if et == "poc_valid":
            summary["poc_valid"] += 1
            mod = ev.get("module")
            if mod:
                summary["by_module"].setdefault(mod, 0)
                summary["by_module"][mod] += 1
        elif et == "no_poc":
            summary["no_poc"] += 1
        elif et == "module_result":
            summary["module_result"] += 1
        elif et == "target_skipped":
            summary["target_skipped"] += 1
        elif et == "hot_reload":
            summary["hot_reload"] += 1
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description="Summarize attack_chain events")
    parser.add_argument("--events", default="data/events/events.ndjson")
    parser.add_argument("--out", default="data/metrics/events_summary.json")
    args = parser.parse_args()

    events = load_events(Path(args.events))
    summary = summarize(events)
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(summary, ensure_ascii=True, indent=2), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=True, indent=2))


if __name__ == "__main__":
    main()
