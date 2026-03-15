#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Compute effectiveness metrics for a run")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--report-root", default="data/reports/research/runs")
    parser.add_argument("--pipeline-log", default="data/pipeline.log")
    parser.add_argument("--metrics-file", default="")
    parser.add_argument("--out", default="")
    return parser.parse_args()


def load_rows(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


def extract_endpoints(value: Any, out: set[str]) -> None:
    if value is None:
        return
    if isinstance(value, str):
        text = value.strip()
        if text.startswith("/") and len(text) <= 200:
            out.add(text)
        return
    if isinstance(value, dict):
        for k, v in value.items():
            extract_endpoints(k, out)
            extract_endpoints(v, out)
        return
    if isinstance(value, list):
        for item in value:
            extract_endpoints(item, out)


def parse_processed_tasks(run_id: str, log_path: Path) -> int:
    if not log_path.exists():
        return 0
    lines = log_path.read_text(encoding="utf-8").splitlines()
    in_segment = False
    total = 0
    for line in lines:
        if f"bootstrap_started run_id={run_id} " in line:
            in_segment = True
            continue
        if in_segment and "bootstrap_started run_id=" in line:
            break
        if not in_segment:
            continue
        if "target_scan_completed" in line and "processed_tasks=" in line:
            try:
                part = line.split("processed_tasks=")[1]
                num = int(part.split()[0].split('"')[0].split(",")[0])
                total += num
            except Exception:
                continue
    return total


def parse_metrics(metrics_path: Path) -> tuple[float | None, float | None]:
    if not metrics_path.exists():
        return None, None
    text = metrics_path.read_text(encoding="utf-8")
    req_total = 0.0
    for match in re.finditer(r'app_requests_total\{[^}]*status="(\d+)"[^}]*\}\s+([0-9\.eE+-]+)', text):
        req_total += float(match.group(2))
    scope_blocked = None
    match = re.search(r"app_scope_blocked_total\s+([0-9\.eE+-]+)", text)
    if match:
        scope_blocked = float(match.group(1))
    return req_total, scope_blocked


def main() -> int:
    args = parse_args()
    run_id = args.run_id.strip()
    report_root = Path(args.report_root)
    run_dir = report_root / run_id
    triage_dir = run_dir / "triage"
    if not triage_dir.exists():
        triage_dir = Path("data/reports/research/triage")
    review_rows = load_rows(triage_dir / "review_queue.jsonl")
    actionable_rows = load_rows(triage_dir / "actionable_findings.jsonl")
    validated_rows = load_rows(triage_dir / "validated_candidates.jsonl")

    endpoints: set[str] = set()
    for row in review_rows + actionable_rows + validated_rows:
        extract_endpoints(row.get("metadata"), endpoints)
        extract_endpoints(row.get("evidence"), endpoints)

    run_stats_path = run_dir / "run_stats.json"
    if run_stats_path.exists():
        try:
            processed_tasks = int(json.loads(run_stats_path.read_text(encoding="utf-8")).get("processed_tasks", 0) or 0)
        except Exception:
            processed_tasks = 0
    else:
        processed_tasks = parse_processed_tasks(run_id, Path(args.pipeline_log))

    total_findings = len(review_rows) + len(actionable_rows)
    P = (len(actionable_rows) / total_findings) if total_findings else 0.0
    V = (len(validated_rows) / len(actionable_rows)) if actionable_rows else 0.0
    C = (len(endpoints) / processed_tasks) if processed_tasks else 0.0
    if C > 1:
        C = 1.0

    metrics_path = Path(args.metrics_file) if args.metrics_file else (run_dir / "metrics" / f"metrics_{run_id}.txt")
    req_total, scope_blocked = parse_metrics(metrics_path)
    K = None
    if req_total and scope_blocked is not None and req_total > 0:
        K = max(0.0, min(1.0, 1.0 - (scope_blocked / req_total)))

    weights = {"P": 0.35, "V": 0.30, "C": 0.20, "K": 0.15}
    available = {"P": P, "V": V, "C": C, "K": K}
    weight_sum = sum(weights[k] for k, v in available.items() if v is not None)
    score = 0.0
    if weight_sum > 0:
        for k, v in available.items():
            if v is None:
                continue
            score += weights[k] * float(v)
        score /= weight_sum

    report = {
        "run_id": run_id,
        "findings_total": total_findings,
        "actionable": len(actionable_rows),
        "validated": len(validated_rows),
        "unique_endpoints": len(endpoints),
        "processed_tasks": processed_tasks,
        "metrics_file": str(metrics_path) if metrics_path.exists() else "",
        "requests_total": req_total,
        "scope_blocked_total": scope_blocked,
        "P": P,
        "V": V,
        "C": C,
        "K": K,
        "effectiveness": score,
        "effectiveness_percent": round(score * 100, 2),
    }

    out_path = Path(args.out) if args.out else (run_dir / "effectiveness.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
