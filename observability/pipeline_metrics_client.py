#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any

from prometheus_client import Counter, Gauge, Histogram, start_http_server

REQUESTS_TOTAL = Counter("app_requests_total", "Total HTTP requests observed")
RESPONSES_403 = Counter("app_responses_403_total", "Total 403 responses observed")
RESPONSES_429 = Counter("app_responses_429_total", "Total 429 responses observed")
FALSE_POSITIVE_EST = Gauge("app_false_positive_estimate", "Estimated false positive rate")
SCAN_DURATION = Histogram("app_scan_duration_seconds", "Observed scan duration seconds")
PIPELINE_RUNS = Counter("app_pipeline_runs_total", "Pipeline run count")
PIPELINE_FAILURES = Counter("app_pipeline_failures_total", "Pipeline run failures")


class MetricsTailer:
    def __init__(self, events_path: Path) -> None:
        self.events_path = events_path
        self.offset = 0

    def tail(self) -> list[dict[str, Any]]:
        if not self.events_path.exists():
            return []
        with self.events_path.open("r", encoding="utf-8") as fh:
            fh.seek(self.offset)
            lines = fh.readlines()
            self.offset = fh.tell()
        out = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except Exception:
                continue
        return out


def _update_from_events(events: list[dict[str, Any]]) -> None:
    for event in events:
        REQUESTS_TOTAL.inc()
        status = int(event.get("status", 0) or 0)
        if status == 403:
            RESPONSES_403.inc()
        if status == 429:
            RESPONSES_429.inc()
        duration = event.get("duration_s") or event.get("latency_s")
        try:
            if duration is not None:
                SCAN_DURATION.observe(float(duration))
        except Exception:
            pass


def _update_from_summary(summary_path: Path) -> None:
    if not summary_path.exists():
        return
    try:
        data = json.loads(summary_path.read_text(encoding="utf-8"))
    except Exception:
        return
    fp_rate = data.get("false_positive_rate")
    if fp_rate is not None:
        try:
            FALSE_POSITIVE_EST.set(float(fp_rate))
        except Exception:
            pass
    run_status = data.get("status")
    if run_status == "completed":
        PIPELINE_RUNS.inc()
    if run_status == "failed":
        PIPELINE_FAILURES.inc()


def main() -> int:
    parser = argparse.ArgumentParser(description="Expose HunterOps metrics for Prometheus")
    parser.add_argument("--events", default="data/events/events.ndjson")
    parser.add_argument("--summary", default="data/metrics/attack_chain_summary.json")
    parser.add_argument("--port", type=int, default=9108)
    parser.add_argument("--interval", type=float, default=5.0)
    args = parser.parse_args()

    events_path = Path(args.events)
    summary_path = Path(args.summary)
    tailer = MetricsTailer(events_path)

    start_http_server(args.port)
    while True:
        events = tailer.tail()
        if events:
            _update_from_events(events)
        _update_from_summary(summary_path)
        time.sleep(args.interval)


if __name__ == "__main__":
    raise SystemExit(main())
