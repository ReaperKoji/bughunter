#!/usr/bin/env python3
import argparse
import json
import time
from pathlib import Path
from typing import Dict, Any


def load_modules_spec(path: Path) -> Dict[str, Any]:
    modules = json.loads(path.read_text(encoding="utf-8"))
    return {m["name"]: m for m in modules}


def write_ndjson(path: Path, obj: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")


def adaptive_backoff(err_ratio: float, base: float) -> float:
    if err_ratio <= 0.02:
        return base
    return base * min(5.0, 1 + (err_ratio * 10))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--modules", required=True, help="modules_spec.json")
    ap.add_argument("--queue", required=True, help="NDJSON tasks queue")
    ap.add_argument("--status", required=True, help="NDJSON output status")
    ap.add_argument("--max-5xx-ratio", type=float, default=0.02)
    args = ap.parse_args()

    spec = load_modules_spec(Path(args.modules))
    queue_path = Path(args.queue)
    status_path = Path(args.status)

    if not queue_path.exists():
        return 0

    total = 0
    errors_5xx = 0
    tasks = [json.loads(line) for line in queue_path.read_text(encoding="utf-8").splitlines() if line.strip()]

    for task in tasks:
        total += 1
        module = task.get("module")
        host = task.get("host", "default")
        mspec = spec.get(module, {})
        throttle = mspec.get("throttling", {"default_req_per_sec_per_host": 1, "max_concurrency": 1})
        rps = max(1, int(throttle.get("default_req_per_sec_per_host", 1)))
        base_sleep = 1.0 / rps

        err_ratio = (errors_5xx / total) if total else 0.0
        sleep_time = adaptive_backoff(err_ratio, base_sleep)
        time.sleep(sleep_time)

        status = {
            "task_id": task.get("task_id"),
            "module": module,
            "host": host,
            "status": "scheduled",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        }
        write_ndjson(status_path, status)

        # simulate status update with safe placeholder (no scanning)
        simulated_code = task.get("simulated_status_code", 200)
        if 500 <= simulated_code < 600:
            errors_5xx += 1
        write_ndjson(status_path, {
            "task_id": task.get("task_id"),
            "module": module,
            "host": host,
            "status": "done",
            "http_status": simulated_code,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        })

        if (errors_5xx / total) > args.max_5xx_ratio:
            write_ndjson(status_path, {
                "task_id": task.get("task_id"),
                "module": module,
                "host": host,
                "status": "paused_high_5xx",
                "ratio_5xx": errors_5xx / total,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            })
            break

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
