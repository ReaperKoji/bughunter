#!/usr/bin/env python3
"""Resilient scheduler wrapper for research_pipeline.py."""

from __future__ import annotations

import argparse
import os
import random
import signal
import subprocess
import sys
import time
from datetime import UTC, datetime


STOP_REQUESTED = False


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except Exception:
        return default


def _timestamp() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _handle_signal(signum: int, _frame: object | None) -> None:
    global STOP_REQUESTED
    STOP_REQUESTED = True
    print(f"[{_timestamp()}] stop_requested signal={signum}", flush=True)


def _sleep_with_stop(seconds: float) -> None:
    remaining = max(0.0, float(seconds))
    while remaining > 0 and not STOP_REQUESTED:
        step = min(1.0, remaining)
        time.sleep(step)
        remaining -= step


def parse_args() -> tuple[argparse.Namespace, list[str]]:
    parser = argparse.ArgumentParser(description="HunterOps pipeline scheduler")
    parser.add_argument("--config", default=os.getenv("HUNTEROPS_CONFIG", "config/engine.yaml"))
    parser.add_argument("--targets-file", default=os.getenv("TARGETS_FILE", "data/targets/in_scope_hosts.txt"))
    parser.add_argument("--target", default=os.getenv("TARGET_LIST", ""))
    parser.add_argument("--plugins", default=os.getenv("HUNTEROPS_PLUGINS", ""))
    parser.add_argument("--run-id", default="")
    parser.add_argument("--out-dir", default=os.getenv("HUNTEROPS_REPORTS_DIR", "/opt/hunterops/reports/research"))
    parser.add_argument("--interval-seconds", type=int, default=_env_int("RUN_INTERVAL_SECONDS", 300))
    parser.add_argument("--max-runtime-seconds", type=int, default=_env_int("RUN_MAX_SECONDS", 0))
    parser.add_argument("--jitter-seconds", type=int, default=_env_int("RUN_JITTER_SECONDS", 20))
    parser.add_argument("--max-backoff-seconds", type=int, default=_env_int("RUN_MAX_BACKOFF_SECONDS", 300))
    parser.add_argument("--alert-dry-run", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--once", action="store_true")
    return parser.parse_known_args()


def build_command(args: argparse.Namespace, extra: list[str]) -> list[str]:
    cmd = [
        sys.executable,
        "scripts/research_pipeline.py",
        "--config",
        args.config,
        "--out-dir",
        args.out_dir,
    ]
    if args.targets_file:
        cmd.extend(["--targets-file", args.targets_file])
    if args.target:
        cmd.extend(["--target", args.target])
    if args.plugins:
        cmd.extend(["--plugins", args.plugins])
    if args.run_id:
        cmd.extend(["--run-id", args.run_id])
    if args.alert_dry_run:
        cmd.append("--alert-dry-run")
    if args.verbose:
        cmd.append("--verbose")
    if extra:
        cmd.extend(extra)
    return cmd


def main() -> int:
    args, extra = parse_args()
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    interval = max(30, int(args.interval_seconds or 0))
    max_runtime = int(args.max_runtime_seconds or 0)
    if max_runtime <= 0:
        max_runtime = max(900, interval * 4)
    jitter = max(0, int(args.jitter_seconds or 0))
    max_backoff = max(0, int(args.max_backoff_seconds or 0))

    backoff = 0.0
    cmd = build_command(args, extra)
    print(f"[{_timestamp()}] scheduler_start interval={interval}s max_runtime={max_runtime}s", flush=True)

    while not STOP_REQUESTED:
        start_ts = time.monotonic()
        timed_out = False
        rc = 0
        print(f"[{_timestamp()}] cycle_start", flush=True)
        try:
            completed = subprocess.run(cmd, check=False, timeout=max_runtime)
            rc = int(completed.returncode or 0)
        except subprocess.TimeoutExpired:
            timed_out = True
            rc = 124
            print(f"[{_timestamp()}] cycle_timeout max_runtime={max_runtime}s", flush=True)
        except Exception as err:
            rc = 1
            print(f"[{_timestamp()}] cycle_error err={err}", flush=True)

        elapsed = time.monotonic() - start_ts
        status = "ok" if rc == 0 else "failed"
        print(
            f"[{_timestamp()}] cycle_done status={status} rc={rc} elapsed={elapsed:.1f}s",
            flush=True,
        )

        if rc != 0 or timed_out:
            if max_backoff > 0:
                backoff = min(max_backoff, backoff * 2 if backoff else 30.0)
        else:
            backoff = 0.0

        if args.once:
            break

        jitter_sec = random.uniform(0, float(jitter)) if jitter else 0.0
        sleep_base = max(5.0, float(interval) - elapsed)
        sleep_for = sleep_base + jitter_sec + backoff
        print(
            f"[{_timestamp()}] sleep seconds={sleep_for:.1f} jitter={jitter_sec:.1f} backoff={backoff:.1f}",
            flush=True,
        )
        _sleep_with_stop(sleep_for)

    print(f"[{_timestamp()}] scheduler_exit", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
