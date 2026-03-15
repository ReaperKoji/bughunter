#!/usr/bin/env python3
from __future__ import annotations

import argparse
from hunterops.runbook import RunbookManager


def main() -> int:
    parser = argparse.ArgumentParser(description="Runbook override actions")
    parser.add_argument("--override-path", default="data/runtime/runbook_override.json")

    sub = parser.add_subparsers(dest="cmd", required=True)

    pause = sub.add_parser("pause", help="Pause scanning")
    pause.add_argument("--minutes", type=int, default=15)
    pause.add_argument("--reason", default="manual_pause")

    resume = sub.add_parser("resume", help="Resume scanning")

    reduce = sub.add_parser("reduce-rate", help="Reduce rate temporarily")
    reduce.add_argument("--multiplier", type=float, default=0.5)
    reduce.add_argument("--minutes", type=int, default=20)
    reduce.add_argument("--reason", default="manual_reduce_rate")

    block = sub.add_parser("block-host", help="Temporarily block a host")
    block.add_argument("host")
    block.add_argument("--minutes", type=int, default=15)
    block.add_argument("--reason", default="manual_block_host")

    unblock = sub.add_parser("unblock-host", help="Remove host block")
    unblock.add_argument("host")

    args = parser.parse_args()
    manager = RunbookManager({"override_path": args.override_path, "enabled": True})

    if args.cmd == "pause":
        manager.pause(minutes=args.minutes, reason=args.reason)
        return 0
    if args.cmd == "resume":
        manager.pause(minutes=0, reason="manual_resume")
        return 0
    if args.cmd == "reduce-rate":
        manager.reduce_rate(multiplier=args.multiplier, minutes=args.minutes, reason=args.reason)
        return 0
    if args.cmd == "block-host":
        manager.block_host(args.host, minutes=args.minutes, reason=args.reason)
        return 0
    if args.cmd == "unblock-host":
        manager.block_host(args.host, minutes=0, reason="manual_unblock")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
