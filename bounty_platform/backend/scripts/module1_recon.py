#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import subprocess
import sys


def main() -> int:
    parser = argparse.ArgumentParser(description="Executa Modulo 1 de Recon via Django management command")
    parser.add_argument("--program", required=True)
    parser.add_argument("--domains", default="")
    parser.add_argument("--authorized-token", required=True)
    parser.add_argument("--subfinder-path", default="subfinder")
    parser.add_argument("--dnsx-path", default="dnsx")
    parser.add_argument("--timeout", type=int, default=600)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
    cmd = [
        sys.executable,
        "manage.py",
        "run_recon_module1",
        "--program",
        args.program,
        "--authorized-token",
        args.authorized_token,
        "--subfinder-path",
        args.subfinder_path,
        "--dnsx-path",
        args.dnsx_path,
        "--timeout",
        str(args.timeout),
    ]
    if args.domains:
        cmd.extend(["--domains", args.domains])
    if args.dry_run:
        cmd.append("--dry-run")

    proc = subprocess.run(cmd, check=False)
    return int(proc.returncode)


if __name__ == "__main__":
    raise SystemExit(main())
