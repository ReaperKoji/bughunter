#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
from pathlib import Path

import httpx


def _write_targets(path: Path, targets: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(targets) + "\n", encoding="utf-8")


async def _probe(url: str) -> bool:
    try:
        async with httpx.AsyncClient(timeout=5.0, follow_redirects=True) as client:
            resp = await client.get(url)
        return int(resp.status_code) < 500
    except Exception:
        return False


async def main_async(targets: list[str], out_file: Path, skip_check: bool) -> None:
    if not skip_check:
        alive = []
        for t in targets:
            ok = await _probe(t)
            if ok:
                alive.append(t)
        if not alive:
            raise SystemExit("No lab targets reachable. Start Juice Shop/DVWA or use --skip-check.")
        targets = alive
    _write_targets(out_file, targets)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run attack pipeline against lab targets")
    parser.add_argument("--targets", default="http://localhost:3000,http://localhost:8080")
    parser.add_argument("--out", default="data/targets/lab_targets.txt")
    parser.add_argument("--skip-check", action="store_true")
    args = parser.parse_args()

    targets = [x.strip() for x in args.targets.split(",") if x.strip()]
    out_file = Path(args.out)
    asyncio.run(main_async(targets, out_file, args.skip_check))
    print(f"[lab_test] targets written: {out_file}")
    print("[lab_test] run: python3 scripts/attack_pipeline.py --config config/lab_attack_pipeline.yaml")


if __name__ == "__main__":
    main()
