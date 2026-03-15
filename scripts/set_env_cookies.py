#!/usr/bin/env python3
"""Update .env cookie entries safely from text files."""

from __future__ import annotations

import argparse
from pathlib import Path


def read_cookie(path: Path) -> str:
    value = path.read_text(encoding="utf-8", errors="ignore").strip()
    if not value:
        raise ValueError(f"cookie file is empty: {path}")
    if value.lower().startswith("cookie:"):
        value = value.split(":", 1)[1].strip()
    return value


def shell_quote_single(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def upsert_env_line(lines: list[str], key: str, value: str) -> list[str]:
    prefix = f"{key}="
    replaced = False
    out: list[str] = []
    for line in lines:
        if line.startswith(prefix):
            out.append(f"{key}={shell_quote_single(value)}")
            replaced = True
        else:
            out.append(line)
    if not replaced:
        out.append(f"{key}={shell_quote_single(value)}")
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description="Set HUNTEROPS_USER_COOKIE and HUNTEROPS_USER_B_COOKIE in .env")
    parser.add_argument("--env-file", default=".env")
    parser.add_argument("--cookie-a-file", required=True)
    parser.add_argument("--cookie-b-file", required=True)
    args = parser.parse_args()

    env_path = Path(args.env_file)
    lines = env_path.read_text(encoding="utf-8", errors="ignore").splitlines() if env_path.exists() else []
    cookie_a = read_cookie(Path(args.cookie_a_file))
    cookie_b = read_cookie(Path(args.cookie_b_file))

    lines = upsert_env_line(lines, "HUNTEROPS_USER_COOKIE", cookie_a)
    lines = upsert_env_line(lines, "HUNTEROPS_USER_B_COOKIE", cookie_b)
    env_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"env_updated={env_path}")
    print(f"cookie_a_len={len(cookie_a)}")
    print(f"cookie_b_len={len(cookie_b)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
