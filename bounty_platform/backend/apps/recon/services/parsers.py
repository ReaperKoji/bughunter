from __future__ import annotations

import json


def parse_subfinder_output(raw_text: str) -> set[str]:
    out: set[str] = set()
    for line in raw_text.splitlines():
        host = line.strip().lower().rstrip(".")
        if host:
            out.add(host)
    return out


def parse_dnsx_jsonl(raw_text: str) -> dict[str, dict]:
    rows: dict[str, dict] = {}
    for line in raw_text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        host = str(obj.get("host", "")).strip().lower().rstrip(".")
        if not host:
            continue
        rows[host] = obj
    return rows


def extract_live_ips(dns_row: dict) -> list[str]:
    out: list[str] = []
    for key in ("a", "aaaa"):
        vals = dns_row.get(key, [])
        if isinstance(vals, list):
            out.extend([str(v).strip() for v in vals if str(v).strip()])
    return sorted(list(set(out)))
