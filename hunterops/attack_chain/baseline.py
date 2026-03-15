from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlsplit

from hunterops.http_client import request_http_async


def _json_key_set(text: str) -> set[str]:
    try:
        obj = json.loads(text)
    except Exception:
        return set()

    def _walk(value: Any, prefix: str = "") -> set[str]:
        keys: set[str] = set()
        if isinstance(value, dict):
            for k, v in value.items():
                key = str(k)
                path = f"{prefix}.{key}" if prefix else key
                keys.add(path)
                keys |= _walk(v, path)
        elif isinstance(value, list):
            for v in value[:6]:
                path = f"{prefix}[]" if prefix else "[]"
                keys.add(path)
                keys |= _walk(v, path)
        return keys

    return _walk(obj)


def _json_key_diff_ratio(a: str, b: str) -> float | None:
    ka = _json_key_set(a)
    kb = _json_key_set(b)
    if not ka and not kb:
        return None
    union = ka | kb
    inter = ka & kb
    if not union:
        return None
    return round(1.0 - (len(inter) / max(1, len(union))), 4)


def _body_diff_ratio(a: str, b: str) -> float:
    la = len(a or "")
    lb = len(b or "")
    if la == 0 and lb == 0:
        return 0.0
    return abs(la - lb) / max(1, max(la, lb))


def _target_host(url: str) -> str:
    try:
        return str(urlsplit(url).hostname or "").strip().lower()
    except Exception:
        return ""


class BaselineComparer:
    def __init__(self, *, methods: list[dict[str, Any]] | None = None, timeout_s: int = 20) -> None:
        self.methods = methods or []
        self.timeout_s = max(5, int(timeout_s))

    async def measure(
        self,
        url: str,
        headers: dict[str, str],
        *,
        target_id: str = "",
        politeness: Any | None = None,
        policy: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        results: dict[str, dict[str, Any]] = {}
        host = _target_host(url)
        policy = policy or {}

        async def _do_request(method: str, body: Any) -> dict[str, Any]:
            if politeness is None:
                return await request_http_async(method, url, headers=headers, body=body, timeout=self.timeout_s)
            async with politeness.guard(
                host,
                target_id,
                per_host_rpm=policy.get("per_host_rpm"),
                per_target_rpm=policy.get("per_target_rpm"),
                concurrency_per_host=policy.get("concurrency_per_host"),
            ):
                return await request_http_async(method, url, headers=headers, body=body, timeout=self.timeout_s)

        for entry in self.methods:
            method = str(entry.get("method", "GET")).upper()
            body = entry.get("body")
            key = method
            resp = await _do_request(method, body)
            results[key] = {
                "status": int(resp.get("status", 0) or 0),
                "text": str(resp.get("text", "")),
            }
        score = 0.0
        notes: list[str] = []
        methods = list(results.keys())
        if len(methods) >= 2:
            base = results[methods[0]]
            for other_key in methods[1:]:
                other = results[other_key]
                status_diff = 1.0 if int(base.get("status", 0)) != int(other.get("status", 0)) else 0.0
                body_diff = _body_diff_ratio(base.get("text", ""), other.get("text", ""))
                json_diff = _json_key_diff_ratio(base.get("text", ""), other.get("text", ""))
                json_diff_val = float(json_diff) if json_diff is not None else 0.0
                pair_score = round((0.4 * status_diff) + (0.4 * body_diff) + (0.2 * json_diff_val), 4)
                score = max(score, pair_score)
                notes.append(f"{methods[0]} vs {other_key} score={pair_score}")
        return {"baseline_score": round(score, 4), "notes": notes, "methods": list(results.keys())}
