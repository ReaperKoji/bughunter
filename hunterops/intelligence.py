from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from hunterops.findings import calculate_impact
from hunterops.types import Finding


SENSITIVE_PATTERNS = {
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "jwt": re.compile(r"eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9._-]+\.[a-zA-Z0-9._-]+"),
    "generic_api_key": re.compile(r"(?i)(api[_-]?key|token|secret)\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}"),
}


def finding_signature(f: Finding) -> str:
    raw = "|".join([f.plugin, f.target, f.category, f.title]).lower()
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def dedupe_findings(findings: list[Finding]) -> list[Finding]:
    seen: set[str] = set()
    out: list[Finding] = []
    semantic_cache: list[tuple[set[str], Finding]] = []
    semantic_bucket: dict[tuple[str, str], list[tuple[set[str], Finding]]] = {}
    for f in findings:
        sig = finding_signature(f)
        if sig in seen:
            continue
        # semantic near-duplicate clustering (bucketed by target+category to reduce O(n^2))
        toks = semantic_tokens(f"{f.target} {f.category} {f.title}")
        bucket_key = (str(f.target).strip().lower(), str(f.category).strip().lower())
        candidates = semantic_bucket.get(bucket_key, semantic_cache)
        is_near_dup = False
        for existing_toks, existing_f in candidates:
            sim = jaccard(toks, existing_toks)
            if sim >= 0.82 and f.target == existing_f.target:
                is_near_dup = True
                break
        if is_near_dup:
            continue
        seen.add(sig)
        f.metadata["signature"] = sig
        out.append(f)
        semantic_cache.append((toks, f))
        semantic_bucket.setdefault(bucket_key, []).append((toks, f))
    return out


def risk_score(f: Finding, feedback: dict[str, Any] | None = None) -> float:
    impact_profile = calculate_impact(f)
    sev_map = {"critical": 95, "high": 80, "medium": 55, "low": 30, "info": 10}
    effective_severity = str(impact_profile.get("adjusted_severity", f.severity)).lower()
    severity = sev_map.get(effective_severity, sev_map.get(f.severity.lower(), 20))
    novelty = float(f.metadata.get("novelty", 0))
    confidence = float(f.metadata.get("confidence", 50))
    impact = float(impact_profile.get("impact_score", f.metadata.get("impact", 50)))
    category = f.category.lower()
    auth_bonus = 10 if "auth" in category or "idor" in category or "role" in category else 0
    data_bonus = 8 if "sensitive" in category or "exposure" in category else 0
    base = severity * 0.45 + novelty * 0.20 + confidence * 0.20 + impact * 0.15 + auth_bonus + data_bonus
    if feedback:
        plugin_adj = float((feedback.get("plugin_adjustments") or {}).get(f.plugin, 0))
        cat_adj = float((feedback.get("category_adjustments") or {}).get(f.category, 0))
        asset_adj = float((feedback.get("asset_adjustments") or {}).get(f.target, 0))
        base += plugin_adj + cat_adj + asset_adj
    return round(min(100.0, max(0.0, base)), 2)


def detect_sensitive(text: str) -> list[dict[str, str]]:
    hits: list[dict[str, str]] = []
    for name, pattern in SENSITIVE_PATTERNS.items():
        for m in pattern.finditer(text):
            hits.append({"type": name, "value": m.group(0)[:80]})
    return hits


def http_diff_score(baseline: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    b_status = int(baseline.get("status", 0))
    c_status = int(current.get("status", 0))
    b_len = int(baseline.get("length", 0))
    c_len = int(current.get("length", 0))
    status_changed = b_status != c_status
    len_delta = abs(c_len - b_len)
    len_ratio = (len_delta / max(1, b_len)) * 100

    b_keys = set((baseline.get("json_keys") or []))
    c_keys = set((current.get("json_keys") or []))
    structural_delta = len((b_keys ^ c_keys))

    score = 0
    if status_changed:
        score += 40
    if len_ratio > 20:
        score += 30
    if structural_delta > 0:
        score += 30
    return {
        "status_changed": status_changed,
        "len_delta": len_delta,
        "len_ratio_pct": round(len_ratio, 2),
        "structural_delta": structural_delta,
        "anomaly_score": min(100, score),
    }


def serialize_findings(findings: list[Finding], feedback: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for f in findings:
        impact_profile = calculate_impact(f)
        metadata = f.metadata.copy() if isinstance(f.metadata, dict) else {}
        metadata["impact_profile"] = impact_profile
        row = {
            "plugin": f.plugin,
            "target": f.target,
            "category": f.category,
            "severity": str(impact_profile.get("adjusted_severity", f.severity)),
            "title": f.title,
            "evidence": f.evidence,
            "metadata": metadata,
            "risk_score": risk_score(f, feedback=feedback),
        }
        rows.append(row)
    return rows


def to_jsonl(rows: list[dict[str, Any]]) -> str:
    return "\n".join(json.dumps(r, ensure_ascii=True) for r in rows) + ("\n" if rows else "")


def semantic_tokens(text: str) -> set[str]:
    return {t for t in re.split(r"[^a-z0-9]+", text.lower()) if t and len(t) > 2}


def jaccard(a: set[str], b: set[str]) -> float:
    if not a and not b:
        return 1.0
    return len(a & b) / max(1, len(a | b))


def load_feedback(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
