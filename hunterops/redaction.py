from __future__ import annotations

import os
import re
from typing import Any

from hunterops.intelligence import SENSITIVE_PATTERNS
from hunterops.sensitivity import (
    CNPJ_RE,
    CPF_RE,
    EMAIL_RE,
    IBAN_RE,
    PHONE_RE,
    TOKEN_RE,
    sensitivity_score,
)
from hunterops.types import Finding


_BEARER_RE = re.compile(r"(?i)\b(bearer\s+)([a-z0-9\-._~+/]+=*)")
_BASIC_RE = re.compile(r"(?i)\b(basic\s+)([a-z0-9\-._~+/]+=*)")

_SENSITIVE_HEADER_KEYS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-session",
    "x-csrf-token",
    "x-xsrf-token",
}


def _mask(value: str) -> str:
    raw = str(value or "")
    if not raw:
        return raw
    if len(raw) <= 8:
        return "*" * len(raw)
    return f"{raw[:4]}...{raw[-4:]}"


def _redact_tokens(text: str) -> str:
    out = str(text or "")
    out = _BEARER_RE.sub(lambda m: f"{m.group(1)}{_mask(m.group(2))}", out)
    out = _BASIC_RE.sub(lambda m: f"{m.group(1)}{_mask(m.group(2))}", out)
    out = TOKEN_RE.sub(lambda m: _mask(m.group(0)), out)
    for pattern in SENSITIVE_PATTERNS.values():
        try:
            out = pattern.sub(lambda m: _mask(m.group(0)), out)
        except Exception:
            continue
    return out


def redact_text(text: str) -> str:
    if os.getenv("HUNTEROPS_REDACT_EVIDENCE", "1").strip() in {"0", "false", "no"}:
        return str(text or "")
    raw = str(text or "")
    if not raw:
        return raw
    score, meta = sensitivity_score(raw)
    out = _redact_tokens(raw)
    if score > 0.0 or any((meta.get("hits") or {}).values()):
        out = EMAIL_RE.sub(lambda m: _mask(m.group(0)), out)
        out = PHONE_RE.sub(lambda m: _mask(m.group(0)), out)
        out = IBAN_RE.sub(lambda m: _mask(m.group(0)), out)
        out = CPF_RE.sub(lambda m: _mask(m.group(0)), out)
        out = CNPJ_RE.sub(lambda m: _mask(m.group(0)), out)
    return out


def _redact_headers(headers: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in (headers or {}).items():
        k = str(key)
        lk = k.strip().lower()
        if lk in _SENSITIVE_HEADER_KEYS:
            out[k] = _mask(str(value or ""))
            continue
        if isinstance(value, str):
            out[k] = redact_text(value)
        else:
            out[k] = value
    return out


def redact_value(value: Any, *, _depth: int = 0, _max_depth: int = 4) -> Any:
    if _depth > _max_depth:
        return value
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, child in value.items():
            lk = str(key).strip().lower()
            if lk in _SENSITIVE_HEADER_KEYS and isinstance(child, str):
                out[key] = _mask(child)
                continue
            if lk == "headers" and isinstance(child, dict):
                out[key] = _redact_headers(child)
                continue
            out[key] = redact_value(child, _depth=_depth + 1, _max_depth=_max_depth)
        return out
    if isinstance(value, list):
        return [redact_value(v, _depth=_depth + 1, _max_depth=_max_depth) for v in value]
    return value


def redact_finding(finding: Finding) -> Finding:
    if os.getenv("HUNTEROPS_REDACT_EVIDENCE", "1").strip() in {"0", "false", "no"}:
        return finding
    evidence = redact_value(finding.evidence)
    metadata = redact_value(finding.metadata)
    if isinstance(metadata, dict):
        metadata = dict(metadata)
        metadata.setdefault("redacted", True)
        metadata.setdefault("redaction_policy", "sensitivity_v1")
    return Finding(
        plugin=finding.plugin,
        target=finding.target,
        category=finding.category,
        severity=finding.severity,
        title=finding.title,
        evidence=evidence if isinstance(evidence, dict) else {},
        metadata=metadata if isinstance(metadata, dict) else {},
    )


def redact_findings(findings: list[Finding]) -> list[Finding]:
    return [redact_finding(f) for f in findings or []]
