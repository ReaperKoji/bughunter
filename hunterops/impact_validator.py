from __future__ import annotations

import hashlib
import json
import re
from typing import Any
from urllib.parse import parse_qsl, urlparse

from hunterops.http_client import request_http_async
from hunterops.runtime_paths import resolve_path
from hunterops.session_profiles import auth_header, load_sessions
from hunterops.types import Finding

SENSITIVE_FIELD_RE = re.compile(
    r"(email|phone|wallet|balance|iban|account|trade|position|transaction|payment|order|portfolio|pii)",
    re.IGNORECASE,
)
EMAIL_VALUE_RE = re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.IGNORECASE)
JSON_SENSITIVE_KEY_RE = re.compile(
    r'"(?:email|phone|wallet|balance|iban|account(?:Id)?|trade(?:Id)?|position(?:Id)?|transaction(?:Id)?|payment(?:Id)?|order(?:Id)?|portfolio(?:Id)?|user(?:Id)?)"\s*:',
    re.IGNORECASE,
)
SENSITIVE_QUERY_PARAM_RE = re.compile(
    r"(?:^|_)(id|user|account|wallet|trade|position|transaction|payment|order|portfolio|email|phone|iban)(?:$|_)",
    re.IGNORECASE,
)


def _json_structure_tokens(value: Any, prefix: str = "") -> set[str]:
    tokens: set[str] = set()
    if isinstance(value, dict):
        for key, child in value.items():
            key_s = str(key)
            path = f"{prefix}.{key_s}" if prefix else key_s
            tokens.add(path)
            tokens |= _json_structure_tokens(child, path)
    elif isinstance(value, list):
        for child in value[:6]:
            path = f"{prefix}[]" if prefix else "[]"
            tokens.add(path)
            tokens |= _json_structure_tokens(child, path)
    return tokens


def _structure_similarity(text_a: str, text_b: str) -> float:
    try:
        obj_a = json.loads(text_a)
        obj_b = json.loads(text_b)
    except Exception:
        ta = {x for x in re.split(r"[^a-z0-9_]+", str(text_a or "").lower()) if x}
        tb = {x for x in re.split(r"[^a-z0-9_]+", str(text_b or "").lower()) if x}
        if not ta and not tb:
            return 100.0
        return round((len(ta & tb) / max(1, len(ta | tb))) * 100.0, 2)
    sa = _json_structure_tokens(obj_a)
    sb = _json_structure_tokens(obj_b)
    if not sa and not sb:
        return 100.0
    return round((len(sa & sb) / max(1, len(sa | sb))) * 100.0, 2)


def _sanitize_request_headers(raw: dict[str, Any]) -> dict[str, str]:
    out: dict[str, str] = {}
    for k, v in raw.items():
        key = str(k).strip()
        if not key:
            continue
        if key.lower() in {"authorization", "cookie", "proxy-authorization"}:
            continue
        out[key] = str(v)
    return out


def _to_int(value: Any, default: int = 0) -> int:
    try:
        return int(value or 0)
    except Exception:
        return int(default)


def _sha_hint(value: str) -> str:
    raw = str(value or "").encode("utf-8", errors="ignore")
    return hashlib.sha256(raw).hexdigest()[:16]


def _normalize_path(path: str) -> str:
    raw = str(path or "").strip()
    if not raw:
        return "/"
    normalized = raw if raw.startswith("/") else f"/{raw}"
    return normalized.lower()


def _response_header(response: dict[str, Any], header_name: str) -> str:
    headers = response.get("headers", {}) if isinstance(response, dict) else {}
    if not isinstance(headers, dict):
        return ""
    target = str(header_name or "").strip().lower()
    for key, value in headers.items():
        if str(key).strip().lower() == target:
            return str(value or "")
    return ""


def _is_json_like_response(response: dict[str, Any]) -> bool:
    text = str(response.get("text", "") or "")
    content_type = _response_header(response, "content-type").lower()
    if "application/json" in content_type or "application/graphql-response+json" in content_type:
        return True
    stripped = text.lstrip()
    return stripped.startswith("{") or stripped.startswith("[")


def _is_api_like_path(path: str, hints: tuple[str, ...]) -> bool:
    normalized = _normalize_path(path)
    for hint in hints:
        hint_n = _normalize_path(hint)
        if normalized == hint_n or normalized.startswith(f"{hint_n.rstrip('/')}/"):
            return True
    return (
        normalized.startswith("/api")
        or "/api/" in normalized
        or normalized.startswith("/graphql")
        or normalized.startswith("/v1/api")
        or normalized.startswith("/v2/api")
    )


def _has_sensitive_query_signal(url: str, sensitive_params: set[str]) -> bool:
    try:
        query_items = parse_qsl(urlparse(url).query, keep_blank_values=True)
    except Exception:
        return False
    for key, value in query_items:
        key_n = str(key or "").strip().lower()
        value_n = str(value or "").strip()
        if not key_n:
            continue
        if key_n in sensitive_params or SENSITIVE_QUERY_PARAM_RE.search(key_n):
            if value_n and value_n.lower() not in {"0", "1", "true", "false", "null", "none"}:
                return True
        if value_n and EMAIL_VALUE_RE.search(value_n):
            return True
    return False


def _sensitive_signal_score(text: str) -> int:
    sample = str(text or "")[:15000]
    if not sample:
        return 0
    score = 0
    lexical_hits = {x.lower() for x in SENSITIVE_FIELD_RE.findall(sample)}
    score += min(4, len(lexical_hits))
    score += min(4, len(JSON_SENSITIVE_KEY_RE.findall(sample)))
    score += min(4, len(EMAIL_VALUE_RE.findall(sample)))
    return score


class ImpactValidator:
    def __init__(
        self,
        *,
        cfg: dict[str, Any],
        runtime: dict[str, Any],
        logger: Any,
    ) -> None:
        self.cfg = cfg if isinstance(cfg, dict) else {}
        self.runtime = runtime if isinstance(runtime, dict) else {}
        self.logger = logger
        self.enabled = bool(self.cfg.get("enabled", False))
        self.sessions_file = resolve_path(str(self.cfg.get("sessions_file", "data/sessions.yaml")))
        self.auth_context_a = str(self.cfg.get("auth_context_a", "user")).strip() or "user"
        self.auth_context_b = str(self.cfg.get("auth_context_b", "user_b")).strip() or "user_b"
        self.max_replays_per_batch = max(1, int(self.cfg.get("max_replays_per_batch", 24) or 24))
        self.timeout_seconds = max(5, int(self.cfg.get("timeout_seconds", self.runtime.get("timeout_seconds", 25)) or 25))
        self.similarity_threshold = float(self.cfg.get("similarity_threshold", 88.0) or 88.0)
        self.anon_success_status = {
            int(x)
            for x in self.cfg.get("anon_success_status", [200, 201])
            if str(x).strip()
        } or {200, 201}
        self.anon_block_status = {
            int(x)
            for x in self.cfg.get("anon_block_status", [401, 403])
            if str(x).strip()
        } or {401, 403}
        self.safe_methods = {
            str(x).strip().upper()
            for x in self.cfg.get("safe_methods", ["GET", "HEAD"])
            if str(x).strip()
        } or {"GET", "HEAD"}
        self.require_json_response = bool(self.cfg.get("require_json_response", True))
        self.min_sensitive_signal_score = max(1, int(self.cfg.get("min_sensitive_signal_score", 3) or 3))
        self.ignore_paths = {
            _normalize_path(str(x))
            for x in self.cfg.get("ignore_paths", ["/", "/index.html"])
            if str(x).strip()
        } or {"/", "/index.html"}
        self.api_path_hints = tuple(
            _normalize_path(str(x))
            for x in self.cfg.get("api_path_hints", ["/api", "/v1/api", "/v2/api", "/graphql", "/open-api"])
            if str(x).strip()
        ) or ("/api", "/v1/api", "/v2/api", "/graphql", "/open-api")
        self.sensitive_query_params = {
            str(x).strip().lower()
            for x in self.cfg.get(
                "sensitive_query_params",
                [
                    "id",
                    "user_id",
                    "userid",
                    "account_id",
                    "accountid",
                    "wallet_id",
                    "walletid",
                    "trade_id",
                    "tradeid",
                    "position_id",
                    "positionid",
                    "transaction_id",
                    "transactionid",
                    "order_id",
                    "orderid",
                    "payment_id",
                    "paymentid",
                    "portfolio_id",
                    "portfolioid",
                    "email",
                    "phone",
                    "iban",
                ],
            )
            if str(x).strip()
        }
        self.candidate_markers = tuple(
            str(x).strip().lower()
            for x in self.cfg.get(
                "candidate_markers",
                ["idor", "bac", "access", "broken_object", "data_exposure", "auth"],
            )
            if str(x).strip()
        )

    def _is_candidate(self, finding: Finding) -> bool:
        category = str(finding.category or "").lower()
        title = str(finding.title or "").lower()
        hay = f"{category} {title}"
        return any(marker in hay for marker in self.candidate_markers)

    async def validate_batch(self, *, target: str, run_id: str, findings: list[Finding]) -> list[Finding]:
        if not self.enabled or not findings:
            return findings
        sessions = load_sessions(self.sessions_file)
        session_a = {"name": self.auth_context_a, **(sessions.get(self.auth_context_a, {}) or {})}
        session_b = {"name": self.auth_context_b, **(sessions.get(self.auth_context_b, {}) or {})}
        headers_a = auth_header(session_a) if session_a else {}
        headers_b = auth_header(session_b) if session_b else {}
        if not headers_a or not headers_b:
            self.logger.warning("impact_validator_sessions_missing headers_a_or_b_empty=true")
            return findings

        out: list[Finding] = []
        validated = 0
        for finding in findings:
            if validated >= self.max_replays_per_batch:
                out.append(finding)
                continue
            if not self._is_candidate(finding):
                out.append(finding)
                continue
            ev = finding.evidence if isinstance(finding.evidence, dict) else {}
            req = ev.get("request_auth_a", ev.get("request", {}))
            if not isinstance(req, dict):
                out.append(finding)
                continue
            method = str(req.get("method", "GET")).strip().upper()
            url = str(req.get("url", ev.get("base_url", ev.get("url", "")))).strip()
            if not url or method not in self.safe_methods:
                out.append(finding)
                continue
            validated += 1
            mutated = await self._validate_single(
                finding=finding,
                target=target,
                run_id=run_id,
                url=url,
                method=method,
                req_headers=_sanitize_request_headers(req.get("headers", {}) if isinstance(req.get("headers"), dict) else {}),
                body=req.get("body", None),
                headers_a=headers_a,
                headers_b=headers_b,
            )
            out.append(mutated)
        if validated:
            self.logger.info(f"impact_validator_batch target={target} validated_candidates={validated}")
        return out

    async def _validate_single(
        self,
        *,
        finding: Finding,
        target: str,
        run_id: str,
        url: str,
        method: str,
        req_headers: dict[str, str],
        body: Any,
        headers_a: dict[str, str],
        headers_b: dict[str, str],
    ) -> Finding:
        headers_owner = dict(req_headers)
        headers_owner.update(headers_a)
        headers_other = dict(req_headers)
        headers_other.update(headers_b)
        headers_anon = dict(req_headers)
        response_owner = await request_http_async(method, url, headers=headers_owner, body=body, timeout=self.timeout_seconds)
        response_other = await request_http_async(method, url, headers=headers_other, body=body, timeout=self.timeout_seconds)
        response_anon = await request_http_async(method, url, headers=headers_anon, body=body, timeout=self.timeout_seconds)

        st_owner = _to_int(response_owner.get("status", 0))
        st_other = _to_int(response_other.get("status", 0))
        st_anon = _to_int(response_anon.get("status", 0))
        txt_owner = str(response_owner.get("text", "") or "")
        txt_other = str(response_other.get("text", "") or "")
        txt_anon = str(response_anon.get("text", "") or "")
        path = _normalize_path(urlparse(url).path)
        api_like_path = _is_api_like_path(path, self.api_path_hints)
        sensitive_query_signal = _has_sensitive_query_signal(url, self.sensitive_query_params)
        owner_json_like = _is_json_like_response(response_owner)
        other_json_like = _is_json_like_response(response_other)
        anon_json_like = _is_json_like_response(response_anon)
        sensitive_score_anon = _sensitive_signal_score(txt_anon)
        path_ignored = path in self.ignore_paths
        sim_owner_other = _structure_similarity(txt_owner, txt_other)
        sim_owner_anon = _structure_similarity(txt_owner, txt_anon)

        metadata = finding.metadata.copy() if isinstance(finding.metadata, dict) else {}
        evidence = finding.evidence.copy() if isinstance(finding.evidence, dict) else {}
        classification = ""
        severity = str(finding.severity or "medium")
        category = str(finding.category or "")
        confidence = float(metadata.get("confidence_score", metadata.get("confidence", 0)) or 0)
        impact = float(metadata.get("impact", 0) or 0)

        critical_public_candidate = (
            st_owner in self.anon_success_status
            and st_anon in self.anon_success_status
            and sim_owner_anon >= self.similarity_threshold
            and not path_ignored
            and (api_like_path or sensitive_query_signal)
            and sensitive_score_anon >= self.min_sensitive_signal_score
        )
        if self.require_json_response and critical_public_candidate and not anon_json_like:
            critical_public_candidate = False

        if critical_public_candidate:
            classification = "critical_public_data_exposure"
            severity = "critical"
            category = "critical_public_data_exposure"
            confidence = max(98.0, confidence)
            impact = max(96.0, impact)
        else:
            confirmed_idor_candidate = (
                st_owner in self.anon_success_status
                and st_other in self.anon_success_status
                and st_anon in self.anon_block_status
                and sim_owner_other >= self.similarity_threshold
                and not path_ignored
                and (api_like_path or sensitive_query_signal)
            )
            if self.require_json_response and confirmed_idor_candidate and not (owner_json_like or other_json_like):
                confirmed_idor_candidate = False
            if confirmed_idor_candidate:
                classification = "confirmed_idor_bac"
                severity = "high"
                category = "confirmed_idor_bac"
                confidence = 100.0
                impact = max(92.0, impact)

        if classification:
            if SENSITIVE_FIELD_RE.search(txt_owner[:5000]):
                impact = max(95.0, impact)
                if classification == "confirmed_idor_bac":
                    severity = "critical"
            metadata["validation_mode"] = classification
            metadata["confidence_score"] = confidence
            metadata["confidence"] = confidence
            metadata["impact"] = impact
            metadata["discovery_source"] = str(metadata.get("discovery_source", finding.plugin))
            metadata["impact_validated"] = True
            metadata["impact_validator_run_id"] = run_id
            evidence["impact_validator_replay"] = {
                "target": target,
                "request": {"method": method, "url": url},
                "owner": {"status": st_owner, "length": _to_int(response_owner.get("length", 0)), "sha_hint": _sha_hint(txt_owner[:500])},
                "other": {"status": st_other, "length": _to_int(response_other.get("length", 0)), "sha_hint": _sha_hint(txt_other[:500])},
                "anonymous": {"status": st_anon, "length": _to_int(response_anon.get("length", 0)), "sha_hint": _sha_hint(txt_anon[:500])},
                "similarity_owner_other": sim_owner_other,
                "similarity_owner_anon": sim_owner_anon,
                "classification": classification,
                "path": path,
                "api_like_path": api_like_path,
                "sensitive_query_signal": sensitive_query_signal,
                "anon_json_like": anon_json_like,
                "sensitive_signal_score_anon": sensitive_score_anon,
            }
            return Finding(
                plugin=finding.plugin,
                target=finding.target,
                category=category,
                severity=severity,
                title=finding.title,
                evidence=evidence,
                metadata=metadata,
            )

        return finding
