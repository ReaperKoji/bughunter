from __future__ import annotations

import asyncio
import difflib
import hashlib
import json
import os
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from hunterops.http_client import request_http_async
from hunterops.plugin_base import Plugin
from hunterops.session_profiles import auth_header, load_sessions
from hunterops.storage import PostgresStorage
from hunterops.types import Finding, Task

SENSITIVE_ENDPOINT_KEYWORDS = (
    "admin",
    "internal",
    "v1/debug",
    "config",
    "staging",
    "export",
    "graphiql",
)
FINANCIAL_ENDPOINT_KEYWORDS = (
    "trade",
    "trading",
    "order",
    "orders",
    "position",
    "positions",
    "portfolio",
    "payment",
    "payout",
    "withdraw",
    "deposit",
    "wallet",
    "balance",
    "transaction",
    "kyc",
    "bank",
    "card",
    "graphql",
    "v1/api",
)
ID_PARAM_HINTS = (
    "id",
    "uid",
    "user_id",
    "account_id",
    "order_id",
    "invoice_id",
    "profile_id",
    "project_id",
    "payment_id",
    "trade_id",
    "position_id",
    "wallet_id",
    "transaction_id",
    "beneficiary_id",
)
DEFAULT_HEADER_CANDIDATES = ("X-Internal-ID", "X-Admin-Profile", "Version-Override", "X-Environment", "X-Tenant")
HEADER_VALUE_CANDIDATES = ("1", "true", "admin", "internal", "beta")
SENSITIVE_FIELDS = (
    "email",
    "cpf",
    "phone",
    "address",
    "token",
    "account",
    "wallet",
    "invoice",
    "user_id",
    "tenant",
    "balance",
    "equity",
    "margin",
    "available",
    "trade",
    "position",
    "transaction",
    "payment",
    "card",
    "bank",
)
TIER_1_SUFFIXES_DEFAULT = ("backend-capital.com",)
TIER_2_SUFFIXES_DEFAULT = ("capital.com",)
EMAIL_RE = re.compile(r"""[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}""")
UUID_RE = re.compile(r"""\b[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}\b""")
NUMERIC_ID_RE = re.compile(r"""\b[1-9][0-9]{2,18}\b""")

IGNORE_DYNAMIC_FIELDS = {
    "timestamp",
    "updated_at",
    "created_at",
    "csrf",
    "csrf_token",
    "session",
    "session_id",
    "nonce",
    "iat",
    "exp",
    "token",
    "request_id",
    "trace_id",
}
IGNORE_DYNAMIC_RE = re.compile(r"(time|timestamp|csrf|nonce|session|token|trace|request_id|updated|created|expiry|expires)$", re.IGNORECASE)


def _normalize_endpoint(raw: str) -> str:
    value = str(raw or "").strip()
    if not value:
        return ""
    if value.startswith("http://") or value.startswith("https://"):
        return urlparse(value).path or "/"
    if value.startswith("/"):
        return value
    return f"/{value}"


def _inject_query(url: str, param: str, value: str) -> str:
    p = urlparse(url)
    q = parse_qsl(p.query, keep_blank_values=True)
    q = [item for item in q if item[0] != param]
    q.append((param, value))
    return urlunparse((p.scheme, p.netloc, p.path, p.params, urlencode(q), p.fragment))


def _remove_dynamic_fields(value: Any) -> Any:
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, child in value.items():
            key_s = str(key)
            key_l = key_s.lower()
            if key_l in IGNORE_DYNAMIC_FIELDS or IGNORE_DYNAMIC_RE.search(key_l):
                continue
            out[key_s] = _remove_dynamic_fields(child)
        return out
    if isinstance(value, list):
        return [_remove_dynamic_fields(x) for x in value[:120]]
    return value


def _load_json(text: str) -> dict[str, Any]:
    if not text:
        return {}
    try:
        obj = json.loads(text)
    except Exception:
        return {}
    return obj if isinstance(obj, dict) else {}


def _structure_paths(value: Any, prefix: str = "") -> set[str]:
    out: set[str] = set()
    if isinstance(value, dict):
        for key, child in value.items():
            key_s = str(key)
            path = f"{prefix}.{key_s}" if prefix else key_s
            out.add(path)
            out |= _structure_paths(child, path)
    elif isinstance(value, list):
        path = f"{prefix}[]" if prefix else "[]"
        out.add(path)
        for item in value[:6]:
            out |= _structure_paths(item, path)
    return out


def _jaccard(a: set[str], b: set[str]) -> float:
    if not a and not b:
        return 1.0
    return len(a & b) / max(1, len(a | b))


def _content_ratio(a: str, b: str) -> float:
    return difflib.SequenceMatcher(None, a, b).ratio()


def _extract_endpoints_and_headers(rows: list[dict[str, Any]]) -> tuple[set[str], set[str]]:
    endpoints: set[str] = set()
    headers: set[str] = set(DEFAULT_HEADER_CANDIDATES)
    for row in rows:
        category = str(row.get("category", "")).lower()
        evidence = row.get("evidence", {}) if isinstance(row.get("evidence"), dict) else {}
        if category in {"js_discovery", "parameter_intelligence", "surface_map"}:
            arr = evidence.get("endpoints", [])
            if isinstance(arr, list):
                for item in arr:
                    if isinstance(item, str):
                        ep = _normalize_endpoint(item)
                        if ep:
                            endpoints.add(ep)
            sample = evidence.get("mapped_sample", [])
            if isinstance(sample, list):
                for item in sample:
                    if not isinstance(item, dict):
                        continue
                    ep = _normalize_endpoint(str(item.get("endpoint", "")))
                    if ep:
                        endpoints.add(ep)
            param_rows = evidence.get("parameter_map_sample", [])
            if isinstance(param_rows, list):
                for item in param_rows:
                    if not isinstance(item, dict):
                        continue
                    ep = _normalize_endpoint(str(item.get("endpoint", "")))
                    if ep:
                        endpoints.add(ep)
            token_names = evidence.get("token_names", [])
            if isinstance(token_names, list):
                for name in token_names:
                    raw = str(name).strip()
                    if raw.lower().startswith("x-") or "override" in raw.lower():
                        headers.add(raw)
            header_names = evidence.get("header_names", []) or evidence.get("possible_headers", [])
            if isinstance(header_names, list):
                for name in header_names:
                    raw = str(name).strip()
                    if raw.lower().startswith("x-") or "override" in raw.lower():
                        headers.add(raw)
    return endpoints, headers


def _sensitive_endpoint_priority(endpoint: str) -> int:
    text = endpoint.lower()
    if any(k in text for k in FINANCIAL_ENDPOINT_KEYWORDS):
        return 130
    if any(k in text for k in SENSITIVE_ENDPOINT_KEYWORDS):
        return 100
    return 72


def _is_financial_endpoint(endpoint: str) -> bool:
    text = str(endpoint or "").lower()
    return any(k in text for k in FINANCIAL_ENDPOINT_KEYWORDS)


def _host_tier(host: str, tier1_suffixes: tuple[str, ...], tier2_suffixes: tuple[str, ...]) -> int:
    value = str(host or "").strip().lower()
    for suffix in tier1_suffixes:
        sfx = str(suffix or "").strip().lower()
        if sfx and (value == sfx or value.endswith("." + sfx)):
            return 1
    for suffix in tier2_suffixes:
        sfx = str(suffix or "").strip().lower()
        if sfx and (value == sfx or value.endswith("." + sfx)):
            return 2
    return 3


def _sensitive_object_hits(text: str, object_values: set[str]) -> list[str]:
    if not text or not object_values:
        return []
    hits: list[str] = []
    lower = text.lower()
    for value in list(object_values)[:500]:
        raw = str(value).strip()
        if not raw:
            continue
        if raw.lower() in lower:
            hits.append(raw)
            if len(hits) >= 20:
                break
    return sorted(set(hits))


def _extract_entities_from_text(text: str, cap: int = 60) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for hit in EMAIL_RE.findall(text):
        out.append(("email", hit.strip()))
    for hit in UUID_RE.findall(text):
        out.append(("object_reference", hit.strip()))
    for hit in NUMERIC_ID_RE.findall(text):
        out.append(("numeric_id", hit.strip()))
    dedupe: set[str] = set()
    compact: list[tuple[str, str]] = []
    for etype, value in out:
        sig = f"{etype}|{value.lower()}"
        if sig in dedupe:
            continue
        dedupe.add(sig)
        compact.append((etype, value))
        if len(compact) >= cap:
            break
    return compact


def _build_spawn_tasks(
    *,
    target: str,
    run_id: str,
    endpoint: str,
    param: str,
    entity_values: list[str],
    current_depth: int,
    max_depth: int,
) -> list[dict[str, Any]]:
    if current_depth >= max_depth:
        return []
    out: list[dict[str, Any]] = []
    dedupe: set[str] = set()
    for raw in entity_values[:40]:
        ep = _inject_query(endpoint, param, raw) if endpoint.startswith("http") else _inject_query(f"https://{target}{endpoint}", param, raw)
        path = urlparse(ep).path or endpoint
        path_q = f"{path}?{urlparse(ep).query}" if urlparse(ep).query else path
        for plugin_name in ("parameter_intelligence", "differential_auth_prover"):
            sig = f"{plugin_name}|{path_q}|{raw}"
            if sig in dedupe:
                continue
            dedupe.add(sig)
            out.append(
                {
                    "plugin": plugin_name,
                    "target": target,
                    "payload": {
                        "run_id": run_id,
                        "seed_paths": [path_q],
                        "trigger": "aggressive_entity_expansion",
                        "priority": 100,
                        "priority_score": 100,
                        "_depth": current_depth + 1,
                    },
                }
            )
    return out[:120]


def _path(value: str) -> Path:
    return Path(value)


class PluginImpl(Plugin):
    name = "differential_auth_prover"

    async def run(self, task: Task, context: dict) -> list[Finding]:
        cfg = context["config"].get("modules", {}).get(self.name, {})
        payload = task.payload if isinstance(task.payload, dict) else {}
        run_id = str(payload.get("run_id", "")).strip()
        if not run_id:
            return []

        timeout = int(context["runtime"].get("timeout_seconds", 25))
        concurrency = max(2, int(context["runtime"].get("concurrency", 10)))
        tier1_suffixes = tuple(str(x).strip().lower() for x in cfg.get("tier1_scope_suffixes", TIER_1_SUFFIXES_DEFAULT) if str(x).strip())
        tier2_suffixes = tuple(str(x).strip().lower() for x in cfg.get("tier2_scope_suffixes", TIER_2_SUFFIXES_DEFAULT) if str(x).strip())
        target_tier = _host_tier(task.target, tier1_suffixes=tier1_suffixes, tier2_suffixes=tier2_suffixes)
        enforce_scope_suffixes = bool(cfg.get("enforce_scope_suffixes", False))
        if enforce_scope_suffixes and target_tier > 2:
            return []

        max_probes_default = int(cfg.get("max_probes", 90))
        max_probes_tier1 = int(cfg.get("max_probes_tier1", max(max_probes_default, 220)))
        max_probes_tier2 = int(cfg.get("max_probes_tier2", max(max_probes_default, 140)))
        if target_tier == 1:
            max_probes = max(40, max_probes_tier1)
        elif target_tier == 2:
            max_probes = max(30, max_probes_tier2)
        else:
            max_probes = max(20, max_probes_default)
        financial_only = bool(cfg.get("financial_endpoint_focus_only", False))
        min_structure = float(cfg.get("min_structure_similarity_pct", 90))
        min_content_similarity = float(cfg.get("min_content_similarity_pct", 85))
        flag_length_header_diff = bool(cfg.get("flag_length_header_diff", True))
        min_length_diff_bytes = max(1, int(cfg.get("min_length_diff_bytes", 1) or 1))
        min_header_count_diff = max(1, int(cfg.get("min_header_count_diff", 1) or 1))
        low_signal_confidence_floor = float(cfg.get("low_signal_confidence_floor", 62) or 62)
        sess_file = str(cfg.get("sessions_file", "data/sessions.yaml"))
        owner_name = str(cfg.get("session_owner", cfg.get("auth_context_a", "user")))
        other_name = str(cfg.get("session_other", cfg.get("auth_context_b", "user_b")))
        max_depth = int(context["runtime"].get("recursion_max_depth", 5))
        current_depth = int(payload.get("_depth", 0) or 0)
        base_url = f"https://{task.target}"

        sessions = load_sessions(_path(sess_file))
        owner_hdr = auth_header(sessions.get(owner_name, {})) if sessions.get(owner_name) else {}
        other_hdr = auth_header(sessions.get(other_name, {})) if sessions.get(other_name) else {}
        unauth_hdr: dict[str, str] = {}
        if not owner_hdr or not other_hdr:
            return []

        pg_cfg = context["config"].get("storage", {}).get("postgres", {})
        dsn_env = str(pg_cfg.get("dsn_env", "HUNTEROPS_POSTGRES_DSN"))
        dsn = os.getenv(dsn_env, "")
        if not bool(pg_cfg.get("enabled", False)) or not dsn:
            return []

        try:
            storage = PostgresStorage(dsn=dsn, enabled=True)
            storage.ensure_research_schema()
        except Exception:
            return []

        try:
            run_rows = storage.fetch_run_findings(run_id=run_id, target=task.target)
            endpoints, header_candidates = _extract_endpoints_and_headers(run_rows)
            endpoints |= set(storage.list_known_endpoints(target=task.target, run_id=run_id, limit=600))
            param_rows = storage.list_endpoint_parameters(run_id=run_id, limit=3000)
            known_entities = storage.list_recent_entities(target=task.target, limit=800)
            object_rows = storage.list_objects(run_id=run_id, target=task.target, limit=1000) if hasattr(storage, "list_objects") else []
        except Exception:
            return []

        seed_paths = payload.get("seed_paths", [])
        if isinstance(seed_paths, list):
            for item in seed_paths:
                if isinstance(item, str):
                    ep = _normalize_endpoint(item)
                    if ep:
                        endpoints.add(ep)
        if not endpoints:
            return []

        params_by_endpoint: dict[str, list[str]] = {}
        for row in param_rows:
            ep = _normalize_endpoint(str(row.get("endpoint", "")))
            pn = str(row.get("param_name", "")).strip()
            if not ep or not pn:
                continue
            params_by_endpoint.setdefault(ep, [])
            if pn not in params_by_endpoint[ep]:
                params_by_endpoint[ep].append(pn)

        entity_values: list[str] = []
        seen_entities: set[str] = set()
        substitution = payload.get("entity_substitution", {}) if isinstance(payload.get("entity_substitution"), dict) else {}
        sub_value = str(substitution.get("entity_value", "")).strip()
        if sub_value:
            entity_values.append(sub_value)
            seen_entities.add(sub_value.lower())
        for row in object_rows:
            val = str(row.get("object_key", "")).strip()
            if val and val.lower() not in seen_entities:
                entity_values.append(val)
                seen_entities.add(val.lower())
        for row in known_entities:
            val = str(row.get("entity_value", "")).strip()
            if val and val.lower() not in seen_entities:
                entity_values.append(val)
                seen_entities.add(val.lower())
        if not entity_values:
            entity_values = ["1", "2", "1001"]

        object_value_set = {str(x).strip().lower() for x in entity_values if str(x).strip()}
        probes: list[tuple[str, str, str]] = []
        dedupe_probe: set[str] = set()
        ordered_endpoints = sorted(endpoints, key=lambda ep: (_sensitive_endpoint_priority(ep), ep), reverse=True)
        for ep in ordered_endpoints:
            if financial_only and not _is_financial_endpoint(ep):
                continue
            params = params_by_endpoint.get(ep, [])
            if not params:
                params = ["id", "user_id", "account_id"]
            params = sorted(
                params,
                key=lambda p: (1 if (str(p).lower() in ID_PARAM_HINTS or "id" in str(p).lower()) else 0),
                reverse=True,
            )
            for param in params:
                pl = param.lower()
                if pl not in ID_PARAM_HINTS and "id" not in pl:
                    continue
                for entity_value in entity_values[:12]:
                    sig = f"{ep}|{param}|{entity_value}"
                    if sig in dedupe_probe:
                        continue
                    dedupe_probe.add(sig)
                    probes.append((ep, param, entity_value))
                    if len(probes) >= max_probes:
                        break
                if len(probes) >= max_probes:
                    break
            if len(probes) >= max_probes:
                break

        sem = asyncio.Semaphore(concurrency)
        findings: list[Finding] = []
        edge_rows: list[dict[str, Any]] = []
        object_upserts: list[dict[str, Any]] = []

        async def run_probe(endpoint: str, param: str, entity_value: str) -> Finding | None:
            probe_url = _inject_query(f"{base_url}{endpoint}", param, entity_value)
            async with sem:
                owner_req = request_http_async("GET", probe_url, headers=owner_hdr, timeout=timeout)
                other_req = request_http_async("GET", probe_url, headers=other_hdr, timeout=timeout)
                unauth_req = request_http_async("GET", probe_url, headers=unauth_hdr, timeout=timeout)
                r_owner, r_other, r_unauth = await asyncio.gather(owner_req, other_req, unauth_req)

            status_owner = int(r_owner.get("status", 0) or 0)
            status_other = int(r_other.get("status", 0) or 0)
            status_unauth = int(r_unauth.get("status", 0) or 0)
            if status_owner not in {200, 201} or status_other not in {200, 201}:
                return None

            owner_len = int(r_owner.get("length", 0) or 0)
            other_len = int(r_other.get("length", 0) or 0)
            owner_header_count = len(r_owner.get("headers", {}) if isinstance(r_owner.get("headers"), dict) else {})
            other_header_count = len(r_other.get("headers", {}) if isinstance(r_other.get("headers"), dict) else {})
            length_diff_bytes = abs(owner_len - other_len)
            header_count_diff = abs(owner_header_count - other_header_count)
            length_delta_ratio_pct = round((length_diff_bytes / max(1.0, float(max(owner_len, other_len)))) * 100.0, 2)
            has_length_header_signal = flag_length_header_diff and (
                length_diff_bytes >= min_length_diff_bytes or header_count_diff >= min_header_count_diff
            )

            owner_json = _remove_dynamic_fields(_load_json(str(r_owner.get("text", ""))))
            other_json = _remove_dynamic_fields(_load_json(str(r_other.get("text", ""))))
            unauth_json = _remove_dynamic_fields(_load_json(str(r_unauth.get("text", ""))))
            owner_norm = json.dumps(owner_json, sort_keys=True, ensure_ascii=True)
            other_norm = json.dumps(other_json, sort_keys=True, ensure_ascii=True)
            unauth_norm = json.dumps(unauth_json, sort_keys=True, ensure_ascii=True)

            owner_struct = _structure_paths(owner_json)
            other_struct = _structure_paths(other_json)
            unauth_struct = _structure_paths(unauth_json)
            structure_sim = round(_jaccard(owner_struct, other_struct) * 100.0, 2)
            content_sim = round(_content_ratio(owner_norm, other_norm) * 100.0, 2)
            unauth_structure = round(_jaccard(owner_struct, unauth_struct) * 100.0, 2)
            unauth_content = round(_content_ratio(owner_norm, unauth_norm) * 100.0, 2)
            data_different = owner_norm != other_norm
            owner_text = str(r_owner.get("text", ""))
            other_text = str(r_other.get("text", ""))
            same_object_exposed = entity_value.lower() in other_text.lower() and status_unauth in {0, 401, 403}
            content_variant = data_different and content_sim <= min_content_similarity
            insecure_success = structure_sim >= min_structure and (content_variant or same_object_exposed)
            if not insecure_success and not has_length_header_signal:
                return None

            sensitive_hits = _sensitive_object_hits(other_text, object_value_set)
            sensitive_field_delta = [field for field in SENSITIVE_FIELDS if field in owner_json and field in other_json and str(owner_json.get(field)) != str(other_json.get(field))]
            unauth_blocked = status_unauth in {0, 401, 403}
            financial_endpoint = _is_financial_endpoint(endpoint)
            financial_field_hit = any(
                marker in str(other_text).lower()
                for marker in (
                    "balance",
                    "equity",
                    "margin",
                    "position",
                    "trade",
                    "transaction",
                    "payment",
                    "wallet",
                )
            )

            delta_factor = max(0.0, min(1.0, (100.0 - content_sim) / 100.0))
            confidence = 60.0
            confidence += max(0.0, min(20.0, (structure_sim - 80.0) * 0.8))
            confidence += 20.0 * delta_factor
            if unauth_blocked:
                confidence += 8.0
            if sensitive_hits:
                confidence += 8.0
            if sensitive_field_delta:
                confidence += 6.0
            if financial_endpoint:
                confidence += 6.0
            if financial_field_hit:
                confidence += 6.0
            if has_length_header_signal:
                confidence += min(8.0, float(length_delta_ratio_pct) / 6.0)
                confidence += min(6.0, float(header_count_diff) * 2.0)
            confidence = round(min(98.0, max(low_signal_confidence_floor, confidence)), 2)

            if insecure_success:
                severity = "critical" if (confidence >= 90 or (financial_endpoint and confidence >= 86)) else "high"
                if financial_endpoint:
                    category = "financial_idor_bac_indicator" if severity != "critical" else "critical_financial_idor_bac"
                else:
                    category = "critical_idor_vulnerability" if severity == "critical" else "idor_behavior_indicator"
            else:
                severity = "medium" if (financial_endpoint or unauth_blocked) else "low"
                category = "idor_response_discrepancy"
            extracted_entities = _extract_entities_from_text(owner_text + "\n" + other_text, cap=40)
            spawn_values = [entity_value] + [x[1] for x in extracted_entities]
            spawn_tasks = _build_spawn_tasks(
                target=task.target,
                run_id=run_id,
                endpoint=endpoint,
                param=param,
                entity_values=spawn_values,
                current_depth=current_depth,
                max_depth=max_depth,
            )
            spawn_tasks.insert(
                0,
                {
                    "plugin": "report_synthesis",
                    "target": task.target,
                    "payload": {
                        "run_id": run_id,
                        "priority": 100,
                        "_depth": current_depth + 1,
                        "seed_paths": [endpoint],
                        "trigger": "differential_auth_prover",
                    },
                },
            )

            edge_rows.extend(
                [
                    {
                        "src_type": "endpoint",
                        "src_key": endpoint,
                        "dst_type": "object",
                        "dst_key": entity_value,
                        "edge_type": "cross_context_object_access",
                        "confidence_score": confidence,
                        "metadata": {"parameter": param, "plugin": self.name},
                    },
                    {
                        "src_type": "auth_context",
                        "src_key": owner_name,
                        "dst_type": "endpoint",
                        "dst_key": endpoint,
                        "edge_type": "authorized_access",
                        "confidence_score": 70.0,
                        "metadata": {"plugin": self.name},
                    },
                    {
                        "src_type": "auth_context",
                        "src_key": other_name,
                        "dst_type": "endpoint",
                        "dst_key": endpoint,
                        "edge_type": "cross_context_access",
                        "confidence_score": confidence,
                        "metadata": {"plugin": self.name, "parameter": param, "entity_id": entity_value},
                    },
                ]
            )
            object_upserts.append(
                {
                    "object_type": "object_reference" if UUID_RE.fullmatch(entity_value) else "numeric_id",
                    "object_key": entity_value,
                    "source_endpoint": endpoint,
                    "confidence_score": confidence,
                    "discovery_source": self.name,
                    "metadata": {"parameter": param, "classification": category},
                }
            )
            for etype, evalue in extracted_entities:
                object_upserts.append(
                    {
                        "object_type": etype,
                        "object_key": evalue,
                        "source_endpoint": endpoint,
                        "confidence_score": max(66.0, confidence - 10.0),
                        "discovery_source": self.name,
                        "metadata": {"parameter": param, "classification": "response_entity"},
                    }
                )

            return Finding(
                plugin=self.name,
                target=task.target,
                category=category,
                severity=severity,
                title=f"Potential IDOR via differential auth replay at {endpoint} using {param}",
                evidence={
                    "request_auth_a": {"method": "GET", "url": probe_url, "headers": owner_hdr},
                    "response_auth_a": {
                        "status": status_owner,
                        "length": owner_len,
                        "headers": r_owner.get("headers", {}),
                        "body": owner_text,
                    },
                    "request_auth_b": {"method": "GET", "url": probe_url, "headers": other_hdr},
                    "response_auth_b": {
                        "status": status_other,
                        "length": other_len,
                        "headers": r_other.get("headers", {}),
                        "body": other_text,
                    },
                    "request_unauthenticated": {"method": "GET", "url": probe_url, "headers": unauth_hdr},
                    "response_unauthenticated": {
                        "status": status_unauth,
                        "length": int(r_unauth.get("length", 0) or 0),
                        "headers": r_unauth.get("headers", {}),
                        "body": str(r_unauth.get("text", "")),
                    },
                    "diff_map": {
                        "entity_id": entity_value,
                        "parameter": param,
                        "status_owner": status_owner,
                        "status_other": status_other,
                        "status_unauthenticated": status_unauth,
                        "owner_length": owner_len,
                        "other_length": other_len,
                        "length_diff_bytes": length_diff_bytes,
                        "length_delta_ratio_pct": length_delta_ratio_pct,
                        "owner_header_count": owner_header_count,
                        "other_header_count": other_header_count,
                        "header_count_diff": header_count_diff,
                        "structure_similarity_pct": structure_sim,
                        "content_similarity_pct": content_sim,
                        "unauth_structure_similarity_pct": unauth_structure,
                        "unauth_content_similarity_pct": unauth_content,
                        "sensitive_object_hits": sensitive_hits,
                        "sensitive_field_delta": sensitive_field_delta,
                        "owner_hash": hashlib.sha256(owner_norm.encode("utf-8")).hexdigest(),
                        "other_hash": hashlib.sha256(other_norm.encode("utf-8")).hexdigest(),
                        "unauth_hash": hashlib.sha256(unauth_norm.encode("utf-8")).hexdigest(),
                        "ignore_dynamic_fields": sorted(list(IGNORE_DYNAMIC_FIELDS)),
                    },
                    "tested_parameter": param,
                    "entity_id": entity_value,
                    "endpoint": endpoint,
                    "discovery_source": self.name,
                    "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                },
                metadata={
                    "novelty": float(payload.get("priority", _sensitive_endpoint_priority(endpoint))),
                    "confidence": confidence,
                    "confidence_score": confidence,
                    "impact": 96 if (severity == "critical" and financial_endpoint) else (94 if severity == "critical" else (88 if financial_endpoint else 84)),
                    "priority_score": _sensitive_endpoint_priority(endpoint),
                    "discovery_source": self.name,
                    "target_tier": target_tier,
                    "financial_endpoint": financial_endpoint,
                    "low_signal_mode": bool(not insecure_success and has_length_header_signal),
                    "business_impact": (
                        "Potential exposure or unauthorized manipulation of trading/payment data path."
                        if financial_endpoint
                        else (
                            "Potential unauthorized object-level data access."
                            if insecure_success
                            else "Cross-user response discrepancy may expose partial identifiers or metadata."
                        )
                    ),
                    "spawn_tasks": spawn_tasks,
                },
            )

        probe_results = await asyncio.gather(*(run_probe(ep, param, val) for ep, param, val in probes), return_exceptions=False)
        for finding in probe_results:
            if isinstance(finding, Finding):
                findings.append(finding)

        # Behavioral header-variation exploration for sensitive/internal routes.
        sensitive_cap = 80 if target_tier == 1 else (55 if target_tier == 2 else 40)
        sensitive_routes = sorted(
            [ep for ep in endpoints if any(k in ep.lower() for k in (*SENSITIVE_ENDPOINT_KEYWORDS, *FINANCIAL_ENDPOINT_KEYWORDS))],
            key=lambda ep: (_sensitive_endpoint_priority(ep), ep),
            reverse=True,
        )[:sensitive_cap]
        header_findings: list[Finding] = []
        if sensitive_routes and header_candidates:
            async def test_header_route(endpoint: str, header_name: str, value: str) -> Finding | None:
                url = f"{base_url}{endpoint}"
                async with sem:
                    baseline = await request_http_async("GET", url, headers=other_hdr, timeout=timeout)
                    mutated_headers = other_hdr.copy()
                    mutated_headers[header_name] = value
                    variant = await request_http_async("GET", url, headers=mutated_headers, timeout=timeout)
                base_status = int(baseline.get("status", 0) or 0)
                var_status = int(variant.get("status", 0) or 0)
                base_len = int(baseline.get("length", 0) or 0)
                var_len = int(variant.get("length", 0) or 0)
                jump = base_status in {0, 401, 403, 404} and var_status in {200, 201}
                structural_jump = var_status in {200, 201} and (var_len > max(60, int(base_len * 1.35)))
                if not jump and not structural_jump:
                    return None
                confidence = 83.0 if jump else 76.0
                edge_rows.append(
                    {
                        "src_type": "header",
                        "src_key": header_name,
                        "dst_type": "endpoint",
                        "dst_key": endpoint,
                        "edge_type": "environmental_jump_header",
                        "confidence_score": confidence,
                        "metadata": {"header_value": value, "plugin": self.name},
                    }
                )
                return Finding(
                    plugin=self.name,
                    target=task.target,
                    category="environmental_jump_indicator",
                    severity="high" if jump else "medium",
                    title=f"Header variation may expose internal route {endpoint} via {header_name}",
                    evidence={
                        "endpoint": endpoint,
                        "header_name": header_name,
                        "header_value": value,
                        "baseline_request": {"method": "GET", "url": url, "headers": other_hdr},
                        "baseline_response": {"status": base_status, "length": base_len},
                        "variant_request": {"method": "GET", "url": url, "headers": mutated_headers},
                        "variant_response": {"status": var_status, "length": var_len, "headers": variant.get("headers", {})},
                        "discovery_source": self.name,
                    },
                    metadata={
                        "novelty": 90,
                        "confidence": confidence,
                        "confidence_score": confidence,
                        "impact": 82 if jump else 70,
                        "priority_score": 100,
                        "discovery_source": self.name,
                    },
                )

            header_jobs = []
            headers_sorted = sorted([h for h in header_candidates if h.lower().startswith("x-") or "override" in h.lower()])[:16]
            header_job_cap = 360 if target_tier == 1 else (260 if target_tier == 2 else 220)
            for ep in sensitive_routes:
                for header_name in headers_sorted:
                    for value in HEADER_VALUE_CANDIDATES[:4]:
                        header_jobs.append(test_header_route(ep, header_name, value))
                        if len(header_jobs) >= header_job_cap:
                            break
                    if len(header_jobs) >= header_job_cap:
                        break
                if len(header_jobs) >= header_job_cap:
                    break
            if header_jobs:
                raw_header_findings = await asyncio.gather(*header_jobs, return_exceptions=False)
                for item in raw_header_findings:
                    if isinstance(item, Finding):
                        header_findings.append(item)
        findings.extend(header_findings)

        # Persist attack graph relationships + discovered objects for cross-pollination.
        if findings:
            try:
                if object_upserts:
                    storage.upsert_objects(run_id=run_id, target=task.target, rows=object_upserts)
                if edge_rows:
                    storage.upsert_attack_graph_edges(
                        run_id=run_id,
                        target=task.target,
                        edges=edge_rows,
                        discovery_source=self.name,
                        confidence_score=78.0,
                    )
            except Exception:
                pass
        return findings
