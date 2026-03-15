from __future__ import annotations

import asyncio
import json
import os
import re
from datetime import UTC, datetime
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from hunterops.evidence import save_http_evidence
from hunterops.http_client import request_http_async
from hunterops.endpoint_cache import EndpointCache
from hunterops.intelligence import http_diff_score
from hunterops.plugin_base import Plugin
from hunterops.storage import PostgresStorage
from hunterops.types import Finding, Task

SCRIPT_RE = re.compile(r"""<script[^>]+src=['"]([^'"]+)['"]""", re.IGNORECASE)
JS_OBJ_KEY_RE = re.compile(r"""['"]([A-Za-z_][A-Za-z0-9_\-]{1,50})['"]\s*:""")
PARAM_HINT_RE = re.compile(r"""[?&]([A-Za-z0-9_\-]{1,50})=""")
EMAIL_RE = re.compile(r"""[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}""")
UUID_RE = re.compile(r"""\b[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}\b""")
NUMERIC_ID_RE = re.compile(r"""\b[1-9][0-9]{2,18}\b""")


class _FormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.fields: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() not in {"input", "select", "textarea"}:
            return
        amap = {k.lower(): (v or "") for k, v in attrs}
        name = amap.get("name", "").strip()
        if name:
            self.fields.add(name)


def infer_param_type(name: str) -> str:
    n = name.lower()
    if any(k in n for k in ("email", "e-mail", "mail")):
        return "email"
    if any(k in n for k in ("id", "uid", "user_id", "account_id", "invoice_id", "order_id", "profile_id")):
        return "numeric_id"
    if any(k in n for k in ("identifier", "reference", "ref")):
        return "identifier"
    if any(k in n for k in ("token", "jwt", "session", "auth", "key", "secret")):
        return "token"
    if any(k in n for k in ("url", "uri", "redirect", "callback")):
        return "url"
    if any(k in n for k in ("file", "image", "avatar", "upload")):
        return "file"
    if any(k in n for k in ("enabled", "active", "flag", "is_")):
        return "boolean"
    if any(k in n for k in ("count", "page", "limit", "offset", "qty", "amount", "number")):
        return "number"
    return "string"


def attack_vectors(param_type: str) -> list[str]:
    mapping = {
        "email": ["data-exposure-review", "privacy-review"],
        "numeric_id": ["access-pattern-check", "object-reference-check"],
        "identifier": ["access-pattern-check", "object-reference-check"],
        "token": ["token-consistency-check", "auth-context-check"],
        "url": ["open-redirect-indicator-check", "ssrf-indicator-check"],
        "file": ["file-handling-review"],
        "boolean": ["logic-branch-review"],
        "number": ["range/overflow-review"],
        "string": ["input-validation-review"],
    }
    return mapping.get(param_type, ["input-validation-review"])


def set_query(url: str, key: str, value: str) -> str:
    p = urlparse(url)
    q = parse_qs(p.query)
    q[key] = [value]
    flat = []
    for k, vals in q.items():
        for v in vals:
            flat.append((k, v))
    return urlunparse((p.scheme, p.netloc, p.path, p.params, urlencode(flat), p.fragment))


def _json_keys(text: str) -> list[str]:
    try:
        obj = json.loads(text)
    except Exception:
        return []
    if isinstance(obj, dict):
        return sorted(list(obj.keys()))
    return []


class PluginImpl(Plugin):
    name = "parameter_intelligence"

    async def run(self, task: Task, context: dict) -> list[Finding]:
        cfg = context["config"].get("modules", {}).get(self.name, {})
        timeout = int(context["runtime"]["timeout_seconds"])
        base = f"https://{task.target}"
        payload = task.payload if isinstance(task.payload, dict) else {}
        default_seeds = cfg.get("seed_paths", ["/", "/search?q=test", "/api/users?id=1", "/api/orders?order_id=1001"])
        payload_seeds = payload.get("seed_paths", []) if isinstance(payload.get("seed_paths"), list) else []
        max_seed_paths = max(1, int(cfg.get("max_seed_paths", 12)))
        seed_candidates = payload_seeds if payload_seeds else default_seeds
        seeds: list[str] = []
        seen_seeds: set[str] = set()
        for raw_seed in seed_candidates if isinstance(seed_candidates, list) else []:
            seed = str(raw_seed).strip()
            if not seed:
                continue
            if not seed.startswith("http"):
                seed = seed if seed.startswith("/") else f"/{seed}"
            if seed in seen_seeds:
                continue
            seen_seeds.add(seed)
            seeds.append(seed)
            if len(seeds) >= max_seed_paths:
                break
        if not seeds:
            seeds = ["/"]
        cache = context.get("endpoint_cache")
        if isinstance(cache, EndpointCache):
            filtered_seeds: list[str] = []
            for seed in seeds:
                if cache.was_seen(plugin=self.name, target=task.target, endpoint=seed):
                    continue
                filtered_seeds.append(seed)
            if not filtered_seeds:
                return []
            seeds = filtered_seeds
        run_id = str(payload.get("run_id", ""))
        evidence_root = Path(str(cfg.get("evidence_dir", "data/evidence/engine")))
        max_safe_probes = int(cfg.get("max_safe_probes", 25))
        max_script_fetch = max(0, int(cfg.get("max_script_fetch", 20)))
        request_delay = max(0.0, float(payload.get("request_delay_seconds", 0) or 0.0))
        user_agent = str(payload.get("user_agent", "")).strip()
        request_headers = {"User-Agent": user_agent} if user_agent else {}

        async def _fetch(url: str) -> dict[str, object]:
            response = await request_http_async("GET", url, headers=request_headers, timeout=timeout)
            if request_delay > 0:
                await asyncio.sleep(request_delay)
            return response

        endpoint_params: dict[str, set[str]] = {}
        script_urls: set[str] = set()
        req_resp: list[dict[str, object]] = []
        for p in seeds:
            url = p if p.startswith("http") else f"{base}{p}"
            r = await _fetch(url)
            text = str(r.get("text", ""))
            ep = urlparse(url).path or "/"
            if isinstance(cache, EndpointCache):
                cache.mark_seen(plugin=self.name, target=task.target, endpoint=ep)
            req_resp.append(
                {
                    "request": {"method": "GET", "url": url, "headers": request_headers},
                    "response": {"status": r.get("status", 0), "length": r.get("length", 0)},
                    "headers": r.get("headers", {}),
                    "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                    "discovery_source": "parameter_intelligence",
                }
            )

            qp = set(parse_qs(urlparse(url).query).keys()) | set(PARAM_HINT_RE.findall(url))
            if qp:
                endpoint_params.setdefault(ep, set()).update(qp)

            fp = _FormParser()
            try:
                fp.feed(text)
            except Exception:
                pass
            if fp.fields:
                endpoint_params.setdefault(ep, set()).update(fp.fields)

            for src in SCRIPT_RE.findall(text):
                if src.startswith("http"):
                    script_urls.add(src)
                elif src.startswith("/"):
                    script_urls.add(base + src)

            if "application/json" in str((r.get("headers") or {}).get("Content-Type", "")).lower():
                try:
                    obj = json.loads(text)
                    if isinstance(obj, dict):
                        endpoint_params.setdefault(ep, set()).update({str(k) for k in obj.keys()})
                except Exception:
                    pass

        for jsu in sorted(script_urls)[:max_script_fetch]:
            if urlparse(jsu).netloc not in {"", task.target}:
                continue
            jsr = await _fetch(jsu)
            js = str(jsr.get("text", ""))
            keys = set(JS_OBJ_KEY_RE.findall(js))
            if keys:
                endpoint_params.setdefault(urlparse(jsu).path or "/", set()).update(keys)

        if not endpoint_params:
            return []
        typed: list[dict[str, object]] = []
        db_rows: list[dict[str, object]] = []
        entity_rows: list[dict[str, object]] = []
        object_rows: list[dict[str, object]] = []
        for ep, params in endpoint_params.items():
            for p in sorted(params):
                ptype = infer_param_type(p)
                row = {
                    "endpoint": ep,
                    "parameter": p,
                    "type": ptype,
                    "attack_vectors": attack_vectors(ptype),
                }
                typed.append(row)
                db_rows.append(
                    {
                        "endpoint": ep,
                        "method": "GET",
                        "param_name": p,
                        "param_location": "query",
                        "param_type": ptype,
                        "risk_score": 70.0 if ptype in {"numeric_id", "identifier"} else 35.0,
                        "discovery_source": "parameter_intelligence",
                        "evidence_ref": "",
                    }
                )

        findings: list[Finding] = [
            Finding(
                plugin=self.name,
                target=task.target,
                category="parameter_intelligence",
                severity="info",
                title=f"Parameter intelligence mapped {len(typed)} endpoint-parameter relations",
                evidence={"request_response_sample": req_resp[:25], "parameter_map_sample": typed[:200]},
                metadata={
                    "novelty": 75,
                    "confidence": 80,
                    "impact": 44,
                    "discovery_source": "parameter_intelligence",
                    "parameters": typed,
                },
            )
        ]

        # Safe IDOR/logic probing (non-destructive): only id-like params, tiny bounded set.
        probes = 0
        for item in typed:
            if probes >= max_safe_probes:
                break
            ptype = str(item.get("type", ""))
            if ptype not in {"numeric_id", "identifier"}:
                continue
            ep = str(item.get("endpoint", ""))
            prm = str(item.get("parameter", ""))
            if not ep or not prm:
                continue
            base_url = f"{base}{ep}" if ep.startswith("/") else ep
            u1 = set_query(base_url, prm, "1")
            u2 = set_query(base_url, prm, "2")
            r1 = await _fetch(u1)
            r2 = await _fetch(u2)
            diff = http_diff_score(
                {"status": r1.get("status", 0), "length": r1.get("length", 0), "json_keys": _json_keys(str(r1.get("text", "")))},
                {"status": r2.get("status", 0), "length": r2.get("length", 0), "json_keys": _json_keys(str(r2.get("text", "")))},
            )
            probes += 1
            if int(r1.get("status", 0)) == 200 and int(r2.get("status", 0)) == 200 and int(diff.get("anomaly_score", 0)) >= 40:
                leaked_identifiers = sorted(list(set(EMAIL_RE.findall(str(r2.get("text", ""))) + UUID_RE.findall(str(r2.get("text", ""))))))[:25]
                leaked_numeric_ids = sorted(list(set(NUMERIC_ID_RE.findall(str(r2.get("text", ""))))))[:25]
                ev = save_http_evidence(
                    evidence_root,
                    self.name,
                    task.target,
                    {"method": "GET", "url": u2, "headers": request_headers},
                    {"base_request_url": u1, "base_response": {"status": r1.get("status", 0), "length": r1.get("length", 0)}, "modified_response": {"status": r2.get("status", 0), "length": r2.get("length", 0)}, "diff": diff},
                )
                findings.append(
                    Finding(
                        plugin=self.name,
                        target=task.target,
                        category="idor_logic_signal",
                        severity="high",
                        title=f"High-confidence object-access anomaly for parameter {prm}",
                        evidence=ev
                        | {
                            "base_url": u1,
                            "modified_url": u2,
                            "tested_parameter": prm,
                            "response_diff": diff,
                            "leaked_identifiers": leaked_identifiers,
                            "evidence_ref": ev.get("response_file", ""),
                        },
                        metadata={
                            "novelty": 88,
                            "confidence": 84,
                            "confidence_score": 84,
                            "impact": 82,
                            "discovery_source": "parameter_intelligence",
                            "spawn_tasks": [
                                {
                                    "plugin": "behavioral_diff_engine",
                                    "target": task.target,
                                    "payload": {
                                        "paths": ["/api/password/recover", "/api/account/update", "/api/profile/update"],
                                        "leaked_indicators": leaked_identifiers,
                                        "trigger": "idor_to_ato_chain",
                                        "priority_score": 100,
                                    },
                                },
                                {
                                    "plugin": "context_aware_fuzzing_engine",
                                    "target": task.target,
                                    "payload": {
                                        "trigger": "idor_to_ato_chain",
                                        "priority_score": 100,
                                    },
                                },
                            ],
                        },
                        )
                    )
                for ident in leaked_identifiers:
                    etype = "email" if "@" in ident else "uuid"
                    entity_rows.append(
                        {
                            "entity_type": etype,
                            "entity_value": ident,
                            "source_plugin": self.name,
                            "source_endpoint": ep,
                            "confidence_score": 86 if etype == "uuid" else 84,
                            "metadata": {"trigger": "idor_logic_signal", "evidence_ref": ev.get("response_file", "")},
                        }
                    )
                    object_rows.append(
                        {
                            "object_type": "email" if etype == "email" else "object_reference",
                            "object_key": ident,
                            "source_endpoint": ep,
                            "confidence_score": 86 if etype == "uuid" else 84,
                            "discovery_source": self.name,
                            "metadata": {"trigger": "idor_logic_signal", "evidence_ref": ev.get("response_file", "")},
                        }
                    )
                for nid in leaked_numeric_ids:
                    entity_rows.append(
                        {
                            "entity_type": "numeric_id",
                            "entity_value": nid,
                            "source_plugin": self.name,
                            "source_endpoint": ep,
                            "confidence_score": 73,
                            "metadata": {"trigger": "idor_logic_signal", "evidence_ref": ev.get("response_file", "")},
                        }
                    )
                    object_rows.append(
                        {
                            "object_type": "numeric_id",
                            "object_key": nid,
                            "source_endpoint": ep,
                            "confidence_score": 73,
                            "discovery_source": self.name,
                            "metadata": {"trigger": "idor_logic_signal", "evidence_ref": ev.get("response_file", "")},
                        }
                    )
                if prm.lower() in {"id", "uid", "user_id", "account_id", "order_id", "invoice_id", "profile_id"}:
                    entity_rows.append(
                        {
                            "entity_type": "numeric_id",
                            "entity_value": "1",
                            "source_plugin": self.name,
                            "source_endpoint": ep,
                            "confidence_score": 68,
                            "metadata": {"trigger": "safe_probe_seed", "parameter": prm},
                        }
                    )
                    object_rows.append(
                        {
                            "object_type": "numeric_id",
                            "object_key": "1",
                            "source_endpoint": ep,
                            "confidence_score": 66,
                            "discovery_source": self.name,
                            "metadata": {"trigger": "safe_probe_seed", "parameter": prm},
                        }
                    )
                    entity_rows.append(
                        {
                            "entity_type": "numeric_id",
                            "entity_value": "2",
                            "source_plugin": self.name,
                            "source_endpoint": ep,
                            "confidence_score": 68,
                            "metadata": {"trigger": "safe_probe_seed", "parameter": prm},
                        }
                    )
                    object_rows.append(
                        {
                            "object_type": "numeric_id",
                            "object_key": "2",
                            "source_endpoint": ep,
                            "confidence_score": 66,
                            "discovery_source": self.name,
                            "metadata": {"trigger": "safe_probe_seed", "parameter": prm},
                        }
                    )
                for dbr in db_rows:
                    if str(dbr.get("endpoint", "")) == ep and str(dbr.get("param_name", "")) == prm:
                        dbr["evidence_ref"] = ev.get("response_file", "")
                        dbr["risk_score"] = 88.0

        # Persist endpoint parameters when postgres is enabled.
        pg_cfg = context["config"].get("storage", {}).get("postgres", {})
        pg_enabled = bool(pg_cfg.get("enabled", False))
        dsn_env = str(pg_cfg.get("dsn_env", "HUNTEROPS_POSTGRES_DSN"))
        dsn = os.getenv(dsn_env, "")
        if pg_enabled and dsn and run_id and db_rows:
            try:
                def _persist_storage() -> None:
                    storage = PostgresStorage(dsn=dsn, enabled=True)
                    storage.ensure_research_schema()
                    storage.upsert_endpoint_parameters(run_id=run_id, rows=db_rows)
                    if entity_rows:
                        storage.upsert_discovered_entities(run_id=run_id, target=task.target, rows=entity_rows)
                    if object_rows:
                        storage.upsert_objects(run_id=run_id, target=task.target, rows=object_rows)
                        storage.upsert_attack_graph_edges(
                            run_id=run_id,
                            target=task.target,
                            edges=[
                                {
                                    "src_type": "endpoint",
                                    "src_key": str(item.get("source_endpoint", "/")),
                                    "dst_type": "object",
                                    "dst_key": str(item.get("object_key", "")),
                                    "edge_type": "parameter_object_signal",
                                    "confidence_score": float(item.get("confidence_score", 60) or 60),
                                    "evidence_ref": str((item.get("metadata", {}) or {}).get("evidence_ref", "")),
                                    "metadata": {"object_type": str(item.get("object_type", "")), "source_plugin": self.name},
                                }
                                for item in object_rows[:500]
                                if str(item.get("object_key", "")).strip()
                            ],
                            discovery_source=self.name,
                            confidence_score=75.0,
                        )

                await asyncio.to_thread(_persist_storage)
            except Exception:
                pass

        return findings
