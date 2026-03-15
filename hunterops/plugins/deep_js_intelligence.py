from __future__ import annotations

import asyncio
import hashlib
import math
import os
import re
from datetime import UTC, datetime
from urllib.parse import parse_qs, urljoin, urlparse

from hunterops.http_client import request_http_async
from hunterops.endpoint_cache import EndpointCache
from hunterops.plugin_base import Plugin
from hunterops.storage import PostgresStorage
from hunterops.types import Finding, Task

SCRIPT_RE = re.compile(r"""<script[^>]+src=['"]([^'"]+)['"]""", re.IGNORECASE)
FETCH_RE = re.compile(r"""fetch\(\s*['"]([^'"]+)['"]""")
AXIOS_RE = re.compile(r"""axios\.(?:get|post|put|patch|delete)\(\s*['"]([^'"]+)['"]""", re.IGNORECASE)
XHR_RE = re.compile(r"""open\(\s*['"](GET|POST|PUT|PATCH|DELETE)['"]\s*,\s*['"]([^'"]+)['"]""", re.IGNORECASE)
PATH_RE = re.compile(r"""['"](/(?:api|v1|v2|graphql|internal|admin)[^'"]*)['"]""", re.IGNORECASE)
GRAPHQL_QUERY_RE = re.compile(r"""(?:query|mutation)\s+[A-Za-z0-9_]+\s*\(""")
SOURCE_MAP_REF_RE = re.compile(r"""(?m)# sourceMappingURL=([^\s*]+)""")
KEY_RE = re.compile(
    r"""(?i)(api[_-]?key|token|secret|authorization)\s*[:=]\s*['"]([A-Za-z0-9_\-./+=]{12,})['"]"""
)
TOKEN_NAME_RE = re.compile(r"""['"](authorization|auth|token|jwt|session|x-api-key)['"]""", re.IGNORECASE)
PARAM_NAME_RE = re.compile(r"""['"]([A-Za-z_][A-Za-z0-9_\-]{1,40})['"]\s*:""")
LONG_STRING_RE = re.compile(r"""['"]([A-Za-z0-9_\-./+=]{20,})['"]""")
COMMENT_HINT_RE = re.compile(r"""(?im)(?:TODO|FIXME|HACK|INTERNAL|DEBUG|SECRET|API[_\-\s]?KEY|TOKEN)[:\-\s]{0,3}([^\n\r]{0,180})""")
PATH_DISCLOSURE_RE = re.compile(r"""(?i)(?:/home/[A-Za-z0-9_./-]+|/var/www/[A-Za-z0-9_./-]+|[A-Za-z]:\\\\[^\s'\"`]{3,})""")
SENTRY_DSN_RE = re.compile(r"""https?://[a-f0-9]{32}@o\d+\.ingest\.sentry\.io/\d+""", re.IGNORECASE)
MIXPANEL_KEY_RE = re.compile(r"""(?i)mixpanel[^\n]{0,120}(?:token|key)['"\s:=]+([A-Za-z0-9]{16,})""")
SEGMENT_KEY_RE = re.compile(r"""(?i)segment[^\n]{0,120}(?:write[_\-\s]?key|api[_\-\s]?key)['"\s:=]+([A-Za-z0-9]{16,})""")
EMAIL_RE = re.compile(r"""[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}""")
UUID_RE = re.compile(r"""\b[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}\b""")
ID_VALUE_RE = re.compile(
    r"""(?i)(?:user_id|account_id|order_id|invoice_id|profile_id|id)\s*[:=]\s*['"]?([0-9]{2,18}|[0-9a-f]{8}\-[0-9a-f]{4}\-[0-9a-f]{4}\-[0-9a-f]{4}\-[0-9a-f]{12})['"]?"""
)


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    freq: dict[str, int] = {}
    for ch in value:
        freq[ch] = freq.get(ch, 0) + 1
    out = 0.0
    ln = float(len(value))
    for c in freq.values():
        p = c / ln
        out -= p * math.log2(p)
    return out


def looks_like_secret(value: str, entropy_threshold: float) -> bool:
    if len(value) < 20:
        return False
    if value.isdigit():
        return False
    return shannon_entropy(value) >= entropy_threshold


def _safe_script_url(base: str, raw: str, target: str) -> str:
    url = raw if raw.startswith("http://") or raw.startswith("https://") else urljoin(base, raw)
    if urlparse(url).netloc in {"", target}:
        return url
    return ""


def _graph_nodes_from_endpoints(endpoints: set[str]) -> list[dict[str, object]]:
    return [{"node_type": "endpoint", "node_key": ep, "metadata": {"source": "deep_js_intelligence"}} for ep in sorted(endpoints) if ep]


def _object_rows_from_entities(entities: list[dict[str, object]]) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    type_map = {
        "uuid": "object_reference",
        "numeric_id": "numeric_id",
        "email": "email",
        "token": "token",
        "identifier": "object_reference",
    }
    for item in entities:
        etype = str(item.get("entity_type", "")).strip().lower()
        evalue = str(item.get("entity_value", "")).strip()
        if not etype or not evalue:
            continue
        rows.append(
            {
                "object_type": type_map.get(etype, etype),
                "object_key": evalue,
                "source_endpoint": str(item.get("source_endpoint", "/")),
                "confidence_score": float(item.get("confidence_score", 60) or 60),
                "discovery_source": "deep_js_intelligence",
                "metadata": item.get("metadata", {}) if isinstance(item.get("metadata"), dict) else {},
            }
        )
    return rows


class PluginImpl(Plugin):
    name = "deep_js_intelligence"

    async def run(self, task: Task, context: dict) -> list[Finding]:
        cfg = context["config"].get("modules", {}).get(self.name, {})
        timeout = int(context["runtime"]["timeout_seconds"])
        max_scripts = int(cfg.get("max_scripts", 30))
        seed_paths = cfg.get("seed_paths", ["/", "/app.js", "/main.js", "/static/js/app.js"])
        entropy_threshold = float(cfg.get("entropy_threshold", 3.7))
        max_source_maps = max(0, int(cfg.get("max_source_maps", 24) or 24))
        include_source_maps = bool(cfg.get("include_source_maps", True))
        include_comment_leaks = bool(cfg.get("include_comment_leaks", True))
        include_metadata_keys = bool(cfg.get("include_metadata_keys", True))
        focus_keywords = [str(x).strip().lower() for x in cfg.get("focus_endpoint_keywords", []) if str(x).strip()]
        payload = task.payload if isinstance(task.payload, dict) else {}
        run_id = str(payload.get("run_id", ""))
        request_delay = max(0.0, float(payload.get("request_delay_seconds", 0) or 0.0))
        user_agent = str(payload.get("user_agent", "")).strip()
        request_headers = {"User-Agent": user_agent} if user_agent else {}

        base = f"https://{task.target}"
        script_urls: set[str] = set()
        req_resp_sample: list[dict[str, object]] = []
        js_artifacts: list[dict[str, str]] = []
        source_map_urls: set[str] = set()
        source_map_assets: list[dict[str, object]] = []
        source_map_paths: set[str] = set()
        comment_leaks: list[str] = []
        path_disclosures: list[str] = []
        metadata_keys: list[dict[str, object]] = []
        metadata_dedupe: set[str] = set()

        async def _fetch(url: str) -> dict[str, object]:
            response = await request_http_async("GET", url, headers=request_headers, timeout=timeout)
            if request_delay > 0:
                await asyncio.sleep(request_delay)
            return response

        for p in seed_paths:
            url = p if str(p).startswith("http") else f"{base}{p}"
            try:
                r = await _fetch(url)
            except Exception:
                continue
            txt = str(r.get("text", ""))
            req_resp_sample.append(
                {
                    "request": {"method": "GET", "url": url, "headers": request_headers},
                    "response": {"status": r.get("status", 0), "length": r.get("length", 0)},
                    "headers": r.get("headers", {}),
                    "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                    "discovery_source": self.name,
                }
            )
            if url.endswith(".js"):
                script_urls.add(url)
            for src in SCRIPT_RE.findall(txt):
                su = _safe_script_url(base + "/", src, task.target)
                if su:
                    script_urls.add(su)

        endpoints: set[str] = set()
        graphql_hints: set[str] = set()
        parameters: set[str] = set()
        object_identifiers: set[str] = set()
        token_names: set[str] = set()
        secrets: list[dict[str, object]] = []
        discovered_entities: list[dict[str, object]] = []
        entity_dedupe: set[str] = set()
        for surl in sorted(script_urls)[:max_scripts]:
            try:
                r = await _fetch(surl)
            except Exception:
                continue
            js = str(r.get("text", ""))
            js_artifacts.append({"url": surl, "sha256": hashlib.sha256(js.encode("utf-8", errors="ignore")).hexdigest()})
            req_resp_sample.append(
                {
                    "request": {"method": "GET", "url": surl, "headers": request_headers},
                    "response": {"status": r.get("status", 0), "length": r.get("length", 0)},
                    "headers": r.get("headers", {}),
                    "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                    "discovery_source": self.name,
                }
            )

            for raw in FETCH_RE.findall(js) + AXIOS_RE.findall(js) + [x[1] for x in XHR_RE.findall(js)] + PATH_RE.findall(js):
                u = raw if raw.startswith("http") else urljoin(base + "/", raw)
                up = urlparse(u)
                if up.netloc not in {"", task.target}:
                    continue
                ep = up.path or "/"
                if focus_keywords and not any(k in ep.lower() for k in focus_keywords):
                    continue
                endpoints.add(ep)
                if "graphql" in (up.path or "").lower():
                    graphql_hints.add(up.path or "/graphql")
                for k in parse_qs(up.query).keys():
                    parameters.add(k)

            if GRAPHQL_QUERY_RE.search(js):
                graphql_hints.add("/graphql")

            for p in PARAM_NAME_RE.findall(js):
                parameters.add(p)
                if any(x in p.lower() for x in ("id", "uid", "user_id", "account_id", "order_id", "invoice_id", "profile_id")):
                    object_identifiers.add(p)
            for t in TOKEN_NAME_RE.findall(js):
                token_names.add(str(t))

            for mk, mv in KEY_RE.findall(js):
                secrets.append({"kind": mk.lower(), "value_prefix": mv[:8], "entropy": round(shannon_entropy(mv), 2)})
                sig = f"token|{mv[:128]}"
                if sig not in entity_dedupe:
                    entity_dedupe.add(sig)
                    discovered_entities.append(
                        {
                            "entity_type": "token",
                            "entity_value": mv[:128],
                            "source_endpoint": urlparse(surl).path or "/",
                            "confidence_score": 72,
                            "metadata": {"kind": mk.lower()},
                        }
                    )
            for s in LONG_STRING_RE.findall(js):
                if looks_like_secret(s, entropy_threshold):
                    secrets.append({"kind": "high_entropy_string", "value_prefix": s[:8], "entropy": round(shannon_entropy(s), 2)})
                    sig = f"token|{s[:128]}"
                    if sig not in entity_dedupe:
                        entity_dedupe.add(sig)
                        discovered_entities.append(
                            {
                                "entity_type": "token",
                                "entity_value": s[:128],
                                "source_endpoint": urlparse(surl).path or "/",
                                "confidence_score": 60,
                                "metadata": {"kind": "high_entropy_string"},
                            }
                        )
            for email in EMAIL_RE.findall(js):
                sig = f"email|{email.lower()}"
                if sig in entity_dedupe:
                    continue
                entity_dedupe.add(sig)
                discovered_entities.append(
                    {
                        "entity_type": "email",
                        "entity_value": email,
                        "source_endpoint": urlparse(surl).path or "/",
                        "confidence_score": 83,
                        "metadata": {"source_url": surl},
                    }
                )
            for uid in UUID_RE.findall(js):
                sig = f"uuid|{uid.lower()}"
                if sig in entity_dedupe:
                    continue
                entity_dedupe.add(sig)
                discovered_entities.append(
                    {
                        "entity_type": "uuid",
                        "entity_value": uid,
                        "source_endpoint": urlparse(surl).path or "/",
                        "confidence_score": 85,
                        "metadata": {"source_url": surl},
                    }
                )
            for iv in ID_VALUE_RE.findall(js):
                value = str(iv).strip()
                if not value:
                    continue
                e_type = "uuid" if UUID_RE.fullmatch(value) else "numeric_id"
                sig = f"{e_type}|{value.lower()}"
                if sig in entity_dedupe:
                    continue
                entity_dedupe.add(sig)
                discovered_entities.append(
                    {
                        "entity_type": e_type,
                        "entity_value": value,
                        "source_endpoint": urlparse(surl).path or "/",
                        "confidence_score": 80 if e_type == "uuid" else 76,
                        "metadata": {"source_url": surl, "extractor": "id_value_pattern"},
                    }
                )
            if include_source_maps:
                for src_map in SOURCE_MAP_REF_RE.findall(js):
                    map_url = urljoin(surl, str(src_map).strip())
                    netloc = urlparse(map_url).netloc
                    if netloc in {"", task.target}:
                        source_map_urls.add(map_url)
            if include_comment_leaks:
                for leak in COMMENT_HINT_RE.findall(js):
                    item = str(leak).strip()
                    if not item:
                        continue
                    if item not in comment_leaks:
                        comment_leaks.append(item[:200])
            for path_hit in PATH_DISCLOSURE_RE.findall(js):
                p = str(path_hit).strip()
                if not p:
                    continue
                if p not in path_disclosures:
                    path_disclosures.append(p[:220])
            if include_metadata_keys:
                for sentry_dsn in SENTRY_DSN_RE.findall(js):
                    sig = f"sentry|{sentry_dsn.lower()}"
                    if sig in metadata_dedupe:
                        continue
                    metadata_dedupe.add(sig)
                    metadata_keys.append({"kind": "sentry_dsn", "value_prefix": sentry_dsn[:32]})
                for mx in MIXPANEL_KEY_RE.findall(js):
                    token = str(mx).strip()
                    if not token:
                        continue
                    sig = f"mixpanel|{token.lower()}"
                    if sig in metadata_dedupe:
                        continue
                    metadata_dedupe.add(sig)
                    metadata_keys.append({"kind": "mixpanel_token", "value_prefix": token[:12]})
                for sk in SEGMENT_KEY_RE.findall(js):
                    token = str(sk).strip()
                    if not token:
                        continue
                    sig = f"segment|{token.lower()}"
                    if sig in metadata_dedupe:
                        continue
                    metadata_dedupe.add(sig)
                    metadata_keys.append({"kind": "segment_key", "value_prefix": token[:12]})

        if include_source_maps and source_map_urls:
            for map_url in sorted(source_map_urls)[:max_source_maps]:
                try:
                    map_resp = await _fetch(map_url)
                except Exception:
                    continue
                map_text = str(map_resp.get("text", ""))
                map_status = int(map_resp.get("status", 0) or 0)
                map_length = int(map_resp.get("length", 0) or 0)
                map_doc = _load_json(map_text)
                raw_sources = map_doc.get("sources", []) if isinstance(map_doc.get("sources"), list) else []
                clean_sources = [str(x).strip() for x in raw_sources if str(x).strip()]
                for src_path in clean_sources[:400]:
                    source_map_paths.add(src_path[:220])
                source_map_assets.append(
                    {
                        "url": map_url,
                        "status": map_status,
                        "length": map_length,
                        "sources_count": len(clean_sources),
                    }
                )
                sources_content = map_doc.get("sourcesContent", [])
                if include_comment_leaks and isinstance(sources_content, list):
                    for content_blob in sources_content[:20]:
                        blob = str(content_blob or "")
                        if not blob:
                            continue
                        for leak in COMMENT_HINT_RE.findall(blob):
                            item = str(leak).strip()
                            if item and item not in comment_leaks:
                                comment_leaks.append(item[:200])
                        for path_hit in PATH_DISCLOSURE_RE.findall(blob):
                            p = str(path_hit).strip()
                            if p and p not in path_disclosures:
                                path_disclosures.append(p[:220])

        if not script_urls and not endpoints and not parameters:
            return []

        cache = context.get("endpoint_cache")
        if isinstance(cache, EndpointCache) and endpoints:
            filtered_endpoints: set[str] = set()
            for ep in endpoints:
                if cache.was_seen(plugin=self.name, target=task.target, endpoint=ep):
                    continue
                filtered_endpoints.add(ep)
            endpoints = filtered_endpoints
            if endpoints:
                cache.mark_many(plugin=self.name, target=task.target, endpoints=sorted(endpoints))

        # Optional: map discovered endpoints into attack_graph_nodes.
        pg_cfg = context["config"].get("storage", {}).get("postgres", {})
        pg_enabled = bool(pg_cfg.get("enabled", False))
        dsn_env = str(pg_cfg.get("dsn_env", "HUNTEROPS_POSTGRES_DSN"))
        dsn = os.getenv(dsn_env, "")
        if pg_enabled and dsn and run_id and endpoints:
            try:
                def _persist_storage() -> None:
                    storage = PostgresStorage(dsn=dsn, enabled=True)
                    storage.ensure_research_schema()
                    storage.upsert_attack_graph_nodes(
                        run_id=run_id,
                        target=task.target,
                        nodes=_graph_nodes_from_endpoints(endpoints),
                        discovery_source=self.name,
                        confidence_score=78.0,
                    )
                    if discovered_entities:
                        for item in discovered_entities:
                            item["source_plugin"] = self.name
                        storage.upsert_discovered_entities(run_id=run_id, target=task.target, rows=discovered_entities)
                        storage.upsert_objects(
                            run_id=run_id,
                            target=task.target,
                            rows=_object_rows_from_entities(discovered_entities),
                        )
                    edge_rows: list[dict[str, object]] = []
                    object_rows = _object_rows_from_entities(discovered_entities)
                    if object_rows:
                        for obj in object_rows[:300]:
                            src_endpoint = str(obj.get("source_endpoint", "/")) or "/"
                            if not src_endpoint.startswith("/"):
                                src_endpoint = urlparse(src_endpoint).path or "/"
                            edge_rows.append(
                                {
                                    "src_type": "endpoint",
                                    "src_key": src_endpoint,
                                    "dst_type": "object",
                                    "dst_key": str(obj.get("object_key", "")),
                                    "edge_type": "js_entity_discovery",
                                    "confidence_score": float(obj.get("confidence_score", 60) or 60),
                                    "metadata": {
                                        "object_type": str(obj.get("object_type", "")),
                                        "source_plugin": self.name,
                                    },
                                }
                            )
                    if edge_rows:
                        storage.upsert_attack_graph_edges(
                            run_id=run_id,
                            target=task.target,
                            edges=edge_rows,
                            discovery_source=self.name,
                            confidence_score=72.0,
                        )

                await asyncio.to_thread(_persist_storage)
            except Exception:
                # Keep non-blocking behavior for research plugin execution.
                pass

        leak_signals = (
            len([x for x in source_map_assets if int(x.get("status", 0) or 0) in {200, 206}])
            + len(comment_leaks)
            + len(path_disclosures)
            + len(metadata_keys)
            + len(secrets)
        )
        has_low_medium_leak = leak_signals > 0
        finding_category = "js_information_leak" if has_low_medium_leak else "js_discovery"
        finding_severity = "low" if has_low_medium_leak else "info"
        finding_title = (
            f"Deep JS intelligence found {leak_signals} low/medium leak signals across {len(endpoints)} endpoints"
            if has_low_medium_leak
            else f"Deep JS intelligence discovered {len(endpoints)} endpoints and {len(parameters)} parameters"
        )
        return [
            Finding(
                plugin=self.name,
                target=task.target,
                category=finding_category,
                severity=finding_severity,
                title=finding_title,
                evidence={
                    "request_response_sample": req_resp_sample[:30],
                    "javascript_assets": sorted(script_urls)[:100],
                    "javascript_artifacts": js_artifacts[:120],
                    "source_map_assets": source_map_assets[:120],
                    "source_map_paths": sorted(source_map_paths)[:300],
                    "comment_leaks": comment_leaks[:200],
                    "path_disclosures": path_disclosures[:200],
                    "metadata_keys": metadata_keys[:120],
                    "endpoints": sorted(endpoints)[:160],
                    "graphql_hints": sorted(graphql_hints)[:30],
                    "parameters": sorted(parameters)[:200],
                    "object_identifiers": sorted(object_identifiers)[:120],
                    "token_names": sorted(token_names)[:80],
                    "potential_secrets": secrets[:120],
                    "discovered_entities": discovered_entities[:200],
                    "discovery_source": self.name,
                },
                metadata={
                    "novelty": 84,
                    "confidence": 84 if has_low_medium_leak else 78,
                    "confidence_score": 84 if has_low_medium_leak else 78,
                    "impact": 58 if has_low_medium_leak else 46,
                    "discovery_source": self.name,
                    "endpoints": sorted(endpoints),
                    "leak_signals": leak_signals,
                },
            )
        ]
