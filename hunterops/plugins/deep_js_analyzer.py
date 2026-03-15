from __future__ import annotations

import re
from datetime import UTC, datetime
from urllib.parse import parse_qs, urljoin, urlparse

from hunterops.endpoint_cache import EndpointCache
from hunterops.http_client import request_http_async
from hunterops.plugin_base import Plugin
from hunterops.types import Finding, Task

SCRIPT_RE = re.compile(r"""<script[^>]+src=['"]([^'"]+)['"]""", re.IGNORECASE)
FETCH_RE = re.compile(r"""fetch\(\s*['"]([^'"]+)['"]""")
AXIOS_RE = re.compile(r"""axios\.(?:get|post|put|patch|delete)\(\s*['"]([^'"]+)['"]""", re.IGNORECASE)
GRAPHQL_RE = re.compile(r"""['"](/[^'"]*graphql[^'"]*)['"]""", re.IGNORECASE)
API_BASE_RE = re.compile(r"""['"](/api(?:/[A-Za-z0-9_\-{}]+)*)['"]""")
PARAM_NAME_RE = re.compile(r"""['"]([A-Za-z_][A-Za-z0-9_\-]{1,40})['"]\s*:""")
TOKEN_NAME_RE = re.compile(r"""['"](authorization|auth|token|jwt|session|x-api-key)['"]""", re.IGNORECASE)
HEADER_RE = re.compile(r"""['"]([Xx]-[A-Za-z0-9\-]+|Authorization|Cookie)['"]\s*:""")


class PluginImpl(Plugin):
    name = "deep_js_analyzer"

    async def run(self, task: Task, context: dict) -> list[Finding]:
        cfg = context["config"].get("modules", {}).get(self.name, {})
        timeout = int(context["runtime"]["timeout_seconds"])
        max_scripts = int(cfg.get("max_scripts", 30))
        seed_paths = cfg.get("seed_paths", ["/", "/app.js", "/main.js"])
        base = f"https://{task.target}"

        scripts: set[str] = set()
        for p in seed_paths:
            url = p if p.startswith("http") else f"{base}{p}"
            r = await request_http_async("GET", url, headers={}, timeout=timeout)
            txt = str(r.get("text", ""))
            if url.endswith(".js"):
                scripts.add(url)
            for s in SCRIPT_RE.findall(txt):
                su = s if s.startswith("http") else urljoin(base + "/", s)
                if urlparse(su).netloc in {"", task.target}:
                    scripts.add(su)

        endpoints: set[str] = set()
        graphql_eps: set[str] = set()
        api_bases: set[str] = set()
        params: set[str] = set()
        object_ids: set[str] = set()
        token_names: set[str] = set()
        auth_headers: set[str] = set()
        req_resp: list[dict[str, object]] = []

        for s in sorted(scripts)[:max_scripts]:
            r = await request_http_async("GET", s, headers={}, timeout=timeout)
            js = str(r.get("text", ""))
            req_resp.append(
                {
                    "request": {"method": "GET", "url": s, "headers": {}},
                    "response": {"status": r.get("status", 0), "length": r.get("length", 0)},
                    "headers": r.get("headers", {}),
                    "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                    "discovery_source": "deep_js_analyzer",
                }
            )
            for raw in FETCH_RE.findall(js) + AXIOS_RE.findall(js):
                u = raw if raw.startswith("http") else urljoin(base + "/", raw)
                if urlparse(u).netloc in {"", task.target}:
                    endpoints.add(urlparse(u).path or "/")
                    for k in parse_qs(urlparse(u).query).keys():
                        params.add(k)
            for g in GRAPHQL_RE.findall(js):
                graphql_eps.add(urlparse(urljoin(base + "/", g)).path or "/graphql")
            for a in API_BASE_RE.findall(js):
                api_bases.add(a)
            for p in PARAM_NAME_RE.findall(js):
                params.add(p)
                if any(x in p.lower() for x in ("id", "uid", "user_id", "account_id", "order_id", "invoice_id", "profile_id")):
                    object_ids.add(p)
            for t in TOKEN_NAME_RE.findall(js):
                token_names.add(str(t))
            for h in HEADER_RE.findall(js):
                auth_headers.add(str(h))

        if not scripts:
            return []
        cache = context.get("endpoint_cache")
        known_endpoints: list[str] = []
        if isinstance(cache, EndpointCache) and endpoints:
            new_endpoints: list[str] = []
            for ep in sorted(endpoints):
                if cache.was_seen(plugin=self.name, target=task.target, endpoint=ep):
                    known_endpoints.append(ep)
                else:
                    new_endpoints.append(ep)
            if new_endpoints:
                cache.mark_many(plugin=self.name, target=task.target, endpoints=new_endpoints)
            endpoints = set(new_endpoints)
        has_signals = bool(graphql_eps or api_bases or object_ids or token_names or auth_headers or params)
        if not endpoints and not has_signals:
            return []
        return [
            Finding(
                plugin=self.name,
                target=task.target,
                category="deep_javascript_intelligence",
                severity="info",
                title=f"Deep JS analyzer mapped {len(endpoints)} endpoints and {len(params)} parameters",
                evidence={
                    "request_response_sample": req_resp[:25],
                    "scripts_sample": sorted(scripts)[:50],
                    "endpoints_sample": sorted(endpoints)[:120],
                    "known_endpoints_sample": sorted(known_endpoints)[:120],
                    "api_bases": sorted(api_bases)[:40],
                    "graphql_endpoints": sorted(graphql_eps)[:20],
                    "parameters_sample": sorted(params)[:120],
                    "object_identifier_params": sorted(object_ids)[:60],
                    "token_names": sorted(token_names)[:30],
                    "authorization_headers": sorted(auth_headers)[:30],
                },
                metadata={
                    "novelty": 80,
                    "confidence": 79,
                    "impact": 45,
                    "discovery_source": "js",
                    "endpoints": sorted(endpoints),
                    "known_endpoints": sorted(known_endpoints),
                },
            )
        ]
