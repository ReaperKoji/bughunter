from __future__ import annotations

import re
from urllib.parse import parse_qs, urljoin, urlparse

from hunterops.endpoint_cache import EndpointCache
from hunterops.http_client import request_http_async
from hunterops.plugin_base import Plugin
from hunterops.types import Finding, Task

FETCH_RE = re.compile(r"""fetch\(\s*['"]([^'"]+)['"]""")
XHR_RE = re.compile(r"""open\(\s*['"](GET|POST|PUT|PATCH|DELETE)['"]\s*,\s*['"]([^'"]+)['"]""", re.IGNORECASE)
AXIOS_RE = re.compile(r"""axios\.(get|post|put|patch|delete)\(\s*['"]([^'"]+)['"]""", re.IGNORECASE)
URL_RE = re.compile(r"""https?://[A-Za-z0-9._:/?&=%#\-]+""")
SCRIPT_RE = re.compile(r"""<script[^>]+src=['"]([^'"]+)['"]""", re.IGNORECASE)


def normalize_endpoint(raw: str, base: str) -> str:
    if raw.startswith("http://") or raw.startswith("https://"):
        return raw
    return urljoin(base, raw)


class PluginImpl(Plugin):
    name = "javascript_deep_analysis"

    async def run(self, task: Task, context: dict) -> list[Finding]:
        cfg = context["config"].get("modules", {}).get(self.name, {})
        timeout = int(context["runtime"]["timeout_seconds"])
        max_scripts = int(cfg.get("max_scripts", 25))
        seed_paths = cfg.get("seed_paths", ["/", "/app.js", "/main.js"])

        script_urls: set[str] = set()
        endpoints: set[str] = set()
        params: set[str] = set()
        internal_urls: set[str] = set()
        base = f"https://{task.target}"

        for p in seed_paths:
            url = p if p.startswith("http") else f"{base}{p}"
            r = await request_http_async("GET", url, headers={}, timeout=timeout)
            text = str(r.get("text", ""))
            for src in SCRIPT_RE.findall(text):
                su = normalize_endpoint(src, base + "/")
                if urlparse(su).netloc in {"", task.target}:
                    script_urls.add(su)
            if url.endswith(".js"):
                script_urls.add(url)

        for surl in sorted(script_urls)[:max_scripts]:
            r = await request_http_async("GET", surl, headers={}, timeout=timeout)
            js = str(r.get("text", ""))
            for m in FETCH_RE.findall(js):
                ep = normalize_endpoint(m, base + "/")
                endpoints.add(ep)
            for _, m in XHR_RE.findall(js):
                ep = normalize_endpoint(m, base + "/")
                endpoints.add(ep)
            for _, m in AXIOS_RE.findall(js):
                ep = normalize_endpoint(m, base + "/")
                endpoints.add(ep)
            for u in URL_RE.findall(js):
                up = urlparse(u)
                if up.netloc == task.target:
                    internal_urls.add(u)
                    endpoints.add(u)
            for ep in list(endpoints):
                up = urlparse(ep)
                for k in parse_qs(up.query).keys():
                    params.add(k)

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
        if not endpoints and not internal_urls:
            return []
        return [
            Finding(
                plugin=self.name,
                target=task.target,
                category="javascript_surface_analysis",
                severity="info",
                title=f"Deep JS analysis extracted {len(endpoints)} endpoints",
                evidence={
                    "scripts_sample": sorted(script_urls)[:40],
                    "endpoints_sample": sorted(endpoints)[:80],
                    "known_endpoints_sample": sorted(known_endpoints)[:80],
                    "internal_urls_sample": sorted(internal_urls)[:80],
                    "params_sample": sorted(params)[:80],
                },
                metadata={
                    "novelty": 76,
                    "confidence": 78,
                    "impact": 42,
                    "endpoints": sorted(endpoints),
                    "known_endpoints": sorted(known_endpoints),
                },
            )
        ]
