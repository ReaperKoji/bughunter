from __future__ import annotations

import re
from urllib.parse import urlparse

from hunterops.endpoint_cache import EndpointCache
from hunterops.http_client import request_http_async
from hunterops.plugin_base import Plugin
from hunterops.types import Finding, Task

SCRIPT_RE = re.compile(r"""<script[^>]+src=['"]([^'"]+)['"]""", re.IGNORECASE)
ROUTE_REACT_RE = re.compile(r"""path\s*[:=]\s*['"](/[^'"]+)['"]""", re.IGNORECASE)
ROUTE_VUE_RE = re.compile(r"""['"]path['"]\s*:\s*['"](/[^'"]+)['"]""", re.IGNORECASE)
ROUTE_NEXT_RE = re.compile(r"""['"](/api/[A-Za-z0-9_/\-{}]+)['"]""")


class PluginImpl(Plugin):
    name = "js_route_mapper"

    async def run(self, task: Task, context: dict) -> list[Finding]:
        cfg = context["config"].get("modules", {}).get(self.name, {})
        timeout = int(context["runtime"]["timeout_seconds"])
        max_scripts = int(cfg.get("max_scripts", 30))
        base = f"https://{task.target}"

        home = await request_http_async("GET", f"{base}/", headers={}, timeout=timeout)
        html = str(home.get("text", ""))
        scripts: set[str] = set()
        for src in SCRIPT_RE.findall(html):
            if src.startswith("http"):
                scripts.add(src)
            elif src.startswith("/"):
                scripts.add(base + src)
            else:
                scripts.add(base + "/" + src)

        routes: set[str] = set()
        for s in sorted(scripts)[:max_scripts]:
            if urlparse(s).netloc not in {"", task.target}:
                continue
            r = await request_http_async("GET", s, headers={}, timeout=timeout)
            js = str(r.get("text", ""))
            for route in ROUTE_REACT_RE.findall(js):
                routes.add(route)
            for route in ROUTE_VUE_RE.findall(js):
                routes.add(route)
            for route in ROUTE_NEXT_RE.findall(js):
                routes.add(route)

        if not routes:
            return []
        mapped = sorted({x for x in routes if x.startswith("/")})
        cache = context.get("endpoint_cache")
        known_endpoints: list[str] = []
        if isinstance(cache, EndpointCache) and mapped:
            new_endpoints: list[str] = []
            for ep in mapped:
                if cache.was_seen(plugin=self.name, target=task.target, endpoint=ep):
                    known_endpoints.append(ep)
                else:
                    new_endpoints.append(ep)
            if new_endpoints:
                cache.mark_many(plugin=self.name, target=task.target, endpoints=new_endpoints)
            mapped = new_endpoints
        if not mapped:
            return []
        return [
            Finding(
                plugin=self.name,
                target=task.target,
                category="js_route_mapping",
                severity="info",
                title=f"JS route mapper extracted {len(mapped)} internal routes",
                evidence={
                    "scripts_sample": sorted(scripts)[:50],
                    "routes_sample": mapped[:120],
                    "known_routes_sample": known_endpoints[:120],
                },
                metadata={"novelty": 73, "confidence": 76, "impact": 38, "endpoints": mapped, "known_endpoints": known_endpoints},
            )
        ]
