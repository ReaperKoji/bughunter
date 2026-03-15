from __future__ import annotations

from urllib.parse import urlparse

from hunterops.http_client import json_keys, request_http_async
from hunterops.endpoint_cache import EndpointCache
from hunterops.plugin_base import Plugin
from hunterops.types import Finding, Task


def classify_endpoint(path: str) -> str:
    p = path.lower()
    if any(x in p for x in ("/auth", "/login", "/session", "/oauth")):
        return "auth"
    if any(x in p for x in ("/admin", "/management", "/root")):
        return "admin"
    if any(x in p for x in ("/upload", "/file", "/media")):
        return "upload"
    if any(x in p for x in ("/search", "/query", "/filter")):
        return "search"
    if any(x in p for x in ("/payment", "/wallet", "/invoice", "/coupon", "/checkout")):
        return "payment"
    if "/api/" in p or p.startswith("/api"):
        return "api"
    return "general"


class PluginImpl(Plugin):
    name = "surface_mapper"

    async def run(self, task: Task, context: dict) -> list[Finding]:
        cfg = context["config"].get("modules", {}).get(self.name, {})
        timeout = int(context["runtime"]["timeout_seconds"])
        base = f"https://{task.target}"
        seeds = set(cfg.get("seed_paths", ["/", "/api", "/login", "/admin", "/graphql", "/api/users"]))
        pack = task.payload.get("program_pack", {}) if isinstance(task.payload, dict) else {}
        for ep in pack.get("critical_endpoints", []) if isinstance(pack, dict) else []:
            if isinstance(ep, str):
                seeds.add(ep)

        cache = context.get("endpoint_cache")
        if isinstance(cache, EndpointCache):
            filtered = set()
            for ep in seeds:
                if cache.was_seen(plugin=self.name, target=task.target, endpoint=ep):
                    continue
                filtered.add(ep)
            if not filtered:
                return []
            seeds = filtered

        mapped: list[dict[str, object]] = []
        for p in sorted(seeds):
            url = p if p.startswith("http") else f"{base}{p}"
            r = await request_http_async("GET", url, headers={}, timeout=timeout)
            up = urlparse(url)
            if isinstance(cache, EndpointCache):
                cache.mark_seen(plugin=self.name, target=task.target, endpoint=up.path or "/")
            mapped.append(
                {
                    "endpoint": up.path or "/",
                    "method": "GET",
                    "status": int(r.get("status", 0)),
                    "content_type": str((r.get("headers") or {}).get("Content-Type", "")),
                    "response_size": int(r.get("length", 0)),
                    "json_structure": json_keys(str(r.get("text", ""))),
                    "class": classify_endpoint(up.path or "/"),
                }
            )

        live = [m for m in mapped if int(m.get("status", 0)) not in {0, 404}]
        if not live:
            return []
        classes: dict[str, int] = {}
        for row in live:
            c = str(row.get("class", "general"))
            classes[c] = classes.get(c, 0) + 1
        return [
            Finding(
                plugin=self.name,
                target=task.target,
                category="surface_map",
                severity="info",
                title=f"Surface mapper classified {len(live)} active endpoints",
                evidence={"class_distribution": classes, "mapped_sample": live[:120]},
                metadata={
                    "novelty": 70,
                    "confidence": 78,
                    "impact": 42,
                    "discovery_source": "surface_mapper",
                    "endpoints": [x.get("endpoint") for x in live],
                    "surface_map": live,
                },
            )
        ]
