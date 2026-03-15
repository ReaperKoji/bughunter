from __future__ import annotations

from urllib.parse import urlparse

from hunterops.http_client import request_http_async
from hunterops.endpoint_cache import EndpointCache
from hunterops.plugin_base import Plugin
from hunterops.types import Finding, Task


def expand_path(path: str) -> set[str]:
    p = path.strip()
    if not p.startswith("/"):
        p = "/" + p
    parts = [x for x in p.split("/") if x]
    out: set[str] = {p}
    if len(parts) >= 2:
        base = "/" + "/".join(parts[:2])
        out.add(base)
        out.add(base + "/{id}")
        out.add(base + "/1")
        out.add(base + "/search")
        out.add(base + "/list")
    if p.endswith("s"):
        out.add(p.rstrip("s"))
    out.add(p + "/health")
    out.add(p + "/status")
    return out


class PluginImpl(Plugin):
    name = "surface_expansion"

    async def run(self, task: Task, context: dict) -> list[Finding]:
        cfg = context["config"].get("modules", {}).get(self.name, {})
        timeout = int(context["runtime"]["timeout_seconds"])
        base = f"https://{task.target}"
        seeds = set(cfg.get("seed_endpoints", ["/api/users", "/api/orders", "/api/profile", "/api/invoices"]))
        payload_eps = task.payload.get("known_endpoints", []) if isinstance(task.payload, dict) else []
        for e in payload_eps:
            if isinstance(e, str):
                seeds.add(urlparse(e).path if e.startswith("http") else e)
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

        candidates: set[str] = set()
        for s in seeds:
            candidates |= expand_path(s)
        hits: list[dict[str, object]] = []
        for ep in sorted(candidates)[:300]:
            url = ep if ep.startswith("http") else f"{base}{ep}"
            r = await request_http_async("GET", url, headers={}, timeout=timeout)
            status = int(r.get("status", 0))
            if isinstance(cache, EndpointCache):
                cache.mark_seen(plugin=self.name, target=task.target, endpoint=ep)
            if status not in {0, 404}:
                hits.append({"endpoint": ep, "status": status, "length": int(r.get("length", 0))})

        if not hits:
            return []
        return [
            Finding(
                plugin=self.name,
                target=task.target,
                category="surface_expansion",
                severity="info",
                title=f"Surface expansion validated {len(hits)} probable routes",
                evidence={"validated_routes": hits[:150], "seed_count": len(seeds), "candidate_count": len(candidates)},
                metadata={"novelty": 74, "confidence": 68, "impact": 40, "endpoints": [h["endpoint"] for h in hits]},
            )
        ]
