from __future__ import annotations

from urllib.parse import urlparse

from hunterops.endpoint_cache import EndpointCache
from hunterops.plugin_base import Plugin
from hunterops.tool_runner import run_command
from hunterops.types import Finding, Task
from hunterops.url_utils import normalize_endpoint, normalize_host


def _extract_endpoints(lines: list[str], target: str) -> list[str]:
    endpoints: set[str] = set()
    target_host = normalize_host(target)
    for raw in lines:
        text = str(raw or "").strip()
        if not text:
            continue
        if text.startswith("http://") or text.startswith("https://"):
            parsed = urlparse(text)
            host = str(parsed.hostname or "").strip().lower()
            if target_host and host and not host.endswith(target_host):
                continue
            path = parsed.path or "/"
            if parsed.query:
                path = f"{path}?{parsed.query}"
            endpoints.add(normalize_endpoint(path))
            continue
        if text.startswith("/"):
            endpoints.add(normalize_endpoint(text))
    return sorted(endpoints)


class PluginImpl(Plugin):
    name = "surface_massive"

    async def run(self, task: Task, context: dict) -> list[Finding]:
        cfg = context["config"].get("modules", {}).get("surface_massive", {})
        timeout = context["runtime"]["timeout_seconds"]
        stealth = context["runtime"]["stealth_mode"]
        proxies = context["runtime"]["proxies"]
        findings: list[Finding] = []
        cache = context.get("endpoint_cache")
        all_endpoints: set[str] = set()

        for cmd_tpl in cfg.get("commands", []):
            cmd = cmd_tpl.format(target=task.target)
            r = await run_command(cmd, timeout=timeout, stealth_mode=stealth, proxies=proxies)
            lines = [x.strip() for x in r["stdout"].splitlines() if x.strip()]
            if lines:
                endpoints = _extract_endpoints(lines, task.target)
                if isinstance(cache, EndpointCache) and endpoints:
                    filtered: list[str] = []
                    for ep in endpoints:
                        if cache.was_seen(plugin=self.name, target=task.target, endpoint=ep):
                            continue
                        filtered.append(ep)
                    endpoints = filtered
                    if endpoints:
                        cache.mark_many(plugin=self.name, target=task.target, endpoints=endpoints)
                if endpoints:
                    all_endpoints.update(endpoints)
                findings.append(
                    Finding(
                        plugin=self.name,
                        target=task.target,
                        category="surface_discovery",
                        severity="info",
                        title=f"{cmd.split()[0]} discovered surface artifacts",
                        evidence={
                            "command": cmd,
                            "sample": lines[:30],
                            "endpoints": endpoints[:200] if endpoints else [],
                            "known_endpoints": endpoints[:200] if endpoints else [],
                        },
                        metadata={
                            "novelty": 70,
                            "confidence": 70,
                            "impact": 25,
                            "endpoints": endpoints[:300] if endpoints else [],
                            "discovery_source": "surface_massive",
                        },
                    )
                )
        if isinstance(cache, EndpointCache) and all_endpoints:
            cache.mark_many(plugin=self.name, target=task.target, endpoints=sorted(all_endpoints))
        return findings
