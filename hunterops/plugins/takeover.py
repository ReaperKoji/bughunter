from __future__ import annotations

from typing import Any

from hunterops.plugin_base import Plugin
from hunterops.tool_runner import run_command
from hunterops.types import Finding, Task


class PluginImpl(Plugin):
    name = "takeover"

    async def run(self, task: Task, context: dict[str, Any]) -> list[Finding]:
        timeout = context["runtime"]["timeout_seconds"]
        stealth = context["runtime"]["stealth_mode"]
        proxies = context["runtime"]["proxies"]
        cmd = f"subzy run --target {task.target} --hide_fails"
        result = await run_command(cmd, timeout=timeout, stealth_mode=stealth, proxies=proxies)
        lines = [x.strip() for x in result["stdout"].splitlines() if x.strip()]
        findings: list[Finding] = []
        if lines:
            findings.append(
                Finding(
                    plugin=self.name,
                    target=task.target,
                    category="subdomain_takeover",
                    severity="low",
                    title="Potential subdomain takeover signal",
                    evidence={"sample": lines[:20], "command": cmd, "endpoint": "/"},
                    metadata={"novelty": 80, "confidence": 74, "impact": 48},
                )
            )
        return findings
