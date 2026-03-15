from __future__ import annotations

from typing import Any

from hunterops.plugin_base import Plugin
from hunterops.tool_runner import run_command
from hunterops.types import Finding, Task


class PluginImpl(Plugin):
    name = "recon"

    async def run(self, task: Task, context: dict[str, Any]) -> list[Finding]:
        cfg = context["config"].get("modules", {}).get("recon", {})
        timeout = context["runtime"]["timeout_seconds"]
        stealth = context["runtime"]["stealth_mode"]
        proxies = context["runtime"]["proxies"]
        extra_targets = cfg.get("extra_discovery_targets", [])
        scoped_targets: list[str] = [task.target]
        if isinstance(extra_targets, list):
            for item in extra_targets:
                value = str(item).strip()
                if value and value not in scoped_targets:
                    scoped_targets.append(value)

        findings: list[Finding] = []
        for scan_target in scoped_targets:
            for cmd_tpl in cfg.get("commands", []):
                cmd = cmd_tpl.format(target=scan_target)
                result = await run_command(cmd, timeout=timeout, stealth_mode=stealth, proxies=proxies)
                lines = [x.strip() for x in result["stdout"].splitlines() if x.strip()]
                if not lines:
                    continue
                findings.append(
                    Finding(
                        plugin=self.name,
                        target=task.target,
                        category="attack_surface",
                        severity="info",
                        title=f"Recon discovered {len(lines)} artifacts via {cmd.split()[0]} on {scan_target}",
                        evidence={"sample": lines[:20], "command": cmd, "rc": result["rc"], "scan_target": scan_target},
                        metadata={"novelty": 60, "confidence": 70, "impact": 30},
                    )
                )
        return findings
