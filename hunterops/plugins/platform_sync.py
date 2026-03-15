from __future__ import annotations

from typing import Any

from hunterops.platforms import (
    fetch_bugcrowd_programs,
    fetch_bugcrowd_submissions,
    fetch_hackerone_programs,
    fetch_hackerone_reports,
    fetch_hackerone_scopes,
    fetch_intigriti_program_activities,
    fetch_intigriti_programs,
)
from hunterops.plugin_base import Plugin
from hunterops.types import Finding, Task


class PluginImpl(Plugin):
    name = "platform_sync"

    async def run(self, task: Task, context: dict[str, Any]) -> list[Finding]:
        if task.target != "__platforms__":
            return []
        timeout = context["runtime"]["timeout_seconds"]
        h1 = fetch_hackerone_programs(timeout=timeout)
        h1_scope = fetch_hackerone_scopes(timeout=timeout)
        h1_reports = fetch_hackerone_reports(timeout=timeout)
        bc = fetch_bugcrowd_programs(timeout=timeout)
        bc_sub = fetch_bugcrowd_submissions(timeout=timeout)
        intigriti_programs = fetch_intigriti_programs(timeout=timeout)
        intigriti_activities = fetch_intigriti_program_activities(timeout=timeout)
        return [
            Finding(
                plugin=self.name,
                target=task.target,
                category="platform_sync",
                severity="info",
                title="Platform sync executed",
                evidence={
                    "hackerone_programs": h1,
                    "hackerone_scope": h1_scope,
                    "hackerone_reports": h1_reports,
                    "bugcrowd_programs": bc,
                    "bugcrowd_submissions": bc_sub,
                    "intigriti_programs": intigriti_programs,
                    "intigriti_program_activities": intigriti_activities,
                },
                metadata={"novelty": 30, "confidence": 80, "impact": 20},
            )
        ]
