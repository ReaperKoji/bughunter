from __future__ import annotations

import importlib.util
import asyncio
import sys
import tempfile
import unittest
from pathlib import Path

from hunterops.types import Finding


def load_module():
    p = Path("scripts/research_pipeline.py")
    spec = importlib.util.spec_from_file_location("research_pipeline", p)
    assert spec is not None
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules["research_pipeline"] = mod
    spec.loader.exec_module(mod)
    return mod


class ResearchPipelineTests(unittest.TestCase):
    def test_reaction_logic_generates_parameter_task(self) -> None:
        mod = load_module()
        logic = mod.ReactionLogic(max_seed_paths=10)
        findings = [
            Finding(
                plugin="deep_js_intelligence",
                target="api.example.com",
                category="js_discovery",
                severity="info",
                title="x",
                evidence={"endpoints": ["/api/users", "/api/orders?id=1"]},
                metadata={"endpoints": ["/graphql"]},
            )
        ]
        tasks = logic.tasks_from_saved_findings(findings, run_id="run-1", pack={"name": "p"})
        self.assertEqual(len(tasks), 2)
        plugins = {t.plugin for t in tasks}
        self.assertIn("parameter_intelligence", plugins)
        self.assertIn("differential_auth_prover", plugins)
        self.assertTrue(all("seed_paths" in t.payload for t in tasks))

    def test_task_endpoints_normalization(self) -> None:
        mod = load_module()
        t = mod.Task(plugin="parameter_intelligence", target="api.example.com", payload={"seed_paths": ["https://api.example.com/api/users?id=1", "/admin"]})
        eps = mod._task_endpoints(t)
        self.assertIn("/api/users", eps)
        self.assertIn("/admin", eps)

    def test_delta_monitor_no_storage(self) -> None:
        mod = load_module()
        dm = mod.DeltaMonitor(storage=None)
        findings = [
            mod.Finding(
                plugin="deep_js_intelligence",
                target="api.example.com",
                category="js_discovery",
                severity="info",
                title="x",
                evidence={"endpoints": ["/api/users"], "javascript_artifacts": [{"url": "https://api.example.com/main.js", "sha256": "abc"}]},
                metadata={},
            )
        ]
        delta = dm.compare(target="api.example.com", run_id="r1", current_findings=findings)
        self.assertEqual(delta["new_endpoints"], [])
        self.assertEqual(delta["changed_js"], [])

    def test_logic_chaining_builds_tasks_from_idor_signal(self) -> None:
        mod = load_module()
        lc = mod.LogicChainingEngine()
        findings = [
            mod.Finding(
                plugin="parameter_intelligence",
                target="api.example.com",
                category="idor_logic_signal",
                severity="high",
                title="x",
                evidence={"leaked_identifiers": ["user@example.com"]},
                metadata={},
            )
        ]
        tasks = lc.build_tasks(findings, run_id="r2", pack={"name": "p"}, available_plugins={"behavioral_diff_engine"})
        self.assertEqual(len(tasks), 1)
        self.assertEqual(tasks[0].plugin, "behavioral_diff_engine")
        self.assertIn("priority_score", tasks[0].payload)

    def test_priority_queue_delta_first_then_cross_pollination(self) -> None:
        mod = load_module()
        queue = mod.HighValuePriorityQueue(max_size=20)
        findings = [
            mod.Finding(
                plugin="logic_prover",
                target="api.example.com",
                category="Broken_Object_Level_Authorization",
                severity="critical",
                title="x",
                evidence={
                    "endpoint": "/api/internal/users",
                    "structure_similarity_pct": 92.0,
                    "leaked_entities": [{"entity_type": "email", "entity_value": "u@example.com"}],
                    "response_auth_a": {"status": 200},
                    "response_auth_b": {"status": 200},
                    "response_unauthenticated": {"status": 403},
                },
                metadata={"probe_count": 1},
            )
        ]
        tasks = [
            mod.Task(plugin="parameter_intelligence", target="api.example.com", payload={"seed_paths": ["/api/profile"], "trigger": "initial_seed"}),
            mod.Task(plugin="parameter_intelligence", target="api.example.com", payload={"seed_paths": ["/api/internal/users"], "trigger": "delta_change_monitor"}),
            mod.Task(plugin="entity_cross_pollinator", target="api.example.com", payload={"seed_paths": ["/api/internal/users"], "trigger": "entity_cross_pollinator"}),
        ]
        ranked = queue.rank(tasks, findings)
        self.assertEqual(ranked[0].payload.get("priority_class"), 0)
        self.assertEqual(ranked[1].payload.get("priority_class"), 1)

    def test_feedback_retry_tasks_apply_backoff_and_rotation(self) -> None:
        mod = load_module()
        scheduler = mod.ResearchScheduler(
            plugins={},
            context={
                "runtime": {
                    "rate_limit_per_sec": 5,
                    "concurrency": 2,
                    "max_retries": 1,
                    "backoff_base_seconds": 0.1,
                    "feedback_max_retries": 2,
                    "feedback_base_delay_seconds": 0.5,
                    "feedback_max_delay_seconds": 5,
                    "user_agents": ["ua-1", "ua-2"],
                    "proxies": ["http://p1:8080"],
                },
                "logger": type("L", (), {"warning": lambda self, msg: None})(),
                "target_rps": {},
            },
            state=mod.ResearchState(run_id="r1", storage=None),
        )
        scheduler.register_feedback("api.example.com", 429)
        feedback = {"api.example.com": {429}}
        current_wave = [mod.Task(plugin="parameter_intelligence", target="api.example.com", payload={"run_id": "r1", "seed_paths": ["/api"]})]
        retries = mod._build_feedback_retry_tasks(current_wave=current_wave, feedback=feedback, scheduler=scheduler, run_id="r1", max_depth=5)
        self.assertEqual(len(retries), 1)
        self.assertEqual(retries[0].payload.get("trigger"), "feedback_retry_429")
        self.assertEqual(retries[0].payload.get("user_agent"), "ua-1")
        self.assertEqual(retries[0].payload.get("proxy"), "http://p1:8080")

    def test_scheduler_reduces_concurrency_after_consecutive_blocking_feedback(self) -> None:
        mod = load_module()
        scheduler = mod.ResearchScheduler(
            plugins={},
            context={
                "runtime": {
                    "rate_limit_per_sec": 5,
                    "concurrency": 8,
                    "max_retries": 1,
                    "backoff_base_seconds": 0.1,
                    "feedback_max_retries": 2,
                    "feedback_base_delay_seconds": 0.5,
                    "feedback_max_delay_seconds": 5,
                    "feedback_streak_threshold": 3,
                    "feedback_hard_pause_seconds": 60,
                },
                "logger": type("L", (), {"warning": lambda self, msg: None})(),
                "target_rps": {},
            },
            state=mod.ResearchState(run_id="r2", storage=None),
        )
        for _ in range(4):
            scheduler.register_feedback("api.example.com", 429)
        self.assertLessEqual(int(scheduler._active_concurrency), 4)  # type: ignore[attr-defined]
        self.assertGreater(float(scheduler.target_delay_remaining("api.example.com")), 50.0)

    def test_report_engine_hook_runs_only_for_high_or_critical(self) -> None:
        mod = load_module()

        class _FakeReportEngine:
            def __init__(self) -> None:
                self.calls = 0

            async def process_round(self, target: str, run_id: str, round_findings: list) -> list:
                self.calls += 1
                return []

        fake = _FakeReportEngine()
        logger = type("L", (), {"error": lambda self, msg: None})()
        low_batch = [
            mod.Finding(
                plugin="x",
                target="api.example.com",
                category="c",
                severity="medium",
                title="t",
                evidence={},
                metadata={},
            )
        ]
        high_batch = [
            mod.Finding(
                plugin="x",
                target="api.example.com",
                category="c",
                severity="high",
                title="t",
                evidence={},
                metadata={},
            )
        ]
        asyncio.run(
            mod._run_report_engine_if_high_critical(
                report_engine=fake,
                target="api.example.com",
                run_id="r1",
                round_findings=low_batch,
                logger=logger,
            )
        )
        asyncio.run(
            mod._run_report_engine_if_high_critical(
                report_engine=fake,
                target="api.example.com",
                run_id="r1",
                round_findings=high_batch,
                logger=logger,
            )
        )
        self.assertEqual(fake.calls, 1)

    def test_alert_router_hook_dispatches_only_actionable_findings_by_default(self) -> None:
        mod = load_module()

        class _FakeAlertRouter:
            def __init__(self) -> None:
                self.available = True
                self.calls: list[str] = []

            async def send_finding(self, finding: object, run_id: str, source: str) -> bool:
                self.calls.append(f"{getattr(finding, 'plugin', '')}:{run_id}:{source}")
                return True

        fake_router = _FakeAlertRouter()
        logger = type("L", (), {"error": lambda self, msg: None})()
        batch = [
            mod.Finding(
                plugin="vulnerability_correlation_engine",
                target="api.example.com",
                category="vulnerability_correlation",
                severity="medium",
                title="corr",
                evidence={},
                metadata={},
            ),
            mod.Finding(
                plugin="business_logic_sniper",
                target="api.example.com",
                category="financial_tampering_indicator",
                severity="critical",
                title="fin",
                evidence={},
                metadata={},
            ),
            mod.Finding(
                plugin="scan",
                target="api.example.com",
                category="scan_signal",
                severity="low",
                title="low",
                evidence={},
                metadata={},
            ),
        ]
        asyncio.run(
            mod._route_alerts_from_batch(
                alert_router=fake_router,
                batch=batch,
                run_id="r1",
                logger=logger,
                source="unit",
            )
        )
        self.assertEqual(len(fake_router.calls), 1)
        self.assertTrue(fake_router.calls[0].startswith("business_logic_sniper:r1:unit"))

    def test_alert_dry_run_sends_critical_and_research_signals(self) -> None:
        mod = load_module()

        class _FakeAlertRouter:
            def __init__(self) -> None:
                self.available = True
                self.discord_research_webhook = "https://discord.example/research"
                self.discord_critical_webhook = "https://discord.example/critical"
                self.slack_research_webhook = "https://slack.example/research"
                self.slack_critical_webhook = "https://slack.example/critical"
                self.calls: list[str] = []
                self.logs = 0

            async def send_finding(self, finding: object, run_id: str, source: str) -> bool:
                self.calls.append(f"{getattr(finding, 'title', '')}|{run_id}|{source}")
                return True

            async def send_critical_log(self, *, message: str, run_id: str = "runtime") -> None:
                self.logs += 1

        router = _FakeAlertRouter()
        logger = type("L", (), {"info": lambda self, msg: None, "error": lambda self, msg: None})()
        with tempfile.TemporaryDirectory() as tmp:
            rc = asyncio.run(
                mod._run_alert_dry_run(
                    alert_router=router,
                    out_dir=Path(tmp),
                    run_id="run-dry",
                    logger=logger,
                )
            )
            self.assertEqual(rc, 0)
            self.assertEqual(len(router.calls), 2)
            self.assertTrue(any("Test Critical Finding" in item for item in router.calls))
            self.assertTrue(any("Test Research Log" in item for item in router.calls))
            self.assertEqual(router.logs, 1)
            self.assertTrue((Path(tmp) / "alert_dry_run" / "dry_run_poc_run-dry.md").exists())

    def test_split_findings_for_triage_separates_actionable_and_review(self) -> None:
        mod = load_module()
        findings = [
            mod.Finding(
                plugin="differential_auth_prover",
                target="api.example.com",
                category="critical_idor_vulnerability",
                severity="critical",
                title="idor",
                evidence={"endpoint": "/api/users/2"},
                metadata={"confidence_score": 92.0, "impact": 95.0},
            ),
            mod.Finding(
                plugin="vulnerability_correlation_engine",
                target="api.example.com",
                category="vulnerability_correlation",
                severity="medium",
                title="corr",
                evidence={"endpoint": "/unknown"},
                metadata={"confidence_score": 60.0, "impact": 60.0},
            ),
        ]
        actionable, review = mod.split_findings_for_triage(findings, triage_cfg={"allow_correlation_submission": False})
        self.assertEqual(len(actionable), 1)
        self.assertEqual(len(review), 1)
        self.assertEqual(actionable[0].plugin, "differential_auth_prover")
        self.assertEqual(review[0].plugin, "vulnerability_correlation_engine")


if __name__ == "__main__":
    unittest.main()
