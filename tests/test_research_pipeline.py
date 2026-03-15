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

    def test_alert_router_requires_actionable_when_enabled(self) -> None:
        mod = load_module()

        class _FakeAlertRouter:
            def __init__(self) -> None:
                self.available = True
                self.calls: list[str] = []

            async def send_finding(self, finding: object, run_id: str, source: str) -> bool:
                self.calls.append(f"{getattr(finding, 'plugin', '')}:{getattr(finding, 'title', '')}:{run_id}:{source}")
                return True

        fake_router = _FakeAlertRouter()
        logger = type("L", (), {"error": lambda self, msg: None})()
        batch = [
            mod.Finding(
                plugin="surface_massive",
                target="api.example.com",
                category="generic_discovery",
                severity="medium",
                title="not-actionable",
                evidence={"endpoint": "/api/private"},
                metadata={"confidence_score": 75.0, "impact": 10.0},
            ),
            mod.Finding(
                plugin="deep_js_intelligence",
                target="api.example.com",
                category="information_disclosure",
                severity="low",
                title="fastlane-actionable",
                evidence={"endpoint": "/"},
                metadata={"confidence_score": 58.0, "impact": 12.0},
            ),
        ]
        asyncio.run(
            mod._route_alerts_from_batch(
                alert_router=fake_router,
                batch=batch,
                run_id="r2",
                logger=logger,
                source="unit",
                triage_cfg={
                    "alert_min_severity": "low",
                    "alert_min_confidence": 55,
                    "alert_require_actionable": True,
                    "actionable_min_severity": "low",
                    "actionable_min_confidence": 55,
                    "actionable_min_impact": 35,
                    "fastlane_low_medium": True,
                },
            )
        )
        self.assertEqual(len(fake_router.calls), 1)
        self.assertIn("fastlane-actionable", fake_router.calls[0])

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

    def test_split_findings_for_triage_filters_low_quality_js_leak(self) -> None:
        mod = load_module()
        findings = [
            mod.Finding(
                plugin="deep_js_intelligence",
                target="capital.com",
                category="js_information_leak",
                severity="low",
                title="Deep JS intelligence found 20 low/medium leak signals across 0 endpoints",
                evidence={"endpoints": [], "request_response_sample": []},
                metadata={"confidence_score": 84.0, "impact": 58.0},
            )
        ]
        actionable, review = mod.split_findings_for_triage(
            findings,
            triage_cfg={
                "actionable_min_severity": "low",
                "actionable_min_confidence": 55,
                "actionable_min_impact": 35,
                "fastlane_low_medium": True,
            },
        )
        self.assertEqual(len(actionable), 0)
        self.assertEqual(len(review), 1)

    def test_shannon_validation_stage_promotes_review_candidate(self) -> None:
        mod = load_module()

        class _FakeStorage:
            def upsert_triage_queue_rows(self, *, run_id: str, rows: list[dict], status: str = "review") -> int:
                return len(rows)

            def list_triage_review_candidates(
                self,
                *,
                run_id: str,
                min_confidence: float,
                min_impact: float,
                min_severity: str,
                limit: int,
            ) -> list[dict]:
                return [
                    {
                        "finding_key": "k1",
                        "target": "api.example.com",
                        "endpoint": "/api/users/1",
                        "severity": "medium",
                        "confidence_score": 78.0,
                        "impact_score": 72.0,
                        "payload": {
                            "plugin": "parameter_intelligence",
                            "target": "api.example.com",
                            "category": "idor_logic_signal",
                            "severity": "medium",
                            "title": "candidate",
                            "risk_score": 66.0,
                            "metadata": {"confidence_score": 78.0, "impact": 72.0},
                            "evidence": {"endpoint": "/api/users/1"},
                        },
                    }
                ]

            def promote_triage_candidate_with_validation(
                self,
                *,
                run_id: str,
                finding_key: str,
                confidence_delta: float,
                evidence_path: str,
                validator_note: str = "",
            ) -> bool:
                return True

            def mark_triage_candidate_validation_failed(self, *, run_id: str, finding_key: str, note: str) -> None:
                return None

        class _FakeAdapter:
            def __init__(self, *, binary_path: str, timeout_seconds: float = 30.0) -> None:
                self.binary_path = binary_path
                self.timeout_seconds = timeout_seconds

            async def validate(self, context: dict) -> object:
                return mod.ShannonResult(
                    validated=True,
                    confidence_delta=6.0,
                    evidence_path="/tmp/validated.md",
                    error=None,
                    exit_code=0,
                )

        cfg = {
            "modules": {
                "shannon_validator": {
                    "enabled": True,
                    "binary_path": "/opt/shannon_ref/shannon",
                    "timeout_seconds": 10,
                    "max_candidates_per_run": 2,
                    "thresholds": {
                        "min_confidence": 75,
                        "min_impact": 70,
                        "min_severity": "medium",
                    },
                }
            }
        }
        logger = type(
            "L",
            (),
            {
                "info": lambda self, msg: None,
                "warning": lambda self, msg: None,
                "error": lambda self, msg: None,
            },
        )()
        actionable_rows: list[dict] = []
        review_rows: list[dict] = [
            {
                "plugin": "parameter_intelligence",
                "target": "api.example.com",
                "category": "idor_logic_signal",
                "severity": "medium",
                "title": "candidate",
                "risk_score": 66.0,
                "metadata": {"confidence_score": 78.0, "impact": 72.0},
                "evidence": {"endpoint": "/api/users/1"},
            }
        ]

        prev_adapter = mod.ShannonAdapter
        try:
            mod.ShannonAdapter = _FakeAdapter  # type: ignore[assignment]
            with tempfile.TemporaryDirectory() as tmp:
                out_dir = Path(tmp)
                actionable, review, validated = asyncio.run(
                    mod._run_shannon_validation_stage(
                        run_id="run-1",
                        cfg=cfg,
                        storage=_FakeStorage(),  # type: ignore[arg-type]
                        logger=logger,
                        out_dir=out_dir,
                        actionable_rows=actionable_rows,
                        review_rows=review_rows,
                    )
                )
                self.assertEqual(len(actionable), 1)
                self.assertEqual(len(review), 0)
                self.assertEqual(len(validated), 1)
                self.assertTrue((out_dir / "triage" / "validated_candidates.json").exists())
        finally:
            mod.ShannonAdapter = prev_adapter  # type: ignore[assignment]


if __name__ == "__main__":
    unittest.main()
