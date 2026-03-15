from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from hunterops.alert_router import AlertRouter
from hunterops.types import Finding


class AlertRouterTests(unittest.IsolatedAsyncioTestCase):
    async def test_send_finding_critical_routes_with_discord_file_and_deduplicates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "poc.md"
            report.write_text("# Poc\n" + ("x" * 3000), encoding="utf-8")
            router = AlertRouter(
                {
                    "enabled": True,
                    "discord_critical_webhook": "https://discord.example/critical",
                    "discord_attach_threshold": 100,
                    "max_embed_poc_chars": 200,
                    "dedupe_ttl_seconds": 600,
                },
                logger=None,
            )
            captured: list[tuple[str, str, str]] = []

            async def fake_post_json(webhook: str, payload: dict, *, route: str) -> None:  # noqa: ANN401
                captured.append(("json", route, str(payload.get("content", ""))))

            async def fake_post_discord_with_file(webhook: str, payload: dict, file_path: Path, *, route: str) -> None:
                captured.append(("file", route, file_path.name))

            router._post_json = fake_post_json  # type: ignore[method-assign]
            router._post_discord_with_file = fake_post_discord_with_file  # type: ignore[method-assign]
            finding = Finding(
                plugin="business_logic_sniper",
                target="api.example.com",
                category="financial_tampering_indicator",
                severity="critical",
                title="critical tampering",
                evidence={"report_path": str(report), "curl_command": "curl -i https://api.example.com/checkout?price=-1", "endpoint": "/api/checkout?price=-1"},
                metadata={"impact": 98, "confidence_score": 91},
            )

            sent_first = await router.send_finding(finding, run_id="run-1", source="unit")
            sent_second = await router.send_finding(finding, run_id="run-1", source="unit")
            self.assertTrue(sent_first)
            self.assertFalse(sent_second)
            self.assertTrue(any(item[0] == "file" and item[1] == "discord_critical" for item in captured))

    async def test_send_finding_medium_routes_to_research_channels(self) -> None:
        router = AlertRouter(
            {
                "enabled": True,
                "discord_research_webhook": "https://discord.example/research",
                "slack_research_webhook": "https://slack.example/research",
                "dedupe_ttl_seconds": 600,
            },
            logger=None,
        )
        captured: list[str] = []

        async def fake_post_json(webhook: str, payload: dict, *, route: str) -> None:  # noqa: ANN401
            captured.append(route)

        router._post_json = fake_post_json  # type: ignore[method-assign]
        finding = Finding(
            plugin="vulnerability_correlation_engine",
            target="api.example.com",
            category="vulnerability_correlation",
            severity="medium",
            title="correlated signal",
            evidence={"endpoint": "/api/profile"},
            metadata={"impact": 60, "confidence_score": 72},
        )
        sent = await router.send_finding(finding, run_id="run-2", source="unit")
        self.assertTrue(sent)
        self.assertIn("discord_research", captured)
        self.assertIn("slack_research", captured)

    async def test_critical_public_data_exposure_dedupes_by_path(self) -> None:
        router = AlertRouter(
            {
                "enabled": True,
                "discord_critical_webhook": "https://discord.example/critical",
                "dedupe_ttl_seconds": 600,
            },
            logger=None,
        )
        captured: list[str] = []

        async def fake_post_json(webhook: str, payload: dict, *, route: str) -> None:  # noqa: ANN401
            captured.append(route)

        router._post_json = fake_post_json  # type: ignore[method-assign]
        finding_a = Finding(
            plugin="impact_validator",
            target="capital.com",
            category="critical_public_data_exposure",
            severity="critical",
            title="critical public data exposure",
            evidence={"endpoint": "/?id=1001"},
            metadata={"impact": 96, "confidence_score": 98},
        )
        finding_b = Finding(
            plugin="impact_validator",
            target="capital.com",
            category="critical_public_data_exposure",
            severity="critical",
            title="critical public data exposure",
            evidence={"endpoint": "/?id=1002&email=test@example.com"},
            metadata={"impact": 96, "confidence_score": 98},
        )
        first = await router.send_finding(finding_a, run_id="run-3", source="unit")
        second = await router.send_finding(finding_b, run_id="run-3", source="unit")
        self.assertTrue(first)
        self.assertFalse(second)
        self.assertEqual(len(captured), 1)


if __name__ == "__main__":
    unittest.main()
