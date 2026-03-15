from __future__ import annotations

import unittest

from hunterops.discord_notifier import BLUE, ORANGE, DiscordDispatch


class _FakeResponse:
    def __init__(self, status_code: int = 204, payload: dict | None = None) -> None:
        self.status_code = status_code
        self._payload = payload or {}

    def json(self) -> dict:
        return self._payload


class _FakeClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []

    async def post(self, url: str, json: dict) -> _FakeResponse:  # noqa: A002 - follows httpx signature
        self.calls.append((url, json))
        return _FakeResponse(204)

    async def aclose(self) -> None:
        return


class _Logger:
    def warning(self, msg: str) -> None:
        return

    def info(self, msg: str) -> None:
        return


class DiscordNotifierTests(unittest.IsolatedAsyncioTestCase):
    async def test_routes_recon_and_findings_and_redacts(self) -> None:
        notifier = DiscordDispatch(
            cfg={
                "enabled": True,
                "recon_webhook_url": "https://discord.local/recon",
                "findings_webhook_url": "https://discord.local/findings",
                "send_startup_check": False,
                "findings_dedupe_persist_ttl_seconds": 0,
            },
            logger=_Logger(),
        )
        fake_client = _FakeClient()
        notifier._client = fake_client  # type: ignore[assignment]

        notifier.route_recon_delta(
            target="api.example.com",
            delta_score=88,
            new_endpoints=["/api/users", "/admin/export"],
            changed_js=["https://api.example.com/main.js"],
            new_parameters=["/api/users:user_id"],
        )
        notifier.route_finding_confirmed(
            target="api.example.com",
            title="Logic discrepancy confirmed",
            impact="Unauthorized access using token=secret-token-value",
            confidence=70,
            endpoint="/api/users?user_id=1002",
            evidence_snippet="Authorization: Bearer secret-token-value",
            report_path="data/evidence/bundles/run_1/report_1.md",
        )
        await notifier.close()

        self.assertEqual(len(fake_client.calls), 2)
        recon_payload = fake_client.calls[0][1]
        finding_payload = fake_client.calls[1][1]
        self.assertEqual(recon_payload["embeds"][0]["color"], BLUE)
        self.assertEqual(finding_payload["embeds"][0]["color"], ORANGE)
        fields_text = str(finding_payload["embeds"][0].get("fields", []))
        self.assertIn("secr...alue", fields_text)
        self.assertNotIn("secret-token-value", fields_text)

    async def test_startup_check_sends_to_both_channels(self) -> None:
        notifier = DiscordDispatch(
            cfg={
                "enabled": True,
                "recon_webhook_url": "https://discord.local/recon",
                "findings_webhook_url": "https://discord.local/findings",
                "send_startup_check": True,
                "findings_dedupe_persist_ttl_seconds": 0,
            },
            logger=_Logger(),
        )
        fake_client = _FakeClient()
        notifier._client = fake_client  # type: ignore[assignment]
        await notifier.send_system_online(run_id="run-1", targets_count=3, plugins_count=5)
        await notifier.close()
        self.assertEqual(len(fake_client.calls), 2)


if __name__ == "__main__":
    unittest.main()
