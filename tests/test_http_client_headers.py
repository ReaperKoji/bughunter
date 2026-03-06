from __future__ import annotations

import unittest
from unittest.mock import AsyncMock, patch

from hunterops.http_client import request_http_async, reset_circuit_breaker_state


class _FakeResponse:
    def __init__(self) -> None:
        self.is_success = True
        self.status_code = 200
        self.headers = {"Content-Type": "application/json"}
        self.text = "{}"
        self.content = b"{}"


class _FakeAsyncClient:
    def __init__(self) -> None:
        self.calls: list[dict[str, str]] = []

    async def request(self, method: str, url: str, headers: dict[str, str] | None = None, **kwargs: object) -> _FakeResponse:  # noqa: ANN401
        self.calls.append(headers or {})
        return _FakeResponse()


class HttpClientHeadersTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        reset_circuit_breaker_state()

    async def asyncTearDown(self) -> None:
        reset_circuit_breaker_state()

    async def test_async_requests_inject_h1_identifier_and_standard_user_agent(self) -> None:
        fake_client = _FakeAsyncClient()
        with patch.dict(
            "os.environ",
            {
                "H1_API_IDENTIFIER": "reaperk0ji",
                "HUNTEROPS_BUG_BOUNTY_USERNAME": "reaperk0ji",
                "HUNTEROPS_TEST_ACCOUNT_EMAIL": "reaperk0ji+bb@example.com",
            },
            clear=False,
        ), patch("hunterops.http_client.httpx", object()), patch(
            "hunterops.http_client.get_async_http_client",
            new=AsyncMock(return_value=fake_client),
        ):
            await request_http_async("GET", "https://example.com/api/health", headers={"X-Test": "1"}, timeout=5)

        self.assertEqual(len(fake_client.calls), 1)
        sent = fake_client.calls[0]
        self.assertEqual(sent.get("X-H1-Client-Identifier"), "reaperk0ji")
        self.assertEqual(sent.get("User-Agent"), "Mozilla/5.0 (HunterOps/3.0; BugBounty; reaperk0ji).")
        self.assertEqual(sent.get("X-Bug-Bounty"), "reaperk0ji")
        self.assertEqual(sent.get("X-Test-Account-Email"), "reaperk0ji+bb@example.com")
        self.assertEqual(sent.get("X-Test"), "1")


if __name__ == "__main__":
    unittest.main()
