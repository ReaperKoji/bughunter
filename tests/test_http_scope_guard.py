from __future__ import annotations

import unittest
from unittest.mock import AsyncMock, patch

from hunterops.http_client import configure_scope_guard, configure_host_policies, request_http_async, reset_circuit_breaker_state


class ScopeGuardTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        reset_circuit_breaker_state()

    async def asyncTearDown(self) -> None:
        configure_scope_guard(enabled=False, patterns=[], allowlist=[], denylist=[])
        configure_host_policies([])
        reset_circuit_breaker_state()

    async def test_scope_blocks_out_of_scope(self) -> None:
        configure_scope_guard(enabled=True, patterns=["allowed.example.com"], allowlist=[], denylist=[])
        with patch("hunterops.http_client.httpx", object()), patch(
            "hunterops.http_client.get_async_http_client",
            new=AsyncMock(side_effect=AssertionError("http_client_should_not_be_called")),
        ):
            resp = await request_http_async("GET", "https://blocked.example.com/secret", headers={}, timeout=5)
        self.assertFalse(resp.get("ok"))
        self.assertTrue(resp.get("blocked"))
        self.assertEqual(resp.get("status"), 403)


if __name__ == "__main__":
    unittest.main()
