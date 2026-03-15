from __future__ import annotations

import asyncio
import unittest
from unittest.mock import AsyncMock, patch

from hunterops.shannon_adapter import ShannonAdapter


class _FakeProcess:
    def __init__(self, *, stdout: bytes, stderr: bytes, returncode: int = 0) -> None:
        self._stdout = stdout
        self._stderr = stderr
        self.returncode = returncode
        self.killed = False

    async def communicate(self, input: bytes | None = None) -> tuple[bytes, bytes]:
        return self._stdout, self._stderr

    def kill(self) -> None:
        self.killed = True

    async def wait(self) -> int:
        return self.returncode


class ShannonAdapterTests(unittest.IsolatedAsyncioTestCase):
    async def test_validate_parses_json_payload(self) -> None:
        process = _FakeProcess(
            stdout=b'{"validated": true, "confidence_delta": 12.5, "evidence_path": "/tmp/poc.md", "error": ""}',
            stderr=b"",
            returncode=0,
        )
        with patch("hunterops.shannon_adapter.os.path.exists", return_value=True), patch(
            "hunterops.shannon_adapter.asyncio.create_subprocess_exec",
            new=AsyncMock(return_value=process),
        ):
            adapter = ShannonAdapter(binary_path="/opt/shannon_ref/shannon", timeout_seconds=5)
            result = await adapter.validate({"target": "api.example.com", "endpoint": "/api/users/1", "metadata": {"x": 1}})

        self.assertTrue(result.validated)
        self.assertAlmostEqual(result.confidence_delta, 12.5)
        self.assertEqual(result.evidence_path, "/tmp/poc.md")
        self.assertEqual(result.error, None)
        self.assertEqual(result.exit_code, 0)

    async def test_validate_timeout_is_fail_safe(self) -> None:
        process = _FakeProcess(stdout=b"", stderr=b"", returncode=0)
        async def _raise_timeout(awaitable, timeout):
            if hasattr(awaitable, "close"):
                awaitable.close()
            raise asyncio.TimeoutError

        with patch("hunterops.shannon_adapter.os.path.exists", return_value=True), patch(
            "hunterops.shannon_adapter.asyncio.create_subprocess_exec",
            new=AsyncMock(return_value=process),
        ), patch(
            "hunterops.shannon_adapter.asyncio.wait_for",
            side_effect=_raise_timeout,
        ):
            adapter = ShannonAdapter(binary_path="/opt/shannon_ref/shannon", timeout_seconds=1)
            result = await adapter.validate({"target": "api.example.com", "endpoint": "/api/users/1", "metadata": {}})

        self.assertFalse(result.validated)
        self.assertIn("shannon_timeout", str(result.error))
        self.assertEqual(result.exit_code, None)
        self.assertTrue(process.killed)


if __name__ == "__main__":
    unittest.main()
