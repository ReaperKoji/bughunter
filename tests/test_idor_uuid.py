from __future__ import annotations

import unittest
from contextlib import asynccontextmanager
from unittest.mock import patch

from hunterops.attack_chain.modules import ModuleContext, IdorModule
from hunterops.attack_chain.types import Target


class _LoggerStub:
    def info(self, _msg: str) -> None:
        return

    def warning(self, _msg: str) -> None:
        return

    def error(self, _msg: str) -> None:
        return


class _PolitenessStub:
    @asynccontextmanager
    async def guard(self, *_args: object, **_kwargs: object):
        yield

    async def wait(self, *_args: object, **_kwargs: object) -> None:
        return


class IdorUuidTests(unittest.IsolatedAsyncioTestCase):
    async def test_idor_uuid_path_detected(self) -> None:
        module = IdorModule()
        original = "11111111-1111-1111-1111-111111111111"
        target = Target(target_id="t-uuid", url=f"https://example.com/api/resource/{original}", program_id="test")
        ctx = ModuleContext(
            timeouts={"total_s": 5},
            politeness=_PolitenessStub(),
            user_agents=[],
            logger=_LoggerStub(),
            stealth_mode=True,
            proxies=None,
            tool_timeout_s=5,
            policy={},
            module_cfg={"method": "GET", "baseline_samples": 1},
            session_name="",
            use_auth=False,
            required_headers={},
            baseline_score=0.0,
            baseline_notes=[],
            baseline_methods=[],
        )

        async def fake_request(method: str, url: str, headers: dict | None = None, body: object = None, timeout: int = 5) -> dict:
            text = "owner_a" if original in url else "owner_b"
            return {"ok": True, "status": 200, "headers": {}, "text": text, "length": len(text)}

        with patch("hunterops.attack_chain.modules.request_http_async", side_effect=fake_request):
            result = await module.run(target, ctx)

        self.assertEqual(result.status, "candidate")
        self.assertIn("path_uuid", result.candidate_poc)


if __name__ == "__main__":
    unittest.main()
