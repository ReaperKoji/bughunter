from __future__ import annotations

import unittest
from contextlib import asynccontextmanager
from unittest.mock import patch

from hunterops.attack_chain.modules import (
    ModuleContext,
    IdorModule,
    SqliModule,
    SstiModule,
    XssModule,
    LfiModule,
)
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


def _ctx(module_cfg: dict) -> ModuleContext:
    return ModuleContext(
        timeouts={"total_s": 5},
        politeness=_PolitenessStub(),
        user_agents=[],
        logger=_LoggerStub(),
        stealth_mode=True,
        proxies=None,
        tool_timeout_s=5,
        policy={},
        module_cfg=module_cfg,
        session_name="",
        use_auth=False,
        required_headers={},
        baseline_score=0.0,
        baseline_notes=[],
        baseline_methods=[],
    )


class AttackChainBodySupportTests(unittest.IsolatedAsyncioTestCase):
    async def test_idor_body_json_detects_change(self) -> None:
        module = IdorModule()
        target = Target(target_id="t1", url="https://example.com/api/transfer", program_id="test")
        module_cfg = {
            "method": "POST",
            "body_template": {"from": "{{acct}}", "to": "x", "amount": 1},
            "placeholders": {"acct": "acct_1"},
            "body_type": "json",
            "baseline_samples": 1,
        }

        async def fake_request(method: str, url: str, headers: dict | None = None, body: object = None, timeout: int = 5) -> dict:
            text = "{\"account\":\"acct_1\",\"email\":\"owner@example.com\"}"
            if isinstance(body, dict) and body.get("from") != "acct_1":
                text = "{\"account\":\"acct_2\",\"email\":\"victim@example.com\"}"
            return {"ok": True, "status": 200, "headers": {}, "text": text, "length": len(text)}

        with patch("hunterops.attack_chain.modules.request_http_async", side_effect=fake_request):
            result = await module.run(target, _ctx(module_cfg))

        self.assertEqual(result.status, "candidate")
        self.assertIn("idor_anomaly", result.evidence)

    async def test_sqli_body_json_detects_error(self) -> None:
        module = SqliModule()
        target = Target(target_id="t2", url="https://example.com/api/search", program_id="test")
        module_cfg = {
            "method": "POST",
            "body_template": {"q": "{{term}}"},
            "placeholders": {"term": "ok"},
            "body_type": "json",
            "baseline_samples": 1,
        }

        async def fake_request(method: str, url: str, headers: dict | None = None, body: object = None, timeout: int = 5) -> dict:
            text = "ok"
            if isinstance(body, dict) and "'" in str(body.get("q", "")):
                text = "SQL syntax error near \"'\""
            return {"ok": True, "status": 200, "headers": {}, "text": text, "length": len(text)}

        with patch("hunterops.attack_chain.modules.request_http_async", side_effect=fake_request):
            result = await module.run(target, _ctx(module_cfg))

        self.assertEqual(result.status, "candidate")
        self.assertTrue(result.evidence.get("error_signature"))

    async def test_ssti_body_json_detects_eval(self) -> None:
        module = SstiModule()
        target = Target(target_id="t3", url="https://example.com/api/render", program_id="test")
        module_cfg = {
            "method": "POST",
            "body_template": {"template": "{{value}}"},
            "placeholders": {"value": "safe"},
            "body_type": "json",
            "baseline_samples": 1,
        }

        async def fake_request(method: str, url: str, headers: dict | None = None, body: object = None, timeout: int = 5) -> dict:
            text = "safe"
            if isinstance(body, dict) and "{{7*7}}HOPS" in str(body.get("template", "")):
                text = "49HOPS"
            return {"ok": True, "status": 200, "headers": {}, "text": text, "length": len(text)}

        with patch("hunterops.attack_chain.modules.request_http_async", side_effect=fake_request):
            result = await module.run(target, _ctx(module_cfg))

        self.assertEqual(result.status, "candidate")
        self.assertTrue(result.evidence.get("ssti_evaluated"))

    async def test_xss_body_json_detects_reflection(self) -> None:
        module = XssModule()
        target = Target(target_id="t4", url="https://example.com/api/search", program_id="test")
        module_cfg = {
            "method": "POST",
            "body_template": {"q": "{{term}}"},
            "placeholders": {"term": "safe"},
            "body_type": "json",
            "baseline_samples": 1,
        }

        async def fake_request(method: str, url: str, headers: dict | None = None, body: object = None, timeout: int = 5) -> dict:
            text = "ok"
            if isinstance(body, dict) and "HUNTEROPS_XSS" in str(body.get("q", "")):
                text = str(body.get("q"))
            return {"ok": True, "status": 200, "headers": {}, "text": text, "length": len(text)}

        with patch("hunterops.attack_chain.modules.request_http_async", side_effect=fake_request):
            result = await module.run(target, _ctx(module_cfg))

        self.assertEqual(result.status, "candidate")
        self.assertTrue(result.evidence.get("payload_reflected"))

    async def test_lfi_body_json_detects_marker(self) -> None:
        module = LfiModule()
        target = Target(target_id="t5", url="https://example.com/api/file", program_id="test")
        module_cfg = {
            "method": "POST",
            "body_template": {"path": "safe"},
            "body_type": "json",
            "baseline_samples": 1,
        }

        async def fake_request(method: str, url: str, headers: dict | None = None, body: object = None, timeout: int = 5) -> dict:
            text = "safe"
            if isinstance(body, dict) and "../../../../etc/hosts" in str(body.get("path", "")):
                text = "127.0.0.1 localhost"
            return {"ok": True, "status": 200, "headers": {}, "text": text, "length": len(text)}

        with patch("hunterops.attack_chain.modules.request_http_async", side_effect=fake_request):
            result = await module.run(target, _ctx(module_cfg))

        self.assertEqual(result.status, "candidate")
        self.assertTrue(result.evidence.get("lfi_marker"))


if __name__ == "__main__":
    unittest.main()
