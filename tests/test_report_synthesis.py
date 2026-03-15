from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path

from hunterops.plugins.report_synthesis import PluginImpl
from hunterops.types import Task


class ReportSynthesisTests(unittest.TestCase):
    def test_synthesizes_markdown_report_with_masked_tokens(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "reports"
            plugin = PluginImpl()
            task = Task(
                plugin="report_synthesis",
                target="api.example.com",
                payload={
                    "run_id": "run_test_001",
                    "findings": [
                        {
                            "plugin": "differential_auth_prover",
                            "target": "api.example.com",
                            "category": "critical_idor_vulnerability",
                            "severity": "critical",
                            "title": "Cross-context access consistency anomaly",
                            "risk_score": 93,
                            "metadata": {
                                "novelty": 90,
                                "impact": 95,
                                "confidence": 92,
                                "confidence_score": 92,
                            },
                            "evidence": {
                                "tested_parameter": "user_id",
                                "request_auth_a": {
                                    "method": "GET",
                                    "url": "https://api.example.com/api/v1/user/settings?user_id=1001",
                                    "headers": {
                                        "Authorization": "Bearer owner_token_abcdefghijklmnop123456",
                                    },
                                },
                                "request_auth_b": {
                                    "method": "GET",
                                    "url": "https://api.example.com/api/v1/user/settings?user_id=1001",
                                    "headers": {
                                        "Authorization": "Bearer attacker_token_abcdefghijklmnop999999",
                                    },
                                },
                                "response_auth_a": {
                                    "status": 200,
                                    "length": 124,
                                    "body": '{"email":"owner@example.com","user_id":1001}',
                                },
                                "response_auth_b": {
                                    "status": 200,
                                    "length": 126,
                                    "body": '{"email":"owner@example.com","user_id":1001}',
                                },
                            },
                        }
                    ],
                },
            )
            context = {
                "config": {
                    "storage": {"postgres": {"enabled": False}},
                    "modules": {
                        "report_synthesis": {
                            "out_dir": str(out_dir),
                            "confidence_threshold": 80,
                            "auth_context_a": "Auth_Context_A",
                            "auth_context_b": "Auth_Context_B",
                            "enable_notifications": False,
                            "enable_os_notification": False,
                            "webhook_url": "",
                            "webhook_env": "",
                        }
                    },
                },
                "runtime": {"timeout_seconds": 30},
                "logger": _LoggerStub(),
            }
            findings = asyncio.run(plugin.run(task, context))
            self.assertEqual(len(findings), 1)
            report_path = Path(findings[0].metadata.get("report_path", ""))
            self.assertTrue(report_path.exists())
            content = report_path.read_text(encoding="utf-8")
            self.assertIn("[IDOR]", content)
            self.assertIn("curl -i -X GET", content)
            self.assertIn("owne...3456", content)
            self.assertIn("atta...9999", content)
            self.assertNotIn("owner_token_abcdefghijklmnop123456", content)
            self.assertNotIn("attacker_token_abcdefghijklmnop999999", content)

    def test_skips_non_replayable_synthesis_when_request_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "reports"
            plugin = PluginImpl()
            task = Task(
                plugin="report_synthesis",
                target="capital.com",
                payload={
                    "run_id": "run_test_002",
                    "findings": [
                        {
                            "plugin": "deep_js_intelligence",
                            "target": "capital.com",
                            "category": "js_information_leak",
                            "severity": "low",
                            "title": "Deep JS intelligence found 10 low/medium leak signals across 0 endpoints",
                            "risk_score": 55,
                            "metadata": {
                                "novelty": 80,
                                "impact": 58,
                                "confidence": 84,
                                "confidence_score": 84,
                            },
                            "evidence": {
                                "endpoints": [],
                                "request_response_sample": [],
                            },
                        }
                    ],
                },
            )
            context = {
                "config": {
                    "storage": {"postgres": {"enabled": False}},
                    "modules": {
                        "report_synthesis": {
                            "out_dir": str(out_dir),
                            "confidence_threshold": 80,
                            "require_replayable_requests": True,
                            "allow_root_endpoint": False,
                            "exclude_categories": ["js_information_leak"],
                            "exclude_source_plugins": ["deep_js_intelligence"],
                            "auth_context_a": "Auth_Context_A",
                            "auth_context_b": "Auth_Context_B",
                            "enable_notifications": False,
                            "enable_os_notification": False,
                            "webhook_url": "",
                            "webhook_env": "",
                        }
                    },
                },
                "runtime": {"timeout_seconds": 30},
                "logger": _LoggerStub(),
            }
            findings = asyncio.run(plugin.run(task, context))
            self.assertEqual(findings, [])


class _LoggerStub:
    def info(self, _msg: str) -> None:
        return

    def warning(self, _msg: str) -> None:
        return

    def error(self, _msg: str) -> None:
        return


if __name__ == "__main__":
    unittest.main()
