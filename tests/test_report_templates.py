from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from hunterops.plugins.security_report_builder import PluginImpl as SecurityReportPlugin
from hunterops.types import Task


class ReportTemplateTests(unittest.IsolatedAsyncioTestCase):
    async def test_intigriti_template_includes_required_header(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "findings.json"
            out = Path(td) / "reports"
            src.write_text(
                json.dumps(
                    {
                        "findings": [
                            {
                                "plugin": "idor",
                                "target": "api.example.com",
                                "category": "idor",
                                "severity": "low",
                                "risk_score": 45,
                                "title": "IDOR test",
                                "evidence": {"base_url": "https://api.example.com/api/users?id=1"},
                                "metadata": {"discovery_source": "idor", "confidence": 70},
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            plugin = SecurityReportPlugin()
            ctx = {
                "config": {
                    "modules": {
                        "security_report_builder": {
                            "findings_source": str(src),
                            "out_dir": str(out),
                            "platform": "intigriti",
                            "templates_path": "config/report_templates.yaml",
                            "intigriti_program_handle": "capital-com",
                        }
                    }
                }
            }
            findings = await plugin.run(Task(plugin="security_report_builder", target="api.example.com"), ctx)
            self.assertEqual(len(findings), 1)
            md_path = Path(findings[0].evidence["markdown_report"])
            self.assertTrue(md_path.exists())
            content = md_path.read_text(encoding="utf-8")
            self.assertIn("X-Intigriti-Username", content)


if __name__ == "__main__":
    unittest.main()
