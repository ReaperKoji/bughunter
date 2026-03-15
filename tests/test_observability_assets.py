from __future__ import annotations

import json
import unittest
from pathlib import Path

import yaml


class ObservabilityAssetsTests(unittest.TestCase):
    def test_grafana_dashboard_json_valid(self) -> None:
        paths = [Path("ops/grafana_dashboard.json"), Path("grafana/dashboard.json")]
        self.assertTrue(any(p.exists() for p in paths))
        for path in paths:
            if not path.exists():
                continue
            data = json.loads(path.read_text(encoding="utf-8"))
            self.assertIn("panels", data)
            self.assertTrue(isinstance(data["panels"], list))

    def test_alert_rules_yaml_valid(self) -> None:
        paths = [Path("ops/alert_rules.yml"), Path("prometheus/alert_rules.yml")]
        self.assertTrue(any(p.exists() for p in paths))
        for path in paths:
            if not path.exists():
                continue
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            self.assertIn("groups", data)
            self.assertTrue(len(data["groups"]) >= 1)


if __name__ == "__main__":
    unittest.main()
