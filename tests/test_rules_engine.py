from __future__ import annotations

import unittest

from hunterops.rules_engine import check_automation_allowed


class RulesEngineTests(unittest.TestCase):
    def test_detects_prohibited_automation(self) -> None:
        decision = check_automation_allowed("Please do not use automated scanners")
        self.assertTrue(decision.manual_only)
        self.assertFalse(decision.automation_allowed)

    def test_allows_when_no_prohibition(self) -> None:
        decision = check_automation_allowed("Automation permitted under rate limits")
        self.assertFalse(decision.manual_only)
        self.assertTrue(decision.automation_allowed)


if __name__ == "__main__":
    unittest.main()
