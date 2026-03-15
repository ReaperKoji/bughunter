from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from hunterops.runbook import RunbookManager


class RunbookTests(unittest.TestCase):
    def test_pause_and_resume(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "runbook.json"
            manager = RunbookManager({"override_path": str(path), "enabled": True, "pause_minutes": 1})
            manager.pause(minutes=1, reason="test")
            paused, _reason = manager.is_paused()
            self.assertTrue(paused)
            manager.pause(minutes=0, reason="resume")
            paused, _reason = manager.is_paused()
            self.assertFalse(paused)

    def test_reduce_rate_applies(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "runbook.json"
            manager = RunbookManager({"override_path": str(path), "enabled": True})
            manager.reduce_rate(multiplier=0.5, minutes=5, reason="test")
            policy = {"per_host_rpm": 60, "per_target_rpm": 30, "concurrency_per_host": 2}
            adjusted = manager.apply_policy(policy)
            self.assertLessEqual(adjusted["per_host_rpm"], 30)

    def test_block_host(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "runbook.json"
            manager = RunbookManager({"override_path": str(path), "enabled": True})
            manager.block_host("example.com", minutes=1, reason="test")
            self.assertTrue(manager.is_host_blocked("example.com"))


if __name__ == "__main__":
    unittest.main()
