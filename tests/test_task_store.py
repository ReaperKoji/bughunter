from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from hunterops.task_store import SQLiteTaskStore
from hunterops.types import Task


class TaskStoreTests(unittest.TestCase):
    def test_sqlite_task_store_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "tasks.db"
            store = SQLiteTaskStore(db_path)
            task = Task(plugin="recon", target="example.com", payload={"k": "v"})
            store.enqueue_tasks("run-1", [task])
            pending = store.list_pending_tasks("run-1")
            self.assertEqual(len(pending), 1)
            store.mark_started("run-1", pending[0].task_id)
            store.mark_done("run-1", pending[0].task_id)
            pending_after = store.list_pending_tasks("run-1")
            self.assertEqual(len(pending_after), 0)

    def test_reset_in_progress(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "tasks.db"
            store = SQLiteTaskStore(db_path)
            task = Task(plugin="scan", target="example.com", payload={"x": 1})
            store.enqueue_tasks("run-2", [task])
            pending = store.list_pending_tasks("run-2")
            self.assertEqual(len(pending), 1)
            store.mark_started("run-2", pending[0].task_id)
            store.reset_in_progress("run-2")
            pending_again = store.list_pending_tasks("run-2")
            self.assertEqual(len(pending_again), 1)


if __name__ == "__main__":
    unittest.main()
