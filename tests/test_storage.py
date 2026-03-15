from __future__ import annotations

import unittest

from hunterops.storage import PostgresStorage


class _FakeCursor:
    def __init__(self, *, fail_on_verified_insert: bool = False) -> None:
        self.fail_on_verified_insert = fail_on_verified_insert
        self.queries: list[str] = []

    def __enter__(self) -> "_FakeCursor":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        return False

    def execute(self, query: str, params=None) -> None:
        self.queries.append(" ".join(str(query).split()).lower())
        q = str(query).lower()
        if self.fail_on_verified_insert and "insert into verified_findings" in q:
            raise RuntimeError("forced_insert_failure")

    def fetchone(self):
        return (
            {
                "plugin": "parameter_intelligence",
                "target": "api.example.com",
                "category": "idor_logic_signal",
                "severity": "high",
                "title": "validated signal",
                "metadata": {"confidence_score": 80.0},
                "evidence": {"endpoint": "/api/users/1"},
            },
            "api.example.com",
            "parameter_intelligence",
            "idor_logic_signal",
            "high",
            "validated signal",
            "/api/users/1",
            "id",
            80.0,
        )


class _FakeConn:
    def __init__(self, *, fail_on_verified_insert: bool = False) -> None:
        self.cursor_obj = _FakeCursor(fail_on_verified_insert=fail_on_verified_insert)
        self.commits = 0
        self.rollbacks = 0

    def cursor(self) -> _FakeCursor:
        return self.cursor_obj

    def commit(self) -> None:
        self.commits += 1

    def rollback(self) -> None:
        self.rollbacks += 1


class StorageTests(unittest.TestCase):
    def test_disabled_storage_noop(self) -> None:
        s = PostgresStorage(dsn="", enabled=False)
        s.write_findings("run", [])
        self.assertTrue(True)

    def test_promote_triage_candidate_with_validation_commits_atomically(self) -> None:
        s = PostgresStorage(dsn="", enabled=True)
        fake_conn = _FakeConn(fail_on_verified_insert=False)
        s._conn = fake_conn

        promoted = s.promote_triage_candidate_with_validation(
            run_id="run-1",
            finding_key="k1",
            confidence_delta=5.0,
            evidence_path="/tmp/evidence.md",
            validator_note="ok",
        )

        self.assertTrue(promoted)
        self.assertEqual(fake_conn.commits, 1)
        self.assertEqual(fake_conn.rollbacks, 0)

    def test_promote_triage_candidate_with_validation_rolls_back_on_failure(self) -> None:
        s = PostgresStorage(dsn="", enabled=True)
        fake_conn = _FakeConn(fail_on_verified_insert=True)
        s._conn = fake_conn

        with self.assertRaises(RuntimeError):
            s.promote_triage_candidate_with_validation(
                run_id="run-1",
                finding_key="k1",
                confidence_delta=5.0,
                evidence_path="/tmp/evidence.md",
                validator_note="boom",
            )

        self.assertEqual(fake_conn.commits, 0)
        self.assertGreaterEqual(fake_conn.rollbacks, 1)


if __name__ == "__main__":
    unittest.main()
