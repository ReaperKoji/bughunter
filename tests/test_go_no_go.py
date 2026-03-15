from __future__ import annotations

import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

import hmac
import hashlib

from hunterops.go_no_go import GoNoGoChecklist
from hunterops.scope_authorization import _canonical_payload


class GoNoGoTests(unittest.TestCase):
    def test_go_no_go_requires_signed_scope(self) -> None:
        checklist = GoNoGoChecklist({"require_signed_scope": True, "require_roe": False})
        result = checklist.evaluate(
            targets=["https://example.com"],
            scope={},
            programs=[],
            auth_required=False,
            sessions_present=True,
            real_mode=True,
        )
        self.assertFalse(result.ok)
        self.assertIn("missing_signed_scope", result.reasons)

    def test_go_no_go_blocks_disallowed_automation(self) -> None:
        programs = [
            {"name": "test", "rules_of_engagement": "Please do not use automated scanners"},
        ]
        checklist = GoNoGoChecklist({"require_signed_scope": False, "require_roe": True})
        result = checklist.evaluate(
            targets=["https://example.com"],
            scope={},
            programs=programs,
            auth_required=False,
            sessions_present=True,
            real_mode=False,
        )
        self.assertFalse(result.ok)
        self.assertTrue(any("automation_not_allowed" in r for r in result.reasons))

    def test_go_no_go_signed_scope_ok(self) -> None:
        key = "unit-test-key"
        os.environ["SCOPE_SIGNING_KEY"] = key
        now = datetime.now(timezone.utc)
        scope = {
            "targets": ["example.com"],
            "authorized_by": "unit-test",
            "valid_from": (now - timedelta(minutes=1)).isoformat().replace("+00:00", "Z"),
            "valid_to": (now + timedelta(minutes=1)).isoformat().replace("+00:00", "Z"),
            "rules_of_engagement": "automation allowed",
            "signature_meta": {"algorithm": "hmac-sha256"},
        }
        payload = _canonical_payload(scope)
        scope["signature"] = hmac.new(key.encode("utf-8"), payload, hashlib.sha256).hexdigest()

        checklist = GoNoGoChecklist({"require_signed_scope": True, "require_roe": True})
        result = checklist.evaluate(
            targets=["https://example.com"],
            scope=scope,
            programs=[{"name": "test", "rules_of_engagement": "automation allowed"}],
            auth_required=False,
            sessions_present=True,
            real_mode=True,
        )
        self.assertTrue(result.ok)
        os.environ.pop("SCOPE_SIGNING_KEY", None)


if __name__ == "__main__":
    unittest.main()
