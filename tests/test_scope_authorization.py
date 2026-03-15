from __future__ import annotations

import os
import unittest
from datetime import datetime, timedelta, timezone

import hmac
import hashlib

from hunterops import scope_authorization as sa
from hunterops.scope_authorization import authorize_targets


class ScopeAuthorizationTests(unittest.TestCase):
    def test_authorized_targets_env(self) -> None:
        os.environ["AUTHORIZED_TARGETS"] = "example.com,*.allowed.com"
        ok, unauthorized = authorize_targets(["example.com", "api.allowed.com"], {})
        self.assertTrue(ok)
        self.assertEqual(unauthorized, [])
        ok, unauthorized = authorize_targets(["blocked.com"], {})
        self.assertFalse(ok)
        self.assertEqual(unauthorized, ["blocked.com"])
        os.environ.pop("AUTHORIZED_TARGETS", None)

    def test_authorized_targets_signed_scope(self) -> None:
        key = "test-signing-key"
        os.environ["SCOPE_SIGNING_KEY"] = key
        now = datetime.now(timezone.utc)
        scope = {
            "targets": ["example.com", "*.allowed.com"],
            "authorized_by": "unit-test",
            "valid_from": (now - timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),
            "valid_to": (now + timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),
            "rules_of_engagement": "automation allowed for test",
            "signature_meta": {"algorithm": "hmac-sha256"},
        }
        payload = sa._canonical_payload(scope)  # type: ignore[attr-defined]
        scope["signature"] = hmac.new(key.encode("utf-8"), payload, hashlib.sha256).hexdigest()

        ok, unauthorized = authorize_targets(["example.com", "api.allowed.com"], scope)
        self.assertTrue(ok)
        self.assertEqual(unauthorized, [])
        ok, unauthorized = authorize_targets(["blocked.com"], scope)
        self.assertFalse(ok)
        self.assertEqual(unauthorized, ["blocked.com"])
        os.environ.pop("SCOPE_SIGNING_KEY", None)


if __name__ == "__main__":
    unittest.main()
