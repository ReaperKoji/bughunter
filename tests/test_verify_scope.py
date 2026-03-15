from __future__ import annotations

import hmac
import hashlib
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
import importlib.util


def _load_verify_module():
    spec = importlib.util.spec_from_file_location("verify_scope", "tools/verify_scope.py")
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


class VerifyScopeTests(unittest.TestCase):
    def test_verify_scope_hmac(self) -> None:
        module = _load_verify_module()
        key = "unit-test-key"
        os.environ["SCOPE_SIGNING_KEY"] = key
        now = datetime.now(timezone.utc)
        scope = {
            "targets": ["localhost"],
            "authorized_by": "unit-test",
            "valid_from": (now - timedelta(minutes=1)).isoformat().replace("+00:00", "Z"),
            "valid_to": (now + timedelta(minutes=1)).isoformat().replace("+00:00", "Z"),
            "rules_of_engagement": "automation allowed",
            "signature_meta": {"algorithm": "hmac-sha256"},
        }
        payload = module._canonical_payload(scope)  # type: ignore[attr-defined]
        scope["signature"] = hmac.new(key.encode("utf-8"), payload, hashlib.sha256).hexdigest()

        ok, reason = module.verify_scope(scope, key_path=Path("config/signer.key"), pub_path=Path("config/signer.pub"))
        self.assertTrue(ok)
        self.assertEqual(reason, "ok")
        os.environ.pop("SCOPE_SIGNING_KEY", None)

    def test_verify_scope_invalid_signature(self) -> None:
        module = _load_verify_module()
        key = "unit-test-key"
        os.environ["SCOPE_SIGNING_KEY"] = key
        now = datetime.now(timezone.utc)
        scope = {
            "targets": ["localhost"],
            "authorized_by": "unit-test",
            "valid_from": (now - timedelta(minutes=1)).isoformat().replace("+00:00", "Z"),
            "valid_to": (now + timedelta(minutes=1)).isoformat().replace("+00:00", "Z"),
            "rules_of_engagement": "automation allowed",
            "signature_meta": {"algorithm": "hmac-sha256"},
            "signature": "bad",
        }
        ok, reason = module.verify_scope(scope, key_path=Path("config/signer.key"), pub_path=Path("config/signer.pub"))
        self.assertFalse(ok)
        self.assertEqual(reason, "bad_signature")
        os.environ.pop("SCOPE_SIGNING_KEY", None)


if __name__ == "__main__":
    unittest.main()
