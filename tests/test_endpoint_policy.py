from __future__ import annotations

import unittest

from hunterops.policy import EndpointPolicyEngine


class EndpointPolicyTests(unittest.TestCase):
    def test_block_and_allow_rules(self) -> None:
        cfg = {
            "endpoint_policies": {
                "default": {
                    "block": [{"prefix": "/admin"}],
                    "allow": [{"prefix": "/admin/health", "methods": ["GET"]}],
                }
            }
        }
        engine = EndpointPolicyEngine(cfg)
        blocked, reason = engine.is_blocked("any", "/admin", "GET")
        self.assertTrue(blocked)
        self.assertEqual(reason, "blocked_by_rule")

        blocked, reason = engine.is_blocked("any", "/admin/health", "GET")
        self.assertFalse(blocked)
        self.assertEqual(reason, "allowed_by_rule")


if __name__ == "__main__":
    unittest.main()
