from __future__ import annotations

import unittest

from hunterops.sensitivity import sensitivity_score


class SensitivityScoringTests(unittest.TestCase):
    def test_detects_email_and_token(self) -> None:
        text = "User email: alice@example.com token: sk_live_1234567890"
        score, meta = sensitivity_score(text)
        self.assertGreaterEqual(score, 0.4)
        self.assertGreater(meta["hits"].get("email", 0), 0)
        self.assertGreater(meta["hits"].get("token", 0), 0)

    def test_detects_iban_and_balance(self) -> None:
        text = "IBAN: GB82WEST12345698765432 balance: 1000"
        score, meta = sensitivity_score(text)
        self.assertGreaterEqual(score, 0.3)
        self.assertGreater(meta["hits"].get("iban", 0), 0)

    def test_negative_sample(self) -> None:
        score, meta = sensitivity_score("hello world")
        self.assertLess(score, 0.1)
        self.assertFalse(meta["injected_match"])


if __name__ == "__main__":
    unittest.main()
