from __future__ import annotations

import unittest
from unittest.mock import patch

from hunterops.attack_chain.baseline import BaselineComparer


class BaselineComparerTests(unittest.IsolatedAsyncioTestCase):
    async def test_baseline_score_low_when_same(self) -> None:
        comparer = BaselineComparer(methods=[{"method": "GET"}, {"method": "POST", "body": {"ping": "1"}}], timeout_s=5)

        async def fake_request(method: str, url: str, headers: dict | None = None, body: object = None, timeout: int = 5) -> dict:
            return {"ok": True, "status": 200, "headers": {}, "text": "same", "length": 4}

        with patch("hunterops.attack_chain.baseline.request_http_async", side_effect=fake_request):
            result = await comparer.measure("https://example.com/api/baseline", headers={})

        self.assertLess(result.get("baseline_score", 1.0), 0.05)

    async def test_baseline_score_high_when_diff(self) -> None:
        comparer = BaselineComparer(methods=[{"method": "GET"}, {"method": "POST", "body": {"ping": "1"}}], timeout_s=5)

        async def fake_request(method: str, url: str, headers: dict | None = None, body: object = None, timeout: int = 5) -> dict:
            text = "get" if method == "GET" else "post-different"
            status = 200 if method == "GET" else 201
            return {"ok": True, "status": status, "headers": {}, "text": text, "length": len(text)}

        with patch("hunterops.attack_chain.baseline.request_http_async", side_effect=fake_request):
            result = await comparer.measure("https://example.com/api/baseline-diff", headers={})

        self.assertGreater(result.get("baseline_score", 0.0), 0.2)


if __name__ == "__main__":
    unittest.main()
