from __future__ import annotations

import unittest

from hunterops import impact_validator as iv
from hunterops.types import Finding


class _Logger:
    def info(self, _msg: str) -> None:
        return

    def warning(self, _msg: str) -> None:
        return

    def error(self, _msg: str) -> None:
        return


class ImpactValidatorTests(unittest.IsolatedAsyncioTestCase):
    async def test_root_html_query_noise_is_not_promoted_to_critical(self) -> None:
        validator = iv.ImpactValidator(
            cfg={
                "enabled": True,
                "similarity_threshold": 88,
                "require_json_response": True,
                "min_sensitive_signal_score": 3,
            },
            runtime={},
            logger=_Logger(),
        )

        async def fake_request(_method: str, _url: str, **_kwargs: object) -> dict[str, object]:
            return {
                "status": 200,
                "headers": {"content-type": "text/html; charset=utf-8"},
                "text": "<html><body>contact support email support@capital.com</body></html>",
                "length": 68,
            }

        prev = iv.request_http_async
        try:
            iv.request_http_async = fake_request  # type: ignore[assignment]
            finding = Finding(
                plugin="parameter_intelligence",
                target="capital.com",
                category="Potential_IDOR_Signal",
                severity="medium",
                title="candidate",
                evidence={},
                metadata={"confidence_score": 82.0, "impact": 40.0},
            )
            result = await validator._validate_single(  # noqa: SLF001
                finding=finding,
                target="capital.com",
                run_id="run-test",
                url="https://capital.com/?id=example%40gmail.com",
                method="GET",
                req_headers={},
                body=None,
                headers_a={"Cookie": "a=1"},
                headers_b={"Cookie": "b=1"},
            )
            self.assertEqual(result.category, "Potential_IDOR_Signal")
            self.assertEqual(result.severity, "medium")
        finally:
            iv.request_http_async = prev  # type: ignore[assignment]

    async def test_api_json_exposure_still_promotes_to_critical(self) -> None:
        validator = iv.ImpactValidator(
            cfg={
                "enabled": True,
                "similarity_threshold": 88,
                "require_json_response": True,
                "min_sensitive_signal_score": 3,
            },
            runtime={},
            logger=_Logger(),
        )

        async def fake_request(_method: str, _url: str, **_kwargs: object) -> dict[str, object]:
            return {
                "status": 200,
                "headers": {"content-type": "application/json"},
                "text": '{"email":"user@example.com","accountId":"1001","balance":1042.33}',
                "length": 66,
            }

        prev = iv.request_http_async
        try:
            iv.request_http_async = fake_request  # type: ignore[assignment]
            finding = Finding(
                plugin="parameter_intelligence",
                target="payment.backend-capital.com",
                category="Potential_IDOR_Signal",
                severity="medium",
                title="candidate",
                evidence={},
                metadata={"confidence_score": 82.0, "impact": 40.0},
            )
            result = await validator._validate_single(  # noqa: SLF001
                finding=finding,
                target="payment.backend-capital.com",
                run_id="run-test",
                url="https://payment.backend-capital.com/v1/api/payments/transactions?id=1001",
                method="GET",
                req_headers={},
                body=None,
                headers_a={"Cookie": "a=1"},
                headers_b={"Cookie": "b=1"},
            )
            self.assertEqual(result.category, "critical_public_data_exposure")
            self.assertEqual(result.severity, "critical")
            self.assertTrue(bool((result.metadata or {}).get("impact_validated")))
        finally:
            iv.request_http_async = prev  # type: ignore[assignment]


if __name__ == "__main__":
    unittest.main()
