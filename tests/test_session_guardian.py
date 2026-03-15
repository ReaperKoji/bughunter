from __future__ import annotations

import tempfile
import time
import unittest
from pathlib import Path

from hunterops import session_guardian as sg
from hunterops.http_client import clear_runtime_session_state, get_runtime_session_state, set_runtime_session_state


class _LoggerStub:
    def info(self, _msg: str) -> None:
        return

    def warning(self, _msg: str) -> None:
        return

    def error(self, _msg: str) -> None:
        return


class SessionGuardianTests(unittest.IsolatedAsyncioTestCase):
    async def test_browser_heartbeat_failure_falls_back_to_http(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            sessions_path = Path(td) / "sessions.yaml"
            sessions_path.write_text(
                "sessions:\n"
                "  - name: user\n"
                "    cookie: SESSION=abc\n",
                encoding="utf-8",
            )
            guardian = sg.SessionGuardian(
                cfg={
                    "enabled": True,
                    "session_names": ["user"],
                    "heartbeat_paths": ["/v1/api/profile"],
                    "browser_heartbeat": True,
                    "disable_browser_on_runtime_errors": True,
                    "playwright_runtime_retry_seconds": 300,
                    "check_interval_seconds": 30,
                },
                runtime={"timeout_seconds": 10},
                logger=_LoggerStub(),
                storage=None,
                sessions_file=sessions_path,
            )
            guardian._playwright_available = True  # force browser path for this test

            async def _boom_browser(**_kwargs: object) -> dict[str, object]:
                raise RuntimeError("browser boom")

            request_calls = {"count": 0}

            async def _ok_http(*_args: object, **_kwargs: object) -> dict[str, object]:
                request_calls["count"] += 1
                return {"status": 200, "text": "ok", "headers": {}, "length": 2}

            prev_http = sg.request_http_async
            try:
                guardian._browser_heartbeat = _boom_browser  # type: ignore[method-assign]
                sg.request_http_async = _ok_http  # type: ignore[assignment]
                events = await guardian.ensure_target_health(target="capital.com", run_id="run-sg-1")
            finally:
                sg.request_http_async = prev_http  # type: ignore[assignment]

            self.assertEqual(events, [])
            self.assertEqual(request_calls["count"], 1)
            self.assertGreater(guardian._playwright_disabled_until, time.monotonic())

    async def test_stale_session_refresh_failure_clears_runtime_override(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            sessions_path = Path(td) / "sessions.yaml"
            sessions_path.write_text(
                "sessions:\n"
                "  - name: user\n"
                "    cookie: SESSION=base\n",
                encoding="utf-8",
            )
            guardian = sg.SessionGuardian(
                cfg={
                    "enabled": True,
                    "session_names": ["user"],
                    "heartbeat_paths": ["/v1/api/profile"],
                    "browser_heartbeat": False,
                    "check_interval_seconds": 30,
                },
                runtime={"timeout_seconds": 10},
                logger=_LoggerStub(),
                storage=None,
                sessions_file=sessions_path,
            )
            clear_runtime_session_state("user")
            set_runtime_session_state("user", cookie="SESSION=stale", headers={})

            async def _stale_http(*_args: object, **_kwargs: object) -> dict[str, object]:
                return {"status": 401, "text": "please login", "headers": {}, "length": 12}

            async def _refresh_fail(**_kwargs: object) -> dict[str, object]:
                return {"ok": False, "reason": "refresh_failed"}

            prev_http = sg.request_http_async
            try:
                sg.request_http_async = _stale_http  # type: ignore[assignment]
                guardian._refresh_session = _refresh_fail  # type: ignore[method-assign]
                events = await guardian.ensure_target_health(target="capital.com", run_id="run-sg-2")
            finally:
                sg.request_http_async = prev_http  # type: ignore[assignment]

            self.assertEqual(len(events), 1)
            self.assertEqual(str(events[0].get("status")), "stale")
            self.assertFalse(bool(events[0].get("refresh_ok")))
            self.assertEqual(get_runtime_session_state("user"), {})
            clear_runtime_session_state("user")

    async def test_refresh_failover_uses_backup_account(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            sessions_path = Path(td) / "sessions.yaml"
            sessions_path.write_text(
                "sessions:\n"
                "  - name: user\n"
                "    cookie: SESSION=base\n"
                "  - name: user_b\n"
                "    cookie: SESSION=backup\n",
                encoding="utf-8",
            )
            guardian = sg.SessionGuardian(
                cfg={
                    "enabled": True,
                    "session_names": ["user", "user_b"],
                    "heartbeat_paths": ["/v1/api/profile"],
                    "browser_heartbeat": False,
                    "check_interval_seconds": 30,
                    "failover_accounts": ["user_b"],
                    "auth_max_attempts": 2,
                },
                runtime={"timeout_seconds": 10},
                logger=_LoggerStub(),
                storage=None,
                sessions_file=sessions_path,
            )
            clear_runtime_session_state("user")
            clear_runtime_session_state("user_b")

            async def _stale_http(*_args: object, **_kwargs: object) -> dict[str, object]:
                return {"status": 401, "text": "please login", "headers": {}, "length": 12}

            async def _refresh_stub(**kwargs: object) -> dict[str, object]:
                session_name = str(kwargs.get("session_name", ""))
                if session_name == "user":
                    return {"ok": False, "reason": "primary_failed"}
                sg.set_runtime_session_state(session_name, cookie="SESSION=backup", headers={})
                return {"ok": True, "reason": "refreshed", "cookie_len": 12}

            prev_http = sg.request_http_async
            try:
                sg.request_http_async = _stale_http  # type: ignore[assignment]
                guardian._refresh_session = _refresh_stub  # type: ignore[method-assign]
                events = await guardian.ensure_target_health(target="capital.com", run_id="run-sg-3")
            finally:
                sg.request_http_async = prev_http  # type: ignore[assignment]

            self.assertEqual(len(events), 1)
            self.assertEqual(str(events[0].get("status")), "refreshed")
            self.assertTrue(bool(events[0].get("refresh_ok")))
            self.assertNotEqual(get_runtime_session_state("user_b"), {})


if __name__ == "__main__":
    unittest.main()
