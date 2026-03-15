from __future__ import annotations

import contextlib
import asyncio
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

from hunterops.http_client import clear_runtime_session_state, get_runtime_session_state, request_http_async, set_runtime_session_state
from hunterops.metrics import inc_auth_failure, inc_auth_retry, set_active_sessions
from hunterops.runtime_paths import ensure_directory, resolve_path
from hunterops.session_profiles import auth_header, load_sessions
from hunterops.storage import PostgresStorage


def _to_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        raw = value.strip().lower()
        if raw in {"1", "true", "yes", "on"}:
            return True
        if raw in {"0", "false", "no", "off"}:
            return False
    if value is None:
        return default
    return bool(value)


def _sanitize_label(value: str) -> str:
    raw = str(value or "").strip().lower()
    if not raw:
        return "session"
    out = []
    for ch in raw:
        if ch.isalnum() or ch in {"_", "-", "."}:
            out.append(ch)
        else:
            out.append("_")
    return "".join(out).strip("_") or "session"


def _cookie_header_to_pairs(cookie_header: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for part in str(cookie_header or "").split(";"):
        chunk = part.strip()
        if not chunk or "=" not in chunk:
            continue
        name, value = chunk.split("=", 1)
        k = str(name).strip()
        v = str(value).strip()
        if not k:
            continue
        out.append((k, v))
    return out


def _default_username_selectors() -> list[str]:
    return [
        "input[type='email']",
        "input[name='email']",
        "input[name='username']",
        "input[name='user']",
        "input[id='username']",
        "input[id='email']",
        "input[type='text']",
    ]


def _default_password_selectors() -> list[str]:
    return [
        "input[type='password']",
        "input[name='password']",
        "input[id='password']",
    ]


def _default_submit_selectors() -> list[str]:
    return [
        "button[type='submit']",
        "input[type='submit']",
        "button[data-test='login-button']",
        "button[id='login']",
        "button[name='login']",
        "button",
    ]


def _as_selector_list(raw: Any, fallback: list[str]) -> list[str]:
    if isinstance(raw, list):
        out = [str(x).strip() for x in raw if str(x).strip()]
        return out or fallback
    if isinstance(raw, str) and raw.strip():
        return [raw.strip()]
    return fallback


def _build_url(target: str, path: str) -> str:
    target_s = str(target or "").strip()
    if not target_s:
        return ""
    if str(path or "").startswith("http://") or str(path or "").startswith("https://"):
        return str(path)
    base = target_s if target_s.startswith("http://") or target_s.startswith("https://") else f"https://{target_s}"
    parsed = urlparse(base)
    clean_path = str(path or "").strip() or "/"
    if not clean_path.startswith("/"):
        clean_path = "/" + clean_path
    return f"{parsed.scheme}://{parsed.netloc}{clean_path}"


def _extract_host(raw: str) -> str:
    try:
        return str(urlparse(str(raw or "")).hostname or "").strip().lower()
    except Exception:
        return ""


@dataclass
class SessionGuardianEvent:
    target: str
    session_name: str
    status: str
    reason: str
    heartbeat_url: str
    refresh_ok: bool = False
    cookie_len: int = 0
    screenshot_path: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "session_name": self.session_name,
            "status": self.status,
            "reason": self.reason,
            "heartbeat_url": self.heartbeat_url,
            "refresh_ok": self.refresh_ok,
            "cookie_len": self.cookie_len,
            "screenshot_path": self.screenshot_path,
        }


class SessionGuardian:
    def __init__(
        self,
        *,
        cfg: dict[str, Any],
        runtime: dict[str, Any],
        logger: Any,
        storage: PostgresStorage | None = None,
        sessions_file: Path | None = None,
    ) -> None:
        self.cfg = cfg if isinstance(cfg, dict) else {}
        self.runtime = runtime if isinstance(runtime, dict) else {}
        self.logger = logger
        self.storage = storage
        self.enabled = _to_bool(self.cfg.get("enabled", False), False)
        self.headless = _to_bool(self.cfg.get("headless", True), True)
        self.browser_heartbeat = _to_bool(self.cfg.get("browser_heartbeat", True), True)
        self.capture_refresh_screenshot = _to_bool(self.cfg.get("capture_refresh_screenshot", True), True)
        self.capture_report_screenshot = _to_bool(self.cfg.get("capture_report_screenshot", True), True)
        self.heartbeat_timeout_seconds = max(
            5,
            int(self.cfg.get("heartbeat_timeout_seconds", self.runtime.get("timeout_seconds", 25)) or 25),
        )
        self.check_interval_seconds = max(30.0, float(self.cfg.get("check_interval_seconds", 300.0) or 300.0))
        self.heartbeat_paths = [
            str(x).strip() for x in (self.cfg.get("heartbeat_paths", ["/"])) if str(x).strip()
        ] or ["/"]
        self.login_indicators = tuple(
            str(x).strip().lower()
            for x in self.cfg.get(
                "login_indicators",
                ["/login", "/signin", "/auth", "/oauth", "saml", "idp"],
            )
            if str(x).strip()
        )
        self.unauthorized_statuses = {
            int(x)
            for x in self.cfg.get("unauthorized_statuses", [401, 403])
            if str(x).strip()
        } or {401, 403}
        self.session_names = [
            str(x).strip().lower() for x in self.cfg.get("session_names", ["user", "user_b"]) if str(x).strip()
        ] or ["user", "user_b"]
        default_sessions = sessions_file or resolve_path("data/sessions.yaml")
        self.sessions_file = resolve_path(str(self.cfg.get("sessions_file", default_sessions)))
        self.vault_file = resolve_path(str(self.cfg.get("vault_file", "config/vault.yaml")))
        self.screenshot_dir = ensure_directory(
            resolve_path(str(self.cfg.get("screenshot_dir", "data/evidence/session_guardian")), prefer_existing=False),
            mode=0o755,
        )
        self._last_check: dict[str, float] = {}
        self._playwright_available: bool | None = None
        self._playwright_disabled_until: float = 0.0
        self._playwright_disabled_reason: str = ""
        self._disable_browser_on_runtime_errors = _to_bool(self.cfg.get("disable_browser_on_runtime_errors", True), True)
        self._playwright_runtime_retry_seconds = max(
            60.0,
            float(self.cfg.get("playwright_runtime_retry_seconds", 900.0) or 900.0),
        )
        self._vault_cache: dict[str, dict[str, Any]] = {}
        self._vault_mtime: float = 0.0
        self._max_report_screenshots = max(1, int(self.cfg.get("max_report_screenshots", 24) or 24))
        self._report_screenshots_taken = 0
        self._auth_failures: dict[str, int] = {}
        self._auth_locked_until: dict[str, float] = {}
        self._auth_backoff_base_s = max(1.0, float(self.cfg.get("auth_backoff_base_s", 2.0) or 2.0))
        self._auth_backoff_max_s = max(2.0, float(self.cfg.get("auth_backoff_max_s", 30.0) or 30.0))
        self._auth_max_attempts = max(1, int(self.cfg.get("auth_max_attempts", 3) or 3))
        self._auth_lockout_window_s = max(30.0, float(self.cfg.get("auth_lockout_window_s", 600.0) or 600.0))

    async def warmup(self) -> None:
        if not self.enabled:
            return
        loaded = self._load_vault()
        if loaded:
            self.logger.info(f"session_guardian_vault_loaded entries={len(loaded)} path={self.vault_file}")
        else:
            self.logger.warning(f"session_guardian_vault_empty path={self.vault_file}")
        await self._hydrate_from_storage()
        has_playwright = await self._has_playwright()
        self.logger.info(
            f"session_guardian_ready enabled={int(self.enabled)} playwright={int(has_playwright)} sessions_file={self.sessions_file}"
        )

    async def _has_playwright(self) -> bool:
        now = time.monotonic()
        if now < self._playwright_disabled_until:
            return False
        if self._playwright_available is not None:
            return self._playwright_available
        try:
            from playwright.async_api import async_playwright  # noqa: F401

            self._playwright_available = True
        except Exception:
            self._playwright_available = False
        return bool(self._playwright_available)

    def _mark_playwright_runtime_failure(self, reason: str) -> None:
        if not self._disable_browser_on_runtime_errors:
            return
        self._playwright_disabled_until = time.monotonic() + self._playwright_runtime_retry_seconds
        self._playwright_disabled_reason = str(reason or "runtime_failure").strip() or "runtime_failure"
        self.logger.warning(
            "session_guardian_playwright_backoff "
            f"retry_in_seconds={int(self._playwright_runtime_retry_seconds)} "
            f"reason={self._playwright_disabled_reason}"
        )

    def _load_vault(self) -> dict[str, dict[str, Any]]:
        path = self.vault_file
        if not path.exists():
            self._vault_cache = {}
            self._vault_mtime = 0.0
            return {}
        try:
            mtime = float(path.stat().st_mtime)
        except Exception:
            mtime = 0.0
        if self._vault_cache and abs(mtime - self._vault_mtime) < 0.001:
            return self._vault_cache
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except Exception:
            doc = {}
        out: dict[str, dict[str, Any]] = {}
        rows = doc.get("sessions", [])
        if isinstance(rows, list):
            for row in rows:
                if not isinstance(row, dict):
                    continue
                name = str(row.get("name", "")).strip().lower()
                if not name:
                    continue
                out[name] = row
        self._vault_cache = out
        self._vault_mtime = mtime
        return out

    async def _hydrate_from_storage(self) -> None:
        if not self.storage or not self.storage.enabled:
            return
        hydrated = 0
        for name in self.session_names:
            try:
                row = self.storage.get_session_state(name)
            except Exception:
                continue
            if not row:
                continue
            cookie = str(row.get("cookie", "")).strip()
            token = str(row.get("token", "")).strip()
            if not cookie and not token:
                continue
            set_runtime_session_state(
                name,
                cookie=cookie,
                token=token,
                token_type=str(row.get("token_type", "Bearer") or "Bearer"),
                headers=row.get("headers", {}) if isinstance(row.get("headers"), dict) else {},
                metadata={"source": "postgres", "updated_at": str(row.get("updated_at", ""))},
            )
            hydrated += 1
        if hydrated:
            self.logger.info(f"session_guardian_hydrated_sessions count={hydrated}")

    def _check_due(self, target: str, session_name: str) -> bool:
        key = f"{target}|{session_name}"
        now = time.monotonic()
        prev = float(self._last_check.get(key, 0.0) or 0.0)
        if now - prev < self.check_interval_seconds:
            return False
        self._last_check[key] = now
        return True

    def _looks_login_like(self, *, final_url: str, status: int, text: str) -> bool:
        if int(status or 0) in self.unauthorized_statuses:
            return True
        url_l = str(final_url or "").strip().lower()
        if url_l:
            for marker in self.login_indicators:
                if marker and marker in url_l:
                    return True
        text_l = str(text or "").strip().lower()
        if text_l:
            for marker in ("sign in", "log in", "password", "authenticate", "sso", "welcome to"):
                if marker in text_l and ("token" not in text_l or "oauth" in text_l):
                    return True
        return False

    async def ensure_target_health(self, *, target: str, run_id: str = "") -> list[dict[str, Any]]:
        if not self.enabled:
            return []
        sessions = load_sessions(self.sessions_file)
        if not sessions:
            return []
        skip_sessions: set[str] = set()
        for primary in self.session_names:
            skip_sessions.update(self._failover_accounts(primary))
        events: list[SessionGuardianEvent] = []
        for session_name in self.session_names:
            if session_name in skip_sessions and len(skip_sessions) < len(self.session_names):
                continue
            if session_name not in sessions:
                continue
            if not self._check_due(target, session_name):
                continue
            try:
                event = await self._heartbeat_and_refresh(
                    target=target,
                    run_id=run_id,
                    session_name=session_name,
                    session_cfg=sessions.get(session_name, {}),
                )
                if event is not None:
                    events.append(event)
            except Exception as err:
                self.logger.error(
                    "session_guardian_unhandled_error "
                    f"target={target} session={session_name} err={type(err).__name__}"
                )
                events.append(
                    SessionGuardianEvent(
                        target=target,
                        session_name=session_name,
                        status="error",
                        reason=f"guardian_exception:{type(err).__name__}",
                        heartbeat_url=_build_url(target, self.heartbeat_paths[0]),
                        refresh_ok=False,
                    )
                )
        return [x.to_dict() for x in events]

    async def _heartbeat_and_refresh(
        self,
        *,
        target: str,
        run_id: str,
        session_name: str,
        session_cfg: dict[str, Any],
    ) -> SessionGuardianEvent | None:
        heartbeat_url = _build_url(target, self.heartbeat_paths[0])
        headers = auth_header({"name": session_name, **(session_cfg if isinstance(session_cfg, dict) else {})})
        status = 0
        final_url = heartbeat_url
        text_sample = ""

        used_http_fallback = False
        if self.browser_heartbeat and await self._has_playwright():
            try:
                browser_check = await self._browser_heartbeat(
                    url=heartbeat_url,
                    headers=headers,
                    session_name=session_name,
                )
                status = int(browser_check.get("status", 0) or 0)
                final_url = str(browser_check.get("final_url", heartbeat_url))
                text_sample = str(browser_check.get("text_sample", ""))
            except Exception as err:
                self._mark_playwright_runtime_failure(f"browser_heartbeat_exception:{type(err).__name__}")
                self.logger.warning(
                    "session_guardian_browser_heartbeat_failed "
                    f"target={target} session={session_name} err={type(err).__name__} fallback=http"
                )
                used_http_fallback = True
        else:
            used_http_fallback = True

        if used_http_fallback:
            resp = await request_http_async(
                "GET",
                heartbeat_url,
                headers=headers,
                timeout=self.heartbeat_timeout_seconds,
            )
            status = int(resp.get("status", 0) or 0)
            text_sample = str(resp.get("text", ""))[:1200]

        stale = self._looks_login_like(final_url=final_url, status=status, text=text_sample)
        if not stale:
            if self.storage and self.storage.enabled:
                with contextlib.suppress(Exception):
                    self.storage.upsert_session_state(
                        session_name=session_name,
                        cookie=str(get_runtime_session_state(session_name).get("cookie", "")),
                        token=str(get_runtime_session_state(session_name).get("token", "")),
                        token_type=str(get_runtime_session_state(session_name).get("token_type", "Bearer") or "Bearer"),
                        headers=get_runtime_session_state(session_name).get("headers", {}),
                        metadata={"target": target, "run_id": run_id, "heartbeat_status": status},
                        status="healthy",
                    )
            return None

        refreshed = await self._refresh_with_failover(
            target=target,
            run_id=run_id,
            session_name=session_name,
            session_cfg=session_cfg,
            reason=f"heartbeat_status={status}",
        )
        if not bool(refreshed.get("ok", False)):
            # Drop stale runtime overrides so auth_header falls back to base sessions/env.
            clear_runtime_session_state(session_name)
            if self.storage and self.storage.enabled:
                with contextlib.suppress(Exception):
                    self.storage.upsert_session_state(
                        session_name=session_name,
                        cookie="",
                        token="",
                        token_type="Bearer",
                        headers={},
                        metadata={"target": target, "run_id": run_id, "reason": str(refreshed.get("reason", ""))},
                        status="stale",
                    )
        return SessionGuardianEvent(
            target=target,
            session_name=session_name,
            status="refreshed" if refreshed.get("ok") else "stale",
            reason=str(refreshed.get("reason", "refresh_failed")),
            heartbeat_url=heartbeat_url,
            refresh_ok=bool(refreshed.get("ok", False)),
            cookie_len=int(refreshed.get("cookie_len", 0) or 0),
            screenshot_path=str(refreshed.get("screenshot_path", "")),
        )

    def _auth_locked(self, session_name: str) -> bool:
        until = float(self._auth_locked_until.get(session_name, 0.0) or 0.0)
        return time.monotonic() < until

    def _record_auth_failure(self, session_name: str) -> None:
        failures = int(self._auth_failures.get(session_name, 0) or 0) + 1
        self._auth_failures[session_name] = failures
        if failures >= self._auth_max_attempts:
            self._auth_locked_until[session_name] = time.monotonic() + self._auth_lockout_window_s
            self._auth_failures[session_name] = 0

    async def _auth_backoff(self, attempt: int) -> None:
        delay = min(self._auth_backoff_max_s, self._auth_backoff_base_s * (2**attempt))
        await asyncio.sleep(delay)

    def _failover_accounts(self, session_name: str) -> list[str]:
        cfg_list = self.cfg.get("failover_accounts", []) if isinstance(self.cfg.get("failover_accounts", []), list) else []
        vault = self._load_vault().get(session_name, {})
        vault_list = vault.get("fallback_accounts", []) if isinstance(vault.get("fallback_accounts", []), list) else []
        combined = [str(x).strip().lower() for x in (cfg_list + vault_list) if str(x).strip()]
        return [x for x in combined if x != session_name]

    def _active_session_count(self) -> int:
        count = 0
        for name in self.session_names:
            state = get_runtime_session_state(name)
            if state.get("cookie") or state.get("token"):
                count += 1
        return count

    async def _refresh_with_failover(
        self,
        *,
        target: str,
        run_id: str,
        session_name: str,
        session_cfg: dict[str, Any],
        reason: str,
    ) -> dict[str, Any]:
        attempts = 0
        candidates = [session_name] + self._failover_accounts(session_name)
        sessions = load_sessions(self.sessions_file)
        last_resp: dict[str, Any] = {"ok": False, "reason": "refresh_failed"}
        for candidate in candidates:
            if self._auth_locked(candidate):
                last_resp = {"ok": False, "reason": f"auth_locked:{candidate}"}
                continue
            if attempts > 0:
                inc_auth_retry(candidate)
                await self._auth_backoff(attempts - 1)
            attempts += 1
            resp = await self._refresh_session(
                target=target,
                run_id=run_id,
                session_name=candidate,
                session_cfg=sessions.get(candidate, session_cfg),
                reason=reason,
            )
            last_resp = resp
            if resp.get("ok"):
                set_active_sessions(self._active_session_count())
                return resp
            self._record_auth_failure(candidate)
            inc_auth_failure(candidate)
            if attempts >= self._auth_max_attempts:
                break
        set_active_sessions(self._active_session_count())
        return last_resp

    async def _browser_heartbeat(self, *, url: str, headers: dict[str, str], session_name: str) -> dict[str, Any]:
        try:
            from playwright.async_api import async_playwright
        except Exception as err:
            return {"status": 0, "final_url": url, "text_sample": f"playwright_unavailable:{type(err).__name__}"}

        domain = _extract_host(url)
        cookies = [
            {"name": name, "value": value, "domain": domain, "path": "/", "secure": True, "httpOnly": False}
            for name, value in _cookie_header_to_pairs(str(headers.get("Cookie", "")))
            if domain
        ]
        timeout_ms = max(5000, int(self.heartbeat_timeout_seconds * 1000))
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=self.headless)
                context = await browser.new_context(ignore_https_errors=True)
                if cookies:
                    with contextlib.suppress(Exception):
                        await context.add_cookies(cookies)
                page = await context.new_page()
                response = None
                try:
                    response = await page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
                    await page.wait_for_timeout(800)
                    content = await page.content()
                    return {
                        "status": int(response.status if response else 0),
                        "final_url": str(page.url),
                        "text_sample": str(content)[:1200],
                        "session_name": session_name,
                    }
                finally:
                    with contextlib.suppress(Exception):
                        await context.close()
                    with contextlib.suppress(Exception):
                        await browser.close()
        except Exception as err:
            self._mark_playwright_runtime_failure(f"browser_heartbeat_runtime_error:{type(err).__name__}")
            return {"status": 0, "final_url": url, "text_sample": f"browser_heartbeat_failed:{type(err).__name__}"}

    def _read_credential(self, row: dict[str, Any], key_plain: str, key_env: str) -> str:
        env_name = str(row.get(key_env, "")).strip()
        if env_name:
            val = str(os.getenv(env_name, "")).strip()
            if val:
                return val
        return str(row.get(key_plain, "")).strip()

    async def _refresh_session(
        self,
        *,
        target: str,
        run_id: str,
        session_name: str,
        session_cfg: dict[str, Any],
        reason: str,
    ) -> dict[str, Any]:
        if not await self._has_playwright():
            return {"ok": False, "reason": "playwright_unavailable"}
        vault = self._load_vault().get(session_name, {})
        if not vault:
            return {"ok": False, "reason": f"vault_entry_missing:{session_name}"}
        login_url = str(vault.get("login_url", "")).strip()
        if not login_url:
            return {"ok": False, "reason": f"vault_login_url_missing:{session_name}"}
        username = self._read_credential(vault, "username", "username_env")
        password = self._read_credential(vault, "password", "password_env")
        if not username or not password:
            return {"ok": False, "reason": f"vault_credentials_missing:{session_name}"}

        username_selectors = _as_selector_list(vault.get("username_selectors"), _default_username_selectors())
        password_selectors = _as_selector_list(vault.get("password_selectors"), _default_password_selectors())
        submit_selectors = _as_selector_list(vault.get("submit_selectors"), _default_submit_selectors())
        timeout_ms = max(5000, int(self.heartbeat_timeout_seconds * 1000))

        try:
            from playwright.async_api import async_playwright
        except Exception:
            return {"ok": False, "reason": "playwright_import_failed"}

        screenshot_path = ""
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=self.headless)
                context = await browser.new_context(ignore_https_errors=True)
                page = await context.new_page()
                try:
                    await page.goto(login_url, wait_until="domcontentloaded", timeout=timeout_ms)
                    await self._fill_first(page, username_selectors, username)
                    await self._fill_first(page, password_selectors, password)
                    await self._click_first(page, submit_selectors)
                    with contextlib.suppress(Exception):
                        await page.wait_for_load_state("networkidle", timeout=timeout_ms)
                    await page.wait_for_timeout(1200)
                    if self.capture_refresh_screenshot:
                        screenshot_path = await self._save_screenshot(
                            page=page,
                            target=target,
                            session_name=session_name,
                            label="post_login_refresh",
                        )
                    cookies = await context.cookies()
                finally:
                    with contextlib.suppress(Exception):
                        await context.close()
                    with contextlib.suppress(Exception):
                        await browser.close()
        except Exception as err:
            self._mark_playwright_runtime_failure(f"refresh_runtime_error:{type(err).__name__}")
            return {"ok": False, "reason": f"playwright_runtime_error:{type(err).__name__}"}

        target_host = _extract_host(_build_url(target, "/"))
        login_host = _extract_host(login_url)
        cookie_parts: list[str] = []
        for item in cookies:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name", "")).strip()
            value = str(item.get("value", "")).strip()
            domain = str(item.get("domain", "")).strip().lstrip(".").lower()
            if not name or not value:
                continue
            if target_host and domain and (target_host.endswith(domain) or domain.endswith(target_host)):
                cookie_parts.append(f"{name}={value}")
                continue
            if login_host and domain and (login_host.endswith(domain) or domain.endswith(login_host)):
                cookie_parts.append(f"{name}={value}")
                continue
        cookie_header = "; ".join(cookie_parts).strip()
        if not cookie_header:
            return {"ok": False, "reason": "refresh_no_cookie", "screenshot_path": screenshot_path}

        raw_session = {"name": session_name, **(session_cfg if isinstance(session_cfg, dict) else {})}
        token_env = str(raw_session.get("token_env", "")).strip()
        token_type = str(raw_session.get("token_type", "Bearer") or "Bearer").strip()
        token = str(os.getenv(token_env, "")).strip() if token_env else str(raw_session.get("token", "")).strip()
        merged_headers = vault.get("headers", {}) if isinstance(vault.get("headers"), dict) else {}
        set_runtime_session_state(
            session_name,
            cookie=cookie_header,
            token=token,
            token_type=token_type,
            headers=merged_headers,
            metadata={"reason": reason, "target": target, "run_id": run_id},
        )
        if self.storage and self.storage.enabled:
            with contextlib.suppress(Exception):
                self.storage.upsert_session_state(
                    session_name=session_name,
                    cookie=cookie_header,
                    token=token,
                    token_type=token_type,
                    headers=merged_headers,
                    metadata={"target": target, "run_id": run_id, "reason": reason},
                    status="refreshed",
                )
        return {
            "ok": True,
            "reason": "refreshed",
            "cookie_len": len(cookie_header),
            "screenshot_path": screenshot_path,
        }

    async def capture_endpoint_screenshot(
        self,
        *,
        target: str,
        url: str,
        label: str,
        session_name: str = "user",
    ) -> str:
        if not self.enabled or not self.capture_report_screenshot:
            return ""
        if self._report_screenshots_taken >= self._max_report_screenshots:
            return ""
        if not await self._has_playwright():
            return ""
        sessions = load_sessions(self.sessions_file)
        session_cfg = sessions.get(str(session_name).strip().lower(), {})
        headers = auth_header({"name": session_name, **session_cfg})
        try:
            from playwright.async_api import async_playwright
        except Exception:
            return ""
        domain = _extract_host(url)
        cookies = [
            {"name": name, "value": value, "domain": domain, "path": "/", "secure": True, "httpOnly": False}
            for name, value in _cookie_header_to_pairs(str(headers.get("Cookie", "")))
            if domain
        ]
        timeout_ms = max(5000, int(self.heartbeat_timeout_seconds * 1000))
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=self.headless)
            context = await browser.new_context(ignore_https_errors=True)
            if cookies:
                with contextlib.suppress(Exception):
                    await context.add_cookies(cookies)
            page = await context.new_page()
            try:
                await page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
                await page.wait_for_timeout(500)
                output = await self._save_screenshot(
                    page=page,
                    target=target,
                    session_name=session_name,
                    label=label,
                )
                if output:
                    self._report_screenshots_taken += 1
                return output
            except Exception:
                return ""
            finally:
                with contextlib.suppress(Exception):
                    await context.close()
                with contextlib.suppress(Exception):
                    await browser.close()

    async def _fill_first(self, page: Any, selectors: list[str], value: str) -> bool:
        for selector in selectors:
            try:
                locator = page.locator(selector)
                if await locator.count() <= 0:
                    continue
                await locator.first.fill(value)
                return True
            except Exception:
                continue
        return False

    async def _click_first(self, page: Any, selectors: list[str]) -> bool:
        for selector in selectors:
            try:
                locator = page.locator(selector)
                if await locator.count() <= 0:
                    continue
                await locator.first.click()
                return True
            except Exception:
                continue
        return False

    async def _save_screenshot(self, *, page: Any, target: str, session_name: str, label: str) -> str:
        ts = int(time.time() * 1000)
        safe_target = _sanitize_label(target.replace("://", "_"))
        safe_name = _sanitize_label(session_name)
        safe_label = _sanitize_label(label)
        path = self.screenshot_dir / f"{safe_target}_{safe_name}_{safe_label}_{ts}.png"
        try:
            await page.screenshot(path=str(path), full_page=True)
            return str(path)
        except Exception:
            return ""
