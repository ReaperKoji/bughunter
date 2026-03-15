from __future__ import annotations

import asyncio
import fnmatch
import json
import os
import socket
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from threading import Lock
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

try:
    import httpx
except Exception:  # pragma: no cover - optional runtime dependency fallback
    httpx = None  # type: ignore[assignment]

from hunterops.rate_limit import AsyncRateLimiter
from hunterops.metrics import inc_request, observe_latency, inc_scope_blocked, inc_program_budget_blocked, inc_scope_blocked_path
from hunterops.secrets import read_secret
from hunterops.url_utils import normalize_endpoint, match_patterns, split_url

_ASYNC_CLIENT: "httpx.AsyncClient | None" = None
_ASYNC_CLIENT_LOOP_ID: int | None = None
_CLIENT_LOCK = asyncio.Lock()
_POOL_CFG = {
    "max_connections": 100,
    "max_keepalive_connections": 20,
    "keepalive_expiry": 10.0,
    "verify_ssl": True,
    "http2": False,
    "retries": 0,
    "linux_socket_tuning": True,
}
_CB_THRESHOLD = max(1, int(os.getenv("HUNTEROPS_CB_429_THRESHOLD", "10") or 10))
_CB_COOLDOWN_SECONDS = max(1.0, float(os.getenv("HUNTEROPS_CB_COOLDOWN_SECONDS", "60") or 60))
_CB_RETRY_AFTER_CAP_SECONDS = max(1.0, float(os.getenv("HUNTEROPS_CB_RETRY_AFTER_CAP_SECONDS", "900") or 900))
_CB_STREAKS: dict[str, int] = {}
_CB_COOLDOWN_UNTIL: dict[str, float] = {}
_CB_LOCK = Lock()
_GLOBAL_HTTP_CFG = {
    "rate_per_sec": max(0.1, float(os.getenv("HUNTEROPS_GLOBAL_HTTP_RPS", "10") or 10)),
    "max_inflight": max(1, int(os.getenv("HUNTEROPS_GLOBAL_HTTP_MAX_INFLIGHT", "10") or 10)),
}
_GLOBAL_ASYNC_GUARD_LOCK = asyncio.Lock()
_GLOBAL_ASYNC_GUARD_LOOP_ID: int | None = None
_GLOBAL_ASYNC_SEMAPHORE: asyncio.Semaphore | None = None
_GLOBAL_ASYNC_RATE_LIMITER: AsyncRateLimiter | None = None
_GLOBAL_SYNC_GUARD_LOCK = Lock()
_GLOBAL_SYNC_LAST_REQUEST_AT = 0.0
_RUNTIME_SESSION_LOCK = Lock()
_RUNTIME_SESSION_STATE: dict[str, dict[str, Any]] = {}
_SCOPE_GUARD = {"enabled": False, "patterns": [], "allowlist": [], "denylist": []}
_HOST_POLICY_LOCK = Lock()
_HOST_POLICIES: list[dict[str, Any]] = []
_HOST_GUARD_LOCK = asyncio.Lock()
_HOST_GUARDS: dict[str, tuple[asyncio.Semaphore, AsyncRateLimiter]] = {}
_HOST_SYNC_LOCK = Lock()
_HOST_SYNC_LAST_REQUEST_AT: dict[str, float] = {}
_PROGRAM_LIMIT_LOCK = Lock()
_PROGRAM_BUDGETS: dict[str, int] = {}
_PROGRAM_REQUESTS: dict[str, int] = {}


def _client_identifier() -> str:
    raw = read_secret("H1_API_IDENTIFIER")
    return raw or "reaperk0ji"


def _bug_bounty_username(identifier: str) -> str:
    direct = read_secret("HUNTEROPS_BUG_BOUNTY_USERNAME")
    if direct:
        return direct
    legacy = read_secret("BUG_BOUNTY_USERNAME")
    if legacy:
        return legacy
    return identifier


def _bug_bounty_test_account_email() -> str:
    direct = read_secret("HUNTEROPS_TEST_ACCOUNT_EMAIL")
    if direct:
        return direct
    legacy = read_secret("BUG_BOUNTY_TEST_ACCOUNT_EMAIL")
    if legacy:
        return legacy
    return ""


def _standard_user_agent(identifier: str) -> str:
    return f"Mozilla/5.0 (HunterOps/3.0; BugBounty; {identifier})."


def _merge_default_headers(headers: dict[str, str] | None) -> dict[str, str]:
    identifier = _client_identifier()
    username = _bug_bounty_username(identifier)
    test_account_email = _bug_bounty_test_account_email()
    merged = headers.copy() if isinstance(headers, dict) else {}
    # Force stable attribution for authorized bug bounty traffic.
    merged["X-H1-Client-Identifier"] = identifier
    merged["User-Agent"] = _standard_user_agent(identifier)
    if username:
        merged.setdefault("X-Bug-Bounty", username)
    if test_account_email:
        merged.setdefault("X-Test-Account-Email", test_account_email)
    return merged


def _target_host(url: str) -> str:
    try:
        return str(urlparse(str(url or "")).hostname or "").strip().lower()
    except Exception:
        return ""


def _header_value(headers: dict[str, str] | None, name: str) -> str:
    if not headers:
        return ""
    needle = str(name).strip().lower()
    for key, value in headers.items():
        if str(key).strip().lower() == needle:
            return str(value)
    return ""


def _parse_retry_after(raw: str) -> float:
    text = str(raw or "").strip()
    if not text:
        return 0.0
    try:
        seconds = float(text)
        if seconds >= 0:
            return min(seconds, _CB_RETRY_AFTER_CAP_SECONDS)
    except Exception:
        pass
    try:
        dt = parsedate_to_datetime(text)
        if dt is None:
            return 0.0
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        delta = (dt.astimezone(timezone.utc) - datetime.now(timezone.utc)).total_seconds()
        if delta <= 0:
            return 0.0
        return min(delta, _CB_RETRY_AFTER_CAP_SECONDS)
    except Exception:
        return 0.0


def _circuit_remaining(host: str) -> float:
    if not host:
        return 0.0
    now = time.monotonic()
    with _CB_LOCK:
        until = float(_CB_COOLDOWN_UNTIL.get(host, 0.0))
    return max(0.0, until - now)


def _is_circuit_open(host: str) -> tuple[bool, float]:
    remaining = _circuit_remaining(host)
    return remaining > 0.0, remaining


def _record_circuit_status(host: str, status_code: int, headers: dict[str, str] | None = None) -> None:
    if not host:
        return
    status = int(status_code or 0)
    now = time.monotonic()
    with _CB_LOCK:
        if status == 429:
            retry_after = _parse_retry_after(_header_value(headers, "Retry-After"))
            if retry_after > 0:
                until = now + retry_after
                current = float(_CB_COOLDOWN_UNTIL.get(host, 0.0))
                _CB_COOLDOWN_UNTIL[host] = max(current, until)
                _CB_STREAKS[host] = 0
                return
            streak = int(_CB_STREAKS.get(host, 0) or 0) + 1
            _CB_STREAKS[host] = streak
            if streak >= _CB_THRESHOLD:
                _CB_COOLDOWN_UNTIL[host] = now + _CB_COOLDOWN_SECONDS
                _CB_STREAKS[host] = 0
        elif status > 0:
            _CB_STREAKS[host] = 0
            cooldown_until = float(_CB_COOLDOWN_UNTIL.get(host, 0.0))
            if cooldown_until and cooldown_until <= now:
                _CB_COOLDOWN_UNTIL.pop(host, None)


def _circuit_open_response(host: str, remaining: float) -> dict[str, Any]:
    return {
        "ok": False,
        "status": 429,
        "headers": {},
        "text": "circuit_open_target_cooldown",
        "length": len("circuit_open_target_cooldown"),
        "circuit_open": True,
        "cooldown_remaining_seconds": round(max(0.0, float(remaining)), 2),
        "target_host": host,
    }


def _blocked_response(reason: str, *, status: int = 403, host: str = "", path: str = "") -> dict[str, Any]:
    text = str(reason or "blocked")
    return {
        "ok": False,
        "status": int(status or 403),
        "headers": {},
        "text": text,
        "length": len(text),
        "blocked": True,
        "block_reason": text,
        "target_host": host,
        "path": path,
    }


def reset_circuit_breaker_state() -> None:
    with _CB_LOCK:
        _CB_STREAKS.clear()
        _CB_COOLDOWN_UNTIL.clear()


def configure_http_pool(
    *,
    max_connections: int | None = None,
    max_keepalive_connections: int | None = None,
    keepalive_expiry: float | None = None,
    verify_ssl: bool | None = None,
    http2: bool | None = None,
    retries: int | None = None,
    linux_socket_tuning: bool | None = None,
) -> None:
    if max_connections is not None:
        _POOL_CFG["max_connections"] = max(1, int(max_connections))
    if max_keepalive_connections is not None:
        _POOL_CFG["max_keepalive_connections"] = max(1, int(max_keepalive_connections))
    if keepalive_expiry is not None:
        _POOL_CFG["keepalive_expiry"] = max(1.0, float(keepalive_expiry))
    if verify_ssl is not None:
        _POOL_CFG["verify_ssl"] = bool(verify_ssl)
    if http2 is not None:
        _POOL_CFG["http2"] = bool(http2)
    if retries is not None:
        _POOL_CFG["retries"] = max(0, int(retries))
    if linux_socket_tuning is not None:
        _POOL_CFG["linux_socket_tuning"] = bool(linux_socket_tuning)


def configure_global_http_limits(
    *,
    rate_per_sec: float | None = None,
    max_inflight: int | None = None,
) -> None:
    global _GLOBAL_ASYNC_GUARD_LOOP_ID
    global _GLOBAL_ASYNC_SEMAPHORE
    global _GLOBAL_ASYNC_RATE_LIMITER
    global _GLOBAL_SYNC_LAST_REQUEST_AT

    if rate_per_sec is not None:
        _GLOBAL_HTTP_CFG["rate_per_sec"] = max(0.1, float(rate_per_sec))
    if max_inflight is not None:
        _GLOBAL_HTTP_CFG["max_inflight"] = max(1, int(max_inflight))
    _GLOBAL_ASYNC_GUARD_LOOP_ID = None
    _GLOBAL_ASYNC_SEMAPHORE = None
    _GLOBAL_ASYNC_RATE_LIMITER = None
    with _GLOBAL_SYNC_GUARD_LOCK:
        _GLOBAL_SYNC_LAST_REQUEST_AT = 0.0


def configure_scope_guard(
    *,
    enabled: bool,
    patterns: list[str] | None = None,
    allowlist: list[str] | None = None,
    denylist: list[str] | None = None,
) -> None:
    _SCOPE_GUARD["enabled"] = bool(enabled)
    _SCOPE_GUARD["patterns"] = [str(p).strip().lower() for p in (patterns or []) if str(p).strip()]
    _SCOPE_GUARD["allowlist"] = [str(p).strip().lower() for p in (allowlist or []) if str(p).strip()]
    _SCOPE_GUARD["denylist"] = [str(p).strip().lower() for p in (denylist or []) if str(p).strip()]


def configure_host_policies(policies: list[dict[str, Any]] | None) -> None:
    global _HOST_POLICIES
    global _HOST_GUARDS
    global _HOST_SYNC_LAST_REQUEST_AT
    global _PROGRAM_BUDGETS
    global _PROGRAM_REQUESTS
    normalized: list[dict[str, Any]] = []
    budgets: dict[str, int] = {}
    for entry in policies or []:
        pattern = str(entry.get("pattern", "")).strip().lower()
        if not pattern:
            continue
        policy = dict(entry)
        policy["pattern"] = pattern
        program_id = str(policy.get("program_id", "")).strip()
        if program_id:
            try:
                budget = int(policy.get("request_budget") or 0)
            except Exception:
                budget = 0
            if budget > 0:
                existing = budgets.get(program_id)
                budgets[program_id] = budget if existing is None else min(existing, budget)
        normalized.append(policy)
    with _HOST_POLICY_LOCK:
        _HOST_POLICIES = normalized
    _HOST_GUARDS = {}
    with _HOST_SYNC_LOCK:
        _HOST_SYNC_LAST_REQUEST_AT = {}
    with _PROGRAM_LIMIT_LOCK:
        _PROGRAM_BUDGETS = budgets
        _PROGRAM_REQUESTS = {}


def _match_host_policy(host: str) -> dict[str, Any] | None:
    if not host:
        return None
    with _HOST_POLICY_LOCK:
        for entry in _HOST_POLICIES:
            pat = str(entry.get("pattern", "")).strip().lower()
            if not pat:
                continue
            if fnmatch.fnmatch(host, pat):
                return entry
    return None


def _scope_allows(host: str, path: str) -> bool:
    if not _SCOPE_GUARD.get("enabled", False):
        return True
    denylist = _SCOPE_GUARD.get("denylist", [])
    if denylist and _match_scope_patterns(host, path, denylist):
        return False
    allowlist = _SCOPE_GUARD.get("allowlist", [])
    if allowlist:
        if _match_scope_patterns(host, path, allowlist):
            return True
    patterns = _SCOPE_GUARD.get("patterns", [])
    if not patterns:
        return False
    return _match_scope_patterns(host, path, patterns)


def _match_scope_patterns(host: str, path: str, patterns: list[str]) -> bool:
    host_val = str(host or "").strip().lower()
    path_val = str(path or "/").strip()
    if not host_val:
        return False
    combined = f"{host_val}{path_val}"
    for pat in patterns or []:
        raw = str(pat or "").strip().lower()
        if not raw:
            continue
        if "/" in raw:
            if fnmatch.fnmatch(combined, raw):
                return True
        else:
            if fnmatch.fnmatch(host_val, raw):
                return True
    return False


def _program_budget_exceeded(program_id: str) -> bool:
    if not program_id:
        return False
    with _PROGRAM_LIMIT_LOCK:
        budget = int(_PROGRAM_BUDGETS.get(program_id, 0) or 0)
        if budget <= 0:
            return False
        used = int(_PROGRAM_REQUESTS.get(program_id, 0) or 0)
        return used >= budget


def _record_program_request(program_id: str) -> None:
    if not program_id:
        return
    with _PROGRAM_LIMIT_LOCK:
        _PROGRAM_REQUESTS[program_id] = int(_PROGRAM_REQUESTS.get(program_id, 0) or 0) + 1


def _sync_host_wait(host: str, rate_per_sec: float) -> None:
    if not host or rate_per_sec <= 0:
        return
    min_interval = 1.0 / max(0.1, float(rate_per_sec))
    with _HOST_SYNC_LOCK:
        now = time.monotonic()
        last = float(_HOST_SYNC_LAST_REQUEST_AT.get(host, 0.0))
        delta = now - last
        if delta < min_interval:
            time.sleep(min_interval - delta)
        _HOST_SYNC_LAST_REQUEST_AT[host] = time.monotonic()


async def _get_async_host_guards(host: str, rate_per_sec: float, max_inflight: int) -> tuple[asyncio.Semaphore, AsyncRateLimiter]:
    async with _HOST_GUARD_LOCK:
        guards = _HOST_GUARDS.get(host)
        if guards is None:
            semaphore = asyncio.Semaphore(max(1, int(max_inflight)))
            limiter = AsyncRateLimiter(float(rate_per_sec))
            guards = (semaphore, limiter)
            _HOST_GUARDS[host] = guards
        return guards


def set_runtime_session_state(
    session_name: str,
    *,
    cookie: str = "",
    token: str = "",
    token_type: str = "Bearer",
    headers: dict[str, str] | None = None,
    metadata: dict[str, Any] | None = None,
) -> None:
    name = str(session_name or "").strip().lower()
    if not name:
        return
    record = {
        "cookie": str(cookie or "").strip(),
        "token": str(token or "").strip(),
        "token_type": str(token_type or "Bearer").strip() or "Bearer",
        "headers": {
            str(k): str(v)
            for k, v in (headers or {}).items()
            if str(k).strip()
        },
        "metadata": metadata if isinstance(metadata, dict) else {},
        "updated_at": time.time(),
    }
    with _RUNTIME_SESSION_LOCK:
        _RUNTIME_SESSION_STATE[name] = record


def get_runtime_session_state(session_name: str) -> dict[str, Any]:
    name = str(session_name or "").strip().lower()
    if not name:
        return {}
    with _RUNTIME_SESSION_LOCK:
        raw = _RUNTIME_SESSION_STATE.get(name, {})
        return dict(raw) if isinstance(raw, dict) else {}


def clear_runtime_session_state(session_name: str = "") -> None:
    name = str(session_name or "").strip().lower()
    with _RUNTIME_SESSION_LOCK:
        if not name:
            _RUNTIME_SESSION_STATE.clear()
            return
        _RUNTIME_SESSION_STATE.pop(name, None)


def apply_runtime_session_headers(session_name: str, headers: dict[str, str] | None = None) -> dict[str, str]:
    merged = dict(headers or {})
    state = get_runtime_session_state(session_name)
    if not state:
        return merged
    token = str(state.get("token", "")).strip()
    token_type = str(state.get("token_type", "Bearer")).strip() or "Bearer"
    cookie = str(state.get("cookie", "")).strip()
    if token:
        merged["Authorization"] = f"{token_type} {token}".strip()
    if cookie:
        merged["Cookie"] = cookie
    for hk, hv in (state.get("headers", {}) or {}).items():
        key = str(hk).strip()
        if not key:
            continue
        merged[key] = str(hv)
    return merged


def _socket_options() -> list[tuple[int, int, int]]:
    if not bool(_POOL_CFG["linux_socket_tuning"]):
        return []
    if os.name != "posix":
        return []
    options: list[tuple[int, int, int]] = [
        (socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1),
        (socket.IPPROTO_TCP, socket.TCP_NODELAY, 1),
    ]
    for attr, value in (
        ("TCP_KEEPIDLE", 30),
        ("TCP_KEEPINTVL", 10),
        ("TCP_KEEPCNT", 3),
    ):
        opt = getattr(socket, attr, None)
        if opt is not None:
            options.append((socket.IPPROTO_TCP, int(opt), int(value)))
    return options


def _sync_global_http_wait() -> None:
    global _GLOBAL_SYNC_LAST_REQUEST_AT
    min_interval = 1.0 / max(0.1, float(_GLOBAL_HTTP_CFG["rate_per_sec"]))
    with _GLOBAL_SYNC_GUARD_LOCK:
        now = time.monotonic()
        delta = now - _GLOBAL_SYNC_LAST_REQUEST_AT
        if delta < min_interval:
            time.sleep(min_interval - delta)
        _GLOBAL_SYNC_LAST_REQUEST_AT = time.monotonic()


async def _get_async_global_http_guards() -> tuple[asyncio.Semaphore, AsyncRateLimiter]:
    global _GLOBAL_ASYNC_GUARD_LOOP_ID
    global _GLOBAL_ASYNC_SEMAPHORE
    global _GLOBAL_ASYNC_RATE_LIMITER
    loop = asyncio.get_running_loop()
    async with _GLOBAL_ASYNC_GUARD_LOCK:
        if (
            _GLOBAL_ASYNC_GUARD_LOOP_ID != id(loop)
            or _GLOBAL_ASYNC_SEMAPHORE is None
            or _GLOBAL_ASYNC_RATE_LIMITER is None
        ):
            _GLOBAL_ASYNC_GUARD_LOOP_ID = id(loop)
            _GLOBAL_ASYNC_SEMAPHORE = asyncio.Semaphore(max(1, int(_GLOBAL_HTTP_CFG["max_inflight"])))
            _GLOBAL_ASYNC_RATE_LIMITER = AsyncRateLimiter(float(_GLOBAL_HTTP_CFG["rate_per_sec"]))
        return _GLOBAL_ASYNC_SEMAPHORE, _GLOBAL_ASYNC_RATE_LIMITER


async def get_async_http_client() -> "httpx.AsyncClient | None":
    global _ASYNC_CLIENT
    global _ASYNC_CLIENT_LOOP_ID
    if httpx is None:
        return None
    loop = asyncio.get_running_loop()
    async with _CLIENT_LOCK:
        if _ASYNC_CLIENT is not None and _ASYNC_CLIENT_LOOP_ID == id(loop):
            return _ASYNC_CLIENT
        if _ASYNC_CLIENT is not None:
            try:
                await _ASYNC_CLIENT.aclose()
            except Exception:
                pass
        limits = httpx.Limits(
            max_connections=int(_POOL_CFG["max_connections"]),
            max_keepalive_connections=int(_POOL_CFG["max_keepalive_connections"]),
            keepalive_expiry=float(_POOL_CFG["keepalive_expiry"]),
        )
        transport = httpx.AsyncHTTPTransport(
            verify=bool(_POOL_CFG["verify_ssl"]),
            limits=limits,
            retries=int(_POOL_CFG["retries"]),
            socket_options=_socket_options(),
            http2=bool(_POOL_CFG["http2"]),
        )
        _ASYNC_CLIENT = httpx.AsyncClient(
            follow_redirects=True,
            transport=transport,
            http2=bool(_POOL_CFG["http2"]),
        )
        _ASYNC_CLIENT_LOOP_ID = id(loop)
        return _ASYNC_CLIENT


async def close_async_http_client() -> None:
    global _ASYNC_CLIENT
    global _ASYNC_CLIENT_LOOP_ID
    async with _CLIENT_LOCK:
        if _ASYNC_CLIENT is not None:
            try:
                await _ASYNC_CLIENT.aclose()
            except Exception:
                pass
        _ASYNC_CLIENT = None
        _ASYNC_CLIENT_LOOP_ID = None


def request_http(
    method: str,
    url: str,
    headers: dict[str, str] | None = None,
    body: dict[str, Any] | str | None = None,
    timeout: int = 20,
) -> dict[str, Any]:
    host, path, _query = split_url(url)
    if not _scope_allows(host, path):
        inc_scope_blocked()
        inc_request(403)
        return _blocked_response("scope_blocked", status=403, host=host, path=path)
    policy = _match_host_policy(host) or {}
    blocked_paths = policy.get("blocked_paths") or []
    if blocked_paths and match_patterns(normalize_endpoint(path), blocked_paths):
        inc_scope_blocked_path()
        inc_request(403)
        return _blocked_response("blocked_path", status=403, host=host, path=path)
    program_id = str(policy.get("program_id", "")).strip()
    if _program_budget_exceeded(program_id):
        inc_program_budget_blocked(program_id)
        inc_request(429)
        return _blocked_response("program_budget_exceeded", status=429, host=host, path=path)
    rate_limit = float(policy.get("rate_per_sec", 0.0) or 0.0)
    if rate_limit > 0:
        _sync_host_wait(host, rate_limit)
    _sync_global_http_wait()
    host = _target_host(url)
    is_open, remaining = _is_circuit_open(host)
    if is_open:
        return _circuit_open_response(host, remaining)
    final_headers = _merge_default_headers(headers)
    required_headers = policy.get("required_headers") if isinstance(policy.get("required_headers"), dict) else {}
    for hk, hv in required_headers.items():
        key = str(hk).strip()
        if not key:
            continue
        final_headers.setdefault(key, str(hv))
    _record_program_request(program_id)
    start_ts = time.monotonic()
    if httpx is not None:
        try:
            limits = httpx.Limits(
                max_connections=int(_POOL_CFG["max_connections"]),
                max_keepalive_connections=int(_POOL_CFG["max_keepalive_connections"]),
                keepalive_expiry=float(_POOL_CFG["keepalive_expiry"]),
            )
            transport = httpx.HTTPTransport(
                verify=bool(_POOL_CFG["verify_ssl"]),
                limits=limits,
                retries=int(_POOL_CFG["retries"]),
                socket_options=_socket_options(),
                http2=bool(_POOL_CFG["http2"]),
            )
            with httpx.Client(
                follow_redirects=True,
                transport=transport,
                timeout=timeout,
                http2=bool(_POOL_CFG["http2"]),
            ) as client:
                if isinstance(body, (dict, list)):
                    resp = client.request(method.upper(), url, headers=final_headers, json=body)
                elif body is not None:
                    resp = client.request(method.upper(), url, headers=final_headers, content=str(body))
                else:
                    resp = client.request(method.upper(), url, headers=final_headers)
            result = {
                "ok": resp.is_success,
                "status": int(resp.status_code),
                "headers": dict(resp.headers.items()),
                "text": resp.text,
                "length": len(resp.content),
            }
            _record_circuit_status(host, int(result.get("status", 0) or 0), result.get("headers"))
            inc_request(int(result.get("status", 0) or 0))
            observe_latency(_target_host(url) or "unknown", time.monotonic() - start_ts)
            return result
        except Exception as e:
            status = 0
            headers_out: dict[str, str] = {}
            text_out = str(e)
            length_out = len(text_out.encode("utf-8", errors="ignore"))
            response = getattr(e, "response", None)
            if response is not None:
                try:
                    status = int(getattr(response, "status_code", 0) or 0)
                except Exception:
                    status = 0
                try:
                    headers_out = dict(getattr(response, "headers", {}).items())
                except Exception:
                    headers_out = {}
                try:
                    text_out = str(getattr(response, "text", text_out))
                except Exception:
                    pass
                try:
                    content = getattr(response, "content", b"")
                    length_out = len(content if isinstance(content, (bytes, bytearray)) else str(content).encode("utf-8", errors="ignore"))
                except Exception:
                    length_out = len(text_out.encode("utf-8", errors="ignore"))
            _record_circuit_status(host, status, headers_out)
            inc_request(int(status or 0))
            observe_latency(_target_host(url) or "unknown", time.monotonic() - start_ts)
            return {"ok": False, "status": status, "headers": headers_out, "text": text_out, "length": length_out}

    # urllib fallback when httpx is unavailable.
    hdrs = headers.copy() if headers else {}
    hdrs = _merge_default_headers(hdrs)
    data = None
    if body is not None:
        if isinstance(body, (dict, list)):
            data = json.dumps(body).encode("utf-8")
            hdrs.setdefault("Content-Type", "application/json")
        else:
            data = str(body).encode("utf-8")
    req = Request(url=url, data=data, headers=hdrs, method=method.upper())
    try:
        with urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            text = raw.decode("utf-8", errors="ignore")
            h = dict(resp.headers.items())
        result = {
            "ok": True,
            "status": int(resp.status),
            "headers": h,
            "text": text,
            "length": len(raw),
        }
        _record_circuit_status(host, int(result.get("status", 0) or 0), result.get("headers"))
        inc_request(int(result.get("status", 0) or 0))
        observe_latency(_target_host(url) or "unknown", time.monotonic() - start_ts)
        return result
    except HTTPError as e:
        b = e.read().decode("utf-8", errors="ignore") if hasattr(e, "read") else ""
        result = {
            "ok": False,
            "status": int(getattr(e, "code", 0) or 0),
            "headers": dict(getattr(e, "headers", {}).items()) if getattr(e, "headers", None) else {},
            "text": b,
            "length": len(b.encode("utf-8")),
        }
        _record_circuit_status(host, int(result.get("status", 0) or 0), result.get("headers"))
        inc_request(int(result.get("status", 0) or 0))
        observe_latency(_target_host(url) or "unknown", time.monotonic() - start_ts)
        return result
    except URLError as e:
        inc_request(0)
        observe_latency(_target_host(url) or "unknown", time.monotonic() - start_ts)
        return {"ok": False, "status": 0, "headers": {}, "text": str(e), "length": 0}


def json_keys(text: str) -> list[str]:
    try:
        obj = json.loads(text)
    except Exception:
        return []
    if isinstance(obj, dict):
        return sorted(list(obj.keys()))
    return []


async def request_http_async(
    method: str,
    url: str,
    headers: dict[str, str] | None = None,
    body: dict[str, Any] | str | None = None,
    timeout: int = 20,
    client: "httpx.AsyncClient | None" = None,
) -> dict[str, Any]:
    host, path, _query = split_url(url)
    if not _scope_allows(host, path):
        inc_scope_blocked()
        inc_request(403)
        return _blocked_response("scope_blocked", status=403, host=host, path=path)
    policy = _match_host_policy(host) or {}
    blocked_paths = policy.get("blocked_paths") or []
    if blocked_paths and match_patterns(normalize_endpoint(path), blocked_paths):
        inc_scope_blocked_path()
        inc_request(403)
        return _blocked_response("blocked_path", status=403, host=host, path=path)
    program_id = str(policy.get("program_id", "")).strip()
    if _program_budget_exceeded(program_id):
        inc_program_budget_blocked(program_id)
        inc_request(429)
        return _blocked_response("program_budget_exceeded", status=429, host=host, path=path)
    required_headers = policy.get("required_headers") if isinstance(policy.get("required_headers"), dict) else {}
    merged_headers = headers.copy() if isinstance(headers, dict) else {}
    for hk, hv in required_headers.items():
        key = str(hk).strip()
        if not key:
            continue
        merged_headers.setdefault(key, str(hv))
    semaphore, rate_limiter = await _get_async_global_http_guards()
    async with semaphore:
        await rate_limiter.wait()
        rate_limit = float(policy.get("rate_per_sec", 0.0) or 0.0)
        max_inflight = int(policy.get("max_inflight", 0) or 0)
        if rate_limit > 0 or max_inflight > 0:
            effective_rate = rate_limit if rate_limit > 0 else 1_000_000.0
            h_sem, h_limiter = await _get_async_host_guards(
                host,
                rate_per_sec=effective_rate,
                max_inflight=max_inflight if max_inflight > 0 else 1,
            )
            async with h_sem:
                await h_limiter.wait()
                _record_program_request(program_id)
                return await _request_http_async_inner(
                    method=method,
                    url=url,
                    headers=merged_headers,
                    body=body,
                    timeout=timeout,
                    client=client,
                )
        _record_program_request(program_id)
        return await _request_http_async_inner(
            method=method,
            url=url,
            headers=merged_headers,
            body=body,
            timeout=timeout,
            client=client,
        )


async def _request_http_async_inner(
    method: str,
    url: str,
    headers: dict[str, str] | None = None,
    body: dict[str, Any] | str | None = None,
    timeout: int = 20,
    client: "httpx.AsyncClient | None" = None,
) -> dict[str, Any]:
    host = _target_host(url)
    is_open, remaining = _is_circuit_open(host)
    if is_open:
        return _circuit_open_response(host, remaining)
    final_headers = _merge_default_headers(headers)
    start_ts = time.monotonic()
    if httpx is None:
        return await asyncio.to_thread(request_http, method, url, final_headers, body, timeout)
    try:
        http_client = client or await get_async_http_client()
        if http_client is None:
            return await asyncio.to_thread(request_http, method, url, final_headers, body, timeout)
        if isinstance(body, (dict, list)):
            resp = await http_client.request(method.upper(), url, headers=final_headers, json=body, timeout=timeout)
        elif body is not None:
            resp = await http_client.request(method.upper(), url, headers=final_headers, content=str(body), timeout=timeout)
        else:
            resp = await http_client.request(method.upper(), url, headers=final_headers, timeout=timeout)
        result = {
            "ok": resp.is_success,
            "status": int(resp.status_code),
            "headers": dict(resp.headers.items()),
            "text": resp.text,
            "length": len(resp.content),
        }
        _record_circuit_status(host, int(result.get("status", 0) or 0), result.get("headers"))
        inc_request(int(result.get("status", 0) or 0))
        observe_latency(_target_host(url) or "unknown", time.monotonic() - start_ts)
        return result
    except Exception as e:
        status = 0
        headers_out: dict[str, str] = {}
        text_out = str(e)
        length_out = len(text_out.encode("utf-8", errors="ignore"))
        response = getattr(e, "response", None)
        if response is not None:
            try:
                status = int(getattr(response, "status_code", 0) or 0)
            except Exception:
                status = 0
            try:
                headers_out = dict(getattr(response, "headers", {}).items())
            except Exception:
                headers_out = {}
            try:
                text_out = str(getattr(response, "text", text_out))
            except Exception:
                pass
            try:
                content = getattr(response, "content", b"")
                length_out = len(content if isinstance(content, (bytes, bytearray)) else str(content).encode("utf-8", errors="ignore"))
            except Exception:
                length_out = len(text_out.encode("utf-8", errors="ignore"))
        _record_circuit_status(host, status, headers_out)
        inc_request(int(status or 0))
        observe_latency(_target_host(url) or "unknown", time.monotonic() - start_ts)
        return {"ok": False, "status": status, "headers": headers_out, "text": text_out, "length": length_out}
