from __future__ import annotations

import asyncio
import json
import os
import socket
import time
from threading import Lock
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

try:
    import httpx
except Exception:  # pragma: no cover - optional runtime dependency fallback
    httpx = None  # type: ignore[assignment]

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
_CB_STREAKS: dict[str, int] = {}
_CB_COOLDOWN_UNTIL: dict[str, float] = {}
_CB_LOCK = Lock()


def _client_identifier() -> str:
    raw = os.getenv("H1_API_IDENTIFIER", "").strip()
    return raw or "reaperk0ji"


def _bug_bounty_username(identifier: str) -> str:
    direct = os.getenv("HUNTEROPS_BUG_BOUNTY_USERNAME", "").strip()
    if direct:
        return direct
    legacy = os.getenv("BUG_BOUNTY_USERNAME", "").strip()
    if legacy:
        return legacy
    return identifier


def _bug_bounty_test_account_email() -> str:
    direct = os.getenv("HUNTEROPS_TEST_ACCOUNT_EMAIL", "").strip()
    if direct:
        return direct
    legacy = os.getenv("BUG_BOUNTY_TEST_ACCOUNT_EMAIL", "").strip()
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


def _record_circuit_status(host: str, status_code: int) -> None:
    if not host:
        return
    status = int(status_code or 0)
    now = time.monotonic()
    with _CB_LOCK:
        if status == 429:
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
    host = _target_host(url)
    is_open, remaining = _is_circuit_open(host)
    if is_open:
        return _circuit_open_response(host, remaining)
    final_headers = _merge_default_headers(headers)
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
                if isinstance(body, dict):
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
            _record_circuit_status(host, int(result.get("status", 0) or 0))
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
            _record_circuit_status(host, status)
            return {"ok": False, "status": status, "headers": headers_out, "text": text_out, "length": length_out}

    # urllib fallback when httpx is unavailable.
    hdrs = headers.copy() if headers else {}
    hdrs = _merge_default_headers(hdrs)
    data = None
    if body is not None:
        if isinstance(body, dict):
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
            _record_circuit_status(host, int(result.get("status", 0) or 0))
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
        _record_circuit_status(host, int(result.get("status", 0) or 0))
        return result
    except URLError as e:
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
    host = _target_host(url)
    is_open, remaining = _is_circuit_open(host)
    if is_open:
        return _circuit_open_response(host, remaining)
    final_headers = _merge_default_headers(headers)
    if httpx is None:
        return await asyncio.to_thread(request_http, method, url, final_headers, body, timeout)
    try:
        http_client = client or await get_async_http_client()
        if http_client is None:
            return await asyncio.to_thread(request_http, method, url, final_headers, body, timeout)
        if isinstance(body, dict):
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
        _record_circuit_status(host, int(result.get("status", 0) or 0))
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
        _record_circuit_status(host, status)
        return {"ok": False, "status": status, "headers": headers_out, "text": text_out, "length": length_out}
