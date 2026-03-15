from __future__ import annotations

from pathlib import Path
from typing import Any
import os

import yaml
from hunterops.http_client import apply_runtime_session_headers


def load_sessions(path: Path) -> dict[str, dict[str, Any]]:
    if not path.exists():
        return {}
    cfg = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    sessions = cfg.get("sessions", [])
    out: dict[str, dict[str, Any]] = {}
    for s in sessions:
        name = str(s.get("name", "")).strip()
        if name:
            out[name] = s
    return out


def auth_header(session: dict[str, Any]) -> dict[str, str]:
    headers: dict[str, str] = {}
    session_name = str(session.get("name", "")).strip().lower()
    token_env = str(session.get("token_env", "")).strip()
    token = os.getenv(token_env, "").strip() if token_env else str(session.get("token", "")).strip()
    token_type = str(session.get("token_type", "Bearer")).strip()
    if token:
        headers["Authorization"] = f"{token_type} {token}".strip()
    cookie_env = str(session.get("cookie_env", "")).strip()
    cookie = os.getenv(cookie_env, "").strip() if cookie_env else str(session.get("cookie", "")).strip()
    if cookie:
        headers["Cookie"] = cookie
    for k, v in (session.get("headers") or {}).items():
        headers[str(k)] = str(v)
    if session_name:
        return apply_runtime_session_headers(session_name, headers)
    return headers
