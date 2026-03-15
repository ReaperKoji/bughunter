from __future__ import annotations

import fnmatch
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse


def normalize_host(raw: str) -> str:
    value = str(raw or "").strip()
    if not value:
        return ""
    if "://" not in value:
        value = f"https://{value}"
    try:
        parsed = urlparse(value)
    except Exception:
        return ""
    host = str(parsed.hostname or "").strip().lower().rstrip(".")
    if not host:
        return ""
    return host


def _normalize_netloc(parsed) -> str:
    host = str(parsed.hostname or "").strip().lower().rstrip(".")
    if not host:
        return ""
    port = parsed.port
    scheme = str(parsed.scheme or "").lower()
    if port and ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        return host
    if port:
        return f"{host}:{port}"
    return host


def normalize_endpoint(raw: str) -> str:
    value = str(raw or "").strip()
    if not value:
        return "/"
    if "://" not in value:
        if value.startswith("//"):
            value = f"https:{value}"
        elif not value.startswith("/"):
            value = f"/{value}"
    parsed = urlparse(value)
    path = parsed.path or "/"
    query = _sorted_query(parsed.query)
    if query:
        return f"{path}?{query}"
    return path


def normalize_url(raw: str, default_scheme: str = "https") -> str:
    value = str(raw or "").strip()
    if not value:
        return ""
    if value.startswith("//"):
        value = f"{default_scheme}:{value}"
    if "://" not in value:
        if value.startswith("/"):
            return normalize_endpoint(value)
        value = f"{default_scheme}://{value}"
    parsed = urlparse(value)
    scheme = str(parsed.scheme or default_scheme).lower()
    netloc = _normalize_netloc(parsed)
    path = parsed.path or "/"
    query = _sorted_query(parsed.query)
    return urlunparse((scheme, netloc, path, "", query, ""))


def split_url(raw: str) -> tuple[str, str, str]:
    value = str(raw or "").strip()
    if not value:
        return "", "", ""
    if "://" not in value:
        if value.startswith("//"):
            value = f"https:{value}"
        elif value.startswith("/"):
            return "", value, ""
        else:
            value = f"https://{value}"
    parsed = urlparse(value)
    host = str(parsed.hostname or "").strip().lower().rstrip(".")
    path = parsed.path or "/"
    query = _sorted_query(parsed.query)
    return host, path, query


def match_patterns(value: str, patterns: list[str]) -> bool:
    val = str(value or "").strip().lower()
    if not val:
        return False
    for raw in patterns or []:
        pat = str(raw or "").strip().lower()
        if not pat:
            continue
        if fnmatch.fnmatch(val, pat):
            return True
    return False


def _sorted_query(raw: str) -> str:
    query = str(raw or "").strip()
    if not query:
        return ""
    pairs = parse_qsl(query, keep_blank_values=True)
    pairs.sort(key=lambda item: (item[0], item[1]))
    return urlencode(pairs, doseq=True)
