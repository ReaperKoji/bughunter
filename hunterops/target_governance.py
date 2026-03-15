from __future__ import annotations

import fnmatch
import logging
from typing import Iterable
from urllib.parse import urlparse


def normalize_target(raw: str) -> str:
    value = str(raw or "").strip()
    if not value:
        return ""
    return value


def target_matches_patterns(target: str, patterns: Iterable[str]) -> bool:
    if not target:
        return False
    raw = str(target).strip()
    host = raw
    if "://" not in raw:
        raw = f"https://{raw}"
    try:
        host = str(urlparse(raw).hostname or host).strip().lower()
    except Exception:
        host = str(host).strip().lower()
    for pat in patterns:
        pattern = str(pat).strip().lower()
        if not pattern:
            continue
        if fnmatch.fnmatch(host, pattern) or fnmatch.fnmatch(raw.lower(), pattern):
            return True
    return False


def apply_target_governance(
    targets: Iterable[str],
    *,
    allow_patterns: Iterable[str] | None = None,
    deny_patterns: Iterable[str] | None = None,
    priority_patterns: Iterable[str] | None = None,
    logger: logging.Logger | None = None,
) -> list[str]:
    allow = [str(x).strip() for x in (allow_patterns or []) if str(x).strip()]
    deny = [str(x).strip() for x in (deny_patterns or []) if str(x).strip()]
    priority = [str(x).strip() for x in (priority_patterns or []) if str(x).strip()]
    cleaned = [t for t in (normalize_target(x) for x in targets) if t]
    input_count = len(cleaned)
    filtered: list[str] = []
    for t in cleaned:
        if allow and not target_matches_patterns(t, allow):
            continue
        if deny and target_matches_patterns(t, deny):
            continue
        filtered.append(t)
    if priority:
        filtered.sort(key=lambda t: (0 if target_matches_patterns(t, priority) else 1, t))
    if logger and (allow or deny or priority):
        logger.info(
            "target_governance_applied "
            f"allow={len(allow)} deny={len(deny)} priority={len(priority)} "
            f"input={input_count} output={len(filtered)}"
        )
    return filtered
