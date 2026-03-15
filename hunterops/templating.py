from __future__ import annotations

import re
from typing import Any

PLACEHOLDER_RE = re.compile(r"\{\{\s*([a-zA-Z0-9_.-]+)\s*\}\}")


def render_template(value: Any, variables: dict[str, Any] | None = None, *, strict: bool = False) -> Any:
    """Safely render templates by simple placeholder substitution.

    Supports strings, dicts, lists. No code execution.
    """
    vars_map = variables or {}
    if isinstance(value, dict):
        return {k: render_template(v, vars_map, strict=strict) for k, v in value.items()}
    if isinstance(value, list):
        return [render_template(v, vars_map, strict=strict) for v in value]
    if not isinstance(value, str):
        return value

    def _replace(match: re.Match[str]) -> str:
        key = match.group(1)
        if key in vars_map:
            return str(vars_map.get(key))
        if strict:
            raise KeyError(f"Missing template variable: {key}")
        return match.group(0)

    return PLACEHOLDER_RE.sub(_replace, value)

