from __future__ import annotations

import asyncio
import contextlib
import json
import os
import re
from dataclasses import dataclass
from typing import Any


_KV_RE = re.compile(r"""([A-Za-z_][A-Za-z0-9_]*)\s*[:=]\s*("?[^"\s;]+"?)""")


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    raw = str(value or "").strip().lower()
    return raw in {"1", "true", "yes", "y", "ok", "validated", "pass"}


def _as_float(value: Any) -> float:
    try:
        return float(value or 0.0)
    except Exception:
        return 0.0


def _as_text(value: Any) -> str:
    return str(value or "").strip()


def _from_mapping(data: dict[str, Any]) -> "ShannonResult":
    validated_raw = data.get("validated", data.get("valid", data.get("is_validated", data.get("success", False))))
    confidence_raw = data.get(
        "confidence_delta",
        data.get("delta_confidence", data.get("confidence_diff", data.get("confidence_delta_score", 0.0))),
    )
    evidence_raw = data.get("evidence_path", data.get("evidence", data.get("evidence_file", data.get("path", ""))))
    error_raw = data.get("error", data.get("message", data.get("reason", "")))
    return ShannonResult(
        validated=_as_bool(validated_raw),
        confidence_delta=_as_float(confidence_raw),
        evidence_path=_as_text(evidence_raw),
        error=_as_text(error_raw) or None,
    )


def _parse_structured_text(text: str) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in _KV_RE.findall(text):
        clean = str(value).strip().strip('"').strip("'")
        out[str(key).strip().lower()] = clean
    return out


def _extract_json_object(raw: str) -> dict[str, Any] | None:
    text = str(raw or "").strip()
    if not text:
        return None
    with contextlib.suppress(Exception):
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            return parsed
        if isinstance(parsed, list) and parsed and isinstance(parsed[0], dict):
            return parsed[0]
    for line in text.splitlines():
        candidate = line.strip()
        if not candidate or "{" not in candidate or "}" not in candidate:
            continue
        start = candidate.find("{")
        end = candidate.rfind("}")
        if start < 0 or end <= start:
            continue
        snippet = candidate[start : end + 1]
        with contextlib.suppress(Exception):
            parsed = json.loads(snippet)
            if isinstance(parsed, dict):
                return parsed
    return None


def _parse_shannon_output(stdout_text: str, stderr_text: str) -> ShannonResult:
    for raw in (stdout_text, stderr_text, f"{stdout_text}\n{stderr_text}"):
        parsed = _extract_json_object(raw)
        if isinstance(parsed, dict):
            return _from_mapping(parsed)

    merged = _parse_structured_text(f"{stdout_text}\n{stderr_text}")
    if merged:
        normalized = {
            "validated": merged.get("validated", merged.get("valid", merged.get("success", ""))),
            "confidence_delta": merged.get(
                "confidence_delta",
                merged.get("delta_confidence", merged.get("confidence_diff", "0")),
            ),
            "evidence_path": merged.get(
                "evidence_path",
                merged.get("evidence", merged.get("evidence_file", merged.get("path", ""))),
            ),
            "error": merged.get("error", merged.get("message", merged.get("reason", ""))),
        }
        return _from_mapping(normalized)

    return ShannonResult(
        validated=False,
        confidence_delta=0.0,
        evidence_path="",
        error="unable_to_parse_shannon_output",
    )


@dataclass
class ShannonResult:
    validated: bool
    confidence_delta: float
    evidence_path: str
    error: str | None
    exit_code: int | None = None


class ShannonAdapter:
    def __init__(self, *, binary_path: str, timeout_seconds: float = 30.0) -> None:
        self.binary_path = str(binary_path or "").strip()
        self.timeout_seconds = max(1.0, float(timeout_seconds or 30.0))

    async def validate(self, context: dict[str, Any]) -> ShannonResult:
        target = str(context.get("target", "")).strip()
        endpoint = str(context.get("endpoint", "")).strip()
        metadata = context.get("metadata", {}) if isinstance(context.get("metadata"), dict) else {}
        payload = {
            "target": target,
            "endpoint": endpoint,
            "metadata": metadata,
        }
        payload_raw = json.dumps(payload, ensure_ascii=True)

        if not self.binary_path:
            return ShannonResult(False, 0.0, "", "shannon_binary_path_missing", None)
        if not os.path.exists(self.binary_path):
            return ShannonResult(False, 0.0, "", f"shannon_binary_not_found path={self.binary_path}", None)

        env = dict(os.environ)
        env["SHANNON_VALIDATION_CONTEXT"] = payload_raw
        cmd = [
            self.binary_path,
            "validate",
            f"TARGET={target}",
            f"ENDPOINT={endpoint}",
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )
        except Exception as err:
            return ShannonResult(False, 0.0, "", f"shannon_spawn_failed type={type(err).__name__} err={err}", None)

        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(input=(payload_raw + "\n").encode("utf-8")),
                timeout=self.timeout_seconds,
            )
        except asyncio.TimeoutError:
            with contextlib.suppress(Exception):
                proc.kill()
            with contextlib.suppress(Exception):
                await proc.wait()
            return ShannonResult(
                validated=False,
                confidence_delta=0.0,
                evidence_path="",
                error=f"shannon_timeout timeout_seconds={self.timeout_seconds}",
                exit_code=None,
            )

        stdout_text = stdout.decode("utf-8", errors="replace").strip()
        stderr_text = stderr.decode("utf-8", errors="replace").strip()
        result = _parse_shannon_output(stdout_text, stderr_text)
        result.exit_code = int(proc.returncode or 0)
        if result.exit_code != 0:
            details = stderr_text or stdout_text or "no_output"
            if not result.error:
                result.error = f"shannon_exit_nonzero code={result.exit_code} details={details[:400]}"
        return result
