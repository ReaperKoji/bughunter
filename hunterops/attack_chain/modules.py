from __future__ import annotations

import hashlib
import copy
import json
import html
import random
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from hunterops.attack_chain.types import ModuleResult, Target
from hunterops.attack_chain.id_cache import DEFAULT_ID_CACHE
from hunterops.http_client import request_http_async
from hunterops.http_client import apply_runtime_session_headers
from hunterops.tool_runner import run_command
from hunterops.templating import render_template
from hunterops.sensitivity import sensitivity_score

SQL_ERROR_RE = re.compile(
    r"(sql syntax|mysql|psql|postgres|sqlite|oracle|syntax error|quoted string|odbc|jdbc|db2)",
    re.IGNORECASE,
)
UUID_RE = re.compile(r"\b[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}\b")
SECRET_RE = re.compile(
    r"(AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|sk_live_[0-9a-zA-Z]{16,}|"
    r"ghp_[0-9A-Za-z]{36,}|xox[baprs]-[0-9A-Za-z-]{10,}|"
    r"-----BEGIN PRIVATE KEY-----|eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})"
)
ENV_LINE_RE = re.compile(r"^[A-Z0-9_]{3,}\s*=\s*.+$", re.MULTILINE)
SOURCE_MAP_RE = re.compile(r"\"sources\"\s*:\s*\[|\"mappings\"\s*:\s*\"", re.IGNORECASE)
META_MARKERS = ("ami-id", "instance-id", "metadata", "compute", "iam", "security-credentials")


@dataclass
class ModuleContext:
    timeouts: dict[str, Any]
    politeness: Any
    user_agents: list[str]
    logger: Any
    stealth_mode: bool = True
    proxies: list[str] | None = None
    tool_timeout_s: int = 60
    policy: dict[str, Any] | None = None
    module_cfg: dict[str, Any] | None = None
    session_name: str = ""
    use_auth: bool = False
    required_headers: dict[str, str] | None = None
    safe_payloads_only: bool = False
    baseline_score: float = 0.0
    baseline_notes: list[str] | None = None
    baseline_methods: list[str] | None = None


class AttackModule:
    name: str = "base"

    async def run(self, target: Target, ctx: ModuleContext) -> ModuleResult:
        raise NotImplementedError

    def score_target(self, target: Target) -> float:
        # Default neutral score. Modules should override with domain-specific heuristics.
        return 0.1

    def applicable(self, target: Target) -> bool:
        return self.score_target(target) > 0.0

    def _pick_ua(self, ctx: ModuleContext) -> str:
        if ctx.user_agents:
            return random.choice(ctx.user_agents)
        return "Mozilla/5.0 (HunterOps/AttackChain)"

    def _headers(self, ctx: ModuleContext) -> dict[str, str]:
        headers: dict[str, str] = {"User-Agent": self._pick_ua(ctx)}
        if isinstance(ctx.required_headers, dict):
            for hk, hv in ctx.required_headers.items():
                key = str(hk).strip()
                if not key:
                    continue
                headers[key] = str(hv)
        if ctx.use_auth and ctx.session_name:
            headers = apply_runtime_session_headers(ctx.session_name, headers)
        return headers

    def _safe_only(self, ctx: ModuleContext) -> bool:
        return bool(getattr(ctx, "safe_payloads_only", False))

    def _payloads(self, ctx: ModuleContext, default_payloads: list[str], safe_payloads: list[str] | None = None) -> list[str]:
        module_cfg = ctx.module_cfg or {}
        if self._safe_only(ctx):
            safe_cfg = module_cfg.get("safe_payloads")
            if isinstance(safe_cfg, list):
                safe_list = [str(x).strip() for x in safe_cfg if str(x).strip()]
                if safe_list:
                    return safe_list
            if safe_payloads:
                safe_list = [str(x).strip() for x in safe_payloads if str(x).strip()]
                if safe_list:
                    return safe_list
            return [str(x).strip() for x in default_payloads if str(x).strip()]
        payloads_cfg = module_cfg.get("payloads")
        if isinstance(payloads_cfg, list):
            payloads = [str(x).strip() for x in payloads_cfg if str(x).strip()]
            if payloads:
                return payloads
        return [str(x).strip() for x in default_payloads if str(x).strip()]

    def _hash(self, text: str) -> str:
        return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()[:16]

    def _body_diff_ratio(self, a: str, b: str) -> float:
        la = len(a)
        lb = len(b)
        if la == 0 and lb == 0:
            return 0.0
        return abs(la - lb) / max(1, max(la, lb))

    def _safe_sample(self, text: str, limit: int = 1200) -> str:
        return str(text or "")[:limit]

    def _sanitize_headers(self, headers: dict[str, str]) -> dict[str, str]:
        out: dict[str, str] = {}
        for k, v in (headers or {}).items():
            key = str(k).strip()
            if not key:
                continue
            if key.lower() in {"authorization", "cookie", "proxy-authorization"}:
                continue
            out[key] = str(v)
        return out

    def _request_meta(self, url: str, headers: dict[str, str], ctx: ModuleContext, *, method: str = "GET", body: Any = None) -> dict[str, Any]:
        body_out: Any = None
        if isinstance(body, (dict, list)):
            try:
                body_out = json.dumps(body, ensure_ascii=True)[:600]
            except Exception:
                body_out = None
        elif isinstance(body, str) and body.strip():
            body_out = body[:600]
        return {
            "method": str(method or "GET").upper(),
            "url": url,
            "headers": self._sanitize_headers(headers),
            "body": body_out,
            "auth_used": bool(ctx.use_auth),
            "auth_session": str(ctx.session_name or "").strip(),
        }

    def _clone_body(self, body: Any) -> Any:
        try:
            return copy.deepcopy(body)
        except Exception:
            return body

    def _encode_multipart(self, fields: Any) -> tuple[str, str]:
        boundary = f"----HunterOps{random.randint(100000, 999999)}"
        if not isinstance(fields, dict):
            payload = str(fields or "")
            return payload, f"multipart/form-data; boundary={boundary}"
        lines: list[str] = []
        for key, value in fields.items():
            name = str(key)
            if not name:
                continue
            if isinstance(value, (dict, list)):
                raw = json.dumps(value, ensure_ascii=True)
            else:
                raw = str(value)
            lines.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{raw}\r\n")
        lines.append(f"--{boundary}--\r\n")
        return "".join(lines), f"multipart/form-data; boundary={boundary}"

    def _prepare_body(self, ctx: ModuleContext, body_template: Any) -> tuple[Any, dict[str, str]]:
        if body_template is None:
            return None, {}
        module_cfg = ctx.module_cfg or {}
        body_type = str(module_cfg.get("body_type", "") or "").strip().lower()
        if not body_type:
            if isinstance(body_template, (dict, list)):
                body_type = "json"
            else:
                body_type = "text"
        if body_type in {"multipart", "form-data"}:
            payload, content_type = self._encode_multipart(body_template)
            return payload, {"Content-Type": content_type}
        if body_type in {"json", "application/json"}:
            return body_template, {"Content-Type": "application/json"}
        if body_type in {"text", "plain", "text/plain"}:
            return str(body_template), {"Content-Type": "text/plain"}
        if body_type in {"form", "urlencoded", "application/x-www-form-urlencoded"}:
            if isinstance(body_template, dict):
                return urlencode([(str(k), str(v)) for k, v in body_template.items()]), {
                    "Content-Type": "application/x-www-form-urlencoded"
                }
            return str(body_template), {"Content-Type": "application/x-www-form-urlencoded"}
        return body_template, {}

    def _parse_url(self, url: str) -> tuple[str, list[tuple[str, str]], tuple[str, str, str, str, str]]:
        parts = urlsplit(url)
        params = parse_qsl(parts.query, keep_blank_values=True)
        return parts.path or "/", params, (parts.scheme, parts.netloc, parts.path, parts.query, parts.fragment)

    def _param_info(self, url: str) -> tuple[list[tuple[str, str]], list[str], bool]:
        _path, params, _parts = self._parse_url(url)
        names = [str(k).lower() for k, _v in params]
        has_numeric = any(str(v).isdigit() for _k, v in params)
        return params, names, has_numeric

    def _build_url(self, parts: tuple[str, str, str, str, str], params: list[tuple[str, str]]) -> str:
        scheme, netloc, path, _query, fragment = parts
        query = urlencode(params, doseq=True)
        return urlunsplit((scheme, netloc, path, query, fragment))

    def _choose_param(self, params: list[tuple[str, str]], preferred: list[str] | None = None) -> int | None:
        if not params:
            return None
        if preferred:
            for idx, (k, _v) in enumerate(params):
                if k.lower() in preferred:
                    return idx
        return 0

    async def _fetch(
        self,
        url: str,
        ctx: ModuleContext,
        target: Target,
        headers: dict[str, str] | None = None,
        *,
        method: str = "GET",
        body: Any = None,
    ) -> dict[str, Any]:
        host = _target_host(url)
        timeout = int(ctx.timeouts.get("total_s", 20) or 20)
        policy = ctx.policy or {}
        async with ctx.politeness.guard(
            host,
            target.target_id,
            per_host_rpm=policy.get("per_host_rpm"),
            per_target_rpm=policy.get("per_target_rpm"),
            concurrency_per_host=policy.get("concurrency_per_host"),
        ):
            return await request_http_async(str(method or "GET").upper(), url, headers=headers or self._headers(ctx), body=body, timeout=timeout)

    async def _fetch_samples(
        self,
        url: str,
        ctx: ModuleContext,
        target: Target,
        headers: dict[str, str],
        *,
        method: str = "GET",
        body: Any = None,
        samples: int = 1,
    ) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for _ in range(max(1, int(samples))):
            out.append(await self._fetch(url, ctx, target, headers=headers, method=method, body=body))
        return out

    def _pick_baseline(self, responses: list[dict[str, Any]]) -> dict[str, Any]:
        if not responses:
            return {"status": 0, "text": "", "headers": {}}
        lengths = [(len(str(r.get("text", ""))), idx) for idx, r in enumerate(responses)]
        lengths.sort()
        _len, idx = lengths[len(lengths) // 2]
        return responses[idx]

    def _baseline_variance(self, responses: list[dict[str, Any]]) -> float:
        if len(responses) < 2:
            return 0.0
        sizes = [len(str(r.get("text", ""))) for r in responses]
        max_len = max(sizes) if sizes else 0
        min_len = min(sizes) if sizes else 0
        if max_len <= 0:
            return 0.0
        return round((max_len - min_len) / max_len, 4)

    def _json_key_set(self, text: str) -> set[str]:
        try:
            obj = json.loads(text)
        except Exception:
            return set()

        def _walk(value: Any, prefix: str = "") -> set[str]:
            keys: set[str] = set()
            if isinstance(value, dict):
                for k, v in value.items():
                    key = str(k)
                    path = f"{prefix}.{key}" if prefix else key
                    keys.add(path)
                    keys |= _walk(v, path)
            elif isinstance(value, list):
                for v in value[:6]:
                    path = f"{prefix}[]" if prefix else "[]"
                    keys.add(path)
                    keys |= _walk(v, path)
            return keys

        return _walk(obj)

    def _json_key_diff_ratio(self, a: str, b: str) -> float | None:
        ka = self._json_key_set(a)
        kb = self._json_key_set(b)
        if not ka and not kb:
            return None
        union = ka | kb
        inter = ka & kb
        if not union:
            return None
        return round(1.0 - (len(inter) / max(1, len(union))), 4)

    def _encode_payload(self, payload: str) -> str:
        try:
            return html.escape(payload)
        except Exception:
            return payload

    def _sensitivity(self, text: str, injected_values: list[str] | None = None) -> tuple[float, dict[str, Any]]:
        return sensitivity_score(text, injected_values or [])

    def _render_body_template(self, ctx: ModuleContext) -> Any:
        module_cfg = ctx.module_cfg or {}
        template = module_cfg.get("body_template")
        if template is None:
            return None
        placeholders = {}
        if isinstance((ctx.policy or {}).get("placeholders"), dict):
            placeholders.update((ctx.policy or {}).get("placeholders") or {})
        if isinstance(module_cfg.get("placeholders"), dict):
            placeholders.update(module_cfg.get("placeholders") or {})
        return render_template(template, placeholders, strict=False)

    def _extract_mutable_fields(self, body: Any) -> list[tuple[list[str | int], Any]]:
        found: list[tuple[list[str | int], Any]] = []
        if isinstance(body, dict):
            for k, v in body.items():
                if isinstance(v, (dict, list)):
                    for path, value in self._extract_mutable_fields(v):
                        found.append(([k] + path, value))
                else:
                    found.append(([k], v))
        elif isinstance(body, list):
            for idx, v in enumerate(body):
                if isinstance(v, (dict, list)):
                    for path, value in self._extract_mutable_fields(v):
                        found.append(([idx] + path, value))
                else:
                    found.append(([idx], v))
        return found

    def _set_nested_value(self, body: Any, path: list[str | int], value: Any) -> Any:
        if not path:
            return body
        cursor = body
        for key in path[:-1]:
            if isinstance(cursor, dict) and key in cursor:
                cursor = cursor[key]
            elif isinstance(cursor, list) and isinstance(key, int) and 0 <= key < len(cursor):
                cursor = cursor[key]
            else:
                return body
        last = path[-1]
        if isinstance(cursor, dict) and isinstance(last, str):
            cursor[last] = value
        elif isinstance(cursor, list) and isinstance(last, int) and 0 <= last < len(cursor):
            cursor[last] = value
        return body

    def _mutate_body_value(self, value: Any, strategy: str = "increment") -> Any:
        if isinstance(value, (int, float)) and strategy == "increment":
            return value + 1
        val = str(value)
        if UUID_RE.search(val):
            return UUID_RE.sub("11111111-1111-1111-1111-111111111111", val)
        if val.isdigit() and strategy == "increment":
            return str(int(val) + 1)
        return val + "1"

    def _mutate_body_for_keys(self, body: Any, preferred: list[str] | None = None, strategy: str = "increment") -> tuple[Any, Any]:
        preferred = [p.lower() for p in (preferred or [])]
        candidates = self._extract_mutable_fields(body)
        if not candidates:
            return body, None
        chosen = candidates[0]
        for path, value in candidates:
            if path and isinstance(path[-1], str) and str(path[-1]).lower() in preferred:
                chosen = (path, value)
                break
        path, value = chosen
        new_val = self._mutate_body_value(value, strategy=strategy)
        mutated = self._set_nested_value(body, path, new_val)
        return mutated, new_val

    def _set_body_value_for_keys(self, body: Any, preferred: list[str] | None, new_value: Any) -> tuple[Any, Any]:
        preferred = [p.lower() for p in (preferred or [])]
        candidates = self._extract_mutable_fields(body)
        if not candidates:
            return body, None
        chosen = candidates[0]
        for path, value in candidates:
            if path and isinstance(path[-1], str) and str(path[-1]).lower() in preferred:
                chosen = (path, value)
                break
        path, old_value = chosen
        mutated = self._set_nested_value(body, path, new_value)
        return mutated, old_value

    def _secret_hits(self, text: str) -> list[str]:
        hits: list[str] = []
        if not text:
            return hits
        for match in SECRET_RE.findall(text):
            if not match:
                continue
            hits.append(match if isinstance(match, str) else str(match))
        return hits


def _target_host(url: str) -> str:
    try:
        return str(urlsplit(url).hostname or "").strip().lower()
    except Exception:
        return ""


def _env_flag(name: str) -> bool:
    return str(__import__("os").environ.get(name, "")).strip().lower() in {"1", "true", "yes"}


class IdorModule(AttackModule):
    name = "idor"

    def score_target(self, target: Target) -> float:
        params, names, has_numeric = self._param_info(target.url)
        if UUID_RE.search(target.url):
            return 0.9
        if not params:
            return 0.0
        if has_numeric:
            return 0.95
        if any(
            n.endswith("id")
            or n in {"user", "account", "order", "uid", "account_id", "user_id", "order_id", "trade_id", "wallet_id"}
            for n in names
        ):
            return 0.7
        return 0.3

    async def run(self, target: Target, ctx: ModuleContext) -> ModuleResult:
        _path, params, parts = self._parse_url(target.url)
        body_template = self._render_body_template(ctx)
        method = str((ctx.module_cfg or {}).get("method", "GET")).upper()
        path_uuid_match = UUID_RE.search(parts[2] or "")
        if not params and body_template is None and not path_uuid_match:
            return ModuleResult(self.name, "no_poc", {"reason": "no_query_params_or_body_or_path_uuid"}, "", {})
        idx = None
        for i, (_k, v) in enumerate(params):
            if str(v).isdigit():
                idx = i
                break
        if idx is None:
            # Try UUID in query params
            for i, (_k, v) in enumerate(params):
                if UUID_RE.search(str(v)):
                    idx = i
                    break
        if idx is None and params and body_template is None and not path_uuid_match:
            return ModuleResult(self.name, "no_poc", {"reason": "no_numeric_or_uuid_param"}, "", {})

        key = None
        val = None
        if idx is not None and params:
            key, val = params[idx]
        headers = self._headers(ctx)
        base_body = self._clone_body(body_template)
        base_body_payload, base_body_headers = self._prepare_body(ctx, base_body)
        base_headers = {**headers, **base_body_headers}
        samples = int((ctx.module_cfg or {}).get("baseline_samples", 1) or 1)
        baseline_samples = await self._fetch_samples(
            target.url, ctx, target, base_headers, samples=samples, method=method, body=base_body_payload
        )
        baseline = self._pick_baseline(baseline_samples)
        baseline_text = str(baseline.get("text", ""))
        new_val = None
        mutated_body = base_body
        program = (target.program_id or "default").lower()

        def _uuid_candidate(original: str) -> str:
            cached = DEFAULT_ID_CACHE.get(program, "uuid")
            for candidate in cached:
                if candidate != original:
                    return candidate
            parts = original.split("-")
            if len(parts) == 5 and len(parts[-1]) == 12:
                perm = parts[-1][::-1]
                candidate = "-".join(parts[:-1] + [perm])
                if candidate != original:
                    return candidate
            return "22222222-2222-2222-2222-222222222222"

        if key is not None:
            if UUID_RE.search(str(val)):
                new_val = _uuid_candidate(str(val))
            else:
                try:
                    new_val = str(int(val) + 1)
                except Exception:
                    new_val = f"{val}1"
            params[idx] = (key, new_val)
            variant_url = self._build_url(parts, params)
        elif path_uuid_match:
            original = path_uuid_match.group(0)
            new_val = _uuid_candidate(original)
            variant_url = target.url.replace(original, new_val, 1)
        else:
            variant_url = target.url
            new_val = ""
            preferred = ["id", "account_id", "user_id", "order_id", "wallet_id", "trade_id"]
            mutated_body, new_val = self._mutate_body_for_keys(self._clone_body(body_template), preferred)

        variant_body_payload, variant_body_headers = self._prepare_body(ctx, mutated_body)
        variant_headers = {**headers, **variant_body_headers}
        variant = await self._fetch(variant_url, ctx, target, headers=variant_headers, method=method, body=variant_body_payload)
        for uuid in UUID_RE.findall(baseline_text):
            DEFAULT_ID_CACHE.add((target.program_id or "default"), "uuid", uuid)

        status_diff = int(baseline.get("status", 0)) != int(variant.get("status", 0))
        variant_text = str(variant.get("text", ""))
        body_diff_ratio = self._body_diff_ratio(baseline_text, variant_text)
        json_key_diff_ratio = self._json_key_diff_ratio(baseline_text, variant_text)
        baseline_variance = self._baseline_variance(baseline_samples)
        text_changed = baseline_text != variant_text
        min_body_diff = float((ctx.module_cfg or {}).get("min_body_diff_ratio", 0.2) or 0.2)
        min_json_diff = float((ctx.module_cfg or {}).get("min_json_key_diff_ratio", 0.2) or 0.2)
        variance_threshold = float((ctx.module_cfg or {}).get("baseline_variance_threshold", 0.15) or 0.15)
        significant_change = (
            body_diff_ratio >= min_body_diff
            or (json_key_diff_ratio is not None and json_key_diff_ratio >= min_json_diff)
            or (text_changed and baseline_variance <= variance_threshold)
        )
        idor_anomaly = (
            int(baseline.get("status", 0)) == 200
            and int(variant.get("status", 0)) == 200
            and significant_change
        )
        sens_score, sens_meta = self._sensitivity(variant_text)

        evidence = {
            "status_base": baseline.get("status"),
            "status_variant": variant.get("status"),
            "status_diff": status_diff,
            "body_diff_ratio": round(body_diff_ratio, 4),
            "json_key_diff_ratio": json_key_diff_ratio,
            "idor_anomaly": idor_anomaly,
            "text_changed": text_changed,
            "baseline_hash": self._hash(self._safe_sample(baseline_text)),
            "variant_hash": self._hash(self._safe_sample(variant.get("text", ""))),
            "param": key,
            "baseline_value": val,
            "variant_value": new_val,
            "baseline_samples": len(baseline_samples),
            "baseline_variance": baseline_variance,
            "sensitivity_score": sens_score,
            "sensitivity_meta": sens_meta,
            "request_url": target.url,
            "variant_url": variant_url,
            "request": self._request_meta(target.url, base_headers, ctx, method=method, body=base_body_payload),
            "request_variant": self._request_meta(variant_url, variant_headers, ctx, method=method, body=variant_body_payload),
        }
        candidate = f"{key}={val} -> {key}={new_val}" if key else (
            f"path_uuid -> {new_val}" if path_uuid_match else f"body_field -> {new_val}"
        )
        status = "candidate" if idor_anomaly else "no_poc"
        return ModuleResult(self.name, status, evidence, candidate, {})


class SqliModule(AttackModule):
    name = "sqli"

    def score_target(self, target: Target) -> float:
        params, names, _has_numeric = self._param_info(target.url)
        if not params:
            return 0.0
        if any(n in {"id", "q", "query", "search", "filter", "where", "order", "sort"} for n in names):
            return 0.6
        return 0.4

    async def run(self, target: Target, ctx: ModuleContext) -> ModuleResult:
        _path, params, parts = self._parse_url(target.url)
        body_template = self._render_body_template(ctx)
        method = str((ctx.module_cfg or {}).get("method", "GET")).upper()
        if not params and body_template is None:
            return ModuleResult(self.name, "no_poc", {"reason": "no_query_params_or_body"}, "", {})
        idx = self._choose_param(params)
        key = None
        val = None
        if idx is None and params:
            return ModuleResult(self.name, "no_poc", {"reason": "no_param"}, "", {})
        if idx is not None and params:
            key, val = params[idx]

        headers = self._headers(ctx)
        base_body = self._clone_body(body_template)
        base_body_payload, base_body_headers = self._prepare_body(ctx, base_body)
        base_headers = {**headers, **base_body_headers}
        samples = int((ctx.module_cfg or {}).get("baseline_samples", 1) or 1)
        baseline_samples = await self._fetch_samples(
            target.url, ctx, target, base_headers, samples=samples, method=method, body=base_body_payload
        )
        baseline = self._pick_baseline(baseline_samples)
        baseline_text = str(baseline.get("text", ""))
        payload_tokens = self._payloads(ctx, ["'"], ["'"])
        token = payload_tokens[0] if payload_tokens else "'"
        if val is not None and "{value}" in token:
            payload = token.format(value=val)
        elif val is not None and token.startswith("'"):
            payload = f"{val}{token}"
        else:
            payload = token
        mutated_body = base_body
        if key is not None:
            params[idx] = (key, payload)
            variant_url = self._build_url(parts, params)
        else:
            variant_url = target.url
            mutated_body, _old = self._set_body_value_for_keys(
                self._clone_body(body_template),
                ["id", "q", "query", "search", "filter", "where"],
                payload,
            )
        variant_body_payload, variant_body_headers = self._prepare_body(ctx, mutated_body)
        variant_headers = {**headers, **variant_body_headers}
        variant = await self._fetch(variant_url, ctx, target, headers=variant_headers, method=method, body=variant_body_payload)

        body = str(variant.get("text", ""))
        error_signature = bool(SQL_ERROR_RE.search(body))
        status_diff = int(baseline.get("status", 0)) != int(variant.get("status", 0))
        body_diff_ratio = self._body_diff_ratio(baseline_text, body)
        json_key_diff_ratio = self._json_key_diff_ratio(baseline_text, body)
        sens_score, sens_meta = self._sensitivity(body)

        evidence = {
            "status_base": baseline.get("status"),
            "status_variant": variant.get("status"),
            "status_diff": status_diff,
            "body_diff_ratio": round(body_diff_ratio, 4),
            "json_key_diff_ratio": json_key_diff_ratio,
            "error_signature": error_signature,
            "param": key,
            "payload": payload,
            "baseline_samples": len(baseline_samples),
            "baseline_variance": self._baseline_variance(baseline_samples),
            "sensitivity_score": sens_score,
            "sensitivity_meta": sens_meta,
            "request_url": target.url,
            "variant_url": variant_url,
            "request": self._request_meta(target.url, base_headers, ctx, method=method, body=base_body_payload),
            "request_variant": self._request_meta(variant_url, variant_headers, ctx, method=method, body=variant_body_payload),
        }

        if (not self._safe_only(ctx)) and _env_flag("HUNTEROPS_SQLMAP") and method == "GET":
            policy = ctx.policy or {}
            await ctx.politeness.wait(
                _target_host(target.url),
                target.target_id,
                per_host_rpm=policy.get("per_host_rpm"),
                per_target_rpm=policy.get("per_target_rpm"),
            )
            cmd = (
                f"sqlmap -u \"{target.url}\" --batch --level=1 --risk=1 --random-agent "
                f"--timeout=10 --retries=1 --threads=2 --smart --flush-session"
            )
            tool = await run_command(
                cmd,
                timeout=ctx.tool_timeout_s,
                stealth_mode=ctx.stealth_mode,
                proxies=ctx.proxies or [],
            )
            evidence["sqlmap_rc"] = tool.get("rc")
            evidence["sqlmap_out"] = (tool.get("stdout", "") or "")[:1000]

        candidate = f"{key}={payload}" if key else f"body_field={payload}"
        status = "candidate" if (error_signature or status_diff) else "no_poc"
        return ModuleResult(self.name, status, evidence, candidate, {})


class SstiModule(AttackModule):
    name = "ssti"

    def score_target(self, target: Target) -> float:
        params, names, _has_numeric = self._param_info(target.url)
        if not params:
            return 0.0
        if any(n in {"template", "view", "render", "name", "q", "query", "msg"} for n in names):
            return 0.7
        return 0.4

    async def run(self, target: Target, ctx: ModuleContext) -> ModuleResult:
        _path, params, parts = self._parse_url(target.url)
        body_template = self._render_body_template(ctx)
        method = str((ctx.module_cfg or {}).get("method", "GET")).upper()
        if not params and body_template is None:
            return ModuleResult(self.name, "no_poc", {"reason": "no_query_params_or_body"}, "", {})
        idx = self._choose_param(params, ["q", "query", "search", "template", "name"])
        if idx is None and body_template is None:
            return ModuleResult(self.name, "no_poc", {"reason": "no_param"}, "", {})

        key = None
        if idx is not None and params:
            key, _val = params[idx]
        headers = self._headers(ctx)
        base_body = self._clone_body(body_template)
        base_body_payload, base_body_headers = self._prepare_body(ctx, base_body)
        base_headers = {**headers, **base_body_headers}
        samples = int((ctx.module_cfg or {}).get("baseline_samples", 1) or 1)
        baseline_samples = await self._fetch_samples(
            target.url, ctx, target, base_headers, samples=samples, method=method, body=base_body_payload
        )
        baseline = self._pick_baseline(baseline_samples)
        baseline_text = str(baseline.get("text", ""))
        payloads = self._payloads(ctx, ["{{7*7}}HOPS"], ["{{7*7}}HOPS"])
        payload = payloads[0] if payloads else "{{7*7}}HOPS"
        mutated_body = base_body
        if key is not None:
            params[idx] = (key, payload)
            variant_url = self._build_url(parts, params)
        else:
            variant_url = target.url
            mutated_body, _old = self._set_body_value_for_keys(
                self._clone_body(body_template),
                ["template", "view", "render", "name", "q", "query", "msg"],
                payload,
            )
        variant_body_payload, variant_body_headers = self._prepare_body(ctx, mutated_body)
        variant_headers = {**headers, **variant_body_headers}
        variant = await self._fetch(variant_url, ctx, target, headers=variant_headers, method=method, body=variant_body_payload)

        body = str(variant.get("text", ""))
        ssti_evaluated = "49HOPS" in body and "49HOPS" not in baseline_text
        body_diff_ratio = self._body_diff_ratio(baseline_text, body)
        json_key_diff_ratio = self._json_key_diff_ratio(baseline_text, body)
        sens_score, sens_meta = self._sensitivity(body)

        evidence = {
            "status_base": baseline.get("status"),
            "status_variant": variant.get("status"),
            "body_diff_ratio": round(body_diff_ratio, 4),
            "json_key_diff_ratio": json_key_diff_ratio,
            "ssti_evaluated": ssti_evaluated,
            "param": key,
            "payload": payload,
            "baseline_samples": len(baseline_samples),
            "baseline_variance": self._baseline_variance(baseline_samples),
            "sensitivity_score": sens_score,
            "sensitivity_meta": sens_meta,
            "request_url": target.url,
            "variant_url": variant_url,
            "request": self._request_meta(target.url, base_headers, ctx, method=method, body=base_body_payload),
            "request_variant": self._request_meta(variant_url, variant_headers, ctx, method=method, body=variant_body_payload),
        }
        candidate = f"{key}={payload}" if key else f"body_field={payload}"
        status = "candidate" if ssti_evaluated else "no_poc"
        return ModuleResult(self.name, status, evidence, candidate, {})


class XssModule(AttackModule):
    name = "xss"

    def score_target(self, target: Target) -> float:
        params, names, _has_numeric = self._param_info(target.url)
        if not params:
            return 0.0
        if any(n in {"q", "query", "search", "s", "term", "keyword"} for n in names):
            return 0.7
        return 0.4

    async def run(self, target: Target, ctx: ModuleContext) -> ModuleResult:
        _path, params, parts = self._parse_url(target.url)
        body_template = self._render_body_template(ctx)
        method = str((ctx.module_cfg or {}).get("method", "GET")).upper()
        if not params and body_template is None:
            return ModuleResult(self.name, "no_poc", {"reason": "no_query_params_or_body"}, "", {})
        idx = self._choose_param(params, ["q", "query", "search", "s", "term"])
        if idx is None and body_template is None:
            return ModuleResult(self.name, "no_poc", {"reason": "no_param"}, "", {})

        key = None
        if idx is not None and params:
            key, _val = params[idx]
        headers = self._headers(ctx)
        base_body = self._clone_body(body_template)
        base_body_payload, base_body_headers = self._prepare_body(ctx, base_body)
        base_headers = {**headers, **base_body_headers}
        samples = int((ctx.module_cfg or {}).get("baseline_samples", 1) or 1)
        baseline_samples = await self._fetch_samples(
            target.url, ctx, target, base_headers, samples=samples, method=method, body=base_body_payload
        )
        baseline = self._pick_baseline(baseline_samples)
        baseline_text = str(baseline.get("text", ""))
        payloads = self._payloads(ctx, ["\"><h1>HUNTEROPS_XSS</h1>"], ["<h1>HUNTEROPS_XSS</h1>"])
        payload = payloads[0] if payloads else "\"><h1>HUNTEROPS_XSS</h1>"
        mutated_body = base_body
        if key is not None:
            params[idx] = (key, payload)
            variant_url = self._build_url(parts, params)
        else:
            variant_url = target.url
            mutated_body, _old = self._set_body_value_for_keys(
                self._clone_body(body_template),
                ["q", "query", "search", "s", "term", "keyword", "comment", "message"],
                payload,
            )
        variant_body_payload, variant_body_headers = self._prepare_body(ctx, mutated_body)
        variant_headers = {**headers, **variant_body_headers}
        variant = await self._fetch(variant_url, ctx, target, headers=variant_headers, method=method, body=variant_body_payload)

        body = str(variant.get("text", ""))
        payload_reflected = payload in body
        payload_reflected_encoded = self._encode_payload(payload) in body
        body_diff_ratio = self._body_diff_ratio(baseline_text, body)
        json_key_diff_ratio = self._json_key_diff_ratio(baseline_text, body)
        sens_score, sens_meta = self._sensitivity(body, [payload])

        evidence = {
            "status_base": baseline.get("status"),
            "status_variant": variant.get("status"),
            "body_diff_ratio": round(body_diff_ratio, 4),
            "json_key_diff_ratio": json_key_diff_ratio,
            "payload_reflected": payload_reflected,
            "payload_reflected_encoded": payload_reflected_encoded,
            "param": key,
            "payload": payload,
            "baseline_samples": len(baseline_samples),
            "baseline_variance": self._baseline_variance(baseline_samples),
            "sensitivity_score": sens_score,
            "sensitivity_meta": sens_meta,
            "request_url": target.url,
            "variant_url": variant_url,
            "request": self._request_meta(target.url, base_headers, ctx, method=method, body=base_body_payload),
            "request_variant": self._request_meta(variant_url, variant_headers, ctx, method=method, body=variant_body_payload),
        }

        if (not self._safe_only(ctx)) and _env_flag("HUNTEROPS_DALFOX"):
            policy = ctx.policy or {}
            await ctx.politeness.wait(
                _target_host(target.url),
                target.target_id,
                per_host_rpm=policy.get("per_host_rpm"),
                per_target_rpm=policy.get("per_target_rpm"),
            )
            cmd = f"dalfox url \"{target.url}\" --silence --no-color --timeout 10 --worker 3"
            tool = await run_command(
                cmd,
                timeout=ctx.tool_timeout_s,
                stealth_mode=ctx.stealth_mode,
                proxies=ctx.proxies or [],
            )
            evidence["dalfox_rc"] = tool.get("rc")
            evidence["dalfox_out"] = (tool.get("stdout", "") or "")[:1000]

        candidate = f"{key}={payload}" if key else f"body_field={payload}"
        status = "candidate" if payload_reflected else "no_poc"
        return ModuleResult(self.name, status, evidence, candidate, {})


class LfiModule(AttackModule):
    name = "lfi"

    def score_target(self, target: Target) -> float:
        params, names, _has_numeric = self._param_info(target.url)
        if not params:
            return 0.0
        if any(n in {"file", "path", "page", "template", "include", "doc"} for n in names):
            return 0.8
        return 0.3

    async def run(self, target: Target, ctx: ModuleContext) -> ModuleResult:
        _path, params, parts = self._parse_url(target.url)
        body_template = self._render_body_template(ctx)
        method = str((ctx.module_cfg or {}).get("method", "GET")).upper()
        if not params and body_template is None:
            return ModuleResult(self.name, "no_poc", {"reason": "no_query_params_or_body"}, "", {})
        idx = self._choose_param(params, ["file", "path", "page", "template", "include"])
        if idx is None and body_template is None:
            return ModuleResult(self.name, "no_poc", {"reason": "no_param"}, "", {})

        key = None
        if idx is not None and params:
            key, _val = params[idx]
        headers = self._headers(ctx)
        base_body = self._clone_body(body_template)
        base_body_payload, base_body_headers = self._prepare_body(ctx, base_body)
        base_headers = {**headers, **base_body_headers}
        samples = int((ctx.module_cfg or {}).get("baseline_samples", 1) or 1)
        baseline_samples = await self._fetch_samples(
            target.url, ctx, target, base_headers, samples=samples, method=method, body=base_body_payload
        )
        baseline = self._pick_baseline(baseline_samples)
        baseline_text = str(baseline.get("text", ""))
        payloads = self._payloads(ctx, ["../../../../etc/hosts"], ["../../../../etc/hosts"])
        payload = payloads[0] if payloads else "../../../../etc/hosts"
        mutated_body = base_body
        if key is not None:
            params[idx] = (key, payload)
            variant_url = self._build_url(parts, params)
        else:
            variant_url = target.url
            mutated_body, _old = self._set_body_value_for_keys(
                self._clone_body(body_template),
                ["file", "path", "page", "template", "include", "doc"],
                payload,
            )
        variant_body_payload, variant_body_headers = self._prepare_body(ctx, mutated_body)
        variant_headers = {**headers, **variant_body_headers}
        variant = await self._fetch(variant_url, ctx, target, headers=variant_headers, method=method, body=variant_body_payload)

        body = str(variant.get("text", ""))
        lfi_marker = "127.0.0.1" in body or "localhost" in body
        body_diff_ratio = self._body_diff_ratio(baseline_text, body)
        json_key_diff_ratio = self._json_key_diff_ratio(baseline_text, body)
        sens_score, sens_meta = self._sensitivity(body)

        evidence = {
            "status_base": baseline.get("status"),
            "status_variant": variant.get("status"),
            "body_diff_ratio": round(body_diff_ratio, 4),
            "json_key_diff_ratio": json_key_diff_ratio,
            "lfi_marker": lfi_marker,
            "param": key,
            "payload": payload,
            "baseline_samples": len(baseline_samples),
            "baseline_variance": self._baseline_variance(baseline_samples),
            "sensitivity_score": sens_score,
            "sensitivity_meta": sens_meta,
            "request_url": target.url,
            "variant_url": variant_url,
            "request": self._request_meta(target.url, base_headers, ctx, method=method, body=base_body_payload),
            "request_variant": self._request_meta(variant_url, variant_headers, ctx, method=method, body=variant_body_payload),
        }

        if (not self._safe_only(ctx)) and _env_flag("HUNTEROPS_FFUF"):
            policy = ctx.policy or {}
            await ctx.politeness.wait(
                _target_host(target.url),
                target.target_id,
                per_host_rpm=policy.get("per_host_rpm"),
                per_target_rpm=policy.get("per_target_rpm"),
            )
            cmd = f"ffuf -u \"{target.url}\" -w wordlists/common.txt -rate 30 -t 3 -timeout 10 -fc 404"
            tool = await run_command(
                cmd,
                timeout=ctx.tool_timeout_s,
                stealth_mode=ctx.stealth_mode,
                proxies=ctx.proxies or [],
            )
            evidence["ffuf_rc"] = tool.get("rc")
            evidence["ffuf_out"] = (tool.get("stdout", "") or "")[:1000]

        candidate = f"{key}={payload}" if key else f"body_field={payload}"
        status = "candidate" if lfi_marker else "no_poc"
        return ModuleResult(self.name, status, evidence, candidate, {})


class RceModule(AttackModule):
    name = "rce"

    def score_target(self, target: Target) -> float:
        if not _env_flag("HUNTEROPS_ALLOW_RCE_SAFE_PROBES"):
            return 0.0
        params, names, _has_numeric = self._param_info(target.url)
        if not params:
            return 0.0
        if any(n in {"cmd", "exec", "command", "ping", "run"} for n in names):
            return 0.8
        return 0.2

    async def run(self, target: Target, ctx: ModuleContext) -> ModuleResult:
        allow_rce = _env_flag("HUNTEROPS_ALLOW_RCE_SAFE_PROBES")
        if not allow_rce:
            return ModuleResult(self.name, "no_poc", {"reason": "rce_safe_probes_disabled"}, "", {})

        _path, params, parts = self._parse_url(target.url)
        body_template = self._render_body_template(ctx)
        method = str((ctx.module_cfg or {}).get("method", "GET")).upper()
        if not params and body_template is None:
            return ModuleResult(self.name, "no_poc", {"reason": "no_query_params_or_body"}, "", {})
        idx = self._choose_param(params, ["cmd", "command", "exec", "query", "ping"])
        if idx is None and body_template is None:
            return ModuleResult(self.name, "no_poc", {"reason": "no_param"}, "", {})

        key = None
        val = None
        if idx is not None and params:
            key, val = params[idx]
        headers = self._headers(ctx)
        base_body = self._clone_body(body_template)
        base_body_payload, base_body_headers = self._prepare_body(ctx, base_body)
        base_headers = {**headers, **base_body_headers}
        samples = int((ctx.module_cfg or {}).get("baseline_samples", 1) or 1)
        baseline_samples = await self._fetch_samples(
            target.url, ctx, target, base_headers, samples=samples, method=method, body=base_body_payload
        )
        baseline = self._pick_baseline(baseline_samples)
        baseline_text = str(baseline.get("text", ""))
        payloads = self._payloads(ctx, ["echo HUNTEROPS_RCE_PROBE"], ["echo HUNTEROPS_RCE_PROBE"])
        token = payloads[0] if payloads else "echo HUNTEROPS_RCE_PROBE"
        if val is not None and "{value}" in token:
            payload = token.format(value=val)
        elif val is not None:
            payload = f"{val};{token}"
        else:
            payload = token
        mutated_body = base_body
        if key is not None:
            params[idx] = (key, payload)
            variant_url = self._build_url(parts, params)
        else:
            variant_url = target.url
            mutated_body, _old = self._set_body_value_for_keys(
                self._clone_body(body_template),
                ["cmd", "command", "exec", "query", "ping"],
                payload,
            )
        variant_body_payload, variant_body_headers = self._prepare_body(ctx, mutated_body)
        variant_headers = {**headers, **variant_body_headers}
        variant = await self._fetch(variant_url, ctx, target, headers=variant_headers, method=method, body=variant_body_payload)

        body = str(variant.get("text", ""))
        rce_marker = "HUNTEROPS_RCE_PROBE" in body
        body_diff_ratio = self._body_diff_ratio(baseline_text, body)
        json_key_diff_ratio = self._json_key_diff_ratio(baseline_text, body)
        sens_score, sens_meta = self._sensitivity(body)

        evidence = {
            "status_base": baseline.get("status"),
            "status_variant": variant.get("status"),
            "body_diff_ratio": round(body_diff_ratio, 4),
            "json_key_diff_ratio": json_key_diff_ratio,
            "rce_marker": rce_marker,
            "param": key,
            "payload": payload,
            "baseline_samples": len(baseline_samples),
            "baseline_variance": self._baseline_variance(baseline_samples),
            "sensitivity_score": sens_score,
            "sensitivity_meta": sens_meta,
            "request_url": target.url,
            "variant_url": variant_url,
            "request": self._request_meta(target.url, base_headers, ctx, method=method, body=base_body_payload),
            "request_variant": self._request_meta(variant_url, variant_headers, ctx, method=method, body=variant_body_payload),
        }
        candidate = f"{key}={payload}" if key else f"body_field={payload}"
        status = "candidate" if rce_marker else "no_poc"
        return ModuleResult(self.name, status, evidence, candidate, {})


class OpenRedirectModule(AttackModule):
    name = "open_redirect"

    def score_target(self, target: Target) -> float:
        params, names, _has_numeric = self._param_info(target.url)
        if not params:
            return 0.0
        if any(n in {"redirect", "redirect_uri", "return", "next", "url", "continue"} for n in names):
            return 0.8
        return 0.3

    async def run(self, target: Target, ctx: ModuleContext) -> ModuleResult:
        _path, params, parts = self._parse_url(target.url)
        body_template = self._render_body_template(ctx)
        method = str((ctx.module_cfg or {}).get("method", "GET")).upper()
        if not params and body_template is None:
            return ModuleResult(self.name, "no_poc", {"reason": "no_query_params_or_body"}, "", {})
        idx = self._choose_param(params, ["redirect_uri", "redirect", "return", "next", "url", "continue"])
        if idx is None and body_template is None:
            return ModuleResult(self.name, "no_poc", {"reason": "no_param"}, "", {})

        key = None
        if idx is not None and params:
            key, _val = params[idx]
        headers = self._headers(ctx)
        base_body = self._clone_body(body_template)
        base_body_payload, base_body_headers = self._prepare_body(ctx, base_body)
        base_headers = {**headers, **base_body_headers}
        baseline = await self._fetch(target.url, ctx, target, headers=base_headers, method=method, body=base_body_payload)
        payloads = self._payloads(ctx, ["https://example.com/hunterops"], ["https://example.com/hunterops"])
        payload = payloads[0] if payloads else "https://example.com/hunterops"
        mutated_body = base_body
        if key is not None:
            params[idx] = (key, payload)
            variant_url = self._build_url(parts, params)
        else:
            variant_url = target.url
            mutated_body, _old = self._set_body_value_for_keys(
                self._clone_body(body_template),
                ["redirect_uri", "redirect", "return", "next", "url", "continue"],
                payload,
            )
        variant_body_payload, variant_body_headers = self._prepare_body(ctx, mutated_body)
        variant_headers = {**headers, **variant_body_headers}
        variant = await self._fetch(variant_url, ctx, target, headers=variant_headers, method=method, body=variant_body_payload)
        location = ""
        if isinstance(variant.get("headers"), dict):
            for hk, hv in variant.get("headers", {}).items():
                if str(hk).lower() == "location":
                    location = str(hv)
                    break
        status = int(variant.get("status", 0) or 0)
        open_redirect = status in {301, 302, 303, 307, 308} and "example.com" in location
        sens_score, sens_meta = self._sensitivity(str(variant.get("text", "")))

        evidence = {
            "status_base": baseline.get("status"),
            "status_variant": variant.get("status"),
            "location": location,
            "open_redirect": open_redirect,
            "param": key,
            "payload": payload,
            "sensitivity_score": sens_score,
            "sensitivity_meta": sens_meta,
            "request_url": target.url,
            "variant_url": variant_url,
            "request": self._request_meta(target.url, base_headers, ctx, method=method, body=base_body_payload),
            "request_variant": self._request_meta(variant_url, variant_headers, ctx, method=method, body=variant_body_payload),
        }
        candidate = f"{key}={payload}" if key else f"body_field={payload}"
        status_out = "candidate" if open_redirect else "no_poc"
        return ModuleResult(self.name, status_out, evidence, candidate, {})


class SensitiveMisconfigModule(AttackModule):
    name = "sensitive_misconfig"

    def score_target(self, target: Target) -> float:
        return 0.5

    async def run(self, target: Target, ctx: ModuleContext) -> ModuleResult:
        parts = urlsplit(target.url)
        base = f"{parts.scheme}://{parts.netloc}"
        module_cfg = ctx.module_cfg or {}
        paths = module_cfg.get(
            "paths",
            ["/.git/config", "/.env", "/.env.local", "/config/.env", "/app.js.map", "/main.js.map", "/bundle.js.map"],
        )
        max_checks = int(module_cfg.get("max_checks", 5) or 5)
        headers = self._headers(ctx)
        checked = 0
        for raw_path in paths:
            if checked >= max_checks:
                break
            path = str(raw_path or "").strip()
            if not path.startswith("/"):
                path = "/" + path
            url = f"{base}{path}"
            checked += 1
            resp = await self._fetch(url, ctx, target, headers=headers)
            status = int(resp.get("status", 0) or 0)
            body = str(resp.get("text", ""))
            if status != 200 or not body:
                continue
            hits = []
            if path.endswith(".env") or path.endswith(".env.local"):
                if ENV_LINE_RE.search(body):
                    hits.append("env_kv")
            if path.endswith(".map"):
                if SOURCE_MAP_RE.search(body):
                    hits.append("sourcemap")
            if path.endswith("/.git/config") or path.endswith("/.git/config/"):
                if "[core]" in body or "repositoryformatversion" in body:
                    hits.append("git_config")
            secret_hits = self._secret_hits(body)
            if secret_hits:
                hits.append("secret_pattern")
            if hits:
                sens_score, sens_meta = self._sensitivity(body)
                evidence = {
                    "status": status,
                    "path": path,
                    "hits": hits,
                    "secret_hits": secret_hits[:5],
                    "sensitivity_score": sens_score,
                    "sensitivity_meta": sens_meta,
                    "request_url": url,
                    "request": self._request_meta(url, headers, ctx),
                }
                return ModuleResult(self.name, "candidate", evidence, path, {})

        return ModuleResult(self.name, "no_poc", {"reason": "no_sensitive_misconfig"}, "", {})


class SsrfSafeProbeModule(AttackModule):
    name = "ssrf_safe_probe"

    def score_target(self, target: Target) -> float:
        params, names, _has_numeric = self._param_info(target.url)
        if not params:
            return 0.0
        if any(n in {"url", "uri", "redirect_uri", "dest", "target", "next", "callback"} for n in names):
            return 0.7
        return 0.2

    async def run(self, target: Target, ctx: ModuleContext) -> ModuleResult:
        _path, params, parts = self._parse_url(target.url)
        body_template = self._render_body_template(ctx)
        method = str((ctx.module_cfg or {}).get("method", "GET")).upper()
        if not params and body_template is None:
            return ModuleResult(self.name, "no_poc", {"reason": "no_query_params_or_body"}, "", {})
        idx = self._choose_param(params, ["url", "uri", "redirect_uri", "dest", "target", "next", "callback"])
        if idx is None and body_template is None:
            return ModuleResult(self.name, "no_poc", {"reason": "no_param"}, "", {})

        key = None
        if idx is not None and params:
            key, _val = params[idx]
        module_cfg = ctx.module_cfg or {}
        payloads = self._payloads(
            ctx,
            ["http://169.254.169.254/latest/meta-data/"],
            ["https://example.com/"],
        )
        payload = str(payloads[0]) if payloads else "https://example.com/"
        headers = self._headers(ctx)
        base_body = self._clone_body(body_template)
        base_body_payload, base_body_headers = self._prepare_body(ctx, base_body)
        base_headers = {**headers, **base_body_headers}
        samples = int((ctx.module_cfg or {}).get("baseline_samples", 1) or 1)
        baseline_samples = await self._fetch_samples(
            target.url, ctx, target, base_headers, samples=samples, method=method, body=base_body_payload
        )
        baseline = self._pick_baseline(baseline_samples)
        baseline_text = str(baseline.get("text", ""))
        mutated_body = base_body
        if key is not None:
            params[idx] = (key, payload)
            variant_url = self._build_url(parts, params)
        else:
            variant_url = target.url
            mutated_body, _old = self._set_body_value_for_keys(
                self._clone_body(body_template),
                ["url", "uri", "redirect_uri", "dest", "target", "next", "callback"],
                payload,
            )
        variant_body_payload, variant_body_headers = self._prepare_body(ctx, mutated_body)
        variant_headers = {**headers, **variant_body_headers}
        variant = await self._fetch(variant_url, ctx, target, headers=variant_headers, method=method, body=variant_body_payload)
        body = str(variant.get("text", "")).lower()
        ssrf_marker = any(m in body for m in META_MARKERS)
        status_diff = int(baseline.get("status", 0)) != int(variant.get("status", 0))
        body_diff_ratio = self._body_diff_ratio(baseline_text, variant.get("text", ""))
        json_key_diff_ratio = self._json_key_diff_ratio(baseline_text, str(variant.get("text", "")))
        sens_score, sens_meta = self._sensitivity(str(variant.get("text", "")))

        evidence = {
            "status_base": baseline.get("status"),
            "status_variant": variant.get("status"),
            "status_diff": status_diff,
            "body_diff_ratio": round(body_diff_ratio, 4),
            "json_key_diff_ratio": json_key_diff_ratio,
            "ssrf_marker": ssrf_marker,
            "param": key,
            "payload": payload,
            "baseline_samples": len(baseline_samples),
            "baseline_variance": self._baseline_variance(baseline_samples),
            "sensitivity_score": sens_score,
            "sensitivity_meta": sens_meta,
            "request_url": target.url,
            "variant_url": variant_url,
            "request": self._request_meta(target.url, base_headers, ctx, method=method, body=base_body_payload),
            "request_variant": self._request_meta(variant_url, variant_headers, ctx, method=method, body=variant_body_payload),
        }
        status_out = "candidate" if ssrf_marker else "no_poc"
        candidate = f"{key}={payload}" if key else f"body_field={payload}"
        return ModuleResult(self.name, status_out, evidence, candidate, {})


class BacAdvancedModule(AttackModule):
    name = "bac_advanced"

    def score_target(self, target: Target) -> float:
        if not target.url:
            return 0.0
        return 0.6

    async def run(self, target: Target, ctx: ModuleContext) -> ModuleResult:
        if not ctx.use_auth or not ctx.session_name:
            return ModuleResult(self.name, "no_poc", {"reason": "auth_session_required"}, "", {})
        module_cfg = ctx.module_cfg or {}
        paths = module_cfg.get("paths", ["/admin", "/internal", "/staff", "/manage", "/console"])
        max_checks = int(module_cfg.get("max_checks", 3) or 3)
        parts = urlsplit(target.url)
        base = f"{parts.scheme}://{parts.netloc}"
        auth_headers = self._headers(ctx)
        anon_headers = {k: v for k, v in auth_headers.items() if k.lower() not in {"authorization", "cookie"}}
        checked = 0
        for raw_path in paths:
            if checked >= max_checks:
                break
            path = str(raw_path or "").strip()
            if not path.startswith("/"):
                path = "/" + path
            url = f"{base}{path}"
            checked += 1
            auth_resp = await self._fetch(url, ctx, target, headers=auth_headers)
            auth_status = int(auth_resp.get("status", 0) or 0)
            if auth_status not in {200, 301, 302}:
                continue
            anon_resp = await self._fetch(url, ctx, target, headers=anon_headers)
            anon_status = int(anon_resp.get("status", 0) or 0)
            auth_text = str(auth_resp.get("text", ""))
            anon_text = str(anon_resp.get("text", ""))
            diff_ratio = self._body_diff_ratio(auth_text, anon_text)
            json_key_diff_ratio = self._json_key_diff_ratio(auth_text, anon_text)
            sens_score, sens_meta = self._sensitivity(anon_text)
            unauthorized_access = anon_status in {200, 301, 302} and diff_ratio <= 0.25
            if unauthorized_access:
                evidence = {
                    "path": path,
                    "auth_status": auth_status,
                    "anon_status": anon_status,
                    "body_diff_ratio": round(diff_ratio, 4),
                    "json_key_diff_ratio": json_key_diff_ratio,
                    "sensitivity_score": sens_score,
                    "sensitivity_meta": sens_meta,
                    "request_url": url,
                    "request_auth": self._request_meta(url, auth_headers, ctx),
                    "request_anon": self._request_meta(url, anon_headers, ctx),
                }
                return ModuleResult(self.name, "candidate", evidence, path, {})

        return ModuleResult(self.name, "no_poc", {"reason": "no_bac_anomaly"}, "", {})


class InfoLeakModule(AttackModule):
    name = "info_leak"

    def score_target(self, target: Target) -> float:
        params, names, _has_numeric = self._param_info(target.url)
        if any(n in {"apikey", "api_key", "token", "secret"} for n in names):
            return 0.7
        return 0.2 if params else 0.1

    async def run(self, target: Target, ctx: ModuleContext) -> ModuleResult:
        body_template = self._render_body_template(ctx)
        method = str((ctx.module_cfg or {}).get("method", "GET")).upper()
        headers = self._headers(ctx)
        base_body = self._clone_body(body_template)
        base_body_payload, base_body_headers = self._prepare_body(ctx, base_body)
        base_headers = {**headers, **base_body_headers}
        resp = await self._fetch(target.url, ctx, target, headers=base_headers, method=method, body=base_body_payload)
        body = str(resp.get("text", ""))
        secret_hits = self._secret_hits(body)
        if not secret_hits:
            return ModuleResult(self.name, "no_poc", {"reason": "no_secret_pattern"}, "", {})
        sens_score, sens_meta = self._sensitivity(body)
        evidence = {
            "status": resp.get("status"),
            "secret_hits": secret_hits[:5],
            "sensitivity_score": sens_score,
            "sensitivity_meta": sens_meta,
            "request_url": target.url,
            "request": self._request_meta(target.url, base_headers, ctx, method=method, body=base_body_payload),
        }
        return ModuleResult(self.name, "candidate", evidence, "secret_pattern_detected", {})


def build_modules() -> dict[str, AttackModule]:
    return {
        "idor": IdorModule(),
        "sqli": SqliModule(),
        "ssti": SstiModule(),
        "xss": XssModule(),
        "lfi": LfiModule(),
        "rce": RceModule(),
        "open_redirect": OpenRedirectModule(),
        "sensitive_misconfig": SensitiveMisconfigModule(),
        "ssrf_safe_probe": SsrfSafeProbeModule(),
        "bac_advanced": BacAdvancedModule(),
        "info_leak": InfoLeakModule(),
    }
