from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from hunterops.async_io import read_json, write_text
from hunterops.plugin_base import Plugin
from hunterops.runtime_paths import resolve_path
from hunterops.storage import PostgresStorage
from hunterops.types import Finding, Task

SENSITIVE_FIELDS = ("email", "cpf", "phone", "address", "token", "account", "wallet", "invoice", "user_id")


def _slugify(value: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9]+", "_", value.strip().lower())
    return s.strip("_")[:120] or "finding"


def _mask_secret(value: str) -> str:
    raw = str(value or "")
    if len(raw) <= 8:
        return "*" * len(raw)
    return f"{raw[:4]}...{raw[-4:]}"


def _mask_auth_header(value: str) -> str:
    raw = str(value or "")
    if not raw:
        return raw
    parts = raw.split(" ", 1)
    if len(parts) == 2:
        return f"{parts[0]} {_mask_secret(parts[1])}"
    return _mask_secret(raw)


def _mask_cookie(value: str) -> str:
    chunks = []
    for item in str(value or "").split(";"):
        kv = item.strip().split("=", 1)
        if len(kv) == 2:
            chunks.append(f"{kv[0]}={_mask_secret(kv[1])}")
        elif kv[0]:
            chunks.append(kv[0])
    return "; ".join(chunks)


def _mask_headers(headers: dict[str, Any]) -> dict[str, str]:
    out: dict[str, str] = {}
    for key, value in headers.items():
        k = str(key)
        v = str(value)
        lk = k.lower()
        if lk == "authorization":
            out[k] = _mask_auth_header(v)
        elif lk == "cookie":
            out[k] = _mask_cookie(v)
        elif any(marker in lk for marker in ("token", "secret", "api-key", "x-api-key")):
            out[k] = _mask_secret(v)
        else:
            out[k] = v
    return out


async def _load_json(path: str) -> dict[str, Any]:
    p = Path(path)
    if not p.exists():
        return {}
    try:
        doc = await read_json(p)
    except Exception:
        return {}
    return doc if isinstance(doc, dict) else {}


def _response_json(response: dict[str, Any]) -> dict[str, Any]:
    body = response.get("body", response.get("text", ""))
    if isinstance(body, dict):
        return body
    if not isinstance(body, str):
        return {}
    try:
        parsed = json.loads(body)
    except Exception:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _extract_endpoint(evidence: dict[str, Any]) -> str:
    req_a = evidence.get("request_auth_a", {}) if isinstance(evidence.get("request_auth_a"), dict) else {}
    req_b = evidence.get("request_auth_b", {}) if isinstance(evidence.get("request_auth_b"), dict) else {}
    req = evidence.get("request", {}) if isinstance(evidence.get("request"), dict) else {}
    for src in (req_a, req_b, req):
        url = src.get("url")
        if isinstance(url, str) and url.strip():
            return urlparse(url).path or "/"
    for key in ("base_url", "modified_url", "url", "endpoint", "path"):
        raw = evidence.get(key)
        if isinstance(raw, str) and raw.strip():
            if raw.startswith("http://") or raw.startswith("https://"):
                return urlparse(raw).path or "/"
            return raw if raw.startswith("/") else f"/{raw}"
    endpoints = evidence.get("endpoints", [])
    if isinstance(endpoints, list):
        for item in endpoints:
            raw = str(item or "").strip()
            if not raw:
                continue
            if raw.startswith("http://") or raw.startswith("https://"):
                return urlparse(raw).path or "/"
            return raw if raw.startswith("/") else f"/{raw}"
    return "/unknown"


def _cwe_for_finding(category: str, title: str) -> tuple[str, str]:
    combined = f"{category} {title}".lower()
    if "idor" in combined or "object" in combined:
        return ("CWE-639", "Authorization Bypass Through User-Controlled Key")
    if "auth_bypass" in combined or "bypass" in combined:
        return ("CWE-288", "Authentication Bypass Using an Alternate Path or Channel")
    if "access" in combined:
        return ("CWE-284", "Improper Access Control")
    if "logic" in combined or "business" in combined:
        return ("CWE-840", "Business Logic Errors")
    return ("CWE-200", "Exposure of Sensitive Information to an Unauthorized Actor")


class ExploitDocGenerator:
    """Generates reproducible and masked curl sequences for security reporting."""

    @staticmethod
    def curl_from_request(request_data: dict[str, Any]) -> str:
        method = str(request_data.get("method", "GET")).upper()
        url = str(request_data.get("url", ""))
        if not url.strip():
            return ""
        headers = request_data.get("headers", {}) if isinstance(request_data.get("headers"), dict) else {}
        masked_headers = _mask_headers(headers)
        command = f"curl -i -X {method} \"{url}\""
        for hk, hv in masked_headers.items():
            command += f" -H \"{hk}: {hv}\""
        body = request_data.get("body")
        if isinstance(body, (str, dict, list)):
            payload = json.dumps(body, ensure_ascii=True) if not isinstance(body, str) else body
            command += f" --data '{payload}'"
        return command

    def generate_pair(self, evidence: dict[str, Any]) -> dict[str, str]:
        req_owner = evidence.get("request_auth_a", {}) if isinstance(evidence.get("request_auth_a"), dict) else {}
        req_attacker = evidence.get("request_auth_b", {}) if isinstance(evidence.get("request_auth_b"), dict) else {}
        if not req_owner:
            req_owner = evidence.get("request", {}) if isinstance(evidence.get("request"), dict) else {}
        if not req_attacker:
            req_attacker = evidence.get("request", {}) if isinstance(evidence.get("request"), dict) else {}
        return {
            "curl_base": self.curl_from_request(req_owner),
            "curl_exploit": self.curl_from_request(req_attacker),
        }


class PluginImpl(Plugin):
    name = "report_synthesis"

    async def _load_rows(self, task: Task, context: dict, run_id: str) -> list[dict[str, Any]]:
        payload = task.payload if isinstance(task.payload, dict) else {}
        pg_cfg = context["config"].get("storage", {}).get("postgres", {})
        dsn_env = str(pg_cfg.get("dsn_env", "HUNTEROPS_POSTGRES_DSN"))
        dsn = os.getenv(dsn_env, "")
        if bool(pg_cfg.get("enabled", False)) and dsn and run_id:
            try:
                storage = PostgresStorage(dsn=dsn, enabled=True)
                rows = await asyncio.to_thread(storage.fetch_run_findings, run_id, task.target)
                if rows:
                    return rows
            except Exception:
                pass
        fallback = payload.get("findings", [])
        if isinstance(fallback, list):
            return [x for x in fallback if isinstance(x, dict)]
        return []

    @staticmethod
    def _confidence(row: dict[str, Any]) -> float:
        meta = row.get("metadata", {}) if isinstance(row.get("metadata"), dict) else {}
        return float(meta.get("confidence_score", meta.get("confidence", 0)) or 0)

    @staticmethod
    def _risk_score(row: dict[str, Any]) -> float:
        return float(row.get("risk_score", 0) or 0)

    async def _load_evidence_artifacts(self, evidence: dict[str, Any]) -> dict[str, Any]:
        merged = evidence.copy()
        req_file = str(evidence.get("request_file", "")).strip()
        resp_file = str(evidence.get("response_file", "")).strip()
        evidence_ref = str(evidence.get("evidence_ref", "")).strip()
        if req_file:
            req_doc = await _load_json(req_file)
            if req_doc:
                merged.setdefault("request", req_doc)
        if resp_file:
            resp_doc = await _load_json(resp_file)
            if resp_doc:
                merged.setdefault("response", resp_doc)
        if evidence_ref:
            ref_doc = await _load_json(evidence_ref)
            if ref_doc:
                merged.setdefault("evidence_ref_payload", ref_doc)
        return merged

    def _leak_point(self, row: dict[str, Any], evidence: dict[str, Any], context_a: str, context_b: str) -> str:
        resp_a = evidence.get("response_auth_a", {}) if isinstance(evidence.get("response_auth_a"), dict) else {}
        resp_b = evidence.get("response_auth_b", {}) if isinstance(evidence.get("response_auth_b"), dict) else {}
        data_a = _response_json(resp_a)
        data_b = _response_json(resp_b)
        if data_a and data_b:
            for field in SENSITIVE_FIELDS:
                if field in data_a and field in data_b:
                    if str(data_a.get(field, "")) != str(data_b.get(field, "")):
                        return f"{context_b} session accessed {context_a} {field} data via the same object reference."
                    return f"{context_b} session received the same sensitive {field} field structure observed in {context_a} context."
                if field in data_b:
                    return f"{context_b} session received sensitive field '{field}' that should require owner-level authorization."
        tested_parameter = str(evidence.get("tested_parameter", "")).strip()
        endpoint = _extract_endpoint(evidence)
        if tested_parameter:
            return f"{context_b} context could access endpoint {endpoint} by manipulating parameter '{tested_parameter}'."
        return f"{context_b} context produced an unauthorized equivalent response at {endpoint}."

    @staticmethod
    def _impact_text(category: str, endpoint: str, parameter: str) -> str:
        c = category.lower()
        if "idor" in c:
            return f"An attacker can iterate '{parameter or 'id'}' on {endpoint} to leak other users' PII and private records."
        if "auth_bypass" in c or "bypass" in c:
            return f"An attacker can bypass access controls on {endpoint}, reaching restricted resources without proper authorization."
        if "logic" in c:
            return f"An attacker can abuse workflow logic in {endpoint}, causing unauthorized state transitions and business impact."
        return f"An attacker can access sensitive data on {endpoint} without proper object-level access controls."

    @staticmethod
    def _remediation_text(cwe: str) -> str:
        if cwe == "CWE-639":
            return "Enforce server-side object ownership checks for every object identifier and deny cross-tenant references."
        if cwe in {"CWE-284", "CWE-288"}:
            return "Centralize authorization checks on the backend and validate role/session context before returning object data."
        if cwe == "CWE-840":
            return "Add workflow state validation and transaction invariants for each sensitive business action."
        return "Restrict sensitive response fields and apply strict authorization validation for all protected endpoints."

    @staticmethod
    def _severity_label(raw: str) -> str:
        sev = str(raw or "medium").lower()
        if sev in {"critical", "high", "medium", "low", "info"}:
            return sev
        return "medium"

    async def _notify_critical(self, title: str, report_path: Path, cfg: dict[str, Any], logger: Any) -> None:
        if not bool(cfg.get("enable_notifications", True)):
            return
        webhook = str(cfg.get("webhook_url", "")).strip()
        webhook_env = str(cfg.get("webhook_env", "")).strip()
        if webhook_env and not webhook:
            webhook = os.getenv(webhook_env, "").strip()
        payload = {
            "event": "critical_synthesized_finding",
            "title": title,
            "report_path": str(report_path),
            "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        }
        if webhook:
            try:
                def _post() -> None:
                    req = Request(
                        webhook,
                        data=json.dumps(payload, ensure_ascii=True).encode("utf-8"),
                        headers={"Content-Type": "application/json"},
                        method="POST",
                    )
                    with urlopen(req, timeout=4):
                        pass

                await asyncio.to_thread(_post)
            except Exception:
                logger.warning("report_synthesis_webhook_notify_failed")
        if os.name == "posix" and bool(cfg.get("enable_os_notification", True)):
            notify = shutil.which("notify-send")
            if notify:
                try:
                    subprocess.Popen(
                        [notify, "HunterOps CRITICAL", f"{title}\n{report_path}"],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        stdin=subprocess.DEVNULL,
                    )
                except Exception:
                    logger.warning("report_synthesis_os_notify_failed")

    async def run(self, task: Task, context: dict) -> list[Finding]:
        cfg = context["config"].get("modules", {}).get(self.name, {})
        logger = context.get("logger")
        run_id = str((task.payload if isinstance(task.payload, dict) else {}).get("run_id", "")).strip()
        if not run_id:
            return []
        threshold = float(cfg.get("confidence_threshold", 80))
        require_replayable_requests = bool(cfg.get("require_replayable_requests", True))
        allow_root_endpoint = bool(cfg.get("allow_root_endpoint", False))
        excluded_categories = {
            str(x).strip().lower()
            for x in cfg.get("exclude_categories", [])
            if str(x).strip()
        }
        excluded_source_plugins = {
            str(x).strip().lower()
            for x in cfg.get("exclude_source_plugins", [])
            if str(x).strip()
        }
        context_a = str(cfg.get("auth_context_a", "Auth_Context_A"))
        context_b = str(cfg.get("auth_context_b", "Auth_Context_B"))
        rows = await self._load_rows(task=task, context=context, run_id=run_id)
        if not rows:
            return []

        out_root = resolve_path(str(cfg.get("out_dir", "data/reports")))
        run_dir = out_root / f"run_{run_id}"
        run_dir.mkdir(parents=True, exist_ok=True)

        doc_gen = ExploitDocGenerator()
        synthesized: list[Finding] = []
        for row in rows:
            confidence = self._confidence(row)
            if confidence <= threshold:
                continue
            category = str(row.get("category", ""))
            source_plugin = str(row.get("plugin", "")).strip().lower()
            if category.lower() in excluded_categories:
                continue
            if source_plugin and source_plugin in excluded_source_plugins:
                continue
            title = str(row.get("title", "Untitled finding"))
            severity = self._severity_label(row.get("severity", "medium"))
            evidence = row.get("evidence", {}) if isinstance(row.get("evidence"), dict) else {}
            evidence = await self._load_evidence_artifacts(evidence)
            endpoint = _extract_endpoint(evidence)
            if not allow_root_endpoint and endpoint == "/":
                continue
            parameter = str(evidence.get("tested_parameter", "")).strip()
            if not parameter:
                parameter = str(evidence.get("parameter", "")).strip()
            cwe_id, cwe_name = _cwe_for_finding(category, title)
            leak_point = self._leak_point(row=row, evidence=evidence, context_a=context_a, context_b=context_b)
            poc = doc_gen.generate_pair(evidence)
            if require_replayable_requests and (not str(poc.get("curl_base", "")).strip() or not str(poc.get("curl_exploit", "")).strip()):
                continue
            impact = self._impact_text(category=category, endpoint=endpoint, parameter=parameter)
            remediation = self._remediation_text(cwe_id)
            novelty = float((row.get("metadata", {}) or {}).get("novelty", 0) or 0)
            risk = self._risk_score(row)

            report_title = f"[{category.upper() or 'FINDING'}] {title}"
            if "idor" in category.lower():
                report_title = f"[IDOR] Unauthorized data access at {endpoint} via {parameter or 'object reference'} manipulation"

            report_slug = _slugify(f"{severity}_{title}")
            report_path = run_dir / f"{severity}_{report_slug}.md"
            markdown = [
                f"# Title: {report_title}",
                "",
                "## Summary",
                f"- Category: {category}",
                f"- CWE: {cwe_id} ({cwe_name})",
                f"- Endpoint: `{endpoint}`",
                f"- Confidence: {confidence}",
                f"- Risk Score: {risk}",
                f"- Novelty: {novelty}",
                f"- Leak Point: {leak_point}",
                "",
                "## Impact",
                impact,
                "",
                "## Steps to Reproduce",
                "1. Send owner-context request (baseline).",
                f"```bash\n{poc['curl_base']}\n```",
                "2. Replay with attacker-context session.",
                f"```bash\n{poc['curl_exploit']}\n```",
                "3. Confirm unauthorized response consistency and exposed fields.",
                "",
                "## Evidence",
                f"- evidence_ref: `{evidence.get('evidence_ref', '')}`",
                f"- request_file: `{evidence.get('request_file', '')}`",
                f"- response_file: `{evidence.get('response_file', '')}`",
                f"- Generated at: {datetime.now(UTC).isoformat().replace('+00:00', 'Z')}",
                "",
                "## Remediation",
                remediation,
                "",
            ]
            await write_text(report_path, "\n".join(markdown))

            if severity == "critical":
                await self._notify_critical(title=title, report_path=report_path, cfg=cfg, logger=logger)

            synthesized.append(
                Finding(
                    plugin=self.name,
                    target=task.target,
                    category="synthesized_security_report",
                    severity=severity,
                    title=f"Synthesized report: {title}",
                    evidence={
                        "report_path": str(report_path),
                        "endpoint": endpoint,
                        "curl_base": poc["curl_base"],
                        "curl_exploit": poc["curl_exploit"],
                        "cwe": cwe_id,
                        "leak_point": leak_point,
                    },
                    metadata={
                        "novelty": novelty,
                        "confidence": confidence,
                        "confidence_score": confidence,
                        "impact": float((row.get("metadata", {}) or {}).get("impact", 70) or 70),
                        "risk_score": risk,
                        "discovery_source": "report_synthesis",
                        "report_path": str(report_path),
                        "endpoint": endpoint,
                        "plugin_source": str(row.get("plugin", "")),
                    },
                )
            )

        return synthesized
