from __future__ import annotations

import asyncio
import json
import re
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

from hunterops.findings import calculate_impact
from hunterops.runtime_paths import ensure_directory, resolve_path
from hunterops.secrets import read_secret
from hunterops.slack_formatter import build_critical_log_blocks, build_finding_blocks
from hunterops.types import Finding

RED = 0xFF0000
ORANGE = 0xFFA500
BLUE = 0x3498DB
GREY = 0x95A5A6
TOKEN_RE = re.compile(r"""(?i)\b(bearer\s+)([a-z0-9\-._~+/]+=*)""")


def _truncate(text: str, limit: int) -> str:
    raw = str(text or "")
    if len(raw) <= limit:
        return raw
    return f"{raw[:limit]}...[+{len(raw) - limit} chars]"


def _mask_secret(value: str) -> str:
    raw = str(value or "")
    if len(raw) <= 8:
        return "*" * len(raw)
    return f"{raw[:4]}...{raw[-4:]}"


def _redact(text: str) -> str:
    value = str(text or "")
    return TOKEN_RE.sub(lambda match: f"{match.group(1)}{_mask_secret(match.group(2))}", value)


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return float(default)


def _pretty_category(category: str) -> str:
    raw = str(category or "").strip().replace("_", " ")
    if not raw:
        return "Unknown"
    return " ".join([token.capitalize() for token in raw.split()])


class AlertRouter:
    """Central router for rich Discord/Slack triage alerts."""

    def __init__(self, cfg: dict[str, Any] | None, *, logger: Any | None = None) -> None:
        settings = cfg if isinstance(cfg, dict) else {}
        self.logger = logger
        self.enabled = bool(settings.get("enabled", True))
        self.timeout_seconds = float(settings.get("timeout_seconds", 5.0))
        self.dedupe_ttl_seconds = max(10.0, float(settings.get("dedupe_ttl_seconds", 1800.0)))
        self.dedupe_persist_ttl_seconds = max(60.0, float(settings.get("dedupe_persist_ttl_seconds", 86400.0)))
        self.dedupe_persist_max_entries = max(1000, int(settings.get("dedupe_persist_max_entries", 20000)))
        self.dedupe_persist_flush_seconds = max(5.0, float(settings.get("dedupe_persist_flush_seconds", 30.0)))
        self.dedupe_persist_file = resolve_path(
            str(settings.get("dedupe_persist_file", "data/processed/alert_dedupe.json")),
            prefer_existing=False,
        )
        self.cooldown_seconds = max(0.0, float(settings.get("cooldown_seconds", 0.0) or 0.0))
        self.cooldown_scope = str(settings.get("cooldown_scope", "target")).strip().lower() or "target"
        self.cooldown_bypass_severities = {
            str(x).strip().lower()
            for x in settings.get("cooldown_bypass_severities", ["critical"]) or []
            if str(x).strip()
        }
        self.cooldown_category_allowlist = {
            str(x).strip().lower()
            for x in settings.get("cooldown_category_allowlist", []) or []
            if str(x).strip()
        }
        self.max_embed_poc_chars = max(200, int(settings.get("max_embed_poc_chars", 1100)))
        self.discord_attach_threshold = max(800, int(settings.get("discord_attach_threshold", 1200)))
        self.discord_max_attachment_bytes = max(1024, int(settings.get("discord_max_attachment_bytes", 7_000_000)))
        self.report_url_base = str(settings.get("report_url_base", "")).strip()

        self.discord_research_webhook = self._resolve_webhook(
            explicit=str(settings.get("discord_research_webhook", "")).strip(),
            env_name=str(settings.get("discord_research_env", "HUNTEROPS_DISCORD_RESEARCH_WEBHOOK")).strip(),
            fallback_env=("HUNTEROPS_DISCORD_RECON_WEBHOOK", "DISCORD_WEBHOOK_URL"),
        )
        self.discord_critical_webhook = self._resolve_webhook(
            explicit=str(settings.get("discord_critical_webhook", "")).strip(),
            env_name=str(settings.get("discord_critical_env", "HUNTEROPS_DISCORD_CRITICAL_WEBHOOK")).strip(),
            fallback_env=("HUNTEROPS_DISCORD_FINDINGS_WEBHOOK", "HUNTEROPS_CRITICAL_WEBHOOK", "DISCORD_WEBHOOK_URL"),
        )
        self.slack_research_webhook = self._resolve_webhook(
            explicit=str(settings.get("slack_research_webhook", "")).strip(),
            env_name=str(settings.get("slack_research_env", "HUNTEROPS_SLACK_RESEARCH_WEBHOOK")).strip(),
        )
        self.slack_critical_webhook = self._resolve_webhook(
            explicit=str(settings.get("slack_critical_webhook", "")).strip(),
            env_name=str(settings.get("slack_critical_env", "HUNTEROPS_SLACK_CRITICAL_WEBHOOK")).strip(),
        )
        self._client: httpx.AsyncClient | None = None
        self._dedupe: dict[str, float] = {}
        self._dedupe_lock = asyncio.Lock()
        self._persisted: dict[str, float] = {}
        self._persist_dirty = False
        self._persist_last_flush = 0.0
        self._load_persisted()
        self._cooldown: dict[str, float] = {}
        self._cooldown_lock = asyncio.Lock()

    @property
    def available(self) -> bool:
        if not self.enabled:
            return False
        return bool(
            self.discord_research_webhook
            or self.discord_critical_webhook
            or self.slack_research_webhook
            or self.slack_critical_webhook
        )

    @staticmethod
    def _resolve_webhook(explicit: str, env_name: str, fallback_env: tuple[str, ...] = ()) -> str:
        if explicit:
            return explicit
        if env_name:
            value = read_secret(env_name)
            if value:
                return value
        for item in fallback_env:
            value = read_secret(item)
            if value:
                return value
        return ""

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self.timeout_seconds, follow_redirects=False)
        return self._client

    def _log(self, level: str, message: str) -> None:
        if self.logger is None:
            return
        try:
            getattr(self.logger, level)(message)
        except Exception:
            return

    @staticmethod
    def _extract_endpoint(finding: Finding) -> tuple[str, str]:
        evidence = finding.evidence if isinstance(finding.evidence, dict) else {}
        for key in ("request", "request_auth_a", "request_auth_b"):
            req = evidence.get(key)
            if not isinstance(req, dict):
                continue
            method = str(req.get("method", "GET")).upper()
            url = str(req.get("url", "")).strip()
            if not url:
                continue
            parsed = urlparse(url)
            path = parsed.path or "/"
            query = f"?{parsed.query}" if parsed.query else ""
            return method, f"{path}{query}"
        for key in ("url", "base_url", "modified_url", "endpoint", "path"):
            value = str(evidence.get(key, "")).strip()
            if not value:
                continue
            if value.startswith("http://") or value.startswith("https://"):
                parsed = urlparse(value)
                return "GET", f"{parsed.path or '/'}{f'?{parsed.query}' if parsed.query else ''}"
            return "GET", value if value.startswith("/") else f"/{value}"
        return "GET", "/"

    @staticmethod
    def _extract_confidence(finding: Finding) -> float:
        metadata = finding.metadata if isinstance(finding.metadata, dict) else {}
        evidence = finding.evidence if isinstance(finding.evidence, dict) else {}
        return _safe_float(metadata.get("confidence_score", metadata.get("confidence", evidence.get("confidence_score", 0))), 0.0)

    @staticmethod
    def _dedupe_endpoint_key(endpoint: str, category: str) -> str:
        raw_endpoint = str(endpoint or "").strip() or "/"
        cat = str(category or "").strip().lower()
        if cat in {"critical_public_data_exposure", "confirmed_idor_bac"}:
            parsed = urlparse(raw_endpoint)
            path = parsed.path or "/"
            return path if path.startswith("/") else f"/{path}"
        return raw_endpoint

    @staticmethod
    def _channel_partition(*, severity: str, impact_score: float) -> str:
        if str(severity).lower() in {"high", "critical"}:
            return "critical"
        if float(impact_score) > 70.0:
            return "critical"
        return "research"

    @staticmethod
    def _severity_label(impact_score: float, fallback: str) -> str:
        if impact_score > 90.0:
            return "CRITICAL"
        if impact_score > 70.0:
            return "HIGH"
        sev = str(fallback or "").strip().upper()
        if sev in {"LOW", "MEDIUM", "INFO"}:
            return sev
        return "MEDIUM"

    @staticmethod
    def _impact_color(impact_score: float) -> int:
        if impact_score > 90.0:
            return RED
        if impact_score > 70.0:
            return ORANGE
        if impact_score >= 40.0:
            return BLUE
        return GREY

    @staticmethod
    def _candidate_paths(finding: Finding) -> list[Path]:
        out: list[Path] = []
        evidence = finding.evidence if isinstance(finding.evidence, dict) else {}
        metadata = finding.metadata if isinstance(finding.metadata, dict) else {}
        for key in ("report_path", "poc_path", "evidence_ref"):
            raw = str(evidence.get(key, metadata.get(key, ""))).strip()
            if not raw:
                continue
            out.append(Path(raw))
        return out

    def _extract_poc_data(self, finding: Finding) -> tuple[str, Path | None]:
        for path in self._candidate_paths(finding):
            if path.exists() and path.is_file():
                if path.suffix.lower() == ".md":
                    text = _redact(path.read_text(encoding="utf-8", errors="ignore"))
                    return text, path
                if path.suffix.lower() == ".json":
                    raw = _redact(path.read_text(encoding="utf-8", errors="ignore"))
                    return raw, path
        evidence = finding.evidence if isinstance(finding.evidence, dict) else {}
        snippet = str(evidence.get("impact", evidence.get("evidence_snippet", ""))).strip()
        return _redact(snippet), None

    @staticmethod
    def _curl_from_request(request_data: dict[str, Any]) -> str:
        method = str(request_data.get("method", "GET")).upper()
        url = str(request_data.get("url", "")).strip()
        if not url:
            return ""
        command = f"curl -i -X {method} \"{url}\""
        headers = request_data.get("headers", {}) if isinstance(request_data.get("headers"), dict) else {}
        for name, value in headers.items():
            h_name = str(name)
            h_value = str(value)
            if h_name.lower() in {"authorization", "cookie"}:
                h_value = "<REDACTED>"
            command += f" -H \"{h_name}: {h_value}\""
        body = request_data.get("body")
        if isinstance(body, (dict, list)):
            command += f" --data '{json.dumps(body, ensure_ascii=True)}'"
        elif isinstance(body, str) and body.strip():
            command += f" --data '{body.strip()}'"
        return command

    def _build_curl(self, finding: Finding) -> str:
        evidence = finding.evidence if isinstance(finding.evidence, dict) else {}
        direct = str(evidence.get("curl_command", "")).strip()
        if direct:
            return _redact(direct)
        for key in ("request_auth_b", "request_auth_a", "request"):
            req = evidence.get(key)
            if isinstance(req, dict):
                built = self._curl_from_request(req)
                if built:
                    return _redact(built)
        for key in ("modified_url", "base_url", "url"):
            url = str(evidence.get(key, "")).strip()
            if url:
                return f"curl -i \"{url}\""
        return "curl -i \"https://<target>/path\""

    async def _is_duplicate(self, key: str) -> bool:
        now = time.time()
        async with self._dedupe_lock:
            for item, stamp in list(self._dedupe.items()):
                if now - float(stamp) > self.dedupe_ttl_seconds:
                    self._dedupe.pop(item, None)
            previous = self._dedupe.get(key)
            if previous is not None and (now - float(previous)) <= self.dedupe_ttl_seconds:
                return True
            self._dedupe[key] = now
            return False

    def _load_persisted(self) -> None:
        if not self.dedupe_persist_file or self.dedupe_persist_ttl_seconds <= 0:
            return
        path = Path(self.dedupe_persist_file)
        if not path.exists():
            return
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return
        if not isinstance(raw, dict):
            return
        now = time.time()
        for key, stamp in raw.items():
            try:
                ts = float(stamp)
            except Exception:
                continue
            if now - ts <= self.dedupe_persist_ttl_seconds:
                self._persisted[str(key)] = ts
        self._prune_persisted(now)

    def _prune_persisted(self, now: float) -> None:
        if not self._persisted:
            return
        ttl = self.dedupe_persist_ttl_seconds
        for key, stamp in list(self._persisted.items()):
            if now - float(stamp) > ttl:
                self._persisted.pop(key, None)
        if len(self._persisted) > self.dedupe_persist_max_entries:
            items = sorted(self._persisted.items(), key=lambda row: row[1])
            for key, _ in items[: max(0, len(items) - self.dedupe_persist_max_entries)]:
                self._persisted.pop(key, None)

    def _flush_persisted(self, now: float) -> None:
        if not self._persist_dirty:
            return
        if not self.dedupe_persist_file:
            return
        try:
            ensure_directory(Path(self.dedupe_persist_file).parent, mode=0o755)
            payload = json.dumps(self._persisted, ensure_ascii=True, indent=2)
            Path(self.dedupe_persist_file).write_text(payload + "\n", encoding="utf-8")
            self._persist_last_flush = now
            self._persist_dirty = False
        except Exception:
            return

    async def _is_duplicate_persistent(self, key: str) -> bool:
        if not self.dedupe_persist_file or self.dedupe_persist_ttl_seconds <= 0:
            return False

    async def _cooldown_allows(self, *, target: str, category: str, severity: str, program: str = "") -> bool:
        if self.cooldown_seconds <= 0:
            return True
        if str(severity).lower() in self.cooldown_bypass_severities:
            return True
        if self.cooldown_category_allowlist and str(category).lower() not in self.cooldown_category_allowlist:
            return True
        scope = self.cooldown_scope
        if scope == "target_category":
            key = f"{target}|{category}"
        elif scope == "target_severity":
            key = f"{target}|{severity}"
        elif scope == "program":
            key = f"program|{program or target}"
        else:
            key = str(target)
        now = time.time()
        async with self._cooldown_lock:
            last = self._cooldown.get(key)
            if last is not None and (now - float(last)) < self.cooldown_seconds:
                return False
            self._cooldown[key] = now
            return True
        now = time.time()
        async with self._dedupe_lock:
            self._prune_persisted(now)
            previous = self._persisted.get(key)
            if previous is not None and (now - float(previous)) <= self.dedupe_persist_ttl_seconds:
                return True
            self._persisted[key] = now
            self._persist_dirty = True
            if (now - self._persist_last_flush) >= self.dedupe_persist_flush_seconds:
                self._flush_persisted(now)
            return False

    async def _post_json(self, webhook: str, payload: dict[str, Any], *, route: str) -> None:
        if not webhook:
            return
        try:
            response = await self._get_client().post(webhook, json=payload)
            if int(response.status_code) >= 400:
                self._log("warning", f"alert_router_dispatch_failed route={route} status={response.status_code}")
        except Exception as err:
            self._log("warning", f"alert_router_dispatch_error route={route} err={type(err).__name__}")

    async def _post_discord_with_file(self, webhook: str, payload: dict[str, Any], file_path: Path, *, route: str) -> None:
        if not webhook:
            return
        try:
            raw = file_path.read_bytes()
            if len(raw) > self.discord_max_attachment_bytes:
                await self._post_json(webhook, payload, route=route)
                return
            multipart = {"payload_json": (None, json.dumps(payload, ensure_ascii=True), "application/json"), "file": (file_path.name, raw, "text/markdown")}
            response = await self._get_client().post(webhook, files=multipart)
            if int(response.status_code) >= 400:
                self._log("warning", f"alert_router_file_dispatch_failed route={route} status={response.status_code}")
        except Exception:
            await self._post_json(webhook, payload, route=route)

    async def send_finding(self, finding: Finding, *, run_id: str, source: str = "research_pipeline") -> bool:
        if not self.available:
            return False
        impact_profile = calculate_impact(finding)
        impact_score = _safe_float(impact_profile.get("impact_score", 0.0))
        severity = str(impact_profile.get("adjusted_severity", finding.severity)).lower()
        method, endpoint = self._extract_endpoint(finding)
        dedupe_endpoint = self._dedupe_endpoint_key(endpoint, finding.category)
        dedupe_key = f"{run_id}|{finding.target}|{dedupe_endpoint}|{finding.category}|{severity}"
        if await self._is_duplicate(dedupe_key):
            return False
        meta = finding.metadata if isinstance(finding.metadata, dict) else {}
        program = str(meta.get("program", meta.get("program_name", ""))).strip()
        if not await self._cooldown_allows(
            target=finding.target,
            category=str(finding.category or ""),
            severity=severity,
            program=program,
        ):
            return False
        persistent_key = f"{finding.target}|{dedupe_endpoint}|{finding.category}|{severity}|{finding.title}"
        if await self._is_duplicate_persistent(persistent_key):
            return False

        confidence = self._extract_confidence(finding)
        severity_label = self._severity_label(impact_score, severity)
        color = self._impact_color(impact_score)
        vuln_type = _pretty_category(finding.category)
        curl_cmd = self._build_curl(finding)
        poc_text, poc_path = self._extract_poc_data(finding)
        poc_inline = _truncate(poc_text, self.max_embed_poc_chars)
        title_prefix = "Potential Financial Logic Flaw" if bool(impact_profile.get("financial_context", False)) else "Potential Security Finding"
        title = f"[{severity_label}] {title_prefix} found on {finding.target}"
        report_path = ""
        evidence = finding.evidence if isinstance(finding.evidence, dict) else {}
        metadata = finding.metadata if isinstance(finding.metadata, dict) else {}
        for key in ("report_path", "poc_path"):
            candidate = str(evidence.get(key, metadata.get(key, ""))).strip()
            if candidate:
                report_path = candidate
                break

        embed = {
            "title": _truncate(title, 250),
            "description": (
                f"**Golden Evidence (curl)**\n```bash\n{_truncate(curl_cmd, 1500)}\n```\n"
                f"**PoC Snippet**\n```markdown\n{_truncate(poc_inline, 1200)}\n```"
            ),
            "color": int(color),
            "fields": [
                {"name": "Endpoint", "value": f"`{_truncate(f'{method} {endpoint}', 220)}`", "inline": False},
                {"name": "Vulnerability Type", "value": f"`{_truncate(vuln_type, 120)}`", "inline": True},
                {"name": "Confidence", "value": f"`{round(confidence, 2)}%`", "inline": True},
                {"name": "Calculated Impact", "value": f"`{round(impact_score, 2)}/100`", "inline": True},
                {"name": "Source", "value": f"`{_truncate(source, 80)}`", "inline": True},
                {"name": "Run ID", "value": f"`{_truncate(run_id, 80)}`", "inline": True},
            ],
        }
        if report_path:
            embed["fields"].append({"name": "PoC/Report Path", "value": f"`{_truncate(report_path, 240)}`", "inline": False})
        discord_payload = {
            "content": "@everyone" if impact_score > 90.0 else "",
            "embeds": [embed],
        }
        slack_payload = build_finding_blocks(
            finding=finding,
            run_id=run_id,
            endpoint_text=f"{method} {endpoint}",
            vuln_type=vuln_type,
            confidence_score=confidence,
            impact_score=impact_score,
            severity_label=severity_label,
            curl_command=curl_cmd,
            poc_snippet=poc_inline,
            report_path=report_path,
            report_url_base=self.report_url_base,
        )
        channel = self._channel_partition(severity=severity, impact_score=impact_score)

        tasks: list[asyncio.Task[Any]] = []
        if channel == "critical":
            if self.discord_critical_webhook:
                if poc_path and poc_path.suffix.lower() == ".md" and len(poc_text) > self.discord_attach_threshold:
                    tasks.append(asyncio.create_task(self._post_discord_with_file(self.discord_critical_webhook, discord_payload, poc_path, route="discord_critical")))
                else:
                    tasks.append(asyncio.create_task(self._post_json(self.discord_critical_webhook, discord_payload, route="discord_critical")))
            if self.slack_critical_webhook:
                tasks.append(asyncio.create_task(self._post_json(self.slack_critical_webhook, slack_payload, route="slack_critical")))
        else:
            if self.discord_research_webhook:
                tasks.append(asyncio.create_task(self._post_json(self.discord_research_webhook, discord_payload, route="discord_research")))
            if self.slack_research_webhook:
                tasks.append(asyncio.create_task(self._post_json(self.slack_research_webhook, slack_payload, route="slack_research")))
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        return bool(tasks)

    async def send_critical_log(self, *, message: str, run_id: str = "runtime") -> None:
        if not self.available:
            return
        dedupe_key = f"log|{run_id}|{message[:120]}"
        if await self._is_duplicate(dedupe_key):
            return
        text = _truncate(_redact(message), 3000)
        discord_payload = {
            "content": "@everyone",
            "embeds": [
                {
                    "title": "CRITICAL LOG SIGNAL",
                    "description": f"```text\n{text}\n```",
                    "color": RED,
                    "fields": [{"name": "Run ID", "value": f"`{_truncate(run_id, 80)}`", "inline": True}],
                }
            ],
        }
        slack_payload = build_critical_log_blocks(message=text, run_id=run_id)
        tasks: list[asyncio.Task[Any]] = []
        if self.discord_critical_webhook:
            tasks.append(asyncio.create_task(self._post_json(self.discord_critical_webhook, discord_payload, route="discord_critical_log")))
        if self.slack_critical_webhook:
            tasks.append(asyncio.create_task(self._post_json(self.slack_critical_webhook, slack_payload, route="slack_critical_log")))
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    def enqueue_critical_log(self, *, message: str, run_id: str = "runtime") -> None:
        if not self.available:
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        loop.create_task(self.send_critical_log(message=message, run_id=run_id))

    async def close(self) -> None:
        try:
            self._flush_persisted(time.time())
        except Exception:
            pass
        if self._client is not None:
            try:
                await self._client.aclose()
            except Exception:
                pass
            self._client = None
