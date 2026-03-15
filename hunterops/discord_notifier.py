from __future__ import annotations

import asyncio
import hashlib
import json
import re
import time
from datetime import UTC, datetime
from pathlib import Path
from threading import Lock
from typing import Any
from urllib.parse import urlparse

import httpx

from hunterops.runtime_paths import ensure_directory, resolve_path
from hunterops.secrets import read_secret
TOKEN_RE = re.compile(r"""(?i)\b(bearer\s+)([a-z0-9\-._~+/]+=*)""")
SECRET_KV_RE = re.compile(r"""(?i)\b(token|secret|api[_-]?key|authorization)\s*[:=]\s*([^\s,;]+)""")
URL_SECRET_RE = re.compile(r"""(?i)(token|key|secret|auth)=([^&\s]+)""")

BLUE = 3447003
ORANGE = 16753920
RED = 15158332


def _mask(value: str) -> str:
    raw = str(value or "")
    if len(raw) <= 8:
        return "*" * len(raw)
    return f"{raw[:4]}...{raw[-4:]}"


def _redact_text(value: str) -> str:
    text = str(value or "")
    if not text:
        return ""
    text = TOKEN_RE.sub(lambda m: f"{m.group(1)}{_mask(m.group(2))}", text)
    text = SECRET_KV_RE.sub(lambda m: f"{m.group(1)}={_mask(m.group(2))}", text)
    text = URL_SECRET_RE.sub(lambda m: f"{m.group(1)}={_mask(m.group(2))}", text)
    return text


def _truncate(value: str, size: int = 700) -> str:
    text = str(value or "")
    if len(text) <= size:
        return text
    return f"{text[:size]}...[+{len(text) - size} chars]"


class DiscordDispatch:
    """Async multi-channel Discord routing with non-blocking delivery."""

    def __init__(self, cfg: dict[str, Any] | None, logger: Any) -> None:
        settings = cfg if isinstance(cfg, dict) else {}
        self.logger = logger
        self.enabled = bool(settings.get("enabled", True))
        self.bot_name = str(settings.get("bot_name", "Pinguinho")).strip() or "Pinguinho"
        self.recon_webhook = str(settings.get("recon_webhook_url", "")).strip()
        self.findings_webhook = str(settings.get("findings_webhook_url", "")).strip()
        recon_env = str(settings.get("recon_webhook_env", "HUNTEROPS_DISCORD_RECON_WEBHOOK")).strip()
        findings_env = str(settings.get("findings_webhook_env", "HUNTEROPS_DISCORD_FINDINGS_WEBHOOK")).strip()
        if recon_env and not self.recon_webhook:
            self.recon_webhook = read_secret(recon_env)
        if findings_env and not self.findings_webhook:
            self.findings_webhook = read_secret(findings_env)
        self.timeout_seconds = float(settings.get("timeout_seconds", 4.0))
        self.max_concurrent = max(1, int(settings.get("max_concurrent", 4)))
        self.send_startup_check = bool(settings.get("send_startup_check", True))
        self.recon_dedupe_ttl_seconds = max(30.0, float(settings.get("recon_dedupe_ttl_seconds", 1800.0)))
        self.findings_dedupe_persist_ttl_seconds = max(60.0, float(settings.get("findings_dedupe_persist_ttl_seconds", 86400.0)))
        self.findings_dedupe_persist_max_entries = max(1000, int(settings.get("findings_dedupe_persist_max_entries", 20000)))
        self.findings_dedupe_persist_flush_seconds = max(5.0, float(settings.get("findings_dedupe_persist_flush_seconds", 30.0)))
        self.findings_dedupe_persist_file = resolve_path(
            str(settings.get("findings_dedupe_persist_file", "data/processed/discord_finding_dedupe.json")),
            prefer_existing=False,
        )
        self._sem = asyncio.Semaphore(self.max_concurrent)
        self._client: httpx.AsyncClient | None = None
        self._pending: set[asyncio.Task[Any]] = set()
        self._recon_dedupe: dict[str, float] = {}
        self._findings_persisted: dict[str, float] = {}
        self._findings_dirty = False
        self._findings_last_flush = 0.0
        self._findings_lock = Lock()
        self._load_findings_persisted()

    @property
    def available(self) -> bool:
        return self.enabled and bool(self.recon_webhook or self.findings_webhook)

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self.timeout_seconds, follow_redirects=False)
        return self._client

    async def _post(self, webhook: str, payload: dict[str, Any], route: str) -> None:
        if not webhook:
            return
        try:
            async with self._sem:
                response = await self._get_client().post(webhook, json=payload)
            if response.status_code == 429:
                retry_after = 0.0
                try:
                    body = response.json()
                    retry_after = float(body.get("retry_after", 0) or 0)
                except Exception:
                    retry_after = 0.0
                self.logger.warning(f"discord_rate_limited route={route} retry_after={retry_after}")
                return
            if response.status_code >= 400:
                self.logger.warning(f"discord_dispatch_failed route={route} status={response.status_code}")
        except Exception as err:
            self.logger.warning(f"discord_dispatch_error route={route} err={err}")

    def _schedule(self, coro: Any) -> None:
        if not self.available:
            return
        task = asyncio.create_task(coro)
        self._pending.add(task)
        task.add_done_callback(lambda t: self._pending.discard(t))

    @staticmethod
    def _normalize_endpoint(endpoint: str) -> str:
        raw = str(endpoint or "").strip()
        if not raw:
            return "/"
        if raw.startswith("http://") or raw.startswith("https://"):
            parsed = urlparse(raw)
            return parsed.path or "/"
        parsed = urlparse(raw)
        path = parsed.path or raw
        return path if path.startswith("/") else f"/{path}"

    def _load_findings_persisted(self) -> None:
        if not self.findings_dedupe_persist_file or self.findings_dedupe_persist_ttl_seconds <= 0:
            return
        path = Path(self.findings_dedupe_persist_file)
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
            if now - ts <= self.findings_dedupe_persist_ttl_seconds:
                self._findings_persisted[str(key)] = ts
        self._prune_findings_persisted(now)

    def _prune_findings_persisted(self, now: float) -> None:
        if not self._findings_persisted:
            return
        ttl = self.findings_dedupe_persist_ttl_seconds
        for key, stamp in list(self._findings_persisted.items()):
            if now - float(stamp) > ttl:
                self._findings_persisted.pop(key, None)
        if len(self._findings_persisted) > self.findings_dedupe_persist_max_entries:
            items = sorted(self._findings_persisted.items(), key=lambda row: row[1])
            for key, _ in items[: max(0, len(items) - self.findings_dedupe_persist_max_entries)]:
                self._findings_persisted.pop(key, None)

    def _flush_findings_persisted(self, now: float) -> None:
        if not self._findings_dirty:
            return
        if not self.findings_dedupe_persist_file:
            return
        try:
            ensure_directory(Path(self.findings_dedupe_persist_file).parent, mode=0o755)
            payload = json.dumps(self._findings_persisted, ensure_ascii=True, indent=2)
            Path(self.findings_dedupe_persist_file).write_text(payload + "\n", encoding="utf-8")
            self._findings_last_flush = now
            self._findings_dirty = False
        except Exception:
            return

    def _is_duplicate_findings_persistent(self, key: str) -> bool:
        if not self.findings_dedupe_persist_file or self.findings_dedupe_persist_ttl_seconds <= 0:
            return False
        now = time.time()
        with self._findings_lock:
            self._prune_findings_persisted(now)
            previous = self._findings_persisted.get(key)
            if previous is not None and (now - float(previous)) <= self.findings_dedupe_persist_ttl_seconds:
                return True
            self._findings_persisted[key] = now
            self._findings_dirty = True
            if (now - self._findings_last_flush) >= self.findings_dedupe_persist_flush_seconds:
                self._flush_findings_persisted(now)
            return False

    @staticmethod
    def _embed(title: str, description: str, color: int, fields: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        embed: dict[str, Any] = {
            "title": _truncate(_redact_text(title), 240),
            "description": _truncate(_redact_text(description), 3500),
            "color": int(color),
            "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        }
        if fields:
            embed["fields"] = fields[:12]
        return embed

    def route_recon_delta(
        self,
        *,
        target: str,
        delta_score: float,
        new_endpoints: list[str],
        changed_js: list[str],
        new_parameters: list[str],
    ) -> None:
        if not self.recon_webhook:
            return
        signature_payload = {
            "target": str(target or "").strip().lower(),
            "new_endpoints": sorted([str(x) for x in new_endpoints if isinstance(x, str)]),
            "changed_js": sorted([str(x) for x in changed_js if isinstance(x, str)]),
            "new_parameters": sorted([str(x) for x in new_parameters if isinstance(x, str)]),
        }
        signature = hashlib.sha1(json.dumps(signature_payload, ensure_ascii=True, sort_keys=True).encode("utf-8")).hexdigest()
        now = time.monotonic()
        for key, stamp in list(self._recon_dedupe.items()):
            if now - float(stamp) > self.recon_dedupe_ttl_seconds:
                self._recon_dedupe.pop(key, None)
        prev = self._recon_dedupe.get(signature)
        if prev is not None and (now - float(prev)) < self.recon_dedupe_ttl_seconds:
            return
        self._recon_dedupe[signature] = now

        description = f"Surface Expansion Detected on `{target}`"
        fields = [
            {"name": "Delta Score", "value": f"`{round(float(delta_score), 2)}`", "inline": True},
            {"name": "New Endpoints", "value": f"`{len(new_endpoints)}`", "inline": True},
            {"name": "Changed JS", "value": f"`{len(changed_js)}`", "inline": True},
            {"name": "New Parameters", "value": f"`{len(new_parameters)}`", "inline": True},
        ]
        if new_endpoints:
            sample = "\n".join([f"- `{_truncate(ep, 90)}`" for ep in new_endpoints[:8]])
            fields.append({"name": "Route Sample", "value": _truncate(sample, 900), "inline": False})
        if changed_js:
            sample = "\n".join([f"- `{_truncate(js, 90)}`" for js in changed_js[:6]])
            fields.append({"name": "JS Delta Sample", "value": _truncate(sample, 700), "inline": False})
        if new_parameters:
            sample = "\n".join([f"- `{_truncate(p, 90)}`" for p in new_parameters[:8]])
            fields.append({"name": "Parameter Delta Sample", "value": _truncate(sample, 700), "inline": False})
        payload = {"username": self.bot_name, "embeds": [self._embed("Surface Expansion Detected", description, BLUE, fields)]}
        self._schedule(self._post(self.recon_webhook, payload, "recon"))

    def route_finding_confirmed(
        self,
        *,
        target: str,
        title: str,
        impact: str,
        confidence: float,
        endpoint: str,
        evidence_snippet: str,
        report_path: str,
        severity_level: str = "",
        estimated_payout: str = "",
        dedupe_key: str = "",
    ) -> None:
        if not self.findings_webhook:
            return
        key = str(dedupe_key or "").strip()
        if not key:
            norm_endpoint = self._normalize_endpoint(endpoint)
            key = f"{target}|{norm_endpoint}|{title}|{severity_level}"
        if self._is_duplicate_findings_persistent(key):
            return
        color = RED if confidence >= 80 else ORANGE
        fields = [
            {"name": "Target", "value": f"`{_truncate(target, 80)}`", "inline": True},
            {"name": "Confidence (C)", "value": f"`{round(float(confidence), 2)}`", "inline": True},
            {"name": "Severity", "value": f"`{_truncate(str(severity_level or 'unspecified'), 40)}`", "inline": True},
            {"name": "Endpoint", "value": f"`{_truncate(endpoint, 150)}`", "inline": False},
            {"name": "Impact", "value": _truncate(_redact_text(impact), 700), "inline": False},
            {"name": "Evidence Snippet", "value": _truncate(_redact_text(evidence_snippet), 900), "inline": False},
            {"name": "Estimated Payout", "value": f"`{_truncate(_redact_text(estimated_payout or 'N/A'), 80)}`", "inline": True},
            {"name": "Report", "value": f"`{_truncate(_redact_text(report_path or 'pending_generation'), 250)}`", "inline": False},
        ]
        payload = {
            "username": self.bot_name,
            "embeds": [self._embed("Vulnerability Confirmed", _truncate(_redact_text(title), 350), color, fields)],
        }
        self._schedule(self._post(self.findings_webhook, payload, "findings"))

    async def send_system_online(self, *, run_id: str, targets_count: int, plugins_count: int) -> None:
        if not self.send_startup_check or not self.available:
            return
        fields = [
            {"name": "Run ID", "value": f"`{_truncate(run_id, 80)}`", "inline": True},
            {"name": "Targets", "value": f"`{targets_count}`", "inline": True},
            {"name": "Plugins", "value": f"`{plugins_count}`", "inline": True},
            {"name": "Status", "value": "`System Online: Research Agent Active`", "inline": False},
        ]
        payload = {"username": self.bot_name, "embeds": [self._embed("System Online", "Research Agent Active", BLUE, fields)]}
        tasks: list[Any] = []
        if self.recon_webhook:
            tasks.append(self._post(self.recon_webhook, payload, "recon_startup"))
        if self.findings_webhook:
            tasks.append(self._post(self.findings_webhook, payload, "findings_startup"))
        if tasks:
            try:
                await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), timeout=self.timeout_seconds + 1.5)
            except Exception:
                # Never block pipeline startup on notifier failures/timeouts.
                self.logger.warning("discord_startup_check_timeout")

    async def close(self) -> None:
        if self._pending:
            try:
                await asyncio.wait_for(asyncio.gather(*list(self._pending), return_exceptions=True), timeout=2.0)
            except Exception:
                pass
        self._pending.clear()
        try:
            self._flush_findings_persisted(time.time())
        except Exception:
            pass
        if self._client is not None:
            try:
                await self._client.aclose()
            except Exception:
                pass
            self._client = None
