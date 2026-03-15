from __future__ import annotations

import asyncio
import json
import os
import shutil
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
from urllib.request import Request, urlopen

from hunterops.http_client import request_http_async
from hunterops.runtime_paths import resolve_path, secure_secret_file
from hunterops.secrets import read_secret
from hunterops.types import Finding

HEADER_INJECTION_KEYS = ("User-Agent", "Referer", "X-Forwarded-For", "X-Api-Version", "From")
PARAM_HINTS = ("url", "link", "src", "redirect", "callback", "next", "return", "dest")
LINUX_BIN_DIR = Path("/usr/local/bin")


def _safe_host(value: str) -> str:
    raw = str(value or "").strip().lower()
    if not raw:
        return ""
    return raw if "/" not in raw else raw.split("/", 1)[0]


def _load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return doc if isinstance(doc, dict) else {}


class OOBEngine:
    """Out-of-band interaction engine for blind vulnerability confirmation."""

    def __init__(self, cfg: dict[str, Any], runtime: dict[str, Any], logger: Any | None = None) -> None:
        self.cfg = cfg or {}
        self.runtime = runtime
        self.logger = logger
        self.enabled = bool(self.cfg.get("enabled", False))
        self.provider = str(self.cfg.get("provider", "custom")).strip().lower()
        self.poll_interval_seconds = int(self.cfg.get("poll_interval_seconds", 30))
        self.max_injections_per_target = int(self.cfg.get("max_injections_per_target", 80))
        self.max_concurrent_per_target = int(self.cfg.get("max_concurrent_per_target", 3))
        self.state_file = resolve_path(str(self.cfg.get("state_file", "data/processed/oob_state.json")))
        self.events_file = resolve_path(str(self.cfg.get("events_file", "data/processed/oob_events.jsonl")))
        self.timeout = int(runtime.get("timeout_seconds", 25))

        domain_env = str(self.cfg.get("callback_domain_env", "HUNTEROPS_OOB_CALLBACK_DOMAIN"))
        poll_env = str(self.cfg.get("poll_url_env", "HUNTEROPS_OOB_POLL_URL"))
        token_env = str(self.cfg.get("api_token_env", "HUNTEROPS_OOB_API_TOKEN"))
        self.callback_domain = read_secret(domain_env) or str(self.cfg.get("callback_domain", "")).strip()
        self.poll_url = read_secret(poll_env) or str(self.cfg.get("poll_url", "")).strip()
        self.api_token = read_secret(token_env) or str(self.cfg.get("api_token", "")).strip()
        self.interactsh_client_bin = self._resolve_binary(str(self.cfg.get("interactsh_binary", "interactsh-client")))
        if self.enabled and not self.interactsh_client_bin and self.logger is not None:
            try:
                self.logger.warning("oob_engine_missing_binary tool=interactsh-client expected=/usr/local/bin/interactsh-client")
            except Exception:
                pass

        self._state = _load_json(self.state_file)
        self._registry = self._state.get("registry", {}) if isinstance(self._state.get("registry"), dict) else {}
        self._seen_events = set(self._state.get("seen_event_ids", [])) if isinstance(self._state.get("seen_event_ids"), list) else set()
        self._lock = asyncio.Lock()
        self._registry_lock = asyncio.Lock()

    @staticmethod
    def _resolve_binary(tool: str) -> str:
        name = str(tool or "").strip()
        if not name:
            return ""
        if "/" in name:
            candidate = Path(name)
            return str(candidate) if candidate.exists() else ""
        preferred = LINUX_BIN_DIR / name
        if preferred.exists() and os.access(preferred, os.X_OK):
            return str(preferred)
        found = shutil.which(name)
        return str(found) if found else ""

    @property
    def available(self) -> bool:
        if not self.enabled:
            return False
        return bool(self.callback_domain and self.poll_url)

    def _persist(self) -> None:
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "updated_at": int(time.time()),
            "registry": self._registry,
            "seen_event_ids": sorted(list(self._seen_events))[-5000:],
        }
        self.state_file.write_text(json.dumps(payload, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
        secure_secret_file(self.state_file)

    def new_correlation_id(self, run_id: str, target: str) -> str:
        token = f"{run_id[:10]}-{_safe_host(target).replace('.', '-')}-{uuid.uuid4().hex[:10]}"
        return token.lower()

    def callback_url(self, correlation_id: str) -> str:
        domain = self.callback_domain.strip().strip(".")
        return f"https://{correlation_id}.{domain}/cb"

    def _register(self, correlation_id: str, metadata: dict[str, Any]) -> None:
        self._registry[correlation_id] = metadata

    async def _send_probe(
        self,
        *,
        target: str,
        url: str,
        headers: dict[str, str],
        correlation_id: str,
        metadata: dict[str, Any],
        rate_limiter: Any | None = None,
        target_waiter: Any | None = None,
        semaphore: asyncio.Semaphore | None = None,
    ) -> bool:
        if semaphore is None:
            semaphore = asyncio.Semaphore(max(1, self.max_concurrent_per_target))
        async with semaphore:
            if rate_limiter is not None and hasattr(rate_limiter, "wait"):
                await rate_limiter.wait()
            if callable(target_waiter):
                await target_waiter(target)
            resp = await request_http_async("GET", url, headers=headers, timeout=self.timeout)
            async with self._registry_lock:
                self._register(correlation_id, metadata)
            return int(resp.get("status", 0)) >= 0

    @staticmethod
    def _param_candidates(parameter_map: list[dict[str, Any]]) -> list[tuple[str, str]]:
        out: list[tuple[str, str]] = []
        for item in parameter_map:
            if not isinstance(item, dict):
                continue
            endpoint = str(item.get("endpoint", "")).strip()
            param = str(item.get("parameter", "")).strip()
            if not endpoint or not param:
                continue
            if any(k in param.lower() for k in PARAM_HINTS):
                out.append((endpoint, param))
        return out

    async def inject_from_findings(
        self,
        target: str,
        run_id: str,
        findings: list[Finding],
        rate_limiter: Any | None = None,
        target_waiter: Any | None = None,
    ) -> int:
        if not self.available:
            return 0
        endpoint_set: set[str] = set()
        param_map: list[dict[str, Any]] = []
        for f in findings:
            if f.target != target:
                continue
            ev = f.evidence if isinstance(f.evidence, dict) else {}
            if f.category == "js_discovery":
                arr = ev.get("endpoints", [])
                if isinstance(arr, list):
                    for e in arr:
                        if isinstance(e, str):
                            endpoint_set.add(e if e.startswith("/") else (urlparse(e).path or "/"))
            if f.category == "parameter_intelligence":
                sample = ev.get("parameter_map_sample", [])
                if isinstance(sample, list):
                    param_map.extend([x for x in sample if isinstance(x, dict)])
        param_targets = self._param_candidates(param_map)
        endpoints = sorted(list(endpoint_set))[: self.max_injections_per_target]
        probes: list[dict[str, Any]] = []
        injected = 0
        for ep in endpoints:
            if injected >= self.max_injections_per_target:
                break
            cid = self.new_correlation_id(run_id=run_id, target=target)
            cb = self.callback_url(cid)
            headers = {
                "User-Agent": f"HunterOps-OOB/{cid}",
                "Referer": cb,
                "X-Forwarded-For": cb,
                "X-Api-Version": cb,
                "From": cb,
            }
            url = f"https://{target}{ep}"
            probes.append(
                {
                    "url": url,
                    "headers": headers,
                    "correlation_id": cid,
                    "metadata": {
                        "run_id": run_id,
                        "target": target,
                        "endpoint": ep,
                        "method": "GET",
                        "headers": headers,
                        "injection_source": "header",
                        "timestamp": int(time.time()),
                    },
                }
            )
            injected += 1
        for ep, prm in param_targets:
            if injected >= self.max_injections_per_target:
                break
            endpoint = ep if ep.startswith("/") else f"/{ep}"
            cid = self.new_correlation_id(run_id=run_id, target=target)
            cb = self.callback_url(cid)
            base = f"https://{target}{endpoint}"
            parsed = urlparse(base)
            q = parse_qsl(parsed.query, keep_blank_values=True)
            q = [x for x in q if x[0] != prm]
            q.append((prm, cb))
            url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(q), parsed.fragment))
            probes.append(
                {
                    "url": url,
                    "headers": {"User-Agent": f"HunterOps-OOB/{cid}"},
                    "correlation_id": cid,
                    "metadata": {
                        "run_id": run_id,
                        "target": target,
                        "endpoint": endpoint,
                        "method": "GET",
                        "parameter": prm,
                        "injected_url": url,
                        "injection_source": "parameter",
                        "timestamp": int(time.time()),
                    },
                }
            )
            injected += 1
        if not probes:
            return 0
        semaphore = asyncio.Semaphore(max(1, self.max_concurrent_per_target))
        tasks = [
            self._send_probe(
                target=target,
                url=str(probe["url"]),
                headers=probe["headers"] if isinstance(probe.get("headers"), dict) else {},
                correlation_id=str(probe["correlation_id"]),
                metadata=probe["metadata"] if isinstance(probe.get("metadata"), dict) else {},
                rate_limiter=rate_limiter,
                target_waiter=target_waiter,
                semaphore=semaphore,
            )
            for probe in probes
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for res in results:
            if isinstance(res, Exception) and self.logger is not None:
                try:
                    self.logger.warning(f"oob_probe_failed target={target} err={res}")
                except Exception:
                    pass
        self._persist()
        return sum(1 for res in results if res is True)

    def _fetch_events(self) -> list[dict[str, Any]]:
        if not self.available:
            return []
        headers = {"Accept": "application/json", "User-Agent": "HunterOps-OOB-Engine/1.0"}
        if self.api_token:
            headers["Authorization"] = f"Bearer {self.api_token}"
        req = Request(url=self.poll_url, headers=headers, method="GET")
        with urlopen(req, timeout=max(5, self.timeout)) as resp:
            raw = resp.read().decode("utf-8", errors="ignore")
        if not raw:
            return []
        doc = json.loads(raw)
        if isinstance(doc, dict):
            for key in ("events", "data", "interactions", "hits"):
                arr = doc.get(key)
                if isinstance(arr, list):
                    return [x for x in arr if isinstance(x, dict)]
        if isinstance(doc, list):
            return [x for x in doc if isinstance(x, dict)]
        return []

    @staticmethod
    def _event_id(evt: dict[str, Any]) -> str:
        for key in ("id", "event_id", "uid", "uuid"):
            value = evt.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        host = str(evt.get("host", evt.get("hostname", evt.get("domain", ""))))
        ts = str(evt.get("timestamp", evt.get("ts", "")))
        return f"{host}|{ts}"

    def _extract_correlation_id(self, event: dict[str, Any]) -> str:
        for key in ("correlation_id", "correlationId", "token", "interaction_id"):
            value = event.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip().lower()
        for key in ("host", "hostname", "domain"):
            value = str(event.get(key, "")).strip().lower()
            if value and self.callback_domain and value.endswith(self.callback_domain.lower()):
                prefix = value[: -len(self.callback_domain.lower())].strip(".")
                if prefix:
                    return prefix
        return ""

    async def poll_and_correlate(self) -> list[Finding]:
        if not self.available:
            return []
        async with self._lock:
            events = await asyncio.to_thread(self._fetch_events)
            findings: list[Finding] = []
            for event in events:
                eid = self._event_id(event)
                if eid in self._seen_events:
                    continue
                self._seen_events.add(eid)
                cid = self._extract_correlation_id(event)
                if not cid or cid not in self._registry:
                    continue
                probe = self._registry.get(cid, {})
                if not isinstance(probe, dict):
                    continue
                target = str(probe.get("target", ""))
                run_id = str(probe.get("run_id", ""))
                oob_evidence = {
                    "correlation_id": cid,
                    "provider": self.provider,
                    "interaction": event,
                    "probe": probe,
                    "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                }
                findings.append(
                    Finding(
                        plugin="oob_engine",
                        target=target,
                        category="oob_interaction_detected",
                        severity="critical",
                        title=f"OOB interaction detected for {probe.get('endpoint', '')}",
                        evidence=oob_evidence,
                        metadata={
                            "novelty": 96,
                            "confidence": 95,
                            "confidence_score": 95,
                            "impact": 94,
                            "run_id": run_id,
                            "discovery_source": "oob_engine",
                            "spawn_tasks": [
                                {
                                    "plugin": "report_synthesis",
                                    "target": target,
                                    "payload": {
                                        "run_id": run_id,
                                        "priority": 100,
                                        "trigger": "oob_hit",
                                        "_depth": int(probe.get("_depth", 0) or 0) + 1,
                                    },
                                }
                            ],
                        },
                    )
                )
                self.events_file.parent.mkdir(parents=True, exist_ok=True)
                with self.events_file.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(oob_evidence, ensure_ascii=True) + "\n")
                secure_secret_file(self.events_file)
            self._persist()
            return findings
