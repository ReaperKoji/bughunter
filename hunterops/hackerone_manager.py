from __future__ import annotations

import base64
import json
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from hunterops.runtime_paths import resolve_path, secure_secret_file
from hunterops.secrets import read_secret
from hunterops.types import Task


def _to_host(value: str) -> str:
    raw = str(value or "").strip().lower()
    if not raw:
        return ""
    if raw.startswith("http://") or raw.startswith("https://"):
        return (urlparse(raw).hostname or "").strip().lower()
    if "/" in raw:
        try:
            return (urlparse(f"https://{raw}").hostname or "").strip().lower()
        except Exception:
            return raw.split("/", 1)[0].strip().lower()
    return raw


def _load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return doc if isinstance(doc, dict) else {}


class HackerOneManager:
    """HackerOne scope intelligence and policy gate for authorized target execution."""

    def __init__(self, cfg: dict[str, Any], logger: Any | None = None) -> None:
        self.cfg = cfg or {}
        self.logger = logger
        self.enabled = bool(self.cfg.get("enabled", False))
        self.strict_scope = bool(self.cfg.get("strict_scope_enforcement", True))
        self.base_url = str(self.cfg.get("base_url", "https://api.hackerone.com/v1")).rstrip("/")
        self.scope_cache_file = resolve_path(str(self.cfg.get("scope_cache_file", "data/processed/h1_scope_cache.json")))
        self.poll_interval_seconds = int(self.cfg.get("poll_interval_seconds", 900))
        self.structured_scope_only = bool(self.cfg.get("structured_scope_only", True))
        self.default_target_rps = float(self.cfg.get("default_target_rps", 1.0))

        user_env = str(self.cfg.get("api_user_env", "HACKERONE_API_USER"))
        token_env = str(self.cfg.get("api_token_env", "HACKERONE_API_TOKEN"))
        self.api_user = read_secret(user_env)
        self.api_token = read_secret(token_env)
        self.program_handles = [str(x).strip() for x in self.cfg.get("program_handles", []) if str(x).strip()]
        if not self.program_handles:
            single = read_secret("HACKERONE_PROGRAM_HANDLE")
            if single:
                self.program_handles = [single]

    @property
    def available(self) -> bool:
        return bool(self.enabled and self.api_user and self.api_token and self.program_handles)

    def _log(self, level: str, message: str) -> None:
        if not self.logger:
            return
        try:
            getattr(self.logger, level)(message)
        except Exception:
            return

    def _auth_headers(self) -> dict[str, str]:
        auth = base64.b64encode(f"{self.api_user}:{self.api_token}".encode("utf-8")).decode("utf-8")
        return {
            "Authorization": f"Basic {auth}",
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "HunterOps-H1-Manager/1.0",
        }

    def _get_json(self, path: str, timeout: int = 20) -> dict[str, Any]:
        url = path if path.startswith("http://") or path.startswith("https://") else f"{self.base_url}/{path.lstrip('/')}"
        req = Request(url=url, headers=self._auth_headers(), method="GET")
        with urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="ignore")
        if not raw:
            return {}
        doc = json.loads(raw)
        return doc if isinstance(doc, dict) else {}

    @staticmethod
    def _extract_targets(program_doc: dict[str, Any], structured_only: bool = True) -> tuple[set[str], dict[str, float]]:
        hosts: set[str] = set()
        rate_limits: dict[str, float] = {}
        data = program_doc.get("data", {})
        rel = data.get("relationships", {}) if isinstance(data, dict) else {}
        scopes = rel.get("structured_scopes", {}).get("data", [])
        included = program_doc.get("included", [])
        scope_ids = {str(x.get("id", "")) for x in scopes if isinstance(x, dict)}
        for item in included:
            if not isinstance(item, dict):
                continue
            if str(item.get("type", "")) != "structured-scope":
                continue
            sid = str(item.get("id", ""))
            if scope_ids and sid not in scope_ids:
                continue
            attrs = item.get("attributes", {}) if isinstance(item.get("attributes"), dict) else {}
            if structured_only:
                eligible = bool(attrs.get("eligible_for_submission", True))
                archived = bool(attrs.get("archived_at"))
                if not eligible or archived:
                    continue
            aid = _to_host(str(attrs.get("asset_identifier", "")))
            if aid:
                hosts.add(aid)
                if attrs.get("max_requests_per_second") is not None:
                    try:
                        rate_limits[aid] = float(attrs.get("max_requests_per_second"))
                    except Exception:
                        pass
        return hosts, rate_limits

    def sync_scopes(self, timeout: int = 20) -> dict[str, Any]:
        if not self.available:
            return {"enabled": False, "reason": "hackerone manager unavailable"}
        prev = _load_json(self.scope_cache_file)
        prev_hosts = {str(x).strip().lower() for x in prev.get("hosts", []) if str(x).strip()}
        new_hosts: set[str] = set()
        new_rate_limits: dict[str, float] = {}
        programs_summary: list[dict[str, Any]] = []
        for handle in self.program_handles:
            try:
                doc = self._get_json(f"hackers/programs/{handle}", timeout=timeout)
            except Exception as err:
                self._log("warning", f"h1_scope_fetch_failed handle={handle} err={err}")
                continue
            hosts, rlimits = self._extract_targets(doc, structured_only=self.structured_scope_only)
            new_hosts |= hosts
            new_rate_limits.update(rlimits)
            programs_summary.append({"handle": handle, "hosts": sorted(list(hosts))[:500]})

        new_hosts = {h for h in new_hosts if h}
        added = sorted(list(new_hosts - prev_hosts))
        removed = sorted(list(prev_hosts - new_hosts))
        payload = {
            "updated_at": int(time.time()),
            "handles": self.program_handles,
            "hosts": sorted(list(new_hosts)),
            "added_hosts": added,
            "removed_hosts": removed,
            "rate_limits": new_rate_limits,
            "programs": programs_summary,
        }
        self.scope_cache_file.parent.mkdir(parents=True, exist_ok=True)
        self.scope_cache_file.write_text(json.dumps(payload, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
        secure_secret_file(self.scope_cache_file)
        return {
            "enabled": True,
            "hosts": sorted(list(new_hosts)),
            "added_hosts": added,
            "removed_hosts": removed,
            "rate_limits": new_rate_limits,
            "programs": programs_summary,
        }

    def current_scope_hosts(self) -> set[str]:
        doc = _load_json(self.scope_cache_file)
        return {str(x).strip().lower() for x in doc.get("hosts", []) if str(x).strip()}

    def target_rps(self, target: str) -> float:
        doc = _load_json(self.scope_cache_file)
        rlimits = doc.get("rate_limits", {}) if isinstance(doc.get("rate_limits"), dict) else {}
        host = _to_host(target)
        if host in rlimits:
            try:
                return float(rlimits[host])
            except Exception:
                pass
        return self.default_target_rps

    def in_scope(self, target: str) -> bool:
        if not self.enabled:
            return True
        hosts = self.current_scope_hosts()
        host = _to_host(target)
        if not hosts:
            return not self.strict_scope
        return host in hosts

    def filter_targets(self, targets: list[str]) -> list[str]:
        if not self.enabled:
            return targets
        return [t for t in targets if self.in_scope(t)]

    def build_priority_tasks_for_updates(self, run_id: str) -> list[Task]:
        if not self.enabled:
            return []
        doc = _load_json(self.scope_cache_file)
        added = [str(x).strip() for x in doc.get("added_hosts", []) if str(x).strip()]
        tasks: list[Task] = []
        for target in added:
            tasks.append(
                Task(
                    plugin="deep_js_intelligence",
                    target=target,
                    payload={
                        "run_id": run_id,
                        "priority": 100,
                        "priority_score": 100,
                        "trigger": "hackerone_scope_update",
                        "_depth": 0,
                    },
                )
            )
        return tasks

    def fetch_known_report_endpoints(self, timeout: int = 20, limit: int = 200) -> set[str]:
        if not self.available:
            return set()
        endpoints: set[str] = set()
        for handle in self.program_handles:
            try:
                doc = self._get_json(
                    f"reports?filter[program]={handle}&filter[state]=triaged&page[size]={max(10, min(limit, 100))}",
                    timeout=timeout,
                )
            except Exception as err:
                self._log("warning", f"h1_reports_fetch_failed handle={handle} err={err}")
                continue
            data = doc.get("data", [])
            if not isinstance(data, list):
                continue
            for item in data:
                if not isinstance(item, dict):
                    continue
                attrs = item.get("attributes", {}) if isinstance(item.get("attributes"), dict) else {}
                for field in ("vulnerability_information", "title"):
                    raw = str(attrs.get(field, ""))
                    if not raw:
                        continue
                    for token in raw.replace("\n", " ").split():
                        if token.startswith("/"):
                            endpoints.add(token.split("?", 1)[0].strip().lower())
            if len(endpoints) >= limit:
                break
        return endpoints

    def suppress_probable_duplicates(self, rows: list[dict[str, Any]], known_endpoints: set[str]) -> list[dict[str, Any]]:
        if not known_endpoints:
            return rows
        out: list[dict[str, Any]] = []
        for row in rows:
            ev = row.get("evidence", {}) if isinstance(row.get("evidence"), dict) else {}
            endpoint = ""
            for key in ("endpoint", "base_url", "modified_url", "url"):
                raw = ev.get(key)
                if isinstance(raw, str) and raw:
                    endpoint = _to_host(raw) if not raw.startswith("/") else raw.split("?", 1)[0].lower()
                    if raw.startswith("http://") or raw.startswith("https://"):
                        endpoint = (urlparse(raw).path or "/").split("?", 1)[0].lower()
                    break
            meta = row.get("metadata", {}) if isinstance(row.get("metadata"), dict) else {}
            confidence = float(meta.get("confidence_score", meta.get("confidence", 0)) or 0)
            if endpoint and endpoint in known_endpoints and confidence < 90:
                meta["duplicate_risk"] = "high"
                row["metadata"] = meta
                continue
            if endpoint and endpoint in known_endpoints:
                meta["duplicate_risk"] = "medium"
                row["metadata"] = meta
            out.append(row)
        return out

    def watch_scope_updates(self, timeout: int = 20) -> dict[str, Any]:
        """Pulls latest scope and returns added/removed hosts to trigger priority scans."""
        result = self.sync_scopes(timeout=timeout)
        added = result.get("added_hosts", []) if isinstance(result.get("added_hosts"), list) else []
        removed = result.get("removed_hosts", []) if isinstance(result.get("removed_hosts"), list) else []
        return {"enabled": bool(result.get("enabled", False)), "added_hosts": added, "removed_hosts": removed}
