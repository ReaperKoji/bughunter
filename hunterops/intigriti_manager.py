from __future__ import annotations

import json
import time
import fnmatch
from pathlib import Path
from typing import Any
from urllib.parse import urlencode, urlparse
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


def _parse_scope_marker(endpoint: str) -> tuple[str, str]:
    raw = str(endpoint or "").strip().lower()
    if not raw:
        return "", ""
    if raw.startswith("http://") or raw.startswith("https://"):
        host = (urlparse(raw).hostname or "").strip().lower()
    else:
        host = raw
        if "/" in host:
            host = host.split("/", 1)[0].strip().lower()
    host = host.strip()
    if not host:
        return "", ""
    if host.startswith("*."):
        suffix = host[2:].strip(".")
        return "", suffix
    host = host.strip(".")
    if "*" in host:
        return "", ""
    return host, ""


class IntigritiManager:
    """Intigriti scope intelligence and policy gate for authorized target execution."""

    def __init__(self, cfg: dict[str, Any], logger: Any | None = None) -> None:
        self.cfg = cfg or {}
        self.logger = logger
        self.enabled = bool(self.cfg.get("enabled", False))
        self.strict_scope = bool(self.cfg.get("strict_scope_enforcement", True))
        self.base_url = str(self.cfg.get("base_url", "https://api.intigriti.com/external/researcher")).rstrip("/")
        self.scope_cache_file = resolve_path(
            str(self.cfg.get("scope_cache_file", "data/processed/intigriti_scope_cache.json"))
        )
        self.poll_interval_seconds = int(self.cfg.get("poll_interval_seconds", 900))
        self.default_target_rps = float(self.cfg.get("default_target_rps", 1.0))
        self.program_handles = [str(x).strip().lower() for x in self.cfg.get("program_handles", []) if str(x).strip()]
        self.include_hosts = [str(x).strip().lower() for x in self.cfg.get("include_hosts", []) if str(x).strip()]
        self.exclude_hosts = [str(x).strip().lower() for x in self.cfg.get("exclude_hosts", []) if str(x).strip()]

        token_env = str(self.cfg.get("api_token_env", "INTIGRITI_API_TOKEN")).strip() or "INTIGRITI_API_TOKEN"
        self.api_token = read_secret(token_env)

    @property
    def available(self) -> bool:
        return bool(self.enabled and self.api_token)

    def _log(self, level: str, message: str) -> None:
        if not self.logger:
            return
        try:
            getattr(self.logger, level)(message)
        except Exception:
            return

    def _auth_headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.api_token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "HunterOps-Intigriti-Manager/1.0",
        }

    def _get_json(self, path: str, timeout: int = 20, params: dict[str, Any] | None = None) -> dict[str, Any]:
        if path.startswith("http://") or path.startswith("https://"):
            url = path
        else:
            url = f"{self.base_url}/{path.lstrip('/')}"
        if params:
            query = urlencode({k: v for k, v in params.items() if v is not None})
            if query:
                joiner = "&" if "?" in url else "?"
                url = f"{url}{joiner}{query}"
        req = Request(url=url, headers=self._auth_headers(), method="GET")
        with urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="ignore")
        if not raw:
            return {}
        doc = json.loads(raw)
        return doc if isinstance(doc, dict) else {}

    def _fetch_programs(self, timeout: int = 20) -> list[dict[str, Any]]:
        programs: list[dict[str, Any]] = []
        offset = 0
        limit = 200
        while True:
            page = self._get_json("v1/programs", timeout=timeout, params={"limit": limit, "offset": offset})
            records = page.get("records", [])
            if not isinstance(records, list) or not records:
                break
            for item in records:
                if isinstance(item, dict):
                    programs.append(item)
            if len(records) < limit:
                break
            offset += limit
            if offset > 4000:
                break
        return programs

    def _is_host_allowed(self, host: str) -> bool:
        candidate = str(host or "").strip().lower()
        if not candidate:
            return False
        if self.include_hosts:
            if not any(fnmatch.fnmatch(candidate, pattern) for pattern in self.include_hosts):
                return False
        if self.exclude_hosts:
            if any(fnmatch.fnmatch(candidate, pattern) for pattern in self.exclude_hosts):
                return False
        return True

    def _resolve_domains_content(self, program: dict[str, Any], timeout: int = 20) -> list[dict[str, Any]]:
        program_id = str(program.get("id", "")).strip()
        if not program_id:
            return []
        try:
            detail = self._get_json(f"v1/programs/{program_id}", timeout=timeout)
        except Exception as err:
            self._log("warning", f"intigriti_program_detail_fetch_failed id={program_id} err={err}")
            return []

        domains = detail.get("domains", {}) if isinstance(detail.get("domains"), dict) else {}
        content = domains.get("content", [])
        if isinstance(content, list) and content:
            return [x for x in content if isinstance(x, dict)]

        version_id = str(domains.get("id", "")).strip()
        if not version_id:
            return []
        try:
            version_doc = self._get_json(f"v1/programs/{program_id}/domains/{version_id}", timeout=timeout)
        except Exception as err:
            self._log("warning", f"intigriti_program_domains_fetch_failed id={program_id} version={version_id} err={err}")
            return []
        version_domains = version_doc.get("domains", {}) if isinstance(version_doc.get("domains"), dict) else {}
        version_content = version_domains.get("content", [])
        if not isinstance(version_content, list):
            return []
        return [x for x in version_content if isinstance(x, dict)]

    def sync_scopes(self, timeout: int = 20) -> dict[str, Any]:
        if not self.available:
            return {"enabled": False, "reason": "intigriti manager unavailable"}

        prev = _load_json(self.scope_cache_file)
        prev_hosts = {str(x).strip().lower() for x in prev.get("hosts", []) if str(x).strip()}
        prev_wildcards = {
            str(x).strip().lower().lstrip(".")
            for x in prev.get("wildcard_suffixes", [])
            if str(x).strip()
        }

        try:
            programs = self._fetch_programs(timeout=timeout)
        except Exception as err:
            return {"enabled": False, "reason": f"intigriti_programs_fetch_failed err={err}"}

        selected_programs: list[dict[str, Any]] = []
        for p in programs:
            handle = str(p.get("handle", "")).strip().lower()
            pid = str(p.get("id", "")).strip().lower()
            if self.program_handles and handle not in self.program_handles and pid not in self.program_handles:
                continue
            selected_programs.append(p)

        hosts: set[str] = set()
        wildcard_suffixes: set[str] = set()
        programs_summary: list[dict[str, Any]] = []

        for program in selected_programs:
            pid = str(program.get("id", "")).strip()
            handle = str(program.get("handle", "")).strip()
            content = self._resolve_domains_content(program, timeout=timeout)
            program_hosts: set[str] = set()
            program_wildcards: set[str] = set()
            for domain in content:
                endpoint = str(domain.get("endpoint", "")).strip()
                host, wildcard_suffix = _parse_scope_marker(endpoint)
                if host:
                    if not self._is_host_allowed(host):
                        continue
                    hosts.add(host)
                    program_hosts.add(host)
                elif wildcard_suffix:
                    wildcard_probe = f"x.{wildcard_suffix}".lower()
                    if not self._is_host_allowed(wildcard_probe):
                        continue
                    wildcard_suffixes.add(wildcard_suffix)
                    program_wildcards.add(wildcard_suffix)
                else:
                    fallback_host = _to_host(endpoint)
                    if fallback_host and "*" not in fallback_host and self._is_host_allowed(fallback_host):
                        hosts.add(fallback_host)
                        program_hosts.add(fallback_host)
            programs_summary.append(
                {
                    "id": pid,
                    "handle": handle,
                    "name": str(program.get("name", "")).strip(),
                    "hosts": sorted(list(program_hosts))[:500],
                    "wildcards": sorted(list(program_wildcards))[:100],
                }
            )

        hosts = {h for h in hosts if h and "*" not in h}
        wildcard_suffixes = {w for w in wildcard_suffixes if w and "*" not in w}

        added = sorted(list(hosts - prev_hosts))
        removed = sorted(list(prev_hosts - hosts))
        wildcard_added = sorted(list(wildcard_suffixes - prev_wildcards))
        wildcard_removed = sorted(list(prev_wildcards - wildcard_suffixes))

        payload = {
            "updated_at": int(time.time()),
            "program_handles_filter": self.program_handles,
            "hosts": sorted(list(hosts)),
            "wildcard_suffixes": sorted(list(wildcard_suffixes)),
            "added_hosts": added,
            "removed_hosts": removed,
            "added_wildcards": wildcard_added,
            "removed_wildcards": wildcard_removed,
            "rate_limits": {},
            "programs": programs_summary,
            "programs_total": len(programs),
            "programs_selected": len(selected_programs),
        }
        self.scope_cache_file.parent.mkdir(parents=True, exist_ok=True)
        self.scope_cache_file.write_text(json.dumps(payload, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
        secure_secret_file(self.scope_cache_file)
        return {
            "enabled": True,
            "hosts": sorted(list(hosts)),
            "wildcard_suffixes": sorted(list(wildcard_suffixes)),
            "added_hosts": added,
            "removed_hosts": removed,
            "added_wildcards": wildcard_added,
            "removed_wildcards": wildcard_removed,
            "programs": programs_summary,
        }

    def current_scope_hosts(self) -> set[str]:
        doc = _load_json(self.scope_cache_file)
        return {str(x).strip().lower() for x in doc.get("hosts", []) if str(x).strip()}

    def _current_wildcard_suffixes(self) -> set[str]:
        doc = _load_json(self.scope_cache_file)
        return {
            str(x).strip().lower().lstrip(".")
            for x in doc.get("wildcard_suffixes", [])
            if str(x).strip()
        }

    def target_rps(self, target: str) -> float:
        return self.default_target_rps

    def in_scope(self, target: str) -> bool:
        if not self.enabled:
            return True
        hosts = self.current_scope_hosts()
        wildcards = self._current_wildcard_suffixes()
        host = _to_host(target)
        if not hosts and not wildcards:
            return not self.strict_scope
        if host in hosts:
            return True
        for suffix in wildcards:
            if host == suffix or host.endswith(f".{suffix}"):
                return True
        return False

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
                        "trigger": "intigriti_scope_update",
                        "_depth": 0,
                    },
                )
            )
        return tasks

    def fetch_known_report_endpoints(self, timeout: int = 20, limit: int = 200) -> set[str]:
        _ = (timeout, limit)
        return set()

    def suppress_probable_duplicates(self, rows: list[dict[str, Any]], known_endpoints: set[str]) -> list[dict[str, Any]]:
        _ = known_endpoints
        return rows

    def watch_scope_updates(self, timeout: int = 20) -> dict[str, Any]:
        result = self.sync_scopes(timeout=timeout)
        added = result.get("added_hosts", []) if isinstance(result.get("added_hosts"), list) else []
        removed = result.get("removed_hosts", []) if isinstance(result.get("removed_hosts"), list) else []
        return {"enabled": bool(result.get("enabled", False)), "added_hosts": added, "removed_hosts": removed}
