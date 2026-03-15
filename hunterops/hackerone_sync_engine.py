from __future__ import annotations

import base64
import json
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from hunterops.runtime_paths import ensure_directory, resolve_path
from hunterops.secrets import read_secret

_PUBLIC_BOUNTY_PROGRAMS_QUERY = """
query PublicBountyPrograms($after: String) {
  teams(
    first: 100
    after: $after
    secure_order_by: { started_accepting_at: { _direction: DESC } }
    where: {
      _and: [
        { _or: [{ submission_state: { _eq: open } }, { external_program: {} }] }
        { _not: { external_program: {} } }
        { _or: [{ _and: [{ state: { _neq: sandboxed } }, { state: { _neq: soft_launched } }] }, { external_program: {} }] }
      ]
    }
  ) {
    pageInfo {
      endCursor
      hasNextPage
    }
    nodes {
      id
      handle
      name
      state
      submission_state
      offers_bounties
      response_efficiency_percentage
    }
  }
}
""".strip()

_STRUCTURED_SCOPES_QUERY = """
query ProgramStructuredScopes($handle: String!, $after: String) {
  team(handle: $handle) {
    structured_scopes(first: 100, after: $after, archived: false) {
      pageInfo {
        endCursor
        hasNextPage
      }
      nodes {
        asset_identifier
        asset_type
        eligible_for_bounty
        eligible_for_submission
        instruction
      }
    }
  }
}
""".strip()


def _as_float(value: Any) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except Exception:
        return None


def _normalize_domain(value: str) -> str:
    raw = str(value or "").strip().lower()
    if not raw:
        return ""
    if raw.startswith("http://") or raw.startswith("https://"):
        host = (urlparse(raw).hostname or "").strip().lower()
    elif "://" in raw:
        host = (urlparse(raw).hostname or "").strip().lower()
    else:
        host = raw.split("/", 1)[0].split(":", 1)[0].strip().lower()
    if host.startswith("*."):
        host = host[2:]
    if host.startswith("."):
        host = host[1:]
    host = host.strip(".")
    if not host or "." not in host:
        return ""
    allowed = set("abcdefghijklmnopqrstuvwxyz0123456789-.")
    if any(ch not in allowed for ch in host):
        return ""
    if ".." in host:
        return ""
    return host


class HackerOneSyncEngine:
    """Pre-flight HackerOne scope sync into local targets and attack graph."""

    def __init__(
        self,
        cfg: dict[str, Any],
        *,
        logger: Any | None = None,
        storage: Any | None = None,
        targets_file: str = "",
    ) -> None:
        self.cfg = cfg or {}
        self.logger = logger
        self.storage = storage
        self.enabled = bool(self.cfg.get("enabled", False))
        self.graphql_endpoint = str(self.cfg.get("graphql_endpoint", "https://api.hackerone.com/graphql")).strip()
        self.sync_interval_seconds = max(0, int(self.cfg.get("sync_interval_seconds", 21600)))
        self.sync_key = str(self.cfg.get("sync_key", "h1_public_bounty_scope_sync")).strip() or "h1_public_bounty_scope_sync"
        self.min_signal = _as_float(self.cfg.get("min_signal"))
        raw_exclude_low_signal = self.cfg.get("exclude_low_signal")
        if raw_exclude_low_signal is None:
            self.exclude_low_signal = self.min_signal is not None
        else:
            self.exclude_low_signal = bool(raw_exclude_low_signal)
        self.confidence_score = float(self.cfg.get("attack_graph_confidence", 98.0) or 98.0)
        configured_targets = str(self.cfg.get("targets_file", "")).strip()
        resolved_targets = configured_targets or targets_file or "targets.txt"
        self.targets_file: Path = resolve_path(resolved_targets, prefer_existing=False)
        self.strict_sync = bool(self.cfg.get("strict_sync", False))
        self.api_identifier = read_secret("H1_API_IDENTIFIER")
        self.api_token = read_secret("H1_API_TOKEN")

    @property
    def available(self) -> bool:
        return bool(self.enabled and self.api_identifier and self.api_token)

    def _log(self, level: str, message: str) -> None:
        if not self.logger:
            return
        try:
            getattr(self.logger, level)(message)
        except Exception:
            return

    def _headers(self) -> dict[str, str]:
        auth_raw = f"{self.api_identifier}:{self.api_token}".encode("utf-8")
        auth = base64.b64encode(auth_raw).decode("utf-8")
        return {
            "Authorization": f"Basic {auth}",
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "HunterOps-H1-Sync-Engine/1.0",
        }

    def _graphql(self, query: str, variables: dict[str, Any], timeout: int) -> dict[str, Any]:
        body = json.dumps({"query": query, "variables": variables}, ensure_ascii=True).encode("utf-8")
        req = Request(url=self.graphql_endpoint, data=body, headers=self._headers(), method="POST")
        with urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="ignore")
        doc = json.loads(raw) if raw else {}
        if not isinstance(doc, dict):
            raise RuntimeError("h1_graphql_invalid_payload")
        if isinstance(doc.get("errors"), list) and doc["errors"]:
            messages: list[str] = []
            for item in doc["errors"]:
                if isinstance(item, dict):
                    msg = str(item.get("message", "")).strip()
                    if msg:
                        messages.append(msg)
            msg_text = "; ".join(messages)[:500]
            raise RuntimeError(msg_text or "h1_graphql_error")
        data = doc.get("data", {})
        return data if isinstance(data, dict) else {}

    def _fetch_public_programs(self, timeout: int) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        after: str | None = None
        seen_handles: set[str] = set()
        while True:
            data = self._graphql(_PUBLIC_BOUNTY_PROGRAMS_QUERY, {"after": after}, timeout=timeout)
            teams = data.get("teams", {}) if isinstance(data.get("teams"), dict) else {}
            nodes = teams.get("nodes", [])
            if isinstance(nodes, list):
                for node in nodes:
                    if not isinstance(node, dict):
                        continue
                    handle = str(node.get("handle", "")).strip().lower()
                    if not handle or handle in seen_handles:
                        continue
                    seen_handles.add(handle)
                    out.append(node)
            page = teams.get("pageInfo", {}) if isinstance(teams.get("pageInfo"), dict) else {}
            has_next = bool(page.get("hasNextPage", False))
            end_cursor = str(page.get("endCursor", "")).strip()
            if not has_next or not end_cursor:
                break
            after = end_cursor
        return out

    def _fetch_structured_scopes(self, *, handle: str, timeout: int) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        after: str | None = None
        while True:
            data = self._graphql(_STRUCTURED_SCOPES_QUERY, {"handle": handle, "after": after}, timeout=timeout)
            team = data.get("team", {}) if isinstance(data.get("team"), dict) else {}
            scopes = team.get("structured_scopes", {}) if isinstance(team.get("structured_scopes"), dict) else {}
            nodes = scopes.get("nodes", [])
            if isinstance(nodes, list):
                out.extend([x for x in nodes if isinstance(x, dict)])
            page = scopes.get("pageInfo", {}) if isinstance(scopes.get("pageInfo"), dict) else {}
            has_next = bool(page.get("hasNextPage", False))
            end_cursor = str(page.get("endCursor", "")).strip()
            if not has_next or not end_cursor:
                break
            after = end_cursor
        return out

    @staticmethod
    def _extract_scope_domain(scope: dict[str, Any]) -> str:
        asset_identifier = str(scope.get("asset_identifier", "")).strip()
        asset_type = str(scope.get("asset_type", "")).strip().upper()
        if asset_type not in {"URL", "DOMAIN"}:
            return ""
        return _normalize_domain(asset_identifier)

    def _targets_file_merge(self, domains: set[str]) -> dict[str, Any]:
        ensure_directory(self.targets_file.parent, mode=0o755)
        existing: set[str] = set()
        if self.targets_file.exists():
            for line in self.targets_file.read_text(encoding="utf-8").splitlines():
                norm = _normalize_domain(line)
                if norm:
                    existing.add(norm)
        merged = sorted(existing | {x for x in domains if x})
        added = sorted({x for x in domains if x} - existing)
        self.targets_file.write_text("\n".join(merged) + ("\n" if merged else ""), encoding="utf-8")
        return {
            "targets_file": str(self.targets_file),
            "previous_total": len(existing),
            "current_total": len(merged),
            "added": added,
            "added_count": len(added),
        }

    def _sync_attack_graph_nodes(self, run_id: str, domain_programs: dict[str, list[str]]) -> int:
        if not self.storage or not bool(getattr(self.storage, "enabled", False)):
            return 0
        inserted = 0
        for domain, handles in domain_programs.items():
            if not domain:
                continue
            metadata = {
                "source": "hackerone_sync_engine",
                "program_handles": sorted(list({str(x).strip().lower() for x in handles if str(x).strip()})),
                "synced_at": int(time.time()),
            }
            try:
                self.storage.upsert_attack_graph_nodes(
                    run_id=run_id,
                    target=domain,
                    nodes=[
                        {
                            "node_type": "domain",
                            "node_key": domain,
                            "metadata": metadata,
                        }
                    ],
                    discovery_source="hackerone_sync_engine",
                    confidence_score=float(self.confidence_score),
                )
                inserted += 1
            except Exception as err:
                self._log("warning", f"h1_preflight_attack_graph_upsert_failed domain={domain} err={err}")
        return inserted

    def _current_state(self) -> dict[str, Any]:
        if not self.storage or not bool(getattr(self.storage, "enabled", False)):
            return {}
        try:
            return self.storage.get_h1_sync_state(self.sync_key)
        except Exception as err:
            self._log("warning", f"h1_preflight_state_read_failed err={err}")
            return {}

    @staticmethod
    def _state_age_seconds(state: dict[str, Any]) -> float | None:
        ts = state.get("last_synced_at")
        if isinstance(ts, datetime):
            dt = ts if ts.tzinfo else ts.replace(tzinfo=UTC)
            return max(0.0, (datetime.now(UTC) - dt).total_seconds())
        return None

    def _cache_fresh(self, state: dict[str, Any]) -> bool:
        if self.sync_interval_seconds <= 0:
            return False
        age = self._state_age_seconds(state)
        return age is not None and age < float(self.sync_interval_seconds)

    def _store_state(self, payload: dict[str, Any]) -> None:
        if not self.storage or not bool(getattr(self.storage, "enabled", False)):
            return
        try:
            self.storage.upsert_h1_sync_state(sync_key=self.sync_key, payload=payload)
        except Exception as err:
            self._log("warning", f"h1_preflight_state_write_failed err={err}")

    def _filter_programs_by_signal(self, programs: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], int]:
        if not programs:
            return [], 0
        min_signal = float(self.min_signal or 0.0)
        selected: list[dict[str, Any]] = []
        excluded = 0
        for program in programs:
            offers_bounties = bool(program.get("offers_bounties", False))
            if not offers_bounties:
                continue
            signal_value = _as_float(program.get("response_efficiency_percentage"))
            if self.exclude_low_signal and signal_value is not None and signal_value < min_signal:
                excluded += 1
                continue
            selected.append(program)
        return selected, excluded

    def sync(self, *, run_id: str, timeout: int = 25) -> dict[str, Any]:
        if not self.enabled:
            return {"enabled": False, "reason": "hackerone sync engine disabled"}
        if not self.available:
            return {"enabled": False, "reason": "missing env H1_API_IDENTIFIER/H1_API_TOKEN"}

        state = self._current_state()
        used_cache = self._cache_fresh(state)
        if used_cache:
            payload = state.get("payload", {}) if isinstance(state.get("payload"), dict) else {}
            domain_programs = {
                str(k).strip().lower(): [str(x).strip().lower() for x in v if str(x).strip()]
                for k, v in (payload.get("domain_programs", {}) or {}).items()
                if isinstance(v, list)
            }
            domains = {str(x).strip().lower() for x in payload.get("domains", []) if str(x).strip()}
            if not domain_programs and domains:
                domain_programs = {domain: [] for domain in domains}
            targets_state = self._targets_file_merge(domains)
            attack_graph_inserted = self._sync_attack_graph_nodes(run_id=run_id, domain_programs=domain_programs)
            return {
                "enabled": True,
                "api_called": False,
                "used_cache": True,
                "programs_total": int(payload.get("programs_total", 0) or 0),
                "programs_selected": int(payload.get("programs_selected", 0) or 0),
                "programs_excluded_low_signal": int(payload.get("programs_excluded_low_signal", 0) or 0),
                "domains": sorted(list(domains)),
                "domains_total": len(domains),
                "attack_graph_nodes_upserted": attack_graph_inserted,
                "targets_file": targets_state,
            }

        public_programs = self._fetch_public_programs(timeout=timeout)
        filtered_programs, excluded_low_signal = self._filter_programs_by_signal(public_programs)
        domain_programs_map: dict[str, set[str]] = {}
        for program in filtered_programs:
            handle = str(program.get("handle", "")).strip().lower()
            if not handle:
                continue
            try:
                scopes = self._fetch_structured_scopes(handle=handle, timeout=timeout)
            except Exception as err:
                self._log("warning", f"h1_preflight_scope_fetch_failed handle={handle} err={err}")
                continue
            for scope in scopes:
                if not bool(scope.get("eligible_for_bounty", False)):
                    continue
                domain = self._extract_scope_domain(scope)
                if not domain:
                    continue
                domain_programs_map.setdefault(domain, set()).add(handle)
        domains = sorted(list(domain_programs_map.keys()))
        domain_programs = {k: sorted(list(v)) for k, v in domain_programs_map.items()}
        targets_state = self._targets_file_merge(set(domains))
        attack_graph_inserted = self._sync_attack_graph_nodes(run_id=run_id, domain_programs=domain_programs)
        payload = {
            "sync_key": self.sync_key,
            "synced_unix": int(time.time()),
            "programs_total": len(public_programs),
            "programs_selected": len(filtered_programs),
            "programs_excluded_low_signal": int(excluded_low_signal),
            "domains": domains,
            "domain_programs": domain_programs,
            "targets_file": str(self.targets_file),
        }
        self._store_state(payload)
        return {
            "enabled": True,
            "api_called": True,
            "used_cache": False,
            "programs_total": len(public_programs),
            "programs_selected": len(filtered_programs),
            "programs_excluded_low_signal": int(excluded_low_signal),
            "domains": domains,
            "domains_total": len(domains),
            "attack_graph_nodes_upserted": attack_graph_inserted,
            "targets_file": targets_state,
        }
