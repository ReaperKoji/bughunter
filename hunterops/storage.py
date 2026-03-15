from __future__ import annotations

import hashlib
import contextlib
import json
import os
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from hunterops.runtime_paths import chmod_if_posix, secure_secret_file
from hunterops.url_utils import normalize_endpoint

try:
    from cryptography.fernet import Fernet, InvalidToken  # type: ignore
except Exception:  # pragma: no cover - optional encryption dependency
    Fernet = None  # type: ignore
    InvalidToken = Exception  # type: ignore


def _normalize_endpoint(value: str) -> str:
    return normalize_endpoint(value)


_DSN_FILE_HINT_RE = re.compile(r"""(?:sslkey|sslcert|sslrootcert)=([^&\s]+)""", re.IGNORECASE)
FINANCIAL_ENTITY_MARKERS = ("invoice", "transaction", "wallet")
FINANCIAL_ENTITY_TYPES = {"invoice_id", "transaction_id", "wallet_id", "invoice", "transaction", "wallet"}


def _get_fernet() -> "Fernet | None":
    key = os.getenv("HUNTEROPS_FINDINGS_ENCRYPTION_KEY", "").strip()
    if not key or Fernet is None:
        return None
    try:
        return Fernet(key.encode("utf-8"))
    except Exception:
        return None


def _encrypt_payload(payload: dict[str, Any], fernet: "Fernet | None") -> dict[str, Any]:
    if fernet is None:
        return payload
    try:
        token = fernet.encrypt(json.dumps(payload, ensure_ascii=True).encode("utf-8")).decode("utf-8")
    except Exception:
        return payload
    return {"__encrypted__": token, "__alg__": "fernet"}


def _decrypt_payload(payload: dict[str, Any], fernet: "Fernet | None") -> dict[str, Any]:
    if fernet is None:
        return payload
    if "__encrypted__" not in payload:
        return payload
    token = str(payload.get("__encrypted__", "")).strip()
    if not token:
        return payload
    try:
        raw = fernet.decrypt(token.encode("utf-8"))
        return json.loads(raw.decode("utf-8"))
    except Exception:
        return payload


def _collect_secret_file_candidates(dsn: str) -> list[Path]:
    out: list[Path] = []
    env_candidates = (
        "PGSSLKEY",
        "PGSSLCERT",
        "PGSSLROOTCERT",
        "HUNTEROPS_SESSIONS_FILE",
        "HUNTEROPS_ENV_FILE",
    )
    for env_name in env_candidates:
        raw = os.getenv(env_name, "").strip()
        if raw:
            out.append(Path(raw).expanduser())

    for match in _DSN_FILE_HINT_RE.findall(str(dsn or "")):
        val = str(match).strip().strip('"').strip("'")
        if val:
            out.append(Path(val).expanduser())
    return out


def _is_financial_entity(
    *,
    entity_type: str,
    entity_value: str,
    source_endpoint: str,
    metadata: dict[str, Any],
) -> bool:
    etype = str(entity_type or "").strip().lower()
    evalue = str(entity_value or "").strip().lower()
    endpoint = str(source_endpoint or "").strip().lower()
    if etype in FINANCIAL_ENTITY_TYPES:
        return True
    if any(marker in etype for marker in FINANCIAL_ENTITY_MARKERS):
        return True
    if any(marker in evalue for marker in FINANCIAL_ENTITY_MARKERS):
        return True
    if any(marker in endpoint for marker in FINANCIAL_ENTITY_MARKERS):
        return True
    if bool(metadata.get("financial_flow", False)):
        return True
    return False


def _severity_rank_value(value: str) -> int:
    raw = str(value or "").strip().lower()
    if raw == "critical":
        return 4
    if raw == "high":
        return 3
    if raw == "medium":
        return 2
    if raw == "low":
        return 1
    return 0


def _triage_finding_key(row: dict[str, Any]) -> str:
    evidence = row.get("evidence", {}) if isinstance(row.get("evidence"), dict) else {}
    metadata = row.get("metadata", {}) if isinstance(row.get("metadata"), dict) else {}
    endpoint = _normalize_endpoint(
        str(
            row.get("endpoint", "")
            or evidence.get("endpoint", "")
            or evidence.get("path", "")
            or evidence.get("url", "")
            or ""
        )
    )
    parameter_name = str(
        row.get("parameter_name", "")
        or metadata.get("parameter_name", metadata.get("parameter", ""))
        or evidence.get("tested_parameter", "")
    ).strip()
    raw = "|".join(
        [
            str(row.get("plugin", "")).strip().lower(),
            str(row.get("target", "")).strip().lower(),
            str(row.get("category", "")).strip().lower(),
            str(row.get("title", "")).strip().lower(),
            endpoint.lower(),
            parameter_name.lower(),
        ]
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class PostgresStorage:
    def __init__(self, dsn: str, enabled: bool = False) -> None:
        self.dsn = dsn
        self.enabled = enabled
        self._conn = None

    def connect(self) -> None:
        if not self.enabled:
            return
        if self._conn is not None and not getattr(self._conn, "closed", False):
            return
        self._conn = None
        for candidate in _collect_secret_file_candidates(self.dsn):
            if candidate.exists():
                secure_secret_file(candidate)
                parent = candidate.parent
                if parent.exists():
                    chmod_if_posix(parent, mode=0o700)
        try:
            import psycopg  # type: ignore
        except Exception as err:
            raise RuntimeError("psycopg is required for postgres storage") from err
        try:
            connect_timeout = max(1, int(os.getenv("HUNTEROPS_PG_CONNECT_TIMEOUT_SECONDS", "5") or 5))
        except Exception:
            connect_timeout = 5
        try:
            statement_timeout_ms = max(1000, int(os.getenv("HUNTEROPS_PG_STATEMENT_TIMEOUT_MS", "12000") or 12000))
        except Exception:
            statement_timeout_ms = 12000
        try:
            lock_timeout_ms = max(500, int(os.getenv("HUNTEROPS_PG_LOCK_TIMEOUT_MS", "3000") or 3000))
        except Exception:
            lock_timeout_ms = 3000
        try:
            idle_tx_timeout_ms = max(
                1000,
                int(os.getenv("HUNTEROPS_PG_IDLE_IN_TX_TIMEOUT_MS", "20000") or 20000),
            )
        except Exception:
            idle_tx_timeout_ms = 20000
        options = (
            f"-c statement_timeout={statement_timeout_ms} "
            f"-c lock_timeout={lock_timeout_ms} "
            f"-c idle_in_transaction_session_timeout={idle_tx_timeout_ms}"
        )
        self._conn = psycopg.connect(self.dsn, connect_timeout=connect_timeout, options=options)
        with self._conn.cursor() as cur:
            cur.execute(
                """
                create table if not exists hunterops_findings (
                  id bigserial primary key,
                  run_id text not null,
                  triage_key text,
                  plugin text not null,
                  target text not null,
                  category text not null,
                  severity text not null,
                  title text not null,
                  risk_score double precision not null,
                  discovery_source text default '',
                  confidence_score double precision default 0,
                  payload jsonb not null,
                  created_at timestamptz default now()
                )
                """
            )
            cur.execute("alter table hunterops_findings add column if not exists discovery_source text default ''")
            cur.execute("alter table hunterops_findings add column if not exists confidence_score double precision default 0")
            cur.execute("alter table hunterops_findings add column if not exists triage_key text")
            cur.execute(
                """
                create unique index if not exists hunterops_findings_run_triage_key_idx
                on hunterops_findings (run_id, triage_key)
                where triage_key is not null and triage_key <> ''
                """
            )
        self._conn.commit()

    def write_findings(self, run_id: str, rows: list[dict[str, Any]]) -> None:
        if not self.enabled:
            return
        if self._conn is None or getattr(self._conn, "closed", False):
            self.connect()
        assert self._conn is not None
        fernet = _get_fernet()
        with self._conn.cursor() as cur:
            for r in rows:
                triage_key = _triage_finding_key(r)
                payload_doc = _encrypt_payload(r, fernet)
                cur.execute(
                    """
                    insert into hunterops_findings
                    (run_id, triage_key, plugin, target, category, severity, title, risk_score, discovery_source, confidence_score, payload)
                    values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb)
                    on conflict do nothing
                    """,
                    (
                        run_id,
                        triage_key,
                        r.get("plugin", ""),
                        r.get("target", ""),
                        r.get("category", ""),
                        r.get("severity", ""),
                        r.get("title", ""),
                        float(r.get("risk_score", 0)),
                        str((r.get("metadata", {}) or {}).get("discovery_source", "")),
                        float((r.get("metadata", {}) or {}).get("confidence_score", (r.get("metadata", {}) or {}).get("confidence", 0))),
                        json.dumps(payload_doc, ensure_ascii=True),
                    ),
                )
        self._conn.commit()

    def list_findings(self, run_id: str, limit: int | None = None) -> list[dict[str, Any]]:
        if not self.enabled:
            return []
        if self._conn is None or getattr(self._conn, "closed", False):
            self.connect()
        assert self._conn is not None
        rows: list[dict[str, Any]] = []
        fernet = _get_fernet()
        with self._conn.cursor() as cur:
            if limit is not None and int(limit) > 0:
                cur.execute(
                    """
                    select payload
                    from hunterops_findings
                    where run_id=%s
                    order by id asc
                    limit %s
                    """,
                    (run_id, int(limit)),
                )
            else:
                cur.execute(
                    """
                    select payload
                    from hunterops_findings
                    where run_id=%s
                    order by id asc
                    """,
                    (run_id,),
                )
            for row in cur.fetchall() or []:
                payload = row[0] if isinstance(row, (list, tuple)) and row else row
                if isinstance(payload, dict):
                    rows.append(_decrypt_payload(payload, fernet))
        return rows

    def purge_findings_older_than(self, hours: int) -> int:
        if not self.enabled:
            return 0
        if hours <= 0:
            return 0
        if self._conn is None or getattr(self._conn, "closed", False):
            self.connect()
        assert self._conn is not None
        with self._conn.cursor() as cur:
            cur.execute(
                "delete from hunterops_findings where created_at < (now() - (%s || ' hours')::interval)",
                (int(hours),),
            )
            deleted = cur.rowcount or 0
        self._conn.commit()
        return int(deleted)

    def ensure_research_schema(self) -> None:
        if not self.enabled:
            return
        if self._conn is None or getattr(self._conn, "closed", False):
            self.connect()
        assert self._conn is not None
        with self._conn.cursor() as cur:
            cur.execute(
                """
                create table if not exists hunterops_scan_state (
                  id bigserial primary key,
                  run_id text not null,
                  plugin text not null,
                  target text not null,
                  endpoint text not null,
                  scanned_at timestamptz default now(),
                  unique(run_id, plugin, target, endpoint)
                )
                """
            )
            cur.execute(
                """
                create table if not exists hunterops_endpoint_cache (
                  plugin text not null,
                  target text not null,
                  endpoint text not null,
                  last_seen timestamptz not null default now(),
                  primary key (plugin, target, endpoint)
                )
                """
            )
            cur.execute(
                """
                create index if not exists hunterops_endpoint_cache_seen_idx
                on hunterops_endpoint_cache (last_seen desc)
                """
            )
            cur.execute(
                """
                create table if not exists attack_graph_nodes (
                  id bigserial primary key,
                  run_id text not null,
                  node_type text not null,
                  node_key text not null,
                  target text not null,
                  discovery_source text not null default '',
                  confidence_score double precision not null default 0,
                  metadata jsonb not null default '{}'::jsonb,
                  created_at timestamptz default now(),
                  unique(run_id, node_type, node_key, target)
                )
                """
            )
            cur.execute(
                """
                create table if not exists attack_graph_edges (
                  id bigserial primary key,
                  run_id text not null,
                  src_node_id bigint not null references attack_graph_nodes(id) on delete cascade,
                  dst_node_id bigint not null references attack_graph_nodes(id) on delete cascade,
                  edge_type text not null,
                  confidence_score double precision not null default 0,
                  evidence_ref text default '',
                  metadata jsonb not null default '{}'::jsonb,
                  created_at timestamptz default now()
                )
                """
            )
            cur.execute(
                """
                create unique index if not exists attack_graph_edges_uq
                on attack_graph_edges (run_id, src_node_id, dst_node_id, edge_type)
                """
            )
            cur.execute(
                """
                create table if not exists objects (
                  id bigserial primary key,
                  run_id text not null,
                  target text not null default '',
                  object_type text not null,
                  object_key text not null,
                  source_endpoint text not null,
                  confidence_score double precision not null default 0,
                  discovery_source text not null default '',
                  metadata jsonb not null default '{}'::jsonb,
                  discovered_at timestamptz default now()
                )
                """
            )
            cur.execute("alter table objects add column if not exists target text not null default ''")
            cur.execute("alter table objects add column if not exists metadata jsonb not null default '{}'::jsonb")
            cur.execute(
                """
                create unique index if not exists objects_uq
                on objects (run_id, target, object_type, object_key, source_endpoint)
                """
            )
            cur.execute(
                """
                create table if not exists object_relationships (
                  id bigserial primary key,
                  run_id text not null,
                  target text not null default '',
                  parent_object_type text not null,
                  parent_object_key text not null,
                  child_object_type text not null,
                  child_object_key text not null,
                  relation_type text not null,
                  confidence_score double precision not null default 0,
                  evidence_ref text default '',
                  metadata jsonb not null default '{}'::jsonb,
                  discovered_at timestamptz default now()
                )
                """
            )
            cur.execute("alter table object_relationships add column if not exists target text not null default ''")
            cur.execute("alter table object_relationships add column if not exists metadata jsonb not null default '{}'::jsonb")
            cur.execute(
                """
                create table if not exists endpoint_parameters (
                  id bigserial primary key,
                  run_id text not null,
                  endpoint text not null,
                  method text not null default 'GET',
                  param_name text not null,
                  param_location text not null,
                  param_type text not null,
                  risk_score double precision not null default 0,
                  discovery_source text not null default '',
                  evidence_ref text default '',
                  first_seen timestamptz default now(),
                  last_seen timestamptz default now(),
                  unique(run_id, endpoint, method, param_name, param_location)
                )
                """
            )
            cur.execute(
                """
                create table if not exists discovered_entities (
                  id bigserial primary key,
                  run_id text not null,
                  target text not null,
                  entity_type text not null,
                  entity_value text not null,
                  source_plugin text not null default '',
                  source_endpoint text not null default '',
                  confidence_score double precision not null default 0,
                  metadata jsonb not null default '{}'::jsonb,
                  first_seen timestamptz default now(),
                  last_seen timestamptz default now(),
                  unique(target, entity_type, entity_value, source_plugin, source_endpoint)
                )
                """
            )
            cur.execute(
                """
                create table if not exists financial_entities (
                  id bigserial primary key,
                  run_id text not null,
                  target text not null,
                  entity_type text not null,
                  entity_value text not null,
                  source_plugin text not null default '',
                  source_endpoint text not null default '',
                  confidence_score double precision not null default 0,
                  metadata jsonb not null default '{}'::jsonb,
                  first_seen timestamptz default now(),
                  last_seen timestamptz default now(),
                  unique(target, entity_type, entity_value, source_plugin, source_endpoint)
                )
                """
            )
            cur.execute(
                """
                create table if not exists verified_findings (
                  id bigserial primary key,
                  run_id text not null,
                  target text not null,
                  plugin text not null,
                  category text not null,
                  severity text not null,
                  title text not null,
                  confidence_score double precision not null default 0,
                  impact_analysis text not null default '',
                  endpoint text not null default '',
                  parameter_name text not null default '',
                  poc_path text not null default '',
                  curl_command text not null default '',
                  metadata jsonb not null default '{}'::jsonb,
                  evidence_json jsonb not null default '{}'::jsonb,
                  created_at timestamptz default now()
                )
                """
            )
            cur.execute(
                """
                create unique index if not exists verified_findings_uq
                on verified_findings (run_id, target, plugin, category, title, endpoint, parameter_name)
                """
            )
            cur.execute(
                """
                create table if not exists triage_queue (
                  id bigserial primary key,
                  run_id text not null,
                  finding_key text not null,
                  target text not null,
                  plugin text not null default '',
                  category text not null default '',
                  severity text not null default 'info',
                  title text not null default '',
                  endpoint text not null default '',
                  parameter_name text not null default '',
                  confidence_score double precision not null default 0,
                  impact_score double precision not null default 0,
                  status text not null default 'review',
                  source text not null default '',
                  evidence_path text not null default '',
                  validator_note text not null default '',
                  payload jsonb not null default '{}'::jsonb,
                  created_at timestamptz default now(),
                  updated_at timestamptz default now(),
                  unique(run_id, finding_key)
                )
                """
            )
            cur.execute(
                """
                create index if not exists triage_queue_lookup_idx
                on triage_queue (run_id, status, confidence_score desc, impact_score desc)
                """
            )
            cur.execute(
                """
                create table if not exists h1_sync_state (
                  sync_key text primary key,
                  last_synced_at timestamptz not null default now(),
                  payload jsonb not null default '{}'::jsonb,
                  updated_at timestamptz not null default now()
                )
                """
            )
            cur.execute(
                """
                create table if not exists hunterops_session_state (
                  session_name text primary key,
                  cookie text not null default '',
                  token text not null default '',
                  token_type text not null default 'Bearer',
                  headers jsonb not null default '{}'::jsonb,
                  metadata jsonb not null default '{}'::jsonb,
                  status text not null default 'unknown',
                  last_refresh_at timestamptz default now(),
                  updated_at timestamptz default now()
                )
                """
            )
        self._conn.commit()

    def was_endpoint_scanned(self, run_id: str, plugin: str, target: str, endpoint: str) -> bool:
        if not self.enabled:
            return False
        if self._conn is None or getattr(self._conn, "closed", False):
            self.connect()
        assert self._conn is not None
        with self._conn.cursor() as cur:
            cur.execute(
                """
                select 1
                from hunterops_scan_state
                where run_id=%s and plugin=%s and target=%s and endpoint=%s
                limit 1
                """,
                (run_id, plugin, target, endpoint),
            )
            row = cur.fetchone()
        return bool(row)

    def mark_endpoint_scanned(self, run_id: str, plugin: str, target: str, endpoint: str) -> None:
        if not self.enabled:
            return
        if self._conn is None or getattr(self._conn, "closed", False):
            self.connect()
        assert self._conn is not None
        with self._conn.cursor() as cur:
            cur.execute(
                """
                insert into hunterops_scan_state (run_id, plugin, target, endpoint)
                values (%s,%s,%s,%s)
                on conflict do nothing
                """,
                (run_id, plugin, target, endpoint),
            )
        self._conn.commit()

    def endpoint_seen_recently(self, *, plugin: str, target: str, endpoint: str, ttl_seconds: int) -> bool:
        if not self.enabled:
            return False
        if ttl_seconds <= 0:
            return False
        if self._conn is None or getattr(self._conn, "closed", False):
            self.connect()
        assert self._conn is not None
        with self._conn.cursor() as cur:
            cur.execute(
                """
                select 1
                from hunterops_endpoint_cache
                where plugin=%s and target=%s and endpoint=%s
                  and last_seen >= (now() - (%s || ' seconds')::interval)
                limit 1
                """,
                (plugin, target, endpoint, int(ttl_seconds)),
            )
            row = cur.fetchone()
        return bool(row)

    def mark_endpoint_seen(self, *, plugin: str, target: str, endpoint: str) -> None:
        if not self.enabled:
            return
        if self._conn is None or getattr(self._conn, "closed", False):
            self.connect()
        assert self._conn is not None
        with self._conn.cursor() as cur:
            cur.execute(
                """
                insert into hunterops_endpoint_cache (plugin, target, endpoint, last_seen)
                values (%s,%s,%s,now())
                on conflict (plugin, target, endpoint)
                do update set last_seen=excluded.last_seen
                """,
                (plugin, target, endpoint),
            )
        self._conn.commit()

    def upsert_session_state(
        self,
        *,
        session_name: str,
        cookie: str = "",
        token: str = "",
        token_type: str = "Bearer",
        headers: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
        status: str = "active",
    ) -> None:
        if not self.enabled:
            return
        if self._conn is None or getattr(self._conn, "closed", False):
            self.connect()
        assert self._conn is not None
        name = str(session_name or "").strip().lower()
        if not name:
            return
        headers_doc = headers if isinstance(headers, dict) else {}
        metadata_doc = metadata if isinstance(metadata, dict) else {}
        with self._conn.cursor() as cur:
            cur.execute(
                """
                insert into hunterops_session_state
                (session_name, cookie, token, token_type, headers, metadata, status, last_refresh_at, updated_at)
                values (%s,%s,%s,%s,%s::jsonb,%s::jsonb,%s,now(),now())
                on conflict (session_name)
                do update set
                  cookie=excluded.cookie,
                  token=excluded.token,
                  token_type=excluded.token_type,
                  headers=excluded.headers,
                  metadata=excluded.metadata,
                  status=excluded.status,
                  last_refresh_at=excluded.last_refresh_at,
                  updated_at=now()
                """,
                (
                    name,
                    str(cookie or ""),
                    str(token or ""),
                    str(token_type or "Bearer"),
                    json.dumps(headers_doc, ensure_ascii=True),
                    json.dumps(metadata_doc, ensure_ascii=True),
                    str(status or "active"),
                ),
            )
        self._conn.commit()

    def get_session_state(self, session_name: str) -> dict[str, Any]:
        if not self.enabled:
            return {}
        if self._conn is None or getattr(self._conn, "closed", False):
            self.connect()
        assert self._conn is not None
        name = str(session_name or "").strip().lower()
        if not name:
            return {}
        with self._conn.cursor() as cur:
            cur.execute(
                """
                select session_name, cookie, token, token_type, headers, metadata, status, last_refresh_at, updated_at
                from hunterops_session_state
                where session_name=%s
                limit 1
                """,
                (name,),
            )
            row = cur.fetchone()
        if not row:
            return {}
        return {
            "session_name": str(row[0] or ""),
            "cookie": str(row[1] or ""),
            "token": str(row[2] or ""),
            "token_type": str(row[3] or "Bearer"),
            "headers": row[4] if isinstance(row[4], dict) else {},
            "metadata": row[5] if isinstance(row[5], dict) else {},
            "status": str(row[6] or ""),
            "last_refresh_at": str(row[7] or ""),
            "updated_at": str(row[8] or ""),
        }

    def upsert_attack_graph_nodes(
        self,
        run_id: str,
        target: str,
        nodes: list[dict[str, Any]],
        discovery_source: str,
        confidence_score: float,
    ) -> None:
        if not self.enabled or not nodes:
            return
        if self._conn is None or getattr(self._conn, "closed", False):
            self.connect()
        assert self._conn is not None
        with self._conn.cursor() as cur:
            for n in nodes:
                cur.execute(
                    """
                    insert into attack_graph_nodes
                    (run_id, node_type, node_key, target, discovery_source, confidence_score, metadata)
                    values (%s,%s,%s,%s,%s,%s,%s::jsonb)
                    on conflict (run_id, node_type, node_key, target)
                    do update set
                      discovery_source=excluded.discovery_source,
                      confidence_score=greatest(attack_graph_nodes.confidence_score, excluded.confidence_score),
                      metadata=excluded.metadata
                    """,
                    (
                        run_id,
                        str(n.get("node_type", "")),
                        str(n.get("node_key", "")),
                        target,
                        discovery_source,
                        float(confidence_score),
                        json.dumps(n.get("metadata", {}), ensure_ascii=True),
                    ),
                )
        self._conn.commit()

    def _ensure_attack_graph_node_id(
        self,
        *,
        cur: Any,
        run_id: str,
        target: str,
        node_type: str,
        node_key: str,
        discovery_source: str,
        confidence_score: float,
        metadata: dict[str, Any] | None = None,
    ) -> int:
        payload = metadata if isinstance(metadata, dict) else {}
        cur.execute(
            """
            insert into attack_graph_nodes
            (run_id, node_type, node_key, target, discovery_source, confidence_score, metadata)
            values (%s,%s,%s,%s,%s,%s,%s::jsonb)
            on conflict (run_id, node_type, node_key, target)
            do update set
              discovery_source=excluded.discovery_source,
              confidence_score=greatest(attack_graph_nodes.confidence_score, excluded.confidence_score),
              metadata=excluded.metadata
            returning id
            """,
            (
                run_id,
                str(node_type or ""),
                str(node_key or ""),
                str(target or ""),
                str(discovery_source or ""),
                float(confidence_score or 0),
                json.dumps(payload, ensure_ascii=True),
            ),
        )
        row = cur.fetchone()
        return int(row[0]) if row and row[0] is not None else 0

    def upsert_attack_graph_edges(
        self,
        *,
        run_id: str,
        target: str,
        edges: list[dict[str, Any]],
        discovery_source: str = "",
        confidence_score: float = 0.0,
    ) -> int:
        if not self.enabled or not edges:
            return 0
        if self._conn is None or getattr(self._conn, "closed", False):
            self.connect()
        assert self._conn is not None
        inserted = 0
        with self._conn.cursor() as cur:
            for edge in edges:
                src_type = str(edge.get("src_type", "")).strip()
                src_key = str(edge.get("src_key", "")).strip()
                dst_type = str(edge.get("dst_type", "")).strip()
                dst_key = str(edge.get("dst_key", "")).strip()
                edge_type = str(edge.get("edge_type", "")).strip()
                if not src_type or not src_key or not dst_type or not dst_key or not edge_type:
                    continue
                src_meta = edge.get("src_metadata", {}) if isinstance(edge.get("src_metadata"), dict) else {}
                dst_meta = edge.get("dst_metadata", {}) if isinstance(edge.get("dst_metadata"), dict) else {}
                src_id = self._ensure_attack_graph_node_id(
                    cur=cur,
                    run_id=run_id,
                    target=target,
                    node_type=src_type,
                    node_key=src_key,
                    discovery_source=str(edge.get("src_discovery_source", discovery_source)),
                    confidence_score=float(edge.get("src_confidence_score", confidence_score) or confidence_score or 0),
                    metadata=src_meta,
                )
                dst_id = self._ensure_attack_graph_node_id(
                    cur=cur,
                    run_id=run_id,
                    target=target,
                    node_type=dst_type,
                    node_key=dst_key,
                    discovery_source=str(edge.get("dst_discovery_source", discovery_source)),
                    confidence_score=float(edge.get("dst_confidence_score", confidence_score) or confidence_score or 0),
                    metadata=dst_meta,
                )
                if src_id <= 0 or dst_id <= 0:
                    continue
                edge_meta = edge.get("metadata", {}) if isinstance(edge.get("metadata"), dict) else {}
                cur.execute(
                    """
                    insert into attack_graph_edges
                    (run_id, src_node_id, dst_node_id, edge_type, confidence_score, evidence_ref, metadata)
                    values (%s,%s,%s,%s,%s,%s,%s::jsonb)
                    on conflict (run_id, src_node_id, dst_node_id, edge_type)
                    do update set
                      confidence_score=greatest(attack_graph_edges.confidence_score, excluded.confidence_score),
                      evidence_ref=excluded.evidence_ref,
                      metadata=excluded.metadata
                    """,
                    (
                        run_id,
                        src_id,
                        dst_id,
                        edge_type,
                        float(edge.get("confidence_score", confidence_score) or confidence_score or 0),
                        str(edge.get("evidence_ref", "")),
                        json.dumps(edge_meta, ensure_ascii=True),
                    ),
                )
                inserted += 1
        self._conn.commit()
        return inserted

    def upsert_objects(self, *, run_id: str, target: str, rows: list[dict[str, Any]]) -> int:
        if not self.enabled or not rows:
            return 0
        if self._conn is None or getattr(self._conn, "closed", False):
            self.connect()
        assert self._conn is not None
        inserted = 0
        with self._conn.cursor() as cur:
            for row in rows:
                object_type = str(row.get("object_type", "")).strip().lower()
                object_key = str(row.get("object_key", "")).strip()
                if not object_type or not object_key:
                    continue
                source_endpoint = _normalize_endpoint(str(row.get("source_endpoint", "")))
                confidence = float(row.get("confidence_score", 0) or 0)
                discovery_source = str(row.get("discovery_source", row.get("source_plugin", ""))).strip()
                metadata = row.get("metadata", {}) if isinstance(row.get("metadata"), dict) else {}
                cur.execute(
                    """
                    insert into objects
                    (run_id, target, object_type, object_key, source_endpoint, confidence_score, discovery_source, metadata)
                    values (%s,%s,%s,%s,%s,%s,%s,%s::jsonb)
                    on conflict (run_id, target, object_type, object_key, source_endpoint)
                    do update set
                      confidence_score=greatest(objects.confidence_score, excluded.confidence_score),
                      discovery_source=excluded.discovery_source,
                      metadata=excluded.metadata
                    """,
                    (
                        run_id,
                        target,
                        object_type,
                        object_key[:1024],
                        source_endpoint,
                        confidence,
                        discovery_source,
                        json.dumps(metadata, ensure_ascii=True),
                    ),
                )
                inserted += 1
        self._conn.commit()
        return inserted

    def list_objects(
        self,
        *,
        run_id: str,
        target: str = "",
        limit: int = 300,
        object_types: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        if not self.enabled:
            return []
        if self._conn is None or getattr(self._conn, "closed", False):
            self.connect()
        assert self._conn is not None
        safe_limit = max(1, min(int(limit), 5000))
        out: list[dict[str, Any]] = []
        with self._conn.cursor() as cur:
            types = [str(x).strip().lower() for x in (object_types or []) if str(x).strip()]
            if target and types:
                cur.execute(
                    """
                    select object_type, object_key, source_endpoint, confidence_score, discovery_source, metadata
                    from objects
                    where run_id=%s and target=%s and object_type = any(%s::text[])
                    order by confidence_score desc, discovered_at desc
                    limit %s
                    """,
                    (run_id, target, types, safe_limit),
                )
            elif target:
                cur.execute(
                    """
                    select object_type, object_key, source_endpoint, confidence_score, discovery_source, metadata
                    from objects
                    where run_id=%s and target=%s
                    order by confidence_score desc, discovered_at desc
                    limit %s
                    """,
                    (run_id, target, safe_limit),
                )
            elif types:
                cur.execute(
                    """
                    select object_type, object_key, source_endpoint, confidence_score, discovery_source, metadata
                    from objects
                    where run_id=%s and object_type = any(%s::text[])
                    order by confidence_score desc, discovered_at desc
                    limit %s
                    """,
                    (run_id, types, safe_limit),
                )
            else:
                cur.execute(
                    """
                    select object_type, object_key, source_endpoint, confidence_score, discovery_source, metadata
                    from objects
                    where run_id=%s
                    order by confidence_score desc, discovered_at desc
                    limit %s
                    """,
                    (run_id, safe_limit),
                )
            rows = cur.fetchall()
            for row in rows:
                out.append(
                    {
                        "object_type": str(row[0] or ""),
                        "object_key": str(row[1] or ""),
                        "source_endpoint": _normalize_endpoint(str(row[2] or "")),
                        "confidence_score": float(row[3] or 0),
                        "discovery_source": str(row[4] or ""),
                        "metadata": row[5] if isinstance(row[5], dict) else {},
                    }
                )
        return out

    def upsert_endpoint_parameters(self, run_id: str, rows: list[dict[str, Any]]) -> None:
        if not self.enabled or not rows:
            return
        if self._conn is None or getattr(self._conn, "closed", False):
            self.connect()
        assert self._conn is not None
        with self._conn.cursor() as cur:
            for r in rows:
                cur.execute(
                    """
                    insert into endpoint_parameters
                    (run_id, endpoint, method, param_name, param_location, param_type, risk_score, discovery_source, evidence_ref)
                    values (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    on conflict (run_id, endpoint, method, param_name, param_location)
                    do update set
                      param_type=excluded.param_type,
                      risk_score=excluded.risk_score,
                      discovery_source=excluded.discovery_source,
                      evidence_ref=excluded.evidence_ref,
                      last_seen=now()
                    """,
                    (
                        run_id,
                        str(r.get("endpoint", "")),
                        str(r.get("method", "GET")),
                        str(r.get("param_name", "")),
                        str(r.get("param_location", "query")),
                        str(r.get("param_type", "string")),
                        float(r.get("risk_score", 0)),
                        str(r.get("discovery_source", "")),
                        str(r.get("evidence_ref", "")),
                    ),
                )
        self._conn.commit()

    def upsert_discovered_entities(self, run_id: str, target: str, rows: list[dict[str, Any]]) -> int:
        if not self.enabled or not rows:
            return 0
        if self._conn is None or getattr(self._conn, "closed", False):
            self.connect()
        assert self._conn is not None
        inserted = 0
        financial_rows: list[dict[str, Any]] = []
        with self._conn.cursor() as cur:
            for r in rows:
                entity_type = str(r.get("entity_type", "")).strip().lower()
                entity_value = str(r.get("entity_value", "")).strip()
                if not entity_type or not entity_value:
                    continue
                source_plugin = str(r.get("source_plugin", "")).strip()
                source_endpoint = _normalize_endpoint(str(r.get("source_endpoint", "")).strip())
                confidence_score = float(r.get("confidence_score", 0) or 0)
                metadata = r.get("metadata", {}) if isinstance(r.get("metadata"), dict) else {}
                cur.execute(
                    """
                    insert into discovered_entities
                    (run_id, target, entity_type, entity_value, source_plugin, source_endpoint, confidence_score, metadata)
                    values (%s,%s,%s,%s,%s,%s,%s,%s::jsonb)
                    on conflict (target, entity_type, entity_value, source_plugin, source_endpoint)
                    do update set
                      run_id=excluded.run_id,
                      confidence_score=greatest(discovered_entities.confidence_score, excluded.confidence_score),
                      metadata=excluded.metadata,
                      last_seen=now()
                    """,
                    (
                        run_id,
                        target,
                        entity_type,
                        entity_value[:512],
                        source_plugin,
                        source_endpoint,
                        confidence_score,
                        json.dumps(metadata, ensure_ascii=True),
                    ),
                )
                inserted += 1
                if _is_financial_entity(
                    entity_type=entity_type,
                    entity_value=entity_value,
                    source_endpoint=source_endpoint,
                    metadata=metadata,
                ):
                    financial_rows.append(
                        {
                            "entity_type": entity_type,
                            "entity_value": entity_value,
                            "source_plugin": source_plugin,
                            "source_endpoint": source_endpoint,
                            "confidence_score": confidence_score,
                            "metadata": metadata | {"financial_flow": True},
                        }
                    )
        self._conn.commit()
        if financial_rows:
            self.upsert_financial_entities(run_id=run_id, target=target, rows=financial_rows)
        return inserted

    def upsert_financial_entities(self, run_id: str, target: str, rows: list[dict[str, Any]]) -> int:
        if not self.enabled or not rows:
            return 0
        if self._conn is None or getattr(self._conn, "closed", False):
            self.connect()
        assert self._conn is not None
        inserted = 0
        with self._conn.cursor() as cur:
            for r in rows:
                entity_type = str(r.get("entity_type", "")).strip().lower()
                entity_value = str(r.get("entity_value", "")).strip()
                if not entity_type or not entity_value:
                    continue
                source_plugin = str(r.get("source_plugin", "")).strip()
                source_endpoint = _normalize_endpoint(str(r.get("source_endpoint", "")).strip())
                confidence_score = float(r.get("confidence_score", 0) or 0)
                metadata = r.get("metadata", {}) if isinstance(r.get("metadata"), dict) else {}
                metadata["financial_flow"] = True
                cur.execute(
                    """
                    insert into financial_entities
                    (run_id, target, entity_type, entity_value, source_plugin, source_endpoint, confidence_score, metadata)
                    values (%s,%s,%s,%s,%s,%s,%s,%s::jsonb)
                    on conflict (target, entity_type, entity_value, source_plugin, source_endpoint)
                    do update set
                      run_id=excluded.run_id,
                      confidence_score=greatest(financial_entities.confidence_score, excluded.confidence_score),
                      metadata=excluded.metadata,
                      last_seen=now()
                    """,
                    (
                        run_id,
                        target,
                        entity_type,
                        entity_value[:512],
                        source_plugin,
                        source_endpoint,
                        confidence_score,
                        json.dumps(metadata, ensure_ascii=True),
                    ),
                )
                inserted += 1
        self._conn.commit()
        return inserted

    def list_recent_entities(self, target: str, limit: int = 200, entity_types: list[str] | None = None) -> list[dict[str, Any]]:
        if not self.enabled:
            return []
        if self._conn is None or getattr(self._conn, "closed", False):
            self.connect()
        assert self._conn is not None
        out: list[dict[str, Any]] = []
        safe_limit = max(1, min(int(limit), 5000))
        with self._conn.cursor() as cur:
            if entity_types:
                kinds = [str(x).strip().lower() for x in entity_types if str(x).strip()]
                cur.execute(
                    """
                    select entity_type, entity_value, source_plugin, source_endpoint, confidence_score, metadata
                    from discovered_entities
                    where target=%s and entity_type = any(%s::text[])
                    order by last_seen desc
                    limit %s
                    """,
                    (target, kinds, safe_limit),
                )
            else:
                cur.execute(
                    """
                    select entity_type, entity_value, source_plugin, source_endpoint, confidence_score, metadata
                    from discovered_entities
                    where target=%s
                    order by last_seen desc
                    limit %s
                    """,
                    (target, safe_limit),
                )
            rows = cur.fetchall()
            for row in rows:
                out.append(
                    {
                        "entity_type": str(row[0] or ""),
                        "entity_value": str(row[1] or ""),
                        "source_plugin": str(row[2] or ""),
                        "source_endpoint": str(row[3] or ""),
                        "confidence_score": float(row[4] or 0),
                        "metadata": row[5] if isinstance(row[5], dict) else {},
                    }
                )
        return out

    def list_financial_entities(self, target: str, limit: int = 200) -> list[dict[str, Any]]:
        if not self.enabled:
            return []
        if self._conn is None or getattr(self._conn, "closed", False):
            self.connect()
        assert self._conn is not None
        out: list[dict[str, Any]] = []
        safe_limit = max(1, min(int(limit), 5000))
        with self._conn.cursor() as cur:
            cur.execute(
                """
                select entity_type, entity_value, source_plugin, source_endpoint, confidence_score, metadata
                from financial_entities
                where target=%s
                order by last_seen desc
                limit %s
                """,
                (target, safe_limit),
            )
            rows = cur.fetchall()
            for row in rows:
                out.append(
                    {
                        "entity_type": str(row[0] or ""),
                        "entity_value": str(row[1] or ""),
                        "source_plugin": str(row[2] or ""),
                        "source_endpoint": str(row[3] or ""),
                        "confidence_score": float(row[4] or 0),
                        "metadata": row[5] if isinstance(row[5], dict) else {},
                    }
                )
        return out

    def list_endpoint_parameters(self, run_id: str, limit: int = 1000) -> list[dict[str, Any]]:
        if not self.enabled:
            return []
        if self._conn is None or getattr(self._conn, "closed", False):
            self.connect()
        assert self._conn is not None
        out: list[dict[str, Any]] = []
        safe_limit = max(1, min(int(limit), 20000))
        with self._conn.cursor() as cur:
            cur.execute(
                """
                select endpoint, method, param_name, param_location, param_type, risk_score
                from endpoint_parameters
                where run_id=%s
                order by risk_score desc, id desc
                limit %s
                """,
                (run_id, safe_limit),
            )
            rows = cur.fetchall()
            for row in rows:
                out.append(
                    {
                        "endpoint": str(row[0] or ""),
                        "method": str(row[1] or "GET"),
                        "param_name": str(row[2] or ""),
                        "param_location": str(row[3] or "query"),
                        "param_type": str(row[4] or "string"),
                        "risk_score": float(row[5] or 0),
                    }
                )
        return out

    def list_known_endpoints(self, target: str, run_id: str = "", limit: int = 500) -> list[str]:
        if not self.enabled:
            return []
        if self._conn is None or getattr(self._conn, "closed", False):
            self.connect()
        assert self._conn is not None
        safe_limit = max(1, min(int(limit), 5000))
        out: set[str] = set()
        with self._conn.cursor() as cur:
            cur.execute(
                """
                select node_key
                from attack_graph_nodes
                where target=%s and node_type='endpoint'
                order by id desc
                limit %s
                """,
                (target, safe_limit),
            )
            for row in cur.fetchall():
                ep = _normalize_endpoint(str(row[0] or ""))
                if ep:
                    out.add(ep)

            if run_id:
                cur.execute(
                    """
                    select endpoint
                    from endpoint_parameters
                    where run_id=%s
                    order by id desc
                    limit %s
                    """,
                    (run_id, safe_limit),
                )
                for row in cur.fetchall():
                    ep = _normalize_endpoint(str(row[0] or ""))
                    if ep:
                        out.add(ep)

            cur.execute(
                """
                select payload
                from hunterops_findings
                where target=%s
                order by id desc
                limit %s
                """,
                (target, safe_limit),
            )
            rows = cur.fetchall()
            for row in rows:
                payload = row[0] if row else {}
                data: dict[str, Any] = {}
                if isinstance(payload, dict):
                    data = payload
                else:
                    try:
                        maybe = json.loads(str(payload))
                        if isinstance(maybe, dict):
                            data = maybe
                    except Exception:
                        data = {}
                if not data:
                    continue
                evidence = data.get("evidence", {}) if isinstance(data.get("evidence"), dict) else {}
                for k in ("url", "base_url", "modified_url", "endpoint", "path"):
                    v = evidence.get(k)
                    if isinstance(v, str):
                        ep = _normalize_endpoint(v)
                        if ep:
                            out.add(ep)
                req = evidence.get("request", {}) if isinstance(evidence.get("request"), dict) else {}
                req_url = req.get("url")
                if isinstance(req_url, str):
                    ep = _normalize_endpoint(req_url)
                    if ep:
                        out.add(ep)
                arr = evidence.get("endpoints", [])
                if isinstance(arr, list):
                    for item in arr:
                        if isinstance(item, str):
                            ep = _normalize_endpoint(item)
                            if ep:
                                out.add(ep)
        normalized = sorted([x for x in out if x and x.startswith("/")])
        return normalized[:safe_limit]

    def get_previous_run_id(self, target: str, current_run_id: str) -> str:
        if not self.enabled:
            return ""
        if self._conn is None or getattr(self._conn, "closed", False):
            self.connect()
        assert self._conn is not None
        with self._conn.cursor() as cur:
            cur.execute(
                """
                select run_id
                from hunterops_findings
                where target=%s and run_id<>%s
                order by id desc
                limit 1
                """,
                (target, current_run_id),
            )
            row = cur.fetchone()
        if not row:
            return ""
        return str(row[0] or "")

    def fetch_run_findings(self, run_id: str, target: str) -> list[dict[str, Any]]:
        if not self.enabled:
            return []
        if self._conn is None or getattr(self._conn, "closed", False):
            self.connect()
        assert self._conn is not None
        out: list[dict[str, Any]] = []
        with self._conn.cursor() as cur:
            cur.execute(
                """
                select payload
                from hunterops_findings
                where run_id=%s and target=%s
                order by id asc
                """,
                (run_id, target),
            )
            rows = cur.fetchall()
            for row in rows:
                payload = row[0] if row else {}
                if isinstance(payload, dict):
                    out.append(payload)
                else:
                    try:
                        out.append(json.loads(str(payload)))
                    except Exception:
                        continue
        return out

    def fetch_run_findings_all(self, run_id: str) -> list[dict[str, Any]]:
        if not self.enabled:
            return []
        if self._conn is None or getattr(self._conn, "closed", False):
            self.connect()
        assert self._conn is not None
        out: list[dict[str, Any]] = []
        with self._conn.cursor() as cur:
            cur.execute(
                """
                select payload
                from hunterops_findings
                where run_id=%s
                order by id asc
                """,
                (run_id,),
            )
            rows = cur.fetchall()
            for row in rows:
                payload = row[0] if row else {}
                if isinstance(payload, dict):
                    out.append(payload)
                else:
                    try:
                        out.append(json.loads(str(payload)))
                    except Exception:
                        continue
        return out

    def upsert_triage_queue_rows(self, *, run_id: str, rows: list[dict[str, Any]], status: str = "review") -> int:
        if not self.enabled:
            return 0
        if self._conn is None or getattr(self._conn, "closed", False):
            self.connect()
        assert self._conn is not None
        normalized_status = str(status or "review").strip().lower() or "review"
        total = 0
        with self._conn.cursor() as cur:
            for row in rows:
                if not isinstance(row, dict):
                    continue
                payload = row.copy()
                metadata = payload.get("metadata", {}) if isinstance(payload.get("metadata"), dict) else {}
                evidence = payload.get("evidence", {}) if isinstance(payload.get("evidence"), dict) else {}
                finding_key = _triage_finding_key(payload)
                endpoint = _normalize_endpoint(
                    str(
                        payload.get("endpoint", "")
                        or evidence.get("endpoint", "")
                        or evidence.get("path", "")
                        or evidence.get("url", "")
                        or ""
                    )
                )
                parameter_name = str(
                    payload.get("parameter_name", "")
                    or metadata.get("parameter_name", metadata.get("parameter", ""))
                    or evidence.get("tested_parameter", "")
                ).strip()
                source = str(metadata.get("source", metadata.get("discovery_source", ""))).strip()
                evidence_path = str(
                    evidence.get("evidence_path", evidence.get("response_file", evidence.get("report_path", "")))
                ).strip()
                confidence = float(
                    metadata.get(
                        "confidence_score",
                        metadata.get("confidence", evidence.get("confidence_score", evidence.get("confidence", 0))),
                    )
                    or 0
                )
                impact = float(metadata.get("impact", evidence.get("impact_score", evidence.get("impact", 0))) or 0)
                cur.execute(
                    """
                    insert into triage_queue
                    (run_id, finding_key, target, plugin, category, severity, title, endpoint, parameter_name,
                     confidence_score, impact_score, status, source, evidence_path, validator_note, payload)
                    values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb)
                    on conflict (run_id, finding_key)
                    do update set
                      target=excluded.target,
                      plugin=excluded.plugin,
                      category=excluded.category,
                      severity=excluded.severity,
                      title=excluded.title,
                      endpoint=excluded.endpoint,
                      parameter_name=excluded.parameter_name,
                      confidence_score=excluded.confidence_score,
                      impact_score=excluded.impact_score,
                      status=case
                        when triage_queue.status='actionable' and excluded.status='review' then triage_queue.status
                        else excluded.status
                      end,
                      source=excluded.source,
                      evidence_path=excluded.evidence_path,
                      payload=excluded.payload,
                      updated_at=now()
                    """,
                    (
                        run_id,
                        finding_key,
                        str(payload.get("target", "")).strip(),
                        str(payload.get("plugin", "")).strip(),
                        str(payload.get("category", "")).strip(),
                        str(payload.get("severity", "")).strip(),
                        str(payload.get("title", "")).strip(),
                        endpoint,
                        parameter_name,
                        confidence,
                        impact,
                        normalized_status,
                        source,
                        evidence_path,
                        "",
                        json.dumps(payload, ensure_ascii=True),
                    ),
                )
                total += 1
        self._conn.commit()
        return total

    def list_triage_review_candidates(
        self,
        *,
        run_id: str,
        min_confidence: float,
        min_impact: float,
        min_severity: str,
        limit: int,
    ) -> list[dict[str, Any]]:
        if not self.enabled:
            return []
        if self._conn is None or getattr(self._conn, "closed", False):
            self.connect()
        assert self._conn is not None
        severity_rank = _severity_rank_value(min_severity)
        safe_limit = max(1, int(limit or 1))
        out: list[dict[str, Any]] = []
        with self._conn.cursor() as cur:
            cur.execute(
                """
                select finding_key, target, endpoint, severity, confidence_score, impact_score, payload
                from triage_queue
                where run_id=%s
                  and status='review'
                  and confidence_score >= %s
                  and impact_score >= %s
                  and (
                    case lower(severity)
                      when 'critical' then 4
                      when 'high' then 3
                      when 'medium' then 2
                      when 'low' then 1
                      else 0
                    end
                  ) >= %s
                order by confidence_score desc, impact_score desc, id asc
                limit %s
                """,
                (
                    run_id,
                    float(min_confidence or 0),
                    float(min_impact or 0),
                    int(severity_rank),
                    safe_limit,
                ),
            )
            for finding_key, target, endpoint, severity, confidence_score, impact_score, payload in cur.fetchall():
                parsed_payload = payload if isinstance(payload, dict) else {}
                if not isinstance(parsed_payload, dict):
                    with contextlib.suppress(Exception):
                        parsed_payload = json.loads(str(payload))
                out.append(
                    {
                        "finding_key": str(finding_key or ""),
                        "target": str(target or ""),
                        "endpoint": str(endpoint or ""),
                        "severity": str(severity or ""),
                        "confidence_score": float(confidence_score or 0),
                        "impact_score": float(impact_score or 0),
                        "payload": parsed_payload if isinstance(parsed_payload, dict) else {},
                    }
                )
        return out

    def mark_triage_candidate_validation_failed(
        self,
        *,
        run_id: str,
        finding_key: str,
        note: str,
    ) -> None:
        if not self.enabled:
            return
        if self._conn is None or getattr(self._conn, "closed", False):
            self.connect()
        assert self._conn is not None
        with self._conn.cursor() as cur:
            cur.execute(
                """
                update triage_queue
                set status='review',
                    source='shannon_validation',
                    validator_note=%s,
                    updated_at=now()
                where run_id=%s and finding_key=%s
                """,
                (str(note or ""), run_id, str(finding_key or "")),
            )
        self._conn.commit()

    def promote_triage_candidate_with_validation(
        self,
        *,
        run_id: str,
        finding_key: str,
        confidence_delta: float,
        evidence_path: str,
        validator_note: str = "",
    ) -> bool:
        if not self.enabled:
            return False
        if self._conn is None or getattr(self._conn, "closed", False):
            self.connect()
        assert self._conn is not None
        try:
            with self._conn.cursor() as cur:
                cur.execute(
                    """
                    select payload, target, plugin, category, severity, title, endpoint, parameter_name, confidence_score
                    from triage_queue
                    where run_id=%s and finding_key=%s
                    for update
                    """,
                    (run_id, str(finding_key or "")),
                )
                row = cur.fetchone()
                if not row:
                    self._conn.rollback()
                    return False
                payload_raw, target, plugin, category, severity, title, endpoint, parameter_name, queue_confidence = row
                payload = payload_raw if isinstance(payload_raw, dict) else {}
                if not isinstance(payload, dict):
                    with contextlib.suppress(Exception):
                        payload = json.loads(str(payload_raw))
                if not isinstance(payload, dict):
                    payload = {}

                metadata = payload.get("metadata", {}) if isinstance(payload.get("metadata"), dict) else {}
                evidence = payload.get("evidence", {}) if isinstance(payload.get("evidence"), dict) else {}
                metadata = metadata.copy()
                evidence = evidence.copy()
                metadata["source"] = "shannon_validation"
                metadata["validation_source"] = "shannon_validation"
                metadata["confidence_delta"] = float(confidence_delta or 0.0)
                if validator_note:
                    metadata["validator_note"] = str(validator_note)
                evidence["evidence_path"] = str(evidence_path or "")
                payload["metadata"] = metadata
                payload["evidence"] = evidence

                existing_confidence = float(
                    metadata.get("confidence_score", metadata.get("confidence", queue_confidence))
                    or queue_confidence
                    or 0
                )
                final_confidence = max(0.0, min(100.0, existing_confidence + float(confidence_delta or 0.0)))
                metadata["confidence_score"] = final_confidence
                payload["metadata"] = metadata

                cur.execute(
                    """
                    update triage_queue
                    set status='actionable',
                        source='shannon_validation',
                        evidence_path=%s,
                        validator_note=%s,
                        confidence_score=%s,
                        payload=%s::jsonb,
                        updated_at=now()
                    where run_id=%s and finding_key=%s
                    """,
                    (
                        str(evidence_path or ""),
                        str(validator_note or ""),
                        float(final_confidence),
                        json.dumps(payload, ensure_ascii=True),
                        run_id,
                        str(finding_key or ""),
                    ),
                )

                cur.execute(
                    """
                    insert into verified_findings
                    (run_id, target, plugin, category, severity, title, confidence_score, impact_analysis, endpoint, parameter_name, poc_path, curl_command, metadata, evidence_json)
                    values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s::jsonb)
                    on conflict (run_id, target, plugin, category, title, endpoint, parameter_name)
                    do update set
                      severity=excluded.severity,
                      confidence_score=greatest(verified_findings.confidence_score, excluded.confidence_score),
                      impact_analysis=excluded.impact_analysis,
                      poc_path=excluded.poc_path,
                      curl_command=excluded.curl_command,
                      metadata=excluded.metadata,
                      evidence_json=excluded.evidence_json
                    """,
                    (
                        run_id,
                        str(target or payload.get("target", "")).strip(),
                        str(plugin or payload.get("plugin", "")).strip(),
                        str(category or payload.get("category", "")).strip(),
                        str(severity or payload.get("severity", "medium")).strip(),
                        str(title or payload.get("title", "")).strip(),
                        float(final_confidence),
                        "Validated by shannon_validation adapter",
                        _normalize_endpoint(str(endpoint or "")),
                        str(parameter_name or ""),
                        str(evidence_path or ""),
                        "",
                        json.dumps(metadata, ensure_ascii=True),
                        json.dumps(evidence, ensure_ascii=True),
                    ),
                )
            self._conn.commit()
            return True
        except Exception:
            with contextlib.suppress(Exception):
                self._conn.rollback()
            raise

    def mark_verified_vulnerability_chain(
        self,
        *,
        run_id: str,
        target: str,
        endpoint: str,
        relation: str = "verified_vulnerability_chain",
        confidence_score: float = 95.0,
        metadata: dict[str, Any] | None = None,
        evidence_ref: str = "",
    ) -> None:
        if not self.enabled:
            return
        ep = _normalize_endpoint(endpoint)
        if not ep:
            return
        edge_metadata = metadata if isinstance(metadata, dict) else {}
        self.upsert_attack_graph_edges(
            run_id=run_id,
            target=target,
            edges=[
                {
                    "src_type": "endpoint",
                    "src_key": ep,
                    "dst_type": "state",
                    "dst_key": "verified_vulnerability_chain",
                    "edge_type": relation,
                    "confidence_score": float(confidence_score or 0),
                    "evidence_ref": str(evidence_ref or ""),
                    "metadata": edge_metadata,
                }
            ],
            discovery_source="research_pipeline",
            confidence_score=float(confidence_score or 0),
        )

    def upsert_verified_finding(
        self,
        *,
        run_id: str,
        target: str,
        plugin: str,
        category: str,
        severity: str,
        title: str,
        confidence_score: float,
        impact_analysis: str,
        endpoint: str = "",
        parameter_name: str = "",
        poc_path: str = "",
        curl_command: str = "",
        metadata: dict[str, Any] | None = None,
        evidence: dict[str, Any] | None = None,
    ) -> None:
        if not self.enabled:
            return
        if self._conn is None or getattr(self._conn, "closed", False):
            self.connect()
        assert self._conn is not None
        md = metadata if isinstance(metadata, dict) else {}
        ev = evidence if isinstance(evidence, dict) else {}
        with self._conn.cursor() as cur:
            cur.execute(
                """
                insert into verified_findings
                (run_id, target, plugin, category, severity, title, confidence_score, impact_analysis, endpoint, parameter_name, poc_path, curl_command, metadata, evidence_json)
                values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s::jsonb)
                on conflict (run_id, target, plugin, category, title, endpoint, parameter_name)
                do update set
                  severity=excluded.severity,
                  confidence_score=greatest(verified_findings.confidence_score, excluded.confidence_score),
                  impact_analysis=excluded.impact_analysis,
                  poc_path=excluded.poc_path,
                  curl_command=excluded.curl_command,
                  metadata=excluded.metadata,
                  evidence_json=excluded.evidence_json
                """,
                (
                    run_id,
                    target,
                    plugin,
                    category,
                    severity,
                    title,
                    float(confidence_score or 0),
                    str(impact_analysis or ""),
                    _normalize_endpoint(endpoint),
                    str(parameter_name or ""),
                    str(poc_path or ""),
                    str(curl_command or ""),
                    json.dumps(md, ensure_ascii=True),
                    json.dumps(ev, ensure_ascii=True),
                ),
            )
        self._conn.commit()

    def get_h1_sync_state(self, sync_key: str) -> dict[str, Any]:
        if not self.enabled:
            return {}
        if self._conn is None or getattr(self._conn, "closed", False):
            self.connect()
        assert self._conn is not None
        with self._conn.cursor() as cur:
            cur.execute(
                """
                select sync_key, last_synced_at, payload
                from h1_sync_state
                where sync_key=%s
                limit 1
                """,
                (str(sync_key or "").strip(),),
            )
            row = cur.fetchone()
        if not row:
            return {}
        payload = row[2] if isinstance(row[2], dict) else {}
        return {
            "sync_key": str(row[0] or ""),
            "last_synced_at": row[1],
            "payload": payload,
        }

    def upsert_h1_sync_state(self, *, sync_key: str, payload: dict[str, Any]) -> None:
        if not self.enabled:
            return
        if self._conn is None or getattr(self._conn, "closed", False):
            self.connect()
        assert self._conn is not None
        body = payload if isinstance(payload, dict) else {}
        with self._conn.cursor() as cur:
            cur.execute(
                """
                insert into h1_sync_state (sync_key, last_synced_at, payload, updated_at)
                values (%s, now(), %s::jsonb, now())
                on conflict (sync_key)
                do update set
                  last_synced_at=excluded.last_synced_at,
                  payload=excluded.payload,
                  updated_at=now()
                """,
                (
                    str(sync_key or "").strip(),
                    json.dumps(body, ensure_ascii=True),
                ),
            )
        self._conn.commit()
