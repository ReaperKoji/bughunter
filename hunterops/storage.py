from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from hunterops.runtime_paths import chmod_if_posix, secure_secret_file


def _normalize_endpoint(value: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    if raw.startswith("http://") or raw.startswith("https://"):
        parsed = urlparse(raw)
        return parsed.path or "/"
    if "://" in raw:
        parsed = urlparse(raw)
        return parsed.path or "/"
    if raw.startswith("/"):
        return raw
    return f"/{raw}"


_DSN_FILE_HINT_RE = re.compile(r"""(?:sslkey|sslcert|sslrootcert)=([^&\s]+)""", re.IGNORECASE)
FINANCIAL_ENTITY_MARKERS = ("invoice", "transaction", "wallet")
FINANCIAL_ENTITY_TYPES = {"invoice_id", "transaction_id", "wallet_id", "invoice", "transaction", "wallet"}


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


class PostgresStorage:
    def __init__(self, dsn: str, enabled: bool = False) -> None:
        self.dsn = dsn
        self.enabled = enabled
        self._conn = None

    def connect(self) -> None:
        if not self.enabled:
            return
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
        self._conn.commit()

    def write_findings(self, run_id: str, rows: list[dict[str, Any]]) -> None:
        if not self.enabled:
            return
        if self._conn is None:
            self.connect()
        assert self._conn is not None
        with self._conn.cursor() as cur:
            for r in rows:
                cur.execute(
                    """
                    insert into hunterops_findings
                    (run_id, plugin, target, category, severity, title, risk_score, discovery_source, confidence_score, payload)
                    values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb)
                    """,
                    (
                        run_id,
                        r.get("plugin", ""),
                        r.get("target", ""),
                        r.get("category", ""),
                        r.get("severity", ""),
                        r.get("title", ""),
                        float(r.get("risk_score", 0)),
                        str((r.get("metadata", {}) or {}).get("discovery_source", "")),
                        float((r.get("metadata", {}) or {}).get("confidence_score", (r.get("metadata", {}) or {}).get("confidence", 0))),
                        json.dumps(r, ensure_ascii=True),
                    ),
                )
        self._conn.commit()

    def ensure_research_schema(self) -> None:
        if not self.enabled:
            return
        if self._conn is None:
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
                create table if not exists h1_sync_state (
                  sync_key text primary key,
                  last_synced_at timestamptz not null default now(),
                  payload jsonb not null default '{}'::jsonb,
                  updated_at timestamptz not null default now()
                )
                """
            )
        self._conn.commit()

    def was_endpoint_scanned(self, run_id: str, plugin: str, target: str, endpoint: str) -> bool:
        if not self.enabled:
            return False
        if self._conn is None:
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
        if self._conn is None:
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
        if self._conn is None:
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
        if self._conn is None:
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
        if self._conn is None:
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
        if self._conn is None:
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
        if self._conn is None:
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
        if self._conn is None:
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
        if self._conn is None:
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
        if self._conn is None:
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
        if self._conn is None:
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
        if self._conn is None:
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
        if self._conn is None:
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
        if self._conn is None:
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
        if self._conn is None:
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
        if self._conn is None:
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
        if self._conn is None:
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
        if self._conn is None:
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
