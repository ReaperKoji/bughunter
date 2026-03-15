from __future__ import annotations

import json
import sqlite3
import threading
from hashlib import sha256
from pathlib import Path
from typing import Any

from hunterops.types import Task


def compute_task_id(task: Task) -> str:
    payload = task.payload if isinstance(task.payload, dict) else {}
    raw = f"{task.plugin}|{task.target}|{json.dumps(payload, sort_keys=True, ensure_ascii=True)}"
    return sha256(raw.encode("utf-8")).hexdigest()


class BaseTaskStore:
    def enqueue_tasks(self, run_id: str, tasks: list[Task]) -> None:
        raise NotImplementedError

    def list_pending_tasks(self, run_id: str, limit: int | None = None) -> list[Task]:
        raise NotImplementedError

    def mark_started(self, run_id: str, task_id: str) -> None:
        raise NotImplementedError

    def mark_done(self, run_id: str, task_id: str) -> None:
        raise NotImplementedError

    def mark_failed(self, run_id: str, task_id: str, error: str = "") -> None:
        raise NotImplementedError

    def mark_skipped(self, run_id: str, task_id: str, reason: str = "") -> None:
        raise NotImplementedError

    def reset_in_progress(self, run_id: str) -> None:
        raise NotImplementedError


class SQLiteTaskStore(BaseTaskStore):
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._conn.execute("pragma journal_mode=wal")
        self._conn.execute("pragma synchronous=normal")
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        with self._lock:
            self._conn.execute(
                """
                create table if not exists hunterops_tasks (
                  run_id text not null,
                  task_id text not null,
                  plugin text not null,
                  target text not null,
                  payload text not null,
                  status text not null default 'pending',
                  attempts integer not null default 0,
                  last_error text default '',
                  created_at text default (datetime('now')),
                  updated_at text default (datetime('now')),
                  primary key (run_id, task_id)
                )
                """
            )
            self._conn.commit()

    def enqueue_tasks(self, run_id: str, tasks: list[Task]) -> None:
        if not run_id:
            return
        with self._lock:
            cur = self._conn.cursor()
            for task in tasks or []:
                task_id = task.task_id or compute_task_id(task)
                payload = task.payload if isinstance(task.payload, dict) else {}
                cur.execute(
                    """
                    insert or ignore into hunterops_tasks
                    (run_id, task_id, plugin, target, payload, status)
                    values (?, ?, ?, ?, ?, 'pending')
                    """,
                    (run_id, task_id, task.plugin, task.target, json.dumps(payload, ensure_ascii=True)),
                )
            self._conn.commit()

    def list_pending_tasks(self, run_id: str, limit: int | None = None) -> list[Task]:
        if not run_id:
            return []
        with self._lock:
            cur = self._conn.cursor()
            sql = """
                select task_id, plugin, target, payload
                from hunterops_tasks
                where run_id = ? and status != 'done'
                order by created_at asc
            """
            if limit is not None:
                sql += " limit ?"
                cur.execute(sql, (run_id, int(limit)))
            else:
                cur.execute(sql, (run_id,))
            rows = cur.fetchall()
        tasks: list[Task] = []
        for task_id, plugin, target, payload in rows:
            try:
                payload_doc = json.loads(payload) if payload else {}
            except Exception:
                payload_doc = {}
            tasks.append(Task(plugin=str(plugin), target=str(target), payload=payload_doc, task_id=str(task_id)))
        return tasks

    def mark_started(self, run_id: str, task_id: str) -> None:
        self._mark_status(run_id, task_id, "in_progress", increment=True)

    def mark_done(self, run_id: str, task_id: str) -> None:
        self._mark_status(run_id, task_id, "done", increment=False)

    def mark_failed(self, run_id: str, task_id: str, error: str = "") -> None:
        self._mark_status(run_id, task_id, "failed", error=error, increment=False)

    def mark_skipped(self, run_id: str, task_id: str, reason: str = "") -> None:
        self._mark_status(run_id, task_id, "skipped", error=reason, increment=False)

    def reset_in_progress(self, run_id: str) -> None:
        if not run_id:
            return
        with self._lock:
            self._conn.execute(
                "update hunterops_tasks set status='pending', updated_at=datetime('now') where run_id=? and status='in_progress'",
                (run_id,),
            )
            self._conn.commit()

    def _mark_status(self, run_id: str, task_id: str, status: str, error: str = "", increment: bool = False) -> None:
        if not run_id or not task_id:
            return
        with self._lock:
            if increment:
                self._conn.execute(
                    """
                    update hunterops_tasks
                    set status=?, attempts=attempts+1, last_error=?, updated_at=datetime('now')
                    where run_id=? and task_id=?
                    """,
                    (status, error, run_id, task_id),
                )
            else:
                self._conn.execute(
                    """
                    update hunterops_tasks
                    set status=?, last_error=?, updated_at=datetime('now')
                    where run_id=? and task_id=?
                    """,
                    (status, error, run_id, task_id),
                )
            self._conn.commit()


class PostgresTaskStore(BaseTaskStore):
    def __init__(self, storage: Any) -> None:
        self.storage = storage
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        if not self.storage or not getattr(self.storage, "enabled", False):
            return
        if self.storage._conn is None:
            self.storage.connect()
        conn = self.storage._conn
        if conn is None:
            return
        with conn.cursor() as cur:
            cur.execute(
                """
                create table if not exists hunterops_tasks (
                  run_id text not null,
                  task_id text not null,
                  plugin text not null,
                  target text not null,
                  payload jsonb not null,
                  status text not null default 'pending',
                  attempts integer not null default 0,
                  last_error text default '',
                  created_at timestamptz default now(),
                  updated_at timestamptz default now(),
                  primary key (run_id, task_id)
                )
                """
            )
        conn.commit()

    def enqueue_tasks(self, run_id: str, tasks: list[Task]) -> None:
        if not run_id or not self.storage or not getattr(self.storage, "enabled", False):
            return
        if self.storage._conn is None:
            self.storage.connect()
        conn = self.storage._conn
        if conn is None:
            return
        with conn.cursor() as cur:
            for task in tasks or []:
                task_id = task.task_id or compute_task_id(task)
                payload = task.payload if isinstance(task.payload, dict) else {}
                cur.execute(
                    """
                    insert into hunterops_tasks
                    (run_id, task_id, plugin, target, payload, status)
                    values (%s,%s,%s,%s,%s::jsonb,'pending')
                    on conflict do nothing
                    """,
                    (run_id, task_id, task.plugin, task.target, json.dumps(payload, ensure_ascii=True)),
                )
        conn.commit()

    def list_pending_tasks(self, run_id: str, limit: int | None = None) -> list[Task]:
        if not run_id or not self.storage or not getattr(self.storage, "enabled", False):
            return []
        if self.storage._conn is None:
            self.storage.connect()
        conn = self.storage._conn
        if conn is None:
            return []
        with conn.cursor() as cur:
            sql = """
                select task_id, plugin, target, payload
                from hunterops_tasks
                where run_id=%s and status != 'done'
                order by created_at asc
            """
            if limit is not None:
                sql += " limit %s"
                cur.execute(sql, (run_id, int(limit)))
            else:
                cur.execute(sql, (run_id,))
            rows = cur.fetchall()
        tasks: list[Task] = []
        for task_id, plugin, target, payload in rows:
            payload_doc = payload if isinstance(payload, dict) else {}
            tasks.append(Task(plugin=str(plugin), target=str(target), payload=payload_doc, task_id=str(task_id)))
        return tasks

    def mark_started(self, run_id: str, task_id: str) -> None:
        self._mark_status(run_id, task_id, "in_progress", increment=True)

    def mark_done(self, run_id: str, task_id: str) -> None:
        self._mark_status(run_id, task_id, "done", increment=False)

    def mark_failed(self, run_id: str, task_id: str, error: str = "") -> None:
        self._mark_status(run_id, task_id, "failed", error=error, increment=False)

    def mark_skipped(self, run_id: str, task_id: str, reason: str = "") -> None:
        self._mark_status(run_id, task_id, "skipped", error=reason, increment=False)

    def reset_in_progress(self, run_id: str) -> None:
        if not run_id or not self.storage or not getattr(self.storage, "enabled", False):
            return
        if self.storage._conn is None:
            self.storage.connect()
        conn = self.storage._conn
        if conn is None:
            return
        with conn.cursor() as cur:
            cur.execute(
                "update hunterops_tasks set status='pending', updated_at=now() where run_id=%s and status='in_progress'",
                (run_id,),
            )
        conn.commit()

    def _mark_status(self, run_id: str, task_id: str, status: str, error: str = "", increment: bool = False) -> None:
        if not run_id or not task_id or not self.storage or not getattr(self.storage, "enabled", False):
            return
        if self.storage._conn is None:
            self.storage.connect()
        conn = self.storage._conn
        if conn is None:
            return
        with conn.cursor() as cur:
            if increment:
                cur.execute(
                    """
                    update hunterops_tasks
                    set status=%s, attempts=attempts+1, last_error=%s, updated_at=now()
                    where run_id=%s and task_id=%s
                    """,
                    (status, error, run_id, task_id),
                )
            else:
                cur.execute(
                    """
                    update hunterops_tasks
                    set status=%s, last_error=%s, updated_at=now()
                    where run_id=%s and task_id=%s
                    """,
                    (status, error, run_id, task_id),
                )
        conn.commit()
