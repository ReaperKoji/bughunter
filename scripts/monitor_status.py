#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import os
import shutil
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import psycopg

from hunterops.secrets import read_secret

def _env(name: str, default: str = "") -> str:
    value = read_secret(name, default=default)
    return str(value).strip()


def _build_dsn() -> str:
    direct = _env("HUNTEROPS_POSTGRES_DSN")
    if direct:
        return direct
    user = _env("POSTGRES_USER", "hunter")
    pwd = _env("POSTGRES_PASSWORD", "hunter")
    db = _env("POSTGRES_DB", "hunterops")
    host = _env("POSTGRES_HOST", "db")
    port = _env("POSTGRES_PORT", "5432")
    return f"postgresql://{user}:{pwd}@{host}:{port}/{db}"


def _find_findings_table(conn: psycopg.Connection[Any]) -> str:
    with conn.cursor() as cur:
        cur.execute("select to_regclass('public.findings'), to_regclass('public.hunterops_findings')")
        row = cur.fetchone()
    findings = str(row[0] or "") if row else ""
    hunterops_findings = str(row[1] or "") if row else ""
    if findings and findings != "None":
        return "findings"
    if hunterops_findings and hunterops_findings != "None":
        return "hunterops_findings"
    return "hunterops_findings"


def _table_exists(conn: psycopg.Connection[Any], table_name: str) -> bool:
    with conn.cursor() as cur:
        cur.execute("select to_regclass(%s)", (f"public.{table_name}",))
        row = cur.fetchone()
    return bool(row and row[0])


@dataclass
class MonitorStats:
    total_findings: int
    new_findings: int
    total_entities: int
    new_entities: int
    last_finding_at: datetime | None
    last_entity_at: datetime | None
    error_429_count: int
    disk_used_pct: float
    ram_used_pct: float


def _ram_usage_pct() -> float:
    meminfo = Path("/proc/meminfo")
    if not meminfo.exists():
        return 0.0
    total_kb = 0.0
    available_kb = 0.0
    for line in meminfo.read_text(encoding="utf-8", errors="ignore").splitlines():
        if line.startswith("MemTotal:"):
            total_kb = float(line.split()[1])
        elif line.startswith("MemAvailable:"):
            available_kb = float(line.split()[1])
    if total_kb <= 0:
        return 0.0
    used = max(0.0, total_kb - available_kb)
    return round((used / total_kb) * 100.0, 2)


def _disk_usage_pct(path: Path) -> float:
    usage = shutil.disk_usage(path)
    if usage.total <= 0:
        return 0.0
    return round((usage.used / usage.total) * 100.0, 2)


def collect_stats(*, dsn: str, window_hours: float, data_path: Path) -> MonitorStats:
    interval = f"{max(1, int(round(window_hours)))} hours"
    with psycopg.connect(dsn, connect_timeout=8) as conn:
        findings_table = _find_findings_table(conn)
        entities_exists = _table_exists(conn, "discovered_entities")
        with conn.cursor() as cur:
            cur.execute(f"select count(*) from {findings_table}")
            total_findings = int((cur.fetchone() or [0])[0] or 0)

            cur.execute(f"select count(*) from {findings_table} where created_at >= now() - (%s)::interval", (interval,))
            new_findings = int((cur.fetchone() or [0])[0] or 0)

            cur.execute(f"select max(created_at) from {findings_table}")
            last_finding_at = cur.fetchone()
            last_finding = last_finding_at[0] if last_finding_at else None

            total_entities = 0
            new_entities = 0
            last_entity = None
            if entities_exists:
                cur.execute("select count(*) from discovered_entities")
                total_entities = int((cur.fetchone() or [0])[0] or 0)
                cur.execute(
                    """
                    select count(*)
                    from discovered_entities
                    where coalesce(last_seen, first_seen, now()) >= now() - (%s)::interval
                    """,
                    (interval,),
                )
                new_entities = int((cur.fetchone() or [0])[0] or 0)
                cur.execute("select max(coalesce(last_seen, first_seen)) from discovered_entities")
                last_entity_row = cur.fetchone()
                last_entity = last_entity_row[0] if last_entity_row else None

            cur.execute(
                f"""
                select count(*)
                from {findings_table}
                where created_at >= now() - (%s)::interval
                  and (
                    payload::text ilike '%"status": 429%'
                    or payload::text ilike '%feedback_retry_429%'
                    or payload::text ilike '%status=429%'
                  )
                """,
                (interval,),
            )
            error_429_count = int((cur.fetchone() or [0])[0] or 0)

    return MonitorStats(
        total_findings=total_findings,
        new_findings=new_findings,
        total_entities=total_entities,
        new_entities=new_entities,
        last_finding_at=last_finding,
        last_entity_at=last_entity,
        error_429_count=error_429_count,
        disk_used_pct=_disk_usage_pct(data_path),
        ram_used_pct=_ram_usage_pct(),
    )


def _format_message(stats: MonitorStats, window_hours: float, *, deadman_triggered: bool) -> str:
    stamp = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    prefix = "DEADMAN ALERT | " if deadman_triggered else ""
    latest_activity = None
    for candidate in (stats.last_finding_at, stats.last_entity_at):
        if candidate and (latest_activity is None or candidate > latest_activity):
            latest_activity = candidate
    latest_text = latest_activity.isoformat().replace("+00:00", "Z") if latest_activity else "n/a"
    return "\n".join(
        [
            f"{prefix}HunterOps Monitor | {stamp}",
            f"Window: last {window_hours:g}h",
            f"Total Findings: {stats.total_findings}",
            f"New Findings: {stats.new_findings}",
            f"New Entities: {stats.new_entities}",
            f"Total Entities: {stats.total_entities}",
            f"Last Activity: {latest_text}",
            f"429 Error Count: {stats.error_429_count}",
            f"Disk Used: {stats.disk_used_pct:.2f}%",
            f"RAM Used: {stats.ram_used_pct:.2f}%",
        ]
    )


async def _send_discord(webhook_url: str, message: str) -> None:
    if not webhook_url:
        return
    payload = {"username": "Pinguinho-Monitor", "content": message}
    async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
        response = await client.post(webhook_url, json=payload)
    if response.status_code >= 400:
        raise RuntimeError(f"discord_notify_failed status={response.status_code}")


async def _send_telegram(bot_token: str, chat_id: str, message: str) -> None:
    if not bot_token or not chat_id:
        return
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = {"chat_id": chat_id, "text": message}
    async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
        response = await client.post(url, json=payload)
    if response.status_code >= 400:
        raise RuntimeError(f"telegram_notify_failed status={response.status_code}")


async def dispatch_notifications(message: str) -> None:
    discord_url = _env("MONITOR_DISCORD_WEBHOOK", _env("DISCORD_WEBHOOK_URL", _env("HUNTEROPS_CRITICAL_WEBHOOK")))
    telegram_token = _env("TELEGRAM_BOT_TOKEN")
    telegram_chat = _env("TELEGRAM_CHAT_ID")

    tasks: list[asyncio.Task[Any]] = []
    if discord_url:
        tasks.append(asyncio.create_task(_send_discord(discord_url, message)))
    if telegram_token and telegram_chat:
        tasks.append(asyncio.create_task(_send_telegram(telegram_token, telegram_chat, message)))
    if not tasks:
        return
    await asyncio.gather(*tasks, return_exceptions=False)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="HunterOps monitoring status dispatcher")
    parser.add_argument("--interval-hours", type=float, default=float(_env("MONITOR_INTERVAL_HOURS", "6") or "6"))
    parser.add_argument("--deadman-hours", type=float, default=float(_env("MONITOR_DEADMAN_HOURS", _env("HUNTEROPS_DEADMAN_HOURS", "0")) or "0"))
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--health-check", action="store_true")
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--data-path", default=_env("HUNTEROPS_DATA_DIR", "/opt/hunterops/data"))
    return parser.parse_args()


async def run_loop(args: argparse.Namespace) -> int:
    dsn = _build_dsn()
    data_path = Path(args.data_path)
    data_path.mkdir(parents=True, exist_ok=True)

    if args.health_check:
        try:
            with psycopg.connect(dsn, connect_timeout=5) as conn:
                with conn.cursor() as cur:
                    cur.execute("select 1")
                    cur.fetchone()
            if not args.quiet:
                print("ok")
            return 0
        except Exception as err:
            if not args.quiet:
                print(f"healthcheck_failed: {err}")
            return 1

    interval_seconds = max(300, int(args.interval_hours * 3600))
    deadman_hours = max(0.0, float(args.deadman_hours or 0))
    while True:
        try:
            stats = collect_stats(dsn=dsn, window_hours=args.interval_hours, data_path=data_path)
            deadman_triggered = False
            if deadman_hours > 0:
                latest_activity = None
                for candidate in (stats.last_finding_at, stats.last_entity_at):
                    if candidate and (latest_activity is None or candidate > latest_activity):
                        latest_activity = candidate
                if latest_activity and (stats.total_findings > 0 or stats.total_entities > 0):
                    age = datetime.now(UTC) - latest_activity.astimezone(UTC)
                    if age >= timedelta(hours=deadman_hours):
                        deadman_triggered = True
            message = _format_message(stats, args.interval_hours, deadman_triggered=deadman_triggered)
            await dispatch_notifications(message)
            if not args.quiet:
                print(message)
        except Exception as err:
            if not args.quiet:
                print(f"monitor_cycle_failed: {err}")
        if args.once:
            return 0
        await asyncio.sleep(interval_seconds)


def main() -> int:
    args = parse_args()
    try:
        return asyncio.run(run_loop(args))
    except KeyboardInterrupt:
        return 130
    except Exception as err:
        print(f"fatal_monitor_error: {err}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
