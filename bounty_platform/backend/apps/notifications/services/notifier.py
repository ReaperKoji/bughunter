from __future__ import annotations

import os

import httpx


def notify_discord(message: str) -> bool:
    webhook = os.getenv("DISCORD_WEBHOOK_URL", "").strip()
    if not webhook:
        return False
    resp = httpx.post(webhook, json={"content": message}, timeout=8.0)
    return resp.status_code in {200, 204}


def notify_telegram(message: str) -> bool:
    bot = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    chat_id = os.getenv("TELEGRAM_CHAT_ID", "").strip()
    if not bot or not chat_id:
        return False
    url = f"https://api.telegram.org/bot{bot}/sendMessage"
    resp = httpx.post(url, json={"chat_id": chat_id, "text": message}, timeout=8.0)
    return resp.status_code == 200


def notify_high_critical(*, title: str, severity: str, target: str, reproduction_command: str) -> dict[str, bool]:
    sev = str(severity).strip().lower()
    if sev not in {"high", "critical"}:
        return {"discord": False, "telegram": False}

    message = (
        f"[{sev.upper()}] {title}\n"
        f"Target: {target}\n"
        f"Repro: {reproduction_command}"
    )
    return {
        "discord": notify_discord(message),
        "telegram": notify_telegram(message),
    }
