from __future__ import annotations

import asyncio
import json
from typing import Any

from fastapi import FastAPI, Query, Body
from fastapi.responses import RedirectResponse

app = FastAPI(title="HunterOps Mock API")

_USERS: dict[int, dict[str, Any]] = {
    1: {"user_id": 1, "email": "owner@example.com", "role": "user"},
    2: {"user_id": 2, "email": "victim@example.com", "role": "user"},
}
_WALLET_STATE = {"balance": 10, "withdraw_count": 0}
_UUID_STORE = {
    "11111111-1111-1111-1111-111111111111": {"uuid": "11111111-1111-1111-1111-111111111111", "owner": "user_a"},
    "22222222-2222-2222-2222-222222222222": {"uuid": "22222222-2222-2222-2222-222222222222", "owner": "user_b"},
}


@app.get("/api/v1/profile")
async def idor_profile(user_id: int = Query(...)) -> dict[str, Any]:
    # Intentionally vulnerable: no ownership check.
    return _USERS.get(user_id, {"user_id": user_id, "email": "unknown@example.com"})


@app.get("/api/cart")
async def cart(price: float = Query(100.0), quantity: int = Query(1)) -> dict[str, Any]:
    # Intentionally vulnerable: accepts negative and near-zero values.
    total = price * quantity
    return {
        "status": "success",
        "price": price,
        "quantity": quantity,
        "total": total,
        "transaction_id": f"txn_{abs(int(total * 10))}",
    }


@app.get("/api/success")
async def success() -> dict[str, Any]:
    # Intentionally vulnerable state machine endpoint.
    return {"status": "success", "message": "order confirmed without payment"}


@app.get("/api/wallet/withdraw")
async def withdraw(amount: int = Query(1)) -> dict[str, Any]:
    # Intentionally vulnerable: check/use race by delaying deduction.
    if amount <= 0:
        return {"ok": False, "error": "invalid amount"}
    if _WALLET_STATE["balance"] < amount:
        return {"ok": False, "error": "insufficient"}
    await asyncio.sleep(0.025)
    _WALLET_STATE["balance"] -= amount
    _WALLET_STATE["withdraw_count"] += 1
    return {
        "ok": True,
        "balance": _WALLET_STATE["balance"],
        "transaction_id": f"wallet_{_WALLET_STATE['withdraw_count']}",
    }


@app.get("/api/coupon/apply")
async def coupon_apply(coupon: list[str] = Query(default=[])) -> dict[str, Any]:
    # Intentionally vulnerable: accepts stacked coupon arrays.
    discount = len(coupon) * 10
    return {"status": "success", "coupon_count": len(coupon), "discount": discount}


@app.post("/api/transfer")
async def transfer(payload: dict[str, Any] = Body(default={})) -> dict[str, Any]:
    # Simulated IDOR via body: different accounts return different data.
    source = payload.get("from", "acct_1")
    if source == "acct_1":
        return {"status": "ok", "account": source, "balance": 100, "email": "owner@example.com"}
    return {"status": "ok", "account": source, "balance": 50, "email": "victim@example.com"}


@app.post("/api/render")
async def render(payload: dict[str, Any] = Body(default={})) -> dict[str, Any]:
    value = json.dumps(payload)
    if "{{7*7}}HOPS" in value:
        return {"rendered": "49HOPS"}
    return {"rendered": "safe"}


@app.post("/api/search")
async def search(payload: dict[str, Any] = Body(default={})) -> dict[str, Any]:
    q = str(payload.get("q", ""))
    return {"results": [q]}


@app.post("/api/file")
async def file_read(payload: dict[str, Any] = Body(default={})) -> dict[str, Any]:
    path = str(payload.get("path", ""))
    if "../../../../etc/hosts" in path:
        return {"content": "127.0.0.1 localhost"}
    return {"content": "not found"}


@app.post("/api/redirect")
async def redirect(payload: dict[str, Any] = Body(default={})) -> RedirectResponse:
    url = str(payload.get("url", "https://example.com"))
    return RedirectResponse(url=url, status_code=302)


@app.post("/api/ssrf")
async def ssrf(payload: dict[str, Any] = Body(default={})) -> dict[str, Any]:
    url = str(payload.get("url", ""))
    if "169.254.169.254" in url:
        return {"meta": "instance-id: i-123"}
    return {"meta": "none"}


@app.get("/api/baseline")
async def baseline_get() -> dict[str, Any]:
    return {"ok": True, "value": "same"}


@app.post("/api/baseline")
async def baseline_post(payload: dict[str, Any] = Body(default={})) -> dict[str, Any]:
    return {"ok": True, "value": "same"}


@app.get("/api/baseline-diff")
async def baseline_diff_get() -> dict[str, Any]:
    return {"ok": True, "value": "get"}


@app.post("/api/baseline-diff")
async def baseline_diff_post(payload: dict[str, Any] = Body(default={})) -> dict[str, Any]:
    return {"ok": True, "value": "post"}


@app.get("/api/resource/{item_id}")
async def resource(item_id: str) -> dict[str, Any]:
    return _UUID_STORE.get(item_id, {"uuid": item_id, "owner": "unknown"})
