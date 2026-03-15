from __future__ import annotations

import asyncio
import random
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Dict

from hunterops.rate_limit import AsyncRateLimiter


@dataclass
class PolitenessConfig:
    per_host_rpm: int = 60
    per_target_rpm: int = 30
    jitter_ms_min: int = 200
    jitter_ms_max: int = 800
    concurrency_per_host: int = 2


class PolitenessManager:
    def __init__(self, cfg: PolitenessConfig) -> None:
        self.cfg = cfg
        self._host_limiters: Dict[str, AsyncRateLimiter] = {}
        self._target_limiters: Dict[str, AsyncRateLimiter] = {}
        self._host_semaphores: Dict[str, asyncio.Semaphore] = {}
        self._lock = asyncio.Lock()

    def _rpm_to_rps(self, rpm: int) -> float:
        return max(0.1, float(rpm) / 60.0)

    async def wait(
        self,
        host: str,
        target_id: str,
        *,
        per_host_rpm: int | None = None,
        per_target_rpm: int | None = None,
    ) -> None:
        host_rpm = int(per_host_rpm) if per_host_rpm is not None and per_host_rpm > 0 else self.cfg.per_host_rpm
        target_rpm = int(per_target_rpm) if per_target_rpm is not None and per_target_rpm > 0 else self.cfg.per_target_rpm
        async with self._lock:
            host_key = f"{host}|{host_rpm}"
            target_key = f"{target_id}|{target_rpm}"
            if host_key not in self._host_limiters:
                self._host_limiters[host_key] = AsyncRateLimiter(self._rpm_to_rps(host_rpm))
            if target_key not in self._target_limiters:
                self._target_limiters[target_key] = AsyncRateLimiter(self._rpm_to_rps(target_rpm))
            host_limiter = self._host_limiters[host_key]
            target_limiter = self._target_limiters[target_key]

        await host_limiter.wait()
        await target_limiter.wait()
        await self._jitter()

    async def _host_guard(self, host: str, concurrency_per_host: int | None = None) -> asyncio.Semaphore:
        limit = int(concurrency_per_host) if concurrency_per_host is not None and concurrency_per_host > 0 else self.cfg.concurrency_per_host
        async with self._lock:
            host_key = f"{host}|{limit}"
            if host_key not in self._host_semaphores:
                self._host_semaphores[host_key] = asyncio.Semaphore(max(1, limit))
            return self._host_semaphores[host_key]

    @asynccontextmanager
    async def guard(
        self,
        host: str,
        target_id: str,
        *,
        per_host_rpm: int | None = None,
        per_target_rpm: int | None = None,
        concurrency_per_host: int | None = None,
    ):
        key = host or "unknown"
        sem = await self._host_guard(key, concurrency_per_host)
        await sem.acquire()
        try:
            await self.wait(
                key,
                target_id,
                per_host_rpm=per_host_rpm,
                per_target_rpm=per_target_rpm,
            )
            yield
        finally:
            sem.release()

    async def _jitter(self) -> None:
        low = max(0, int(self.cfg.jitter_ms_min))
        high = max(low, int(self.cfg.jitter_ms_max))
        if high <= 0:
            return
        delay = random.uniform(low, high) / 1000.0
        await asyncio.sleep(delay)


def monotonic_ts() -> float:
    return time.monotonic()
