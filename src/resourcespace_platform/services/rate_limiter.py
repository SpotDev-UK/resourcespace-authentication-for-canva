"""In-process fixed-window rate limiter.

Keyed by `(scope, client-ip)`. Single-instance only. For horizontal scale,
replace with a Redis-backed token bucket behind the same interface.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass


@dataclass
class RateLimitResult:
    allowed: bool
    retry_after_ms: int = 0


class RateLimiter:
    def __init__(self, *, max_requests: int, window_ms: int) -> None:
        self._max_requests = max_requests
        self._window_ms = window_ms
        self._buckets: dict[str, dict[str, int]] = {}
        self._lock = threading.Lock()

    def consume(self, key: str) -> RateLimitResult:
        now = int(time.time() * 1000)
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None or bucket["resetAt"] <= now:
                self._buckets[key] = {"count": 1, "resetAt": now + self._window_ms}
                return RateLimitResult(allowed=True)
            if bucket["count"] >= self._max_requests:
                return RateLimitResult(allowed=False, retry_after_ms=bucket["resetAt"] - now)
            bucket["count"] += 1
            return RateLimitResult(allowed=True)


def create_rate_limiter(*, max_requests: int, window_ms: int) -> RateLimiter:
    return RateLimiter(max_requests=max_requests, window_ms=window_ms)
