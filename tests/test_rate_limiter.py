"""Tests for in-process rate limiter hygiene."""
from __future__ import annotations

import time

from resourcespace_platform.services.rate_limiter import create_rate_limiter


def test_rate_limiter_prunes_stale_bucket_keys() -> None:
    limiter = create_rate_limiter(max_requests=2, window_ms=50)
    first = limiter.consume("oauth_token:1.2.3.4")
    second = limiter.consume("oauth_token:5.6.7.8")
    assert first.allowed and second.allowed
    assert len(limiter._buckets) == 2  # noqa: SLF001

    time.sleep(0.06)
    third = limiter.consume("oauth_token:9.9.9.9")
    assert third.allowed
    assert set(limiter._buckets) == {"oauth_token:9.9.9.9"}  # noqa: SLF001
