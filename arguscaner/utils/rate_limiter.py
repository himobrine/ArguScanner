"""AdaptiveRateLimiter - Token bucket rate limiting for scan pipeline."""

from __future__ import annotations

import asyncio
import time
from typing import Any


class AdaptiveRateLimiter:
    """Token bucket rate limiter with adaptive RPS adjustment.

    Supports dynamic RPS reduction on WAF triggers and gradual restore.
    """

    def __init__(self, rps_limit: int = 100, burst_limit: int = 20):
        self.max_rps = rps_limit
        self.current_rps = rps_limit
        self.burst_limit = burst_limit
        self._tokens = float(burst_limit)
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    def _refill(self) -> None:
        """Refill tokens based on elapsed time."""
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._tokens = min(
            self.burst_limit,
            self._tokens + elapsed * self.current_rps,
        )
        self._last_refill = now

    async def acquire(self) -> None:
        """Acquire a token, waiting if necessary."""
        async with self._lock:
            while True:
                self._refill()
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                wait_time = (1.0 - self._tokens) / self.current_rps
                await asyncio.sleep(wait_time)

    def reduce_rps(self, ratio: float) -> None:
        """Reduce current RPS by a ratio (0.0 to 1.0).

        Used when WAF is detected.
        """
        self.current_rps = max(1, int(self.max_rps * (1.0 - ratio)))

    def restore_rps(self) -> None:
        """Restore RPS to maximum."""
        self.current_rps = self.max_rps

    def get_status(self) -> dict[str, Any]:
        """Get current limiter status."""
        return {
            "max_rps": self.max_rps,
            "current_rps": self.current_rps,
            "tokens": round(self._tokens, 2),
            "burst_limit": self.burst_limit,
        }
