"""ProxyManager - Proxy pool management for scan pipeline."""

from __future__ import annotations

import random
from typing import Any


class ProxyManager:
    """Manages a pool of proxy servers for request rotation.

    Supports proxy rotation on WAF triggers and failure tracking.
    """

    def __init__(self, sources: list[str] | None = None):
        self.sources = sources or []
        self._proxies: list[str] = list(self.sources)
        self._failed: set[str] = set()
        self._rotation_count = 0

    def get_proxy(self) -> str | None:
        """Get a random available proxy.

        Returns:
            Proxy string or None if pool is exhausted.
        """
        available = [p for p in self._proxies if p not in self._failed]
        if not available:
            return None
        return random.choice(available)

    def mark_failed(self, proxy: str) -> None:
        """Mark a proxy as failed."""
        self._failed.add(proxy)

    def rotate(self) -> str | None:
        """Rotate to a different proxy.

        Returns:
            New proxy string or None if exhausted.
        """
        self._rotation_count += 1
        return self.get_proxy()

    def reset(self) -> None:
        """Reset all failure tracking."""
        self._failed.clear()
        self._rotation_count = 0

    def get_status(self) -> dict[str, Any]:
        """Get proxy pool status."""
        return {
            "total": len(self._proxies),
            "available": len(self._proxies) - len(self._failed),
            "failed": len(self._failed),
            "rotations": self._rotation_count,
        }

    @property
    def is_exhausted(self) -> bool:
        """Check if all proxies have failed."""
        return len(self._failed) >= len(self._proxies) and len(self._proxies) > 0
