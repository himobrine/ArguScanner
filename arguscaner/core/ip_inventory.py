"""Persistent inventory of IPs that have already been port-scanned.

The inventory is used by the recursive scan engine so that discovered IPs are
never port-scanned twice. It is safe for use from the scheduler's worker
threads (a process-local lock guards read-modify-write cycles) and writes are
committed with an atomic replace.
"""

from __future__ import annotations

import ipaddress
import json
import os
import threading
import time
from pathlib import Path
from typing import Any, Iterable


_LOCK_GUARD = threading.Lock()
_LOCKS: dict[str, threading.Lock] = {}


def _lock_for(path: Path) -> threading.Lock:
    key = str(path.resolve()).lower()
    with _LOCK_GUARD:
        lock = _LOCKS.get(key)
        if lock is None:
            lock = threading.Lock()
            _LOCKS[key] = lock
        return lock


def normalize_ip(value: Any) -> str | None:
    """Normalize an IP (optionally with a port/brackets) to a canonical string."""
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None

    # [2001:db8::1]:443 -> 2001:db8::1
    if text.startswith("[") and "]" in text:
        text = text[1:text.index("]")]
    elif text.count(":") == 1 and "." in text:
        host, _, port = text.rpartition(":")
        if port.isdigit():
            text = host

    # Strip an IPv6 zone identifier (fe80::1%eth0)
    text = text.split("%", 1)[0]
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def find_task_root(workdir: Path) -> Path:
    """Return the nearest ancestor that contains task.json.

    Recursive rounds run in ``<task>/rounds/rNNN`` sub-directories. They do not
    write their own task.json, so walking up finds the real task root.
    """
    current = Path(workdir).resolve()
    for _ in range(8):
        if (current / "task.json").exists():
            return current
        if current.parent == current:
            break
        current = current.parent
    return Path(workdir).resolve()


class IpInventory:
    """Read/write the set of IPs that have already been port-scanned."""

    VERSION = 1

    def __init__(self, path: Path):
        self.path = Path(path)
        self._lock = _lock_for(self.path)

    @classmethod
    def for_workdir(
        cls, workdir: Path, settings: dict[str, Any] | None = None
    ) -> "IpInventory":
        """Build an inventory for a task or the whole workspace.

        ``recursive.ip_cache_scope``:
          - ``task`` (default): <task>/.state/scanned_ips.json
          - ``workspace``: <workspace>/.state/scanned_ips.json
        """
        cfg = (settings or {}).get("recursive", {})
        scope = str(cfg.get("ip_cache_scope", "task")).lower()
        root = find_task_root(workdir)
        base = root.parent if scope == "workspace" else root
        return cls(base / ".state" / "scanned_ips.json")

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def load(self) -> dict[str, Any]:
        with self._lock:
            return self._load_unlocked()

    def _load_unlocked(self) -> dict[str, Any]:
        if not self.path.exists():
            return {"version": self.VERSION, "ips": {}}
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {"version": self.VERSION, "ips": {}}
        if not isinstance(data, dict):
            return {"version": self.VERSION, "ips": {}}
        data.setdefault("version", self.VERSION)
        if not isinstance(data.get("ips"), dict):
            data["ips"] = {}
        return data

    def _save_unlocked(self, data: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_name(
            f"{self.path.name}.{os.getpid()}.{threading.get_ident()}.tmp"
        )
        tmp.write_text(
            json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        os.replace(tmp, self.path)

    # ------------------------------------------------------------------
    # Queries / updates
    # ------------------------------------------------------------------

    def is_scanned(self, ip: Any) -> bool:
        normalized = normalize_ip(ip)
        if not normalized:
            return False
        return normalized in self.load().get("ips", {})

    def filter_unscanned(
        self, ips: Iterable[Any]
    ) -> tuple[list[str], list[str]]:
        """Return ``(unscanned, already_scanned)`` preserving order."""
        known = self.load().get("ips", {})
        unscanned: list[str] = []
        skipped: list[str] = []
        seen: set[str] = set()
        for value in ips:
            normalized = normalize_ip(value)
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            if normalized in known:
                skipped.append(normalized)
            else:
                unscanned.append(normalized)
        return unscanned, skipped

    def mark_scanned(
        self,
        ip: Any,
        ports: Iterable[int] | None = None,
        task_id: str = "",
        source: str = "",
    ) -> bool:
        """Record an IP as scanned. Returns False for non-IP values."""
        normalized = normalize_ip(ip)
        if not normalized:
            return False
        now = time.time()
        with self._lock:
            data = self._load_unlocked()
            entry = data["ips"].get(normalized)
            if not isinstance(entry, dict):
                entry = {
                    "first_scanned": now,
                    "ports": [],
                }
            entry["last_scanned"] = now
            if task_id:
                entry["task_id"] = task_id
            if source:
                entry["source"] = source
            if ports:
                merged = set(entry.get("ports") or [])
                merged.update(int(p) for p in ports if str(p).isdigit())
                entry["ports"] = sorted(merged)
            data["ips"][normalized] = entry
            self._save_unlocked(data)
        return True

    def mark_many(
        self,
        ips: Iterable[Any],
        ports_by_ip: dict[str, Iterable[int]] | None = None,
        task_id: str = "",
        source: str = "",
    ) -> int:
        """Record multiple IPs. Returns the number of IPs written."""
        normalized = []
        seen: set[str] = set()
        for value in ips:
            item = normalize_ip(value)
            if item and item not in seen:
                seen.add(item)
                normalized.append(item)
        if not normalized:
            return 0

        now = time.time()
        ports_by_ip = ports_by_ip or {}
        with self._lock:
            data = self._load_unlocked()
            for item in normalized:
                entry = data["ips"].get(item)
                if not isinstance(entry, dict):
                    entry = {"first_scanned": now, "ports": []}
                entry["last_scanned"] = now
                if task_id:
                    entry["task_id"] = task_id
                if source:
                    entry["source"] = source
                ports = [int(p) for p in ports_by_ip.get(item, []) if str(p).isdigit()]
                if ports:
                    merged = set(entry.get("ports") or [])
                    merged.update(ports)
                    entry["ports"] = sorted(merged)
                data["ips"][item] = entry
            self._save_unlocked(data)
        return len(normalized)
