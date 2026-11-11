"""ScanLogger - JSON-Lines logging for scan pipeline."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any


class ScanLogger:
    """Structured JSON-Lines logger for scan operations.

    Writes one JSON object per line to run.jsonl in the task workdir.
    """

    def __init__(self, workdir: Path, task_id: str):
        self.workdir = workdir
        self.task_id = task_id
        self.log_file = workdir / "run.jsonl"
        self.workdir.mkdir(parents=True, exist_ok=True)

    def _write_entry(self, entry: dict[str, Any]) -> None:
        """Append a JSON entry to the log file."""
        entry["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        entry["task_id"] = self.task_id
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    def log_task_start(self, target: str) -> None:
        """Log task start."""
        self._write_entry({
            "event": "task_start",
            "target": target,
            "level": "INFO",
        })

    def log_task_complete(self, result: Any) -> None:
        """Log task completion."""
        self._write_entry({
            "event": "task_complete",
            "total_duration": getattr(result, "total_duration", 0),
            "failed_stages": getattr(result, "failed_stages", []),
            "interrupted_count": getattr(result, "interrupted_count", 0),
            "level": "INFO",
        })

    def log_stage_start(self, stage: str) -> None:
        """Log stage start."""
        self._write_entry({
            "event": "stage_start",
            "stage": stage,
            "level": "INFO",
        })

    def log_stage_end(
        self,
        stage: str,
        status: str,
        duration: float,
        record_count: int = 0,
        error: str | None = None,
    ) -> None:
        """Log stage completion."""
        entry: dict[str, Any] = {
            "event": "stage_end",
            "stage": stage,
            "status": status,
            "duration": round(duration, 3),
            "record_count": record_count,
            "level": "INFO" if status == "done" else "ERROR",
        }
        if error:
            entry["error"] = error
        self._write_entry(entry)

    def log_stage_skip(self, stage: str, reason: str = "already_completed") -> None:
        """Log stage skip."""
        self._write_entry({
            "event": "stage_skip",
            "stage": stage,
            "reason": reason,
            "level": "INFO",
        })

    def log_error(self, stage: str, error: str) -> None:
        """Log an error."""
        self._write_entry({
            "event": "error",
            "stage": stage,
            "error": error,
            "level": "ERROR",
        })

    def log_waf_trigger(self, stage: str, status_code: int, proxy: str | None = None) -> None:
        """Log WAF trigger event."""
        entry: dict[str, Any] = {
            "event": "waf_trigger",
            "stage": stage,
            "status_code": status_code,
            "level": "WARNING",
        }
        if proxy:
            entry["proxy"] = proxy
        self._write_entry(entry)

    def get_logs(self) -> list[dict[str, Any]]:
        """Read all log entries from the log file."""
        entries = []
        if not self.log_file.exists():
            return entries
        with open(self.log_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    entries.append(json.loads(line))
        return entries

    def get_recent_logs(self, count: int = 50) -> list[dict[str, Any]]:
        """Get the most recent log entries."""
        all_logs = self.get_logs()
        return all_logs[-count:]
