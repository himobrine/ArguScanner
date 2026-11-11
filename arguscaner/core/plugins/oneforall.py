"""OneForAll plugin - Subdomain enumeration."""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any

from arguscaner.core.plugins.base_plugin import (
    BasePlugin,
    PluginCondition,
)
from arguscaner.utils.target_classifier import TargetType
from arguscaner.utils.tool_paths import resolve_tool


class OneForAllPlugin(BasePlugin):
    """Subdomain enumeration plugin using OneForAll.

    Only meaningful for domain targets. For IP/CIDR targets this plugin
    is skipped by the scheduler via supported_target_types.

    OneForAll CLI contract (v0.4.5):
        oneforall.py --target <domain> --fmt json --path <file> run
    The ``run`` subcommand is mandatory; there is no ``--output`` flag.
    """

    name = "oneforall"
    description = "OneForAll 子域名枚举（仅域名目标）"
    version = "1.0.0"
    command_template = (
        "{{python}} {{oneforall_path}} --target {{target}} "
        "--fmt json --path {{raw_output}} run"
    )
    output_filename = "oneforall_output.jsonl"
    raw_filename = "oneforall_raw.json"
    output_schema = {
        "domain": "str",
        "ip": "str",
        "source": "str",
        "timestamp": "str",
    }
    supported_target_types: list[TargetType] = [TargetType.DOMAIN]
    input_requirements: list[str] = []
    conditions: list[PluginCondition] = [
        PluginCondition(
            field="target_type",
            operator="eq",
            value="domain",
            description="需要域名目标（子域名枚举仅适用于域名）",
        ),
    ]

    def __init__(self, settings: dict[str, Any] | None = None):
        super().__init__(settings)
        cfg = (settings or {}).get("plugins", {}).get("oneforall", {})
        self.oneforall_path = resolve_tool(
            "oneforall", settings, cfg.get("oneforall_path"), plugin="oneforall"
        ).path

    def execute(self, target: str, workdir: Path, proxy: str | None = None) -> Path:
        """Execute subdomain enumeration and normalize to JSONL."""
        output_file = self._stage_file(workdir, self.output_filename)
        raw_file = self._stage_file(workdir, self.raw_filename)
        output_file.parent.mkdir(parents=True, exist_ok=True)

        from arguscaner.utils.target_classifier import TargetClassifier
        domain = TargetClassifier._extract_from_url(target)

        args = [
            sys.executable,
            self.oneforall_path,
            "--target", domain,
            "--fmt", "json",
            "--path", str(raw_file),
            "run",
        ]
        self._run_args(
            args,
            workdir,
            timeout=self.settings.get("defaults", {}).get("timeout", 300),
        )

        records = self._parse_raw(raw_file)
        self._write_jsonl(records, output_file)
        return output_file

    def _parse_raw(self, raw_file: Path) -> list[dict[str, Any]]:
        """Parse OneForAll's raw JSON array into normalized records.

        OneForAll exports one row per subdomain with keys such as
        ``subdomain``, ``url``, ``ip``, ``alive``. A missing/empty file yields
        an empty list (the scheduler records a zero-record success).
        """
        if not raw_file.exists():
            return []
        try:
            data = json.loads(raw_file.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return []

        if isinstance(data, dict):
            data = data.get("data") or data.get("results") or [data]
        if not isinstance(data, list):
            return []

        now = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        records: list[dict[str, Any]] = []
        for row in data:
            if not isinstance(row, dict):
                continue
            domain = row.get("subdomain") or row.get("domain") or row.get("url") or ""
            domain = str(domain).strip()
            if not domain:
                continue
            if "://" in domain:
                from urllib.parse import urlparse

                domain = urlparse(domain).hostname or domain
            records.append({
                "domain": domain,
                "ip": row.get("ip") or "",
                "source": "oneforall",
                "timestamp": row.get("timestamp") or now,
            })
        return records

    def parse_output(self, output_file: Path) -> list[dict[str, Any]]:
        """Parse the normalized JSONL output."""
        return self._read_jsonl(output_file)
