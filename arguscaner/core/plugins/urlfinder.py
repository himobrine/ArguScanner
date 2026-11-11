"""UrlFinderPlugin - URL and JS extraction from web pages."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from arguscaner.core.plugins.base_plugin import (
    BasePlugin,
    PluginCondition,
    PluginSkipped,
)
from arguscaner.utils.target_classifier import TargetType
from arguscaner.utils.tool_paths import resolve_tool


class UrlFinderPlugin(BasePlugin):
    """URLFinder 页面 URL 和 JS 提取插件。

    使用 URLFinder 从网页和 JavaScript 文件中提取 URL。
    支持域名和 IP 目标类型。
    """

    name = "urlfinder"
    description = "URLFinder 页面 URL 和 JS 提取"
    version = "1.0.0"
    command_template = "{{urlfinder_path}} -u {{target}} -s all -m 3 -o {{output_dir}} -time 10"
    output_filename = "urlfinder_output.jsonl"
    output_schema = {
        "type": "str",
        "data": "str",
        "source": "str",
        "status": "str",
        "timestamp": "str",
    }
    supported_target_types: list[TargetType] = [
        TargetType.DOMAIN,
        TargetType.IP,
    ]
    input_requirements: list[str] = []
    conditions: list[PluginCondition] = []

    def __init__(self, settings: dict[str, Any] | None = None):
        super().__init__(settings)
        cfg = (settings or {}).get("plugins", {}).get("urlfinder", {})
        self.urlfinder_path = resolve_tool(
            "urlfinder", settings, cfg.get("urlfinder_path"), plugin="urlfinder"
        ).path
        self.timeout = cfg.get("timeout", 300)
        self.retry = cfg.get("retry", 2)
        self.retry_delay = cfg.get("retry_delay", 5)

    def execute(self, target: str, workdir: Path, proxy: str | None = None) -> Path:
        """Execute URL extraction.

        The first pass crawls only the original target. Inside a recursive
        round every discovered host is crawled into its own output directory,
        and a tracking file prevents a host from being crawled twice.
        """
        output_file = self._stage_file(workdir, self.output_filename)
        output_file.parent.mkdir(parents=True, exist_ok=True)

        round_mode = (workdir / "round_targets.jsonl").exists()
        cfg = self.settings.get("plugins", {}).get("urlfinder", {})
        max_targets = int(cfg.get("max_targets", 50))

        bound_targets: list[str] = []
        if self._bound_inputs:
            seen_bound: set[str] = set()
            for rec in self._input_records(workdir):
                value = (
                    rec.get("url")
                    or rec.get("host")
                    or rec.get("domain")
                    or rec.get("data")
                    or rec.get("target")
                    or ""
                )
                value = str(value).strip()
                if value and value not in seen_bound:
                    seen_bound.add(value)
                    bound_targets.append(value)
            bound_targets = bound_targets[:max_targets]

        if round_mode:
            hosts = self._round_hosts(target, workdir)
            already = self._read_hosts_file(
                self._stage_file(workdir, "urlfinder_hosts.txt")
            )
            pending = [h for h in hosts if h not in already]
            pending = pending[:max_targets]
            if not pending:
                if hosts:
                    raise PluginSkipped(
                        f"所有主机均已执行 URLFinder（跳过 {len(hosts)} 个）"
                    )
                raise PluginSkipped("没有可执行 URLFinder 的主机")
        elif bound_targets:
            pending = bound_targets
        else:
            host = self._host_from_value(target)
            pending = [host] if host else []
            if not pending:
                raise PluginSkipped("没有可执行 URLFinder 的目标")

        records: list[dict[str, Any]] = []
        seen_records: set[tuple[str, str, str]] = set()
        completed: list[str] = []
        first_error: Exception | None = None

        for item in pending:
            if round_mode:
                host = item
                output_dir = self._stage_file(workdir, "urlfinder_output") / self._slug(host)
                host_target = self._ensure_url(host)
                record_target = host
            elif bound_targets:
                host = self._host_from_value(item) or item
                output_dir = self._stage_file(workdir, "urlfinder_output") / self._slug(host)
                host_target = item if "://" in item else self._ensure_url(item)
                record_target = host
            else:
                host = item
                output_dir = self._stage_file(workdir, "urlfinder_output")
                host_target = self._ensure_url(target)
                record_target = target
            output_dir.mkdir(parents=True, exist_ok=True)

            args = [
                self.urlfinder_path,
                "-u", host_target,
                "-s", "all",
                "-m", "3",
                "-o", str(output_dir),
                "-time", "10",
            ]
            if proxy:
                args += ["-proxy", proxy]

            try:
                self._run_args(args, workdir, timeout=self.timeout)
            except Exception as exc:  # noqa: BLE001 - per-host isolation
                if not round_mode:
                    raise
                first_error = first_error or exc
                continue

            completed.append(host)
            for rec in self._parse_output_dir(
                output_dir, record_target
            ):
                key = (
                    str(rec.get("type", "")),
                    str(rec.get("data", "")),
                    str(rec.get("source", "")),
                )
                if key in seen_records:
                    continue
                seen_records.add(key)
                records.append(rec)

        if round_mode:
            self._append_hosts_file(
                self._stage_file(workdir, "urlfinder_hosts.txt"), completed
            )
            if not completed and first_error is not None:
                raise first_error
            if not completed:
                raise PluginSkipped("URLFinder 未能完成任何主机")
        elif not completed:
            raise PluginSkipped("URLFinder 未执行")

        self._write_jsonl(records, output_file)
        return output_file

    @staticmethod
    def _slug(host: str) -> str:
        """Build a filesystem-safe slug from a host."""
        import re

        slug = re.sub(r"[^A-Za-z0-9_.-]+", "_", host).strip("._")
        return slug[:96] or "host"

    def _ensure_url(self, target: str) -> str:
        """Ensure target has http(s):// prefix."""
        from arguscaner.utils.target_classifier import TargetClassifier
        if "://" not in target:
            if TargetClassifier.is_ip(target):
                return f"http://{target}"
            return f"http://{target}"
        return target

    def parse_output(self, output_file: Path) -> list[dict[str, Any]]:
        """Parse URLFinder JSONL output."""
        return self._read_jsonl(output_file)

    def _parse_output_dir(self, output_dir: Path, target: str) -> list[dict[str, Any]]:
        """Parse all JSON files in the URLFinder output directory."""
        records = []
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ")

        for json_file in output_dir.rglob("*.json"):
            try:
                data = json.loads(json_file.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                continue

            # Extract JS URLs from jsOther
            for item in data.get("jsOther") or []:
                url = item.get("Url", "")
                if url:
                    records.append(self._decorate_record({
                        "type": "js_url",
                        "data": url,
                        "source": item.get("Source", ""),
                        "status": item.get("Status", ""),
                        "timestamp": timestamp,
                    }, target))

            # Extract regular URLs from urlOther
            for item in data.get("urlOther") or []:
                url = item.get("Url", "")
                if url:
                    records.append(self._decorate_record({
                        "type": "url",
                        "data": url,
                        "source": item.get("Source", ""),
                        "status": item.get("Status", ""),
                        "timestamp": timestamp,
                    }, target))

            # Extract domains
            for domain in data.get("domain") or []:
                if domain:
                    records.append(self._decorate_record({
                        "type": "subdomain",
                        "data": domain,
                        "source": target,
                        "status": "",
                        "timestamp": timestamp,
                    }, target))

        return records
