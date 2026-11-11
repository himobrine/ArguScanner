"""HttpxProbe plugin - HTTP alive detection."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from arguscaner.core.plugins.base_plugin import (
    BasePlugin,
    PluginCondition,
    PluginSkipped,
)
from arguscaner.utils.target_classifier import TargetType
from arguscaner.utils.tool_paths import resolve_tool


class HttpxProbePlugin(BasePlugin):
    """HTTP alive detection plugin using httpx.

    Works on domains and IPs. For IP targets it probes the IP directly.
    """

    name = "httpx_probe"
    description = "httpx HTTP 存活检测（域名和 IP）"
    version = "1.0.0"
    command_template = "httpx -l {{input_file}} -o {{output}} -json -silent"
    output_filename = "httpx_output.jsonl"
    output_schema = {
        "url": "str",
        "status": "int",
        "title": "str",
        "length": "int",
        "ip": "str",
        "source": "str",
    }
    supported_target_types: list[TargetType] = [TargetType.DOMAIN, TargetType.IP]
    input_requirements: list[str] = []
    conditions: list[PluginCondition] = [
        PluginCondition(
            field="target_type",
            operator="in",
            value=["domain", "ip"],
            description="需要域名或 IP 目标",
        ),
    ]

    def execute(self, target: str, workdir: Path, proxy: str | None = None) -> Path:
        """Execute HTTP alive detection."""
        output_file = self._stage_file(workdir, self.output_filename)
        output_file.parent.mkdir(parents=True, exist_ok=True)

        hosts = self._collect_hosts(target, workdir)
        if not hosts:
            raise PluginSkipped("没有新的 HTTP 探测目标（主机均已探测）")

        input_file = self._stage_file(workdir, "httpx_input.txt")
        input_file.write_text("\n".join(hosts) + "\n", encoding="utf-8")

        args = [
            self._httpx_bin,
            "-l", str(input_file),
            "-o", str(output_file),
            "-json",
            "-silent",
        ]
        cfg = self.settings.get("plugins", {}).get("httpx_probe", {})
        threads = cfg.get("threads")
        if threads:
            args += ["-threads", str(threads)]
        if cfg.get("rate_limit"):
            args += ["-rate-limit", str(cfg["rate_limit"])]
        extra_args = cfg.get("extra_args") or []
        args.extend(str(extra) for extra in extra_args)
        if proxy:
            args += ["-proxy", proxy]
        self._run_args(
            args,
            workdir,
            timeout=self.settings.get("defaults", {}).get("timeout", 3000),
        )

        return output_file

    def _collect_hosts(self, target: str, workdir: Path) -> list[str]:
        """Collect hosts to probe, skipping hosts already probed in a round.

        The first pass reads OneForAll output (plus the target fallback); in a
        recursive round it reads the round target list and skips hosts that
        already have live URLs in the copied ``http_probe.jsonl``.
        """
        cfg = self.settings.get("plugins", {}).get("httpx_probe", {})
        max_hosts = int(cfg.get("max_hosts", 5000))
        round_mode = (workdir / "round_targets.jsonl").exists()

        values: list[str] = []
        if round_mode:
            values.extend(self._round_hosts(target, workdir))
            already_probed = {
                self._host_from_value(rec.get("url", ""))
                for rec in self._read_jsonl(workdir / "http_probe.jsonl")
            }
            already_probed.discard("")
        else:
            if self._bound_inputs:
                for rec in self._input_records(workdir):
                    values.append(
                        rec.get("domain")
                        or rec.get("host")
                        or rec.get("url")
                        or rec.get("ip")
                        or rec.get("target")
                        or ""
                    )
            else:
                for rec in self._read_jsonl(workdir / "subdomain_enum.jsonl"):
                    values.append(rec.get("domain") or rec.get("host") or "")
                for rec in self._read_jsonl(workdir / "oneforall_output.jsonl"):
                    values.append(rec.get("domain") or rec.get("host") or "")
            values.append(target)
            already_probed = set()

        hosts: list[str] = []
        seen: set[str] = set()
        for value in values:
            host = self._host_from_value(value)
            if not host or host in seen or host in already_probed:
                continue
            seen.add(host)
            hosts.append(host)
            if len(hosts) >= max_hosts:
                break
        return hosts

    @property
    def _httpx_bin(self) -> str:
        return resolve_tool("httpx", self.settings, plugin="httpx_probe").path

    def _create_input_from_target(self, target: str, workdir: Path) -> Path:
        """Create httpx input file from target when oneforall output is missing."""
        from arguscaner.utils.target_classifier import TargetClassifier
        input_file = workdir / "httpx_input.txt"
        urls = []
        if TargetClassifier.is_ip(target):
            urls = [f"http://{target}", f"https://{target}"]
        else:
            host = target
            if "://" in target:
                from urllib.parse import urlparse
                host = urlparse(target).hostname or target
            urls = [f"http://{host}", f"https://{host}"]
        input_file.write_text("\n".join(urls) + "\n", encoding="utf-8")
        return input_file

    def parse_output(self, output_file: Path) -> list[dict[str, Any]]:
        """Parse httpx JSON output."""
        records = []
        for rec in self._read_jsonl(output_file):
            records.append({
                "url": rec.get("url", ""),
                "status": rec.get("status_code") or rec.get("status", 0),
                "title": rec.get("title", ""),
                "length": rec.get("content_length") or rec.get("length", 0),
                "ip": rec.get("ip") or rec.get("a", [""])[0] if isinstance(rec.get("a"), list) else rec.get("ip", ""),
                "source": "httpx",
            })
        return records