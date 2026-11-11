"""IpDiscovery plugin - resolve discovered hosts to IP addresses.

This plugin is the first step of every recursive round ("先做 IP 探测"). It
collects hosts/URLs from all upstream stage outputs, resolves them concurrently
and writes a normalized host -> IP mapping that the port scanner consumes.
"""

from __future__ import annotations

import ipaddress
import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor, wait
from pathlib import Path
from typing import Any

from arguscaner.core.plugins.base_plugin import BasePlugin, PluginSkipped
from arguscaner.utils.target_classifier import TargetType


_HOST_RE = re.compile(r"^[A-Za-z0-9_.:-]+$")


class IpDiscoveryPlugin(BasePlugin):
    """Resolve hosts from previous stages into IPv4/IPv6 addresses."""

    name = "ip_discovery"
    description = "IP 探测：解析子域名/URL 到 IP（递归扫描第一步）"
    version = "1.0.0"
    command_template = ""
    output_filename = "ip_discovery_output.jsonl"
    output_schema = {
        "host": "str",
        "ip": "str",
        "source": "str",
        "timestamp": "str",
    }
    supported_target_types: list[TargetType] = [
        TargetType.DOMAIN,
        TargetType.IP,
        TargetType.CIDR,
    ]
    input_requirements: list[str] = []
    conditions: list = []

    #: Stage files that may contain hosts/URLs/IPs.
    INPUT_FILES = [
        "round_targets.jsonl",
        "subdomain_enum.jsonl",
        "http_probe.jsonl",
        "js_url_extract.jsonl",
        "urlfinder_extract.jsonl",
        "api_probe.jsonl",
        "oneforall_output.jsonl",
        "httpx_output.jsonl",
    ]

    def __init__(self, settings: dict[str, Any] | None = None):
        super().__init__(settings)
        cfg = (settings or {}).get("plugins", {}).get("ip_discovery", {})
        self.dns_workers = int(cfg.get("dns_workers", 20))
        self.dns_timeout = float(cfg.get("dns_timeout", 5))
        self.expand_cidr = bool(cfg.get("expand_cidr", False))
        self.max_cidr_hosts = int(cfg.get("max_cidr_hosts", 256))
        self.max_hosts = int(cfg.get("max_hosts", 5000))

    # ------------------------------------------------------------------
    # Input collection
    # ------------------------------------------------------------------

    @staticmethod
    def _looks_like_host(value: str) -> bool:
        if not value or len(value) > 253:
            return False
        if " " in value or "\t" in value:
            return False
        return bool(_HOST_RE.match(value))

    def _iter_candidates(self, target: str, workdir: Path):
        """Yield ``(host, source)`` pairs from all known stage outputs."""
        # Per-file field priority. The file name becomes the source label.
        field_map = {
            "round_targets.jsonl": ("target", "host", "domain", "ip", "url"),
            "subdomain_enum.jsonl": ("domain", "host", "ip"),
            "http_probe.jsonl": ("url", "host", "ip"),
            "js_url_extract.jsonl": ("url", "data", "host", "target"),
            "urlfinder_extract.jsonl": ("url", "data", "host", "target"),
            "api_probe.jsonl": ("url", "host"),
            "oneforall_output.jsonl": ("domain", "host", "ip"),
            "httpx_output.jsonl": ("url", "host", "ip"),
        }

        seen_files = set()
        if self._bound_inputs:
            for path in self._input_files(workdir):
                source = path.stem.removesuffix("_output")
                for rec in self._read_jsonl(path):
                    for key in ("target", "host", "domain", "ip", "url"):
                        value = rec.get(key)
                        if not value:
                            continue
                        host = self._host_from_value(value)
                        if host:
                            yield host, source
                            break
        else:
            for file_name in self.INPUT_FILES:
                path = workdir / file_name
                if not path.exists():
                    continue
                seen_files.add(file_name)
                source = file_name.removesuffix(".jsonl").replace("_output", "")
                for rec in self._read_jsonl(path):
                    for key in field_map.get(file_name, ("host", "ip")):
                        value = rec.get(key)
                        if not value:
                            continue
                        host = self._host_from_value(value)
                        if host:
                            yield host, source
                            break

        # The original target is always included so a round can still scan
        # the root asset even when no upstream output exists.
        host = self._host_from_value(target)
        if host:
            yield host, "target"

    # ------------------------------------------------------------------
    # Resolution
    # ------------------------------------------------------------------

    def _resolve_one(self, host: str) -> list[str]:
        """Resolve a single host/CIDR to a list of IP strings."""
        try:
            return [str(ipaddress.ip_address(host))]
        except ValueError:
            pass

        if "/" in host:
            try:
                network = ipaddress.ip_network(host, strict=False)
            except ValueError:
                network = None
            if network is not None:
                if not self.expand_cidr:
                    return []
                if network.num_addresses > self.max_cidr_hosts:
                    return []
                if network.prefixlen >= 31:
                    return [str(ip) for ip in network]
                return [str(ip) for ip in network.hosts()]

        try:
            infos = socket.getaddrinfo(
                host, None, type=socket.SOCK_STREAM
            )
        except (socket.gaierror, OSError, UnicodeError):
            return []

        result: list[str] = []
        seen: set[str] = set()
        for info in infos:
            addr = info[4][0].split("%", 1)[0]
            try:
                normalized = str(ipaddress.ip_address(addr))
            except ValueError:
                continue
            if normalized not in seen:
                seen.add(normalized)
                result.append(normalized)
        return result

    # ------------------------------------------------------------------
    # Plugin interface
    # ------------------------------------------------------------------

    def execute(self, target: str, workdir: Path, proxy: str | None = None) -> Path:
        output_file = self._stage_file(workdir, self.output_filename)
        output_file.parent.mkdir(parents=True, exist_ok=True)

        candidates: list[tuple[str, str]] = []
        seen_hosts: set[str] = set()
        for host, source in self._iter_candidates(target, workdir):
            if host and host not in seen_hosts:
                seen_hosts.add(host)
                candidates.append((host, source))
            if len(candidates) >= self.max_hosts:
                break

        if not candidates:
            raise PluginSkipped("没有可解析的主机")

        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ")
        records: list[dict[str, Any]] = []
        seen_pairs: set[tuple[str, str]] = set()
        errors = 0

        overall_timeout = max(5.0, self.dns_timeout * 2)
        with ThreadPoolExecutor(max_workers=max(1, self.dns_workers)) as pool:
            future_map = {
                pool.submit(self._resolve_one, host): (host, source)
                for host, source in candidates
            }
            done, not_done = wait(future_map, timeout=overall_timeout)
            for future in not_done:
                future.cancel()
            for future in done:
                host, source = future_map[future]
                try:
                    ips = future.result()
                except Exception:
                    errors += 1
                    continue
                if not ips:
                    if not self._is_ip_or_network(host):
                        errors += 1
                    continue
                for ip in ips:
                    key = (host, ip)
                    if key in seen_pairs:
                        continue
                    seen_pairs.add(key)
                    records.append({
                        "host": host,
                        "ip": ip,
                        "source": source,
                        "timestamp": timestamp,
                    })

        records.sort(key=lambda r: (r["host"], r["ip"]))
        self._write_jsonl(records, output_file)
        return output_file

    @staticmethod
    def _is_ip_or_network(value: str) -> bool:
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            pass
        try:
            ipaddress.ip_network(value, strict=False)
            return True
        except ValueError:
            return False

    def parse_output(self, output_file: Path) -> list[dict[str, Any]]:
        return self._read_jsonl(output_file)
