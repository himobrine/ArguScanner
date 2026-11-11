"""NmapScan plugin - Port scanning."""

from __future__ import annotations

import json
import re
import socket
import subprocess
import time
from pathlib import Path
from typing import Any

from arguscaner.core.ip_inventory import IpInventory, find_task_root, normalize_ip
from arguscaner.core.plugins.base_plugin import (
    BasePlugin,
    CommandError,
    PluginCondition,
    PluginSkipped,
)
from arguscaner.utils.target_classifier import TargetType
from arguscaner.utils.tool_paths import resolve_tool


class NmapScanPlugin(BasePlugin):
    """Port scanning plugin using Nmap.

    Works on all target types (domain, IP, CIDR). When an
    ``ip_discovery.jsonl`` file is present (recursive rounds), every discovered
    IP is scanned through ``-iL``; otherwise the original target is scanned,
    preserving the first-pass behaviour.

    IPs present in the persistent inventory are skipped, so a host is never
    port-scanned twice within a task (or workspace, when configured).
    """

    name = "nmap_scan"
    description = "Nmap 端口扫描（所有目标类型，支持多 IP 与已扫描 IP 去重）"
    version = "1.1.0"
    command_template = 'nmap -sS -sV -p- -Pn --min-rate 1000 --stats-every 10s -oX "{{output}}.xml" -oN "{{output}}" -iL "{{targets_file}}"'
    output_filename = "nmap_output.txt"
    output_schema = {
        "ip": "str",
        "host": "str",
        "port": "int",
        "protocol": "str",
        "service": "str",
        "banner": "str",
        "state": "str",
    }
    supported_target_types: list[TargetType] = [
        TargetType.DOMAIN,
        TargetType.IP,
        TargetType.CIDR,
    ]
    input_requirements: list[str] = []
    conditions: list[PluginCondition] = []

    # Regex to parse nmap Stats line:
    # Stats: 0:02:14 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
    _STATS_RE = re.compile(
        r"Stats:\s+(\d+:\d+:\d+)\s+elapsed;\s+(\d+)\s+hosts?\s+completed"
    )
    _REPORT_RE = re.compile(r"^Nmap scan report for (.+)$")
    _PORT_RE = re.compile(r"^(\d+)/(\w+)\s+(\S+)\s+(\S+)\s*(.*)$")

    def execute(self, target: str, workdir: Path, proxy: str | None = None) -> Path:
        """Execute port scanning with real-time progress tracking."""
        output_file = self._stage_file(workdir, self.output_filename)
        output_file.parent.mkdir(parents=True, exist_ok=True)

        inventory = IpInventory.for_workdir(workdir, self.settings)
        recursive_cfg = self.settings.get("recursive", {})
        skip_scanned = bool(recursive_cfg.get("skip_scanned_ips", False))
        if recursive_cfg.get("rescan_ips"):
            skip_scanned = False

        targets, skipped = self._collect_targets(
            target, workdir, inventory, skip_scanned
        )
        if not targets:
            if skipped:
                raise PluginSkipped(
                    f"所有目标 IP 均已扫描过（跳过 {len(skipped)} 个）"
                )
            raise PluginSkipped("没有可扫描的 IP 目标")

        max_ips = int(recursive_cfg.get("max_ips_per_round", 1024))
        if len(targets) > max_ips:
            targets = targets[:max_ips]

        targets_file = self._stage_file(workdir, "nmap_targets.txt")
        targets_file.write_text("\n".join(targets) + "\n", encoding="utf-8")
        target_label = ", ".join(targets[:5])
        if len(targets) > 5:
            target_label += f" ... (+{len(targets) - 5})"

        cfg = self.settings.get("plugins", {}).get("nmap_scan", {})
        ports = str(cfg.get("ports") or "-")
        timing = str(cfg.get("timing") or "")
        min_rate = str(cfg.get("min_rate") or "1000")
        extra_args = [str(a) for a in (cfg.get("extra_args") or [])]

        args = [
            self._nmap_bin,
            "-sS", "-sV", "-p", ports, "-Pn",
            "--min-rate", min_rate,
            "--stats-every", "10s",
            "-oX", f"{output_file}.xml",
            "-oN", str(output_file),
            "-iL", str(targets_file),
        ]
        if timing:
            args.insert(1, timing)
        args.extend(extra_args)

        start_time = time.time()
        progress_file = self._stage_file(workdir, "nmap_progress.json")

        self._write_progress(progress_file, {
            "status": "starting",
            "elapsed": "0:00:00",
            "elapsed_seconds": 0,
            "hosts_completed": 0,
            "current_task": "",
            "target": target_label,
            "target_count": len(targets),
            "skipped_ips": skipped,
        })

        try:
            process = subprocess.Popen(
                args,
                shell=False,
                cwd=str(workdir),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
            )

            output_lines = []
            for line in process.stdout:
                line = line.rstrip("\n\r")
                output_lines.append(line)
                self._try_parse_stats(line, progress_file, start_time, target_label)

            process.wait()

            output_text = "\n".join(output_lines)
            output_file.write_text(output_text, encoding="utf-8")

            if process.returncode != 0:
                stderr_snippet = output_text[:500]
                raise CommandError(
                    f"命令执行失败 (exit {process.returncode}): {args}\n{stderr_snippet}",
                    returncode=process.returncode,
                )

            # Record every host that actually appeared in the nmap report,
            # even when it exposes no open ports.
            report_hosts = self._extract_report_hosts(output_text)
            ports_by_ip = self._open_ports_by_ip(output_text)
            task_id = self._task_id(workdir)
            scanned_ips = []
            for host, ip in report_hosts:
                normalized = normalize_ip(ip) or normalize_ip(host)
                if normalized:
                    scanned_ips.append(normalized)
            if not scanned_ips:
                # Some nmap wrappers omit the report header; fall back to the
                # explicit target list so the inventory still advances.
                scanned_ips = [
                    normalize_ip(item) for item in targets if normalize_ip(item)
                ]
            inventory.mark_many(
                scanned_ips,
                ports_by_ip=ports_by_ip,
                task_id=task_id,
                source=f"port_scan:{target}",
            )

            self._write_progress(progress_file, {
                "status": "done",
                "elapsed": self._format_elapsed(time.time() - start_time),
                "elapsed_seconds": round(time.time() - start_time, 1),
                "hosts_completed": len(report_hosts) or len(targets),
                "current_task": "completed",
                "target": target_label,
                "target_count": len(targets),
                "skipped_ips": skipped,
            })

        except Exception:
            self._write_progress(progress_file, {
                "status": "failed",
                "elapsed": self._format_elapsed(time.time() - start_time),
                "elapsed_seconds": round(time.time() - start_time, 1),
                "hosts_completed": 0,
                "current_task": "failed",
                "target": target_label,
                "target_count": len(targets),
                "skipped_ips": skipped,
            })
            raise

        return output_file

    # ------------------------------------------------------------------
    # Target selection
    # ------------------------------------------------------------------

    def _collect_targets(
        self,
        target: str,
        workdir: Path,
        inventory: IpInventory,
        skip_scanned: bool,
    ) -> tuple[list[str], list[str]]:
        """Return ``(targets_to_scan, skipped_ips)``.

        Prefers the IPs produced by the recursive ``ip_discovery`` stage. When
        that file is absent or empty, falls back to the original target so the
        first pass keeps its historical behaviour.
        """
        candidates: list[str] = []
        for rec in self._input_records(workdir, "ip_discovery.jsonl"):
            ip = normalize_ip(rec.get("ip"))
            if ip:
                candidates.append(ip)

        if not candidates:
            resolved = self._resolve_target(target)
            if resolved:
                candidates.append(resolved)

        deduped: list[str] = []
        seen: set[str] = set()
        for item in candidates:
            key = normalize_ip(item) or item
            if key not in seen:
                seen.add(key)
                deduped.append(item)

        if not skip_scanned:
            return deduped, []

        to_scan: list[str] = []
        skipped: list[str] = []
        for item in deduped:
            normalized = normalize_ip(item)
            if normalized and inventory.is_scanned(normalized):
                skipped.append(normalized)
            else:
                to_scan.append(item)
        return to_scan, skipped

    @property
    def _nmap_bin(self) -> str:
        return resolve_tool("nmap", self.settings, plugin="nmap_scan").path

    def _resolve_target(self, target: str) -> str:
        """Resolve URL/hostname to IP address for nmap."""
        hostname = self._host_from_value(target) or target
        try:
            return socket.gethostbyname(hostname)
        except socket.gaierror:
            return hostname

    # ------------------------------------------------------------------
    # Output parsing
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_report_target(value: str) -> tuple[str, str]:
        """Split 'host (1.2.3.4)' into ``(host, ip)``."""
        raw = value.strip()
        match = re.match(r"^(.*?)\s+\(([^)]+)\)$", raw)
        if match:
            return match.group(1).strip(), match.group(2).strip()
        return raw, raw

    def _extract_report_hosts(self, text: str) -> list[tuple[str, str]]:
        hosts: list[tuple[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for line in text.splitlines():
            match = self._REPORT_RE.match(line.strip())
            if not match:
                continue
            host, ip = self._parse_report_target(match.group(1))
            key = (host, ip)
            if key not in seen:
                seen.add(key)
                hosts.append(key)
        return hosts

    def _open_ports_by_ip(self, text: str) -> dict[str, list[int]]:
        result: dict[str, list[int]] = {}
        current_ip = ""
        for line in text.splitlines():
            stripped = line.strip()
            report = self._REPORT_RE.match(stripped)
            if report:
                _, current_ip = self._parse_report_target(report.group(1))
                continue
            port_match = self._PORT_RE.match(stripped)
            if port_match and current_ip:
                state = port_match.group(3).lower()
                if state == "open":
                    normalized = normalize_ip(current_ip) or current_ip
                    result.setdefault(normalized, []).append(int(port_match.group(1)))
        return {ip: sorted(set(ports)) for ip, ports in result.items()}

    def parse_output(self, output_file: Path) -> list[dict[str, Any]]:
        """Parse nmap normal output (-oN), returning open ports only."""
        if not output_file.exists():
            return []
        text = output_file.read_text(encoding="utf-8")

        records: list[dict[str, Any]] = []
        current_ip = ""
        current_host = ""
        for line in text.splitlines():
            stripped = line.strip()
            report = self._REPORT_RE.match(stripped)
            if report:
                current_host, current_ip = self._parse_report_target(report.group(1))
                continue

            port_match = self._PORT_RE.match(stripped)
            if not port_match or not current_ip:
                continue
            state = port_match.group(3).lower()
            if state != "open":
                continue
            records.append({
                "ip": normalize_ip(current_ip) or current_ip,
                "host": current_host if current_host != current_ip else "",
                "port": int(port_match.group(1)),
                "protocol": port_match.group(2),
                "state": state,
                "service": port_match.group(4),
                "banner": port_match.group(5).strip(),
            })
        return records

    @staticmethod
    def _task_id(workdir: Path) -> str:
        root = find_task_root(workdir)
        meta_file = root / "task.json"
        if not meta_file.exists():
            return ""
        try:
            return str(json.loads(meta_file.read_text(encoding="utf-8")).get("task_id", ""))
        except (OSError, json.JSONDecodeError):
            return ""

    # ------------------------------------------------------------------
    # Progress helpers
    # ------------------------------------------------------------------

    def _try_parse_stats(
        self, line: str, progress_file: Path, start_time: float, target: str
    ) -> None:
        """Try to parse a nmap Stats line and write progress."""
        m = self._STATS_RE.search(line)
        if m:
            elapsed_str = m.group(1)
            hosts_completed = int(m.group(2))
            elapsed_seconds = time.time() - start_time

            # Extract current task from the line
            current_task = line.split(";", 1)[1].strip() if ";" in line else ""

            self._write_progress(progress_file, {
                "status": "running",
                "elapsed": elapsed_str,
                "elapsed_seconds": round(elapsed_seconds, 1),
                "hosts_completed": hosts_completed,
                "current_task": current_task,
                "target": target,
            })

    def _write_progress(self, progress_file: Path, data: dict) -> None:
        """Write progress to JSON file."""
        data["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        try:
            progress_file.write_text(
                json.dumps(data, ensure_ascii=False), encoding="utf-8"
            )
        except OSError:
            pass

    @staticmethod
    def _format_elapsed(seconds: float) -> str:
        """Format seconds as H:MM:SS."""
        h = int(seconds // 3600)
        m = int((seconds % 3600) // 60)
        s = int(seconds % 60)
        return f"{h}:{m:02d}:{s:02d}"
