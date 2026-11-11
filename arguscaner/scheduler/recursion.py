"""Multi-round recursive scan controller.

After the first pipeline pass, this controller repeatedly scans newly
discovered assets until no new assets appear (or a configured limit is hit).
It intentionally does not assume a fixed number of rounds: a round can reveal
new hosts, new IPs (via DNS) and new API endpoints, each of which feeds the next
round.

Round directories live in ``<task>/rounds/rNNN/`` and never contain task.json,
so :func:`arguscaner.core.ip_inventory.find_task_root` still resolves to the
real task directory.
"""

from __future__ import annotations

import copy
import ipaddress
import json
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse

from arguscaner.core.ip_inventory import normalize_ip
from arguscaner.scheduler.logger import ScanLogger
from arguscaner.scheduler.scheduler_core import PipelineScheduler

CONFIGS_DIR = Path(__file__).parent.parent / "configs"
DEFAULT_ROUND_PIPELINE = CONFIGS_DIR / "pipeline_recursive.yaml"

#: Cross-round tracking files (hosts/origins that were already processed).
TRACKER_FILES = (
    "api_probe_origins.txt",
    "jsfinder_hosts.txt",
    "urlfinder_hosts.txt",
)

_HOST_RE = re.compile(r"^[A-Za-z0-9_.:-]+$")


# ---------------------------------------------------------------------------
# Asset model
# ---------------------------------------------------------------------------


def normalize_host(value: Any) -> str:
    """Return a lowercase hostname/IP from a URL, host:port or host."""
    if value is None:
        return ""
    text = str(value).strip()
    if not text:
        return ""
    if "://" in text:
        text = urlparse(text).hostname or ""
    elif "/" in text and not text.startswith("/"):
        try:
            ipaddress.ip_network(text, strict=False)
        except ValueError:
            text = text.split("/", 1)[0]
    if text.startswith("[") and "]" in text:
        text = text[1:text.index("]")]
    elif text.count(":") == 1 and "." in text:
        host, _, port = text.rpartition(":")
        if port.isdigit():
            text = host
    text = text.split("%", 1)[0].strip().rstrip(".").lower()
    if text.startswith("*."):
        text = text[2:]
    if not text or not _HOST_RE.match(text):
        return ""
    return text


def _looks_like_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


@dataclass
class Asset:
    """A single discovered asset."""

    value: str
    kind: str  # host | url | ip | api
    source: str = ""
    round_num: int = 0
    url: str = ""


class AssetCatalog:
    """Tracks every asset ever discovered so rounds can be incremental."""

    def __init__(self) -> None:
        self.hosts: dict[str, dict[str, Any]] = {}
        self.urls: dict[str, dict[str, Any]] = {}
        self.ips: dict[str, dict[str, Any]] = {}
        self.api_endpoints: dict[str, dict[str, Any]] = {}
        self.host_urls: dict[str, str] = {}

    # -- registration -----------------------------------------------------

    def add(self, asset: Asset) -> str | None:
        """Register an asset and return a new host value if one appeared."""
        value = str(asset.value or "").strip()
        if not value:
            return None

        new_host: str | None = None
        if asset.kind == "ip":
            ip = normalize_ip(value)
            if not ip:
                return None
            self.ips.setdefault(ip, {
                "ip": ip,
                "source": asset.source,
                "round": asset.round_num,
            })
            new_host = self._register_host(ip, asset)
        elif asset.kind == "host":
            host = normalize_host(value)
            if not host:
                return None
            new_host = self._register_host(host, asset)
        elif asset.kind in ("url", "api"):
            if "://" not in value:
                return None
            host = normalize_host(value)
            if not host:
                return None
            self.urls.setdefault(value, {
                "url": value,
                "source": asset.source,
                "round": asset.round_num,
            })
            if asset.kind == "api":
                self.api_endpoints.setdefault(value, {
                    "url": value,
                    "source": asset.source,
                    "round": asset.round_num,
                })
            self.host_urls.setdefault(host, value)
            new_host = self._register_host(host, asset, preferred_url=value)
        return new_host

    def _register_host(
        self,
        host: str,
        asset: Asset,
        preferred_url: str = "",
    ) -> str | None:
        if preferred_url:
            self.host_urls.setdefault(host, preferred_url)
        if host in self.hosts:
            return None
        self.hosts[host] = {
            "host": host,
            "source": asset.source,
            "round": asset.round_num,
            "url": self.host_urls.get(host, ""),
        }
        return host

    def add_all(self, assets: Iterable[Asset]) -> list[str]:
        """Register assets and return newly discovered hosts in order."""
        new_hosts: list[str] = []
        seen: set[str] = set()
        for asset in assets:
            host = self.add(asset)
            if host and host not in seen:
                seen.add(host)
                new_hosts.append(host)
        return new_hosts

    # -- round target generation -----------------------------------------

    def targets_for(self, hosts: Iterable[str], round_num: int) -> list[dict[str, Any]]:
        """Build ``round_targets.jsonl`` payloads for a batch of hosts."""
        targets: list[dict[str, Any]] = []
        for host in hosts:
            entry = self.hosts.get(host, {})
            url = self.host_urls.get(host, "")
            targets.append({
                "target": host,
                "host": host,
                "url": url,
                "source": entry.get("source", ""),
                "round": round_num,
            })
        return targets

    def summary(self) -> dict[str, int]:
        return {
            "hosts": len(self.hosts),
            "urls": len(self.urls),
            "ips": len(self.ips),
            "api_endpoints": len(self.api_endpoints),
        }


# ---------------------------------------------------------------------------
# Asset collection
# ---------------------------------------------------------------------------


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    records: list[dict[str, Any]] = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(item, dict):
                    records.append(item)
    except OSError:
        return []
    return records


def collect_assets(workdir: Path, round_num: int = 0) -> list[Asset]:
    """Extract every asset discoverable from a workdir's stage outputs."""
    assets: list[Asset] = []

    def add(value: Any, kind: str, source: str) -> None:
        if value is None or value == "":
            return
        assets.append(Asset(str(value), kind, source, round_num))

    def add_host_value(value: Any, source: str) -> None:
        host = normalize_host(value)
        if not host:
            return
        add(host, "ip" if _looks_like_ip(host) else "host", source)

    for rec in _read_jsonl(workdir / "subdomain_enum.jsonl"):
        source = "subdomain_enum"
        add_host_value(rec.get("domain") or rec.get("host"), source)
        add_host_value(rec.get("ip"), source)

    for rec in _read_jsonl(workdir / "oneforall_output.jsonl"):
        source = "oneforall"
        add_host_value(rec.get("domain") or rec.get("host"), source)
        add_host_value(rec.get("ip"), source)

    for filename in ("http_probe.jsonl", "httpx_output.jsonl"):
        for rec in _read_jsonl(workdir / filename):
            source = filename.removesuffix(".jsonl")
            url = rec.get("url") or rec.get("host")
            if url:
                add(url, "url", source)
            add_host_value(rec.get("host"), source)
            add_host_value(rec.get("ip"), source)

    for filename in ("js_url_extract.jsonl", "urlfinder_extract.jsonl"):
        for rec in _read_jsonl(workdir / filename):
            source = filename.removesuffix(".jsonl")
            data = rec.get("data")
            if not data:
                continue
            if rec.get("type") == "subdomain":
                add_host_value(data, source)
            elif "://" in str(data):
                add(data, "url", source)
            else:
                add_host_value(data, source)

    for rec in _read_jsonl(workdir / "api_probe.jsonl"):
        url = rec.get("url")
        if url:
            add(url, "api", "api_probe")
        add_host_value(rec.get("host"), "api_probe")

    for rec in _read_jsonl(workdir / "ip_discovery.jsonl"):
        add_host_value(rec.get("host"), "ip_discovery")
        ip = rec.get("ip")
        if ip:
            add(ip, "ip", "ip_discovery")

    for rec in _read_jsonl(workdir / "port_scan.jsonl"):
        add_host_value(rec.get("ip"), "port_scan")
        add_host_value(rec.get("host"), "port_scan")

    return assets


# ---------------------------------------------------------------------------
# Round lifecycle helpers
# ---------------------------------------------------------------------------


def prepare_round_dir(
    round_dir: Path,
    targets: list[dict[str, Any]],
    previous_dir: Path | None = None,
) -> None:
    """Create a round directory with targets and cross-round trackers."""
    round_dir.mkdir(parents=True, exist_ok=True)

    with open(round_dir / "round_targets.jsonl", "w", encoding="utf-8") as f:
        for target in targets:
            f.write(json.dumps(target, ensure_ascii=False) + "\n")

    if previous_dir is not None:
        for name in TRACKER_FILES:
            src = previous_dir / name
            if src.exists():
                _merge_tracker(src, round_dir / name)


def _merge_tracker(src: Path, dest: Path) -> None:
    """Merge a tracker file into dest, preserving order and uniqueness."""
    values: list[str] = []
    seen: set[str] = set()
    for path in (dest, src):
        if not path.exists():
            continue
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError:
            continue
        for line in lines:
            item = line.strip()
            if item and item not in seen:
                seen.add(item)
                values.append(item)
    if values:
        dest.write_text("\n".join(values) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# Recursive scanner
# ---------------------------------------------------------------------------


class RecursiveScanner:
    """Run incremental scan rounds until no new assets are discovered."""

    def __init__(
        self,
        workdir: Path,
        target: str,
        target_type: str,
        task_id: str,
        settings: dict[str, Any],
    ):
        self.workdir = Path(workdir)
        self.task_id = task_id
        self.target = target
        self.target_type = target_type
        self.settings = settings
        cfg = settings.get("recursive", {})
        self.cfg = cfg
        self.max_rounds = max(1, int(cfg.get("max_rounds", 5)))
        # IP caps are enforced by the nmap/ip_discovery plugins themselves.
        self.max_assets_per_round = max(1, int(cfg.get("max_assets_per_round", 1000)))
        self.rounds_dir = self.workdir / "rounds"
        self.round_pipeline = self._resolve_round_pipeline(cfg.get("pipeline"))
        self.round_settings = self._build_round_settings(settings)
        self.catalog = AssetCatalog()
        self.target_host = normalize_host(target)
        self._queued: set[str] = set()

    # -- setup ------------------------------------------------------------

    @staticmethod
    def _resolve_round_pipeline(value: Any) -> Path:
        if not value:
            return DEFAULT_ROUND_PIPELINE
        path = Path(str(value))
        if path.is_absolute():
            return path
        candidate = CONFIGS_DIR / path
        if candidate.exists():
            return candidate
        if path.exists():
            return path
        return DEFAULT_ROUND_PIPELINE

    @staticmethod
    def _build_round_settings(settings: dict[str, Any]) -> dict[str, Any]:
        round_settings = copy.deepcopy(settings)
        recursive_cfg = round_settings.setdefault("recursive", {})
        # Rounds must never start nested recursion.
        recursive_cfg["enabled"] = False
        if not recursive_cfg.get("rescan_ips"):
            recursive_cfg["skip_scanned_ips"] = True
        return round_settings

    # -- public entry point ----------------------------------------------

    def run(self, logger: ScanLogger | None = None) -> list[dict[str, Any]]:
        """Execute recursive rounds and return per-round metadata."""
        if not self.round_pipeline.exists():
            if logger:
                logger.log_error(
                    "recursive", f"递归流程不存在：{self.round_pipeline}"
                )
            return []

        initial_assets = collect_assets(self.workdir, 0)
        initial_new = self.catalog.add_all(initial_assets)
        queue = [
            host for host in initial_new
            if host and host != self.target_host
        ]
        self._queued.update(queue)

        rounds: list[dict[str, Any]] = []
        max_extra_rounds = max(0, self.max_rounds - 1)
        previous_dir: Path | None = None

        while queue and len(rounds) < max_extra_rounds:
            round_num = len(rounds) + 1
            batch = queue[: self.max_assets_per_round]
            queue = queue[self.max_assets_per_round:]
            round_dir = self.rounds_dir / f"r{round_num:03d}"
            targets = self.catalog.targets_for(batch, round_num)
            prepare_round_dir(
                round_dir,
                targets,
                previous_dir if previous_dir is not None else self.workdir,
            )

            if logger:
                logger.log_stage_start(f"round_{round_num}")

            start = time.time()
            error: str | None = None
            stage_results: dict[str, Any] = {}
            try:
                scheduler = PipelineScheduler(
                    self.round_pipeline, self.round_settings
                )
                result = scheduler.run(
                    self.target,
                    round_dir,
                    self.task_id,
                    recursive=False,
                    save_meta=False,
                )
                stage_results = result.stages
            except Exception as exc:  # noqa: BLE001 - keep earlier rounds
                error = str(exc)

            duration = time.time() - start
            new_hosts: list[str] = []
            if error is None:
                new_hosts = self.catalog.add_all(
                    collect_assets(round_dir, round_num)
                )
                for host in new_hosts:
                    if (
                        host
                        and host != self.target_host
                        and host not in self._queued
                    ):
                        self._queued.add(host)
                        queue.append(host)

            if logger:
                logger.log_stage_end(
                    f"round_{round_num}",
                    "failed" if error else "done",
                    duration,
                    len(batch),
                    error=error,
                )

            rounds.append({
                "round": round_num,
                "dir": str(round_dir),
                "targets": len(batch),
                "target_hosts": list(batch),
                "new_hosts": list(new_hosts),
                "stage_results": stage_results,
                "duration": round(duration, 3),
                "error": error,
            })
            previous_dir = round_dir

            if error:
                break

        summary = self.catalog.summary()
        if logger:
            logger.log_stage_end(
                "recursive_summary",
                "done",
                0,
                summary.get("hosts", 0),
            )
        return rounds
