"""JsFinderPlugin - JavaScript URL and subdomain extraction."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

from arguscaner.core.plugins.base_plugin import (
    BasePlugin,
    PluginCondition,
    PluginSkipped,
)
from arguscaner.utils.target_classifier import TargetType
from arguscaner.utils.tool_paths import resolve_tool


class JsFinderPlugin(BasePlugin):
    """JavaScript URL 和子域名提取插件。

    使用 JSFinder 从网页和 JavaScript 文件中提取 URL 和子域名。
    支持域名和 IP 目标类型。
    """

    name = "jsfinder"
    description = "JSFinder JavaScript URL 和子域名提取"
    version = "1.0.0"
    command_template = "python {{jsfinder_path}} -u {{target}} -ou {{urls_file}} -os {{subdomains_file}}"
    output_filename = "jsfinder_output.jsonl"
    output_schema = {
        "type": "str",
        "data": "str",
        "source": "str",
        "timestamp": "str",
    }
    supported_target_types: list[TargetType] = [
        TargetType.DOMAIN,
        TargetType.IP,
    ]
    input_requirements: list[str] = []
    conditions: list[PluginCondition] = []

    # Noise URL patterns to filter out (tracking pixels, static assets, analytics)
    NOISE_URL_PATTERNS: list[str] = [
        r"\.gif($|\?)", r"\.png($|\?)", r"\.jpg($|\?)", r"\.jpeg($|\?)",
        r"\.ico($|\?)", r"\.css($|\?)", r"\.svg($|\?)", r"\.webp($|\?)",
        r"/nocache/fesplg/s\.gif", r"/log/webb\.min",
        r"hm\.baidu\.com/hm\.js", r"hm\.baidu\.com/hm\.gif",
        r"sestat\.baidu\.com", r"sp[0-3]\.baidu\.com/.+\.gif",
        r"ss[0-3]\.baidu\.com/.+\.gif", r"dj[0-9]\.baidu\.com/v\.gif",
        r"sclick\.baidu\.com/w\.gif", r"click\.hm\.baidu\.com/app\.gif",
        r"hpd\.baidu\.com/v\.gif", r"sptidc.*\.baidu\.com/s\.gif",
        r"m\.baidu\.com/logo\.gif", r"/favicon\.ico",
        r"\.min\.js($|\?)", r"\.min\.css($|\?)",
        r"bdimg\.share\.baidu\.com", r"s\.share\.baidu\.com",
        r"-open\.baidu\.com/stat/", r"opendata\.baidu\.com/api",
        r"activity\.baidu\.com/activity/felog",
    ]

    # Noise subdomain patterns to filter out
    NOISE_SUBDOMAIN_PATTERNS: list[str] = [
        r"^sp[0-3]\.", r"^ss[0-3]\.", r"^dj[0-9]\.",
        r"^sestat\.", r"^sptidc", r"^sclick\.",
        r"^click\.hm\.", r"^hpd\.",
        r"^nsclick\.", r"^opendata\.", r"^open\.",
        r"^bdimg\.share\.", r"^s\.share\.",
        r"^eclick\.", r"^velocity\.",
    ]

    def __init__(self, settings: dict[str, Any] | None = None):
        super().__init__(settings)
        jsfinder_cfg = (settings or {}).get("plugins", {}).get("jsfinder", {})
        self.jsfinder_path = resolve_tool(
            "jsfinder", settings, jsfinder_cfg.get("jsfinder_path"), plugin="jsfinder"
        ).path
        self.timeout = jsfinder_cfg.get("timeout", 300)
        self.retry = jsfinder_cfg.get("retry", 2)
        self.retry_delay = jsfinder_cfg.get("retry_delay", 5)

    def execute(self, target: str, workdir: Path, proxy: str | None = None) -> Path:
        """Execute JavaScript URL extraction.

        The first pass crawls the original target only, preserving the
        historical behaviour. Inside a recursive round (``round_targets.jsonl``
        present) every discovered host is crawled in turn, with a tracking file
        so a host is never crawled twice across rounds.
        """
        import sys

        output_file = self._stage_file(workdir, self.output_filename)
        output_file.parent.mkdir(parents=True, exist_ok=True)

        round_mode = (workdir / "round_targets.jsonl").exists()
        cfg = self.settings.get("plugins", {}).get("jsfinder", {})
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
            seen_file = self._stage_file(workdir, "jsfinder_hosts.txt")
            already = self._read_hosts_file(seen_file)
            pending = [h for h in hosts if h not in already]
            pending = pending[:max_targets]
            if not pending:
                if hosts:
                    raise PluginSkipped(
                        f"所有主机均已执行 JSFinder（跳过 {len(hosts)} 个）"
                    )
                raise PluginSkipped("没有可执行 JSFinder 的主机")
        elif bound_targets:
            pending = bound_targets
            if not pending:
                raise PluginSkipped("没有可执行 JSFinder 的目标")
        else:
            host = self._host_from_value(target)
            pending = [host] if host else []
            if not pending:
                raise PluginSkipped("没有可执行 JSFinder 的目标")

        records: list[dict[str, Any]] = []
        seen_records: set[tuple[str, str]] = set()
        completed: list[str] = []
        first_error: Exception | None = None

        for item in pending:
            if round_mode:
                host = item
                host_target = self._ensure_url(host)
                record_target = host
            elif bound_targets:
                host = self._host_from_value(item) or item
                host_target = item if "://" in item else self._ensure_url(item)
                record_target = host
            else:
                host = item
                host_target = self._ensure_url(target)
                record_target = target

            slug = self._slug(host)
            if round_mode or bound_targets:
                urls_file = self._stage_file(workdir, f"jsfinder_urls_{slug}.txt")
                subdomains_file = self._stage_file(workdir, f"jsfinder_subdomains_{slug}.txt")
            else:
                urls_file = self._stage_file(workdir, "jsfinder_urls.txt")
                subdomains_file = self._stage_file(workdir, "jsfinder_subdomains.txt")

            args = [
                sys.executable,
                self.jsfinder_path,
                "-u", host_target,
                "-ou", str(urls_file),
                "-os", str(subdomains_file),
            ]

            try:
                self._run_args(args, workdir, timeout=self.timeout)
            except Exception as exc:  # noqa: BLE001 - per-host isolation
                if not round_mode:
                    raise
                first_error = first_error or exc
                continue

            completed.append(host)
            for rec in self._merge_output_files(
                urls_file, subdomains_file, record_target
            ):
                key = (str(rec.get("type", "")), str(rec.get("data", "")))
                if key in seen_records:
                    continue
                seen_records.add(key)
                records.append(rec)

        if round_mode:
            self._append_hosts_file(self._stage_file(workdir, "jsfinder_hosts.txt"), completed)
            if not completed and first_error is not None:
                raise first_error
            if not completed:
                raise PluginSkipped("JSFinder 未能完成任何主机")
        elif not completed:
            raise PluginSkipped("JSFinder 未执行")

        self._write_jsonl(records, output_file)
        return output_file

    @staticmethod
    def _slug(host: str) -> str:
        """Build a filesystem-safe slug from a host."""
        import re

        slug = re.sub(r"[^A-Za-z0-9_.-]+", "_", host).strip("._")
        return slug[:96] or "host"

    def _ensure_url(self, target: str) -> str:
        """Ensure target has http(s):// prefix for crawling."""
        from arguscaner.utils.target_classifier import TargetClassifier
        if "://" not in target:
            if TargetClassifier.is_ip(target):
                return f"http://{target}"
            return f"http://{target}"
        return target

    def parse_output(self, output_file: Path) -> list[dict[str, Any]]:
        """解析 jsfinder JSONL 输出。"""
        return self._read_jsonl(output_file)

    def _merge_output_files(
        self,
        urls_file: Path,
        subdomains_file: Path,
        target: str,
    ) -> list[dict[str, Any]]:
        """合并 JSFinder 输出的两个文件为统一格式。"""
        import re
        import time

        records = []
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ")

        if urls_file.exists():
            with open(urls_file, "r", encoding="utf-8") as f:
                for line in f:
                    url = line.strip()
                    if url and not self._is_noise_url(url):
                        records.append(
                            self._decorate_record(
                                {
                                    "type": "url",
                                    "data": url,
                                    "source": f"http://{target}/",
                                    "timestamp": timestamp,
                                },
                                target,
                            )
                        )

        if subdomains_file.exists():
            with open(subdomains_file, "r", encoding="utf-8") as f:
                for line in f:
                    subdomain = line.strip()
                    if subdomain and not self._is_noise_subdomain(subdomain):
                        records.append(
                            self._decorate_record(
                                {
                                    "type": "subdomain",
                                    "data": subdomain,
                                    "source": f"http://{target}/",
                                    "timestamp": timestamp,
                                },
                                target,
                            )
                        )

        return records

    def _is_noise_url(self, url: str) -> bool:
        """Check if a URL matches noise patterns (tracking, static assets, analytics)."""
        import re
        for pattern in self.NOISE_URL_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE):
                return True
        return False

    def _is_noise_subdomain(self, subdomain: str) -> bool:
        """Check if a subdomain matches noise patterns (analytics, CDN, tracking)."""
        import re
        for pattern in self.NOISE_SUBDOMAIN_PATTERNS:
            if re.search(pattern, subdomain, re.IGNORECASE):
                return True
        return False
