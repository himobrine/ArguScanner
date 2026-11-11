"""ApiProbe plugin - discover API documentation / endpoints with httpx.

The plugin reuses the httpx binary that is already required by the pipeline.
It probes a curated wordlist of common API paths on every discovered origin and
classifies the responses (Swagger/OpenAPI, GraphQL, Actuator, JSON APIs).
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from arguscaner.core.plugins.base_plugin import BasePlugin, PluginSkipped
from arguscaner.utils.target_classifier import TargetType
from arguscaner.utils.tool_paths import resolve_tool


CONFIGS_DIR = Path(__file__).parent.parent.parent / "configs"


class ApiProbePlugin(BasePlugin):
    """Probe live web origins for common API endpoints."""

    name = "api_probe"
    description = "API 探测：Swagger/OpenAPI/GraphQL/Actuator 等接口发现"
    version = "1.0.0"
    command_template = (
        'httpx -l {{input_file}} -path "{{paths}}" -mc 200,201,202,204,206,'
        "301,302,307,308,401,403,405 -json -silent -o {{output}}"
    )
    output_filename = "api_probe_output.jsonl"
    raw_filename = "api_probe_raw.jsonl"
    output_schema = {
        "url": "str",
        "status": "int",
        "content_type": "str",
        "api_type": "str",
        "title": "str",
        "evidence": "str",
        "source": "str",
        "timestamp": "str",
    }
    supported_target_types: list[TargetType] = [TargetType.DOMAIN, TargetType.IP]
    input_requirements: list[str] = []
    conditions: list = []

    MATCH_CODES = "200,201,202,204,206,301,302,307,308,401,403,405"

    def __init__(self, settings: dict[str, Any] | None = None):
        super().__init__(settings)
        cfg = (settings or {}).get("plugins", {}).get("api_probe", {})
        self.threads = int(cfg.get("threads", 10))
        self.timeout = int(cfg.get("timeout", 10))
        self.rate_limit = int(cfg.get("rate_limit", 20))
        self.max_origins = int(cfg.get("max_origins", 100))
        self.max_paths = int(cfg.get("max_paths", 80))
        self.include_scheme_fallback = bool(cfg.get("include_scheme_fallback", True))
        self.wordlist = self._resolve_wordlist(cfg.get("wordlist"))

    # ------------------------------------------------------------------
    # Input resolution
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_wordlist(value: Any) -> Path:
        if not value:
            return CONFIGS_DIR / "wordlists" / "api_paths.txt"
        path = Path(str(value))
        if path.is_absolute():
            return path
        candidate = CONFIGS_DIR / path
        if candidate.exists():
            return candidate
        return CONFIGS_DIR.parent / path

    @staticmethod
    def _origin(value: str) -> str | None:
        text = str(value or "").strip()
        if not text:
            return None
        if "://" not in text:
            return None
        parsed = urlparse(text)
        if not parsed.scheme or not parsed.netloc:
            return None
        return f"{parsed.scheme}://{parsed.netloc}".lower()

    def _already_probed_origins(self, workdir: Path) -> set[str]:
        """Origins already probed in this task (cross-round tracker)."""
        origins = self._read_hosts_file(
            self._stage_file(workdir, "api_probe_origins.txt")
        )
        for rec in self._read_jsonl(workdir / "api_probe.jsonl"):
            origin = self._origin(rec.get("url", ""))
            if origin:
                origins.add(origin)
        return origins

    def _collect_origins(self, target: str, workdir: Path) -> list[str]:
        values: list[Any] = []
        round_hosts: list[str] = []
        if self._bound_inputs:
            for rec in self._input_records(workdir):
                values.append(
                    rec.get("url")
                    or rec.get("host")
                    or rec.get("domain")
                    or rec.get("data")
                    or rec.get("target")
                )
        else:
            for rec in self._read_jsonl(workdir / "http_probe.jsonl"):
                values.append(rec.get("url") or rec.get("host"))
            for rec in self._read_jsonl(workdir / "round_targets.jsonl"):
                values.append(rec.get("url"))
                host = self._host_from_value(
                    rec.get("host") or rec.get("target") or rec.get("ip")
                )
                if host:
                    round_hosts.append(host)

        origins: list[str] = []
        seen: set[str] = set()
        origin_hosts: set[str] = set()
        for value in values:
            if not value:
                continue
            origin = self._origin(str(value))
            if origin and origin not in seen:
                seen.add(origin)
                origins.append(origin)
                origin_hosts.add(self._host_from_value(origin))

        # Round targets often only carry a host (no scheme). Probe both
        # schemes so IP hops discovered by DNS are still covered.
        schemes = (
            ("http", "https") if self.include_scheme_fallback else ("https",)
        )
        for host in round_hosts:
            if host in origin_hosts:
                continue
            for scheme in schemes:
                origin = f"{scheme}://{host}"
                if origin not in seen:
                    seen.add(origin)
                    origins.append(origin)

        if not origins:
            host = self._host_from_value(target)
            if host:
                origins = [f"http://{host}", f"https://{host}"]

        probed = self._already_probed_origins(workdir)
        pending = [o for o in origins if o not in probed]
        return pending[: self.max_origins]

    # ------------------------------------------------------------------
    # Wordlist
    # ------------------------------------------------------------------

    def _load_paths(self) -> list[str]:
        if not self.wordlist.exists():
            return []
        paths: list[str] = []
        for line in self.wordlist.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if not line.startswith("/"):
                line = "/" + line
            if line not in paths:
                paths.append(line)
        return paths[: self.max_paths]

    # ------------------------------------------------------------------
    # Classification
    # ------------------------------------------------------------------

    @staticmethod
    def _classify(url: str, status: int, content_type: str, title: str) -> str | None:
        """Return an API type, or None when the response is not API-related."""
        path = urlparse(url).path.lower()
        combined = f"{path} {title.lower()}"
        ct = (content_type or "").lower()

        if status <= 0 or status == 404:
            return None

        graphql = ("graphql" in combined) or ("graphiql" in combined) or (
            "playground" in combined
        )
        swagger = any(
            token in combined
            for token in ("swagger", "openapi", "api-docs", "api_docs", "redoc")
        )
        actuator = "actuator" in combined
        json_api = any(
            token in ct
            for token in ("json", "yaml", "xml", "protobuf", "graphql")
        )
        known = graphql or swagger or actuator

        # A 401/403 on a known API path is itself a useful finding.
        if not (known or json_api):
            return None
        if status in (401, 403) and not known:
            return None

        if graphql:
            return "graphql"
        if swagger:
            return "swagger/openapi"
        if actuator:
            return "actuator"
        if json_api:
            return "json-api"
        return "api"

    # ------------------------------------------------------------------
    # Plugin interface
    # ------------------------------------------------------------------

    def execute(self, target: str, workdir: Path, proxy: str | None = None) -> Path:
        output_file = self._stage_file(workdir, self.output_filename)
        raw_file = self._stage_file(workdir, self.raw_filename)
        output_file.parent.mkdir(parents=True, exist_ok=True)

        origins = self._collect_origins(target, workdir)
        if not origins:
            raise PluginSkipped("没有新的 API 探测目标（origin 均已探测）")

        paths = self._load_paths()
        if not paths:
            raise PluginSkipped(f"API 路径字典为空或不存在：{self.wordlist}")

        input_file = self._stage_file(workdir, "api_input.txt")
        input_file.write_text("\n".join(origins) + "\n", encoding="utf-8")

        args = [
            self._httpx_bin,
            "-l", str(input_file),
            "-path", ",".join(paths),
            "-mc", self.MATCH_CODES,
            "-json",
            "-silent",
            "-threads", str(self.threads),
            "-timeout", str(self.timeout),
            "-rate-limit", str(self.rate_limit),
            "-o", str(raw_file),
        ]
        if proxy:
            args += ["-proxy", proxy]

        self._run_args(
            args,
            workdir,
            timeout=max(300, self.timeout * len(paths)),
        )
        # Record every probed origin so later rounds do not probe it again,
        # even when no API endpoint was found.
        self._append_hosts_file(
            self._stage_file(workdir, "api_probe_origins.txt"), origins
        )

        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ")
        records: list[dict[str, Any]] = []
        seen: set[str] = set()
        for rec in self._read_jsonl(raw_file):
            url = str(rec.get("url", "")).strip()
            if not url or url in seen:
                continue
            try:
                status = int(rec.get("status_code") or rec.get("status") or 0)
            except (TypeError, ValueError):
                status = 0
            content_type = str(
                rec.get("content_type") or rec.get("content-type") or ""
            ).strip()
            title = str(rec.get("title") or "").strip()
            api_type = self._classify(url, status, content_type, title)
            if not api_type:
                continue
            seen.add(url)
            path = urlparse(url).path or "/"
            evidence = (
                f"status={status}; content-type={content_type or '-'}; path={path}"
            )
            records.append({
                "url": url,
                "status": status,
                "content_type": content_type,
                "api_type": api_type,
                "title": title,
                "evidence": evidence,
                "source": "api_probe",
                "timestamp": timestamp,
            })

        records.sort(key=lambda r: r["url"])
        self._write_jsonl(records, output_file)
        return output_file

    @property
    def _httpx_bin(self) -> str:
        return resolve_tool("httpx", self.settings, plugin="api_probe").path

    def parse_output(self, output_file: Path) -> list[dict[str, Any]]:
        return self._read_jsonl(output_file)
