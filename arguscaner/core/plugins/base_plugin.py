"""BasePlugin - Abstract base class for all scanner plugins."""

from __future__ import annotations

import json
import os
import shlex
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from arguscaner.utils.target_classifier import TargetClassifier, TargetType


class CommandError(RuntimeError):
    """Raised when a plugin subprocess exits with a non-zero code.

    Carries the raw exit code so the scheduler can apply the configured
    retry policy (retryable_exit_codes / non_retryable_exit_codes).
    """

    def __init__(self, message: str, returncode: int | None = None):
        super().__init__(message)
        self.returncode = returncode


class PluginSkipped(RuntimeError):
    """Raised when a plugin intentionally skips its work.

    This is *not* a failure: the scheduler records the stage as SKIPPED so
    downstream stages can still run (e.g. all IPs were already port-scanned).
    """


@dataclass
class PluginCondition:
    """Describes a condition that must be met for a plugin to execute.

    field: Which context attribute to check (target_type, enabled, has_record, etc.)
    operator: Comparison (eq, ne, in)
    value: Expected value
    description: Human-readable explanation for UI/CLI display.
    """

    field: str
    operator: str = "eq"
    value: Any = None
    description: str = ""

    def check(self, context: dict[str, Any]) -> tuple[bool, str]:
        """Evaluate the condition against a context dict.

        Returns (meets, reason). reason explains why if not met.
        """
        actual = context.get(self.field)

        if self.operator == "eq":
            meets = actual == self.value
        elif self.operator == "ne":
            meets = actual != self.value
        elif self.operator == "in":
            meets = actual in self.value if isinstance(self.value, (list, tuple, set)) else False
        else:
            meets = False

        if meets:
            return True, ""
        expected = f"{self.field} {self.operator} {self.value}"
        return False, f"条件不满足：{expected}（实际值：{actual}）"


class BasePlugin(ABC):
    """Abstract base class that all scanner plugins must implement.

    Each plugin wraps a CLI tool (OneForAll, httpx, Nmap, etc.) and provides
    a standardized interface for execution and output parsing.

    Plugins declare metadata (description, version, supported target types,
    input requirements) and conditions that gate execution.
    """

    name: str = "base"
    description: str = ""
    version: str = "1.0.0"
    command_template: str = ""
    output_filename: str = "output.jsonl"
    output_schema: dict[str, str] = {}

    #: Which target types this plugin can meaningfully process. Empty = all.
    supported_target_types: list[TargetType] = []

    #: Names of stages whose output this plugin needs as input.
    input_requirements: list[str] = []

    #: Built-in conditions that gate execution.
    conditions: list[PluginCondition] = []

    def __init__(self, settings: dict[str, Any] | None = None):
        self.settings = settings or {}
        self.enabled = self._load_enabled()
        self.stage_id: str = ""
        self._bound_inputs: list[Path] = []
        self._scoped: bool = False

    # ------------------------------------------------------------------
    # Stage binding (execution isolation + declared data inputs)
    # ------------------------------------------------------------------

    def bind_stage(
        self,
        stage_id: str,
        input_files: list[Path] | None = None,
        scoped: bool = False,
    ) -> None:
        """Attach this instance to a pipeline stage.

        ``input_files`` are the declared upstream artifacts.  ``scoped`` is set
        when the same plugin runs more than once in a pipeline, so plugin-owned
        files get a stage suffix to avoid collisions.
        """
        self.stage_id = stage_id
        self._bound_inputs = [Path(p) for p in (input_files or [])]
        self._scoped = bool(scoped)

    def _stage_file(self, workdir: Path, name: str) -> Path:
        """Return a plugin-owned file path, stage-scoped when needed."""
        if not self._scoped or not self.stage_id:
            return Path(workdir) / name
        path = Path(name)
        return Path(workdir) / f"{path.stem}__{self.stage_id}{path.suffix}"

    def _input_files(self, workdir: Path, *defaults: str) -> list[Path]:
        """Declared input files, falling back to the legacy file names."""
        if self._bound_inputs:
            return [path for path in self._bound_inputs if path.exists()]
        return [
            Path(workdir) / name
            for name in defaults
            if (Path(workdir) / name).exists()
        ]

    def _input_records(self, workdir: Path, *defaults: str) -> list[dict[str, Any]]:
        """Read all declared input records (legacy names as fallback)."""
        records: list[dict[str, Any]] = []
        for path in self._input_files(workdir, *defaults):
            records.extend(self._read_jsonl(path))
        return records

    def _load_enabled(self) -> bool:
        """Load enabled state from settings configuration."""
        plugins_cfg = self.settings.get("plugins", {})
        entry = plugins_cfg.get(self.name, {})
        if isinstance(entry, dict):
            return entry.get("enabled", True)
        return True

    # ------------------------------------------------------------------
    # Metadata helpers for UI/CLI display
    # ------------------------------------------------------------------

    @property
    def info(self) -> dict[str, Any]:
        """Return plugin metadata for display in UI/CLI."""
        return {
            "name": self.name,
            "description": self.description,
            "version": self.version,
            "command_template": self.command_template,
            "output_schema": self.output_schema,
            "supported_target_types": [
                t.value for t in self.supported_target_types
            ] or ["all"],
            "input_requirements": self.input_requirements,
            "conditions": [
                {
                    "field": c.field,
                    "operator": c.operator,
                    "value": c.value,
                    "description": c.description,
                }
                for c in self.conditions
            ],
            "enabled": self.enabled,
        }

    # ------------------------------------------------------------------
    # Condition evaluation
    # ------------------------------------------------------------------

    def check_conditions(self, context: dict[str, Any]) -> tuple[bool, str]:
        """Check if the plugin can execute given the context.

        Verifies enabled state, target type support, and built-in conditions.

        Args:
            context: Context dict with keys like 'target_type', 'target'.

        Returns:
            (meets, reason). reason explains why execution is not allowed.
        """
        if not self.enabled:
            return False, f"插件 '{self.name}' 已禁用"

        target_type = context.get("target_type")
        if target_type is not None and self.supported_target_types:
            if target_type not in self.supported_target_types:
                supported = ", ".join(t.value for t in self.supported_target_types)
                return (
                    False,
                    f"目标类型 '{target_type}' 不被插件 '{self.name}' 支持（支持的类型：{supported}）",
                )

        for cond in self.conditions:
            meets, reason = cond.check(context)
            if not meets:
                return False, reason

        return True, ""

    # ------------------------------------------------------------------
    # Command rendering
    # ------------------------------------------------------------------

    def render_command(self, target: str, output_file: Path, proxy: str | None = None) -> str:
        """Render the command template with substituted variables."""
        cmd = self.command_template
        cmd = cmd.replace("{{target}}", target)
        cmd = cmd.replace("{{output}}", str(output_file))
        if proxy:
            cmd = cmd.replace("{{proxy}}", proxy)
        return cmd

    # ------------------------------------------------------------------
    # Abstract interface
    # ------------------------------------------------------------------

    @abstractmethod
    def execute(self, target: str, workdir: Path, proxy: str | None = None) -> Path:
        """Execute the plugin against a target.

        Args:
            target: The scan target (domain, IP, CIDR).
            workdir: Working directory for output files.
            proxy: Optional proxy string.

        Returns:
            Path to the output file.
        """

    @abstractmethod
    def parse_output(self, output_file: Path) -> list[dict[str, Any]]:
        """Parse the plugin output file into structured records.

        Args:
            output_file: Path to the plugin's output file.

        Returns:
            List of dictionaries, each representing one record.
        """

    # ------------------------------------------------------------------
    # Base helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _to_argv(cmd: str | list[str]) -> list[str]:
        """Convert a command template/string into an argument vector.

        Shell is never used. Windows-style quoted paths are unquoted with
        ``shlex`` in non-POSIX mode so backslashes are preserved.
        """
        if isinstance(cmd, (list, tuple)):
            return [str(a) for a in cmd]
        if os.name == "nt":
            parts = shlex.split(cmd, posix=False)
            cleaned: list[str] = []
            for part in parts:
                if len(part) >= 2 and part[0] == part[-1] and part[0] in ('"', "'"):
                    part = part[1:-1]
                cleaned.append(part)
            return cleaned
        return shlex.split(cmd)

    def _run_args(
        self, args: list[str], workdir: Path, timeout: int = 3000
    ) -> subprocess.CompletedProcess:
        """Execute an argument vector without a shell."""
        return self._run_command(args, workdir, timeout)

    def _run_command(self, cmd: str | list[str], workdir: Path, timeout: int = 3000) -> subprocess.CompletedProcess:
        """Execute a command without a shell and with a timeout.

        ``cmd`` may be an argv list (preferred) or a string template, which is
        split into argv. Shell metacharacters are therefore never interpreted.

        Raises CommandError if the command exits with a non-zero return code.
        """
        args = self._to_argv(cmd)
        result = subprocess.run(
            args,
            shell=False,
            cwd=str(workdir),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
        if result.returncode != 0:
            stderr_snippet = (result.stderr or result.stdout or "")[:500]
            raise CommandError(
                f"命令执行失败 (exit {result.returncode}): {args}\n{stderr_snippet}",
                returncode=result.returncode,
            )
        return result

    def _write_jsonl(self, records: list[dict[str, Any]], output_file: Path) -> None:
        """Write records to a JSONL file."""
        output_file.parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, "w", encoding="utf-8") as f:
            for record in records:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")

    def _read_jsonl(self, input_file: Path) -> list[dict[str, Any]]:
        """Read records from a JSONL file."""
        records = []
        if not input_file.exists():
            return records
        with open(input_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return records

    # ------------------------------------------------------------------
    # Target helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _strip_www(target: str) -> str:
        """Safely strip www prefix (fixes lstrip bug)."""
        return TargetClassifier.strip_www(target)

    @staticmethod
    def _host_from_value(value: Any) -> str:
        """Extract a lowercase hostname/IP from a URL, host:port or host."""
        if value is None:
            return ""
        text = str(value).strip()
        if not text:
            return ""
        if "://" in text:
            from urllib.parse import urlparse

            text = urlparse(text).hostname or ""
        elif "/" in text and not text.startswith("/"):
            # Preserve CIDR notation (10.0.0.0/24) instead of treating the
            # prefix as a URL path.
            is_cidr = False
            try:
                import ipaddress

                ipaddress.ip_network(text, strict=False)
                is_cidr = True
            except ValueError:
                is_cidr = False
            if not is_cidr:
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
        return text

    def _round_hosts(self, target: str, workdir: Path) -> list[str]:
        """Return hosts that a round-based batch stage should process.

        Outside a recursive round (no ``round_targets.jsonl``) this is simply
        the original target, preserving the first-pass behaviour. Inside a
        round it returns the discovered hosts plus live URLs.
        """
        if self._bound_inputs:
            values: list[Any] = []
            for rec in self._input_records(workdir):
                for key in ("target", "host", "domain", "ip", "url"):
                    if rec.get(key):
                        values.append(rec[key])
            return self._unique_hosts(values)

        round_file = workdir / "round_targets.jsonl"
        if not round_file.exists():
            host = self._host_from_value(target)
            return [host] if host else []

        values = []
        for rec in self._read_jsonl(round_file):
            for key in ("target", "host", "domain", "ip", "url"):
                if rec.get(key):
                    values.append(rec[key])
        for rec in self._read_jsonl(workdir / "http_probe.jsonl"):
            value = rec.get("url") or rec.get("host")
            if value:
                values.append(value)

        return self._unique_hosts(values)

    def _unique_hosts(self, values: list[Any]) -> list[str]:
        hosts: list[str] = []
        seen: set[str] = set()
        for value in values:
            host = self._host_from_value(value)
            if host and host not in seen:
                seen.add(host)
                hosts.append(host)
        return hosts

    @staticmethod
    def _read_hosts_file(path: Path) -> set[str]:
        if not path.exists():
            return set()
        try:
            return {
                line.strip().lower()
                for line in path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            }
        except OSError:
            return set()

    @staticmethod
    def _append_hosts_file(path: Path, hosts: list[str]) -> None:
        if not hosts:
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a", encoding="utf-8") as f:
            for host in hosts:
                f.write(host + "\n")

    def _decorate_record(self, record: dict[str, Any], target: str) -> dict[str, Any]:
        """Add target and target_type metadata to a record."""
        rec = dict(record)
        rec["target"] = target
        try:
            rec["target_type"] = TargetClassifier.classify(target).value
        except ValueError:
            rec["target_type"] = "unknown"
        return rec


class PluginRegistry:
    """Central registry of all available plugins (builtin + custom)."""

    CUSTOM_PLUGINS_DIR = Path(__file__).parent.parent.parent / "configs" / "custom_plugins"

    def __init__(self, settings: dict[str, Any] | None = None):
        self.settings = settings or {}
        self._plugins: dict[str, BasePlugin] = self._build_registry()
        self._custom_names: set[str] = set()
        self._load_custom_plugins()

    def _build_registry(self) -> dict[str, BasePlugin]:
        """Import and instantiate all builtin plugin classes."""
        from arguscaner.core.plugins.oneforall import OneForAllPlugin
        from arguscaner.core.plugins.httpx_probe import HttpxProbePlugin
        from arguscaner.core.plugins.nmap_scan import NmapScanPlugin
        from arguscaner.core.plugins.jsfinder import JsFinderPlugin
        from arguscaner.core.plugins.urlfinder import UrlFinderPlugin
        from arguscaner.core.plugins.ip_discovery import IpDiscoveryPlugin
        from arguscaner.core.plugins.api_probe import ApiProbePlugin

        classes = [
            OneForAllPlugin,
            HttpxProbePlugin,
            NmapScanPlugin,
            JsFinderPlugin,
            UrlFinderPlugin,
            IpDiscoveryPlugin,
            ApiProbePlugin,
        ]
        return {
            cls.name: cls(self.settings)
            for cls in classes
        }

    def _load_custom_plugins(self) -> None:
        """扫描 custom_plugins 目录，加载 YAML 声明式插件。"""
        if not self.CUSTOM_PLUGINS_DIR.exists():
            return
        from arguscaner.core.plugins.generic_plugin import GenericPlugin

        for yaml_file in sorted(self.CUSTOM_PLUGINS_DIR.glob("*.yaml")):
            try:
                plugin = GenericPlugin.from_yaml_file(yaml_file, self.settings)
                self._plugins[plugin.name] = plugin
                self._custom_names.add(plugin.name)
            except Exception:
                continue

    def get(self, name: str) -> BasePlugin:
        """Get a plugin instance by name."""
        plugin = self._plugins.get(name)
        if plugin is None:
            raise ValueError(f"未知插件：{name}。可用插件：{list(self._plugins.keys())}")
        return plugin

    def spawn(self, name: str, settings: dict[str, Any] | None = None) -> BasePlugin:
        """Create an isolated plugin instance (used per pipeline stage)."""
        plugin = self.get(name)
        from arguscaner.core.plugins.generic_plugin import GenericPlugin

        merged = settings if settings is not None else self.settings
        if isinstance(plugin, GenericPlugin):
            return GenericPlugin(plugin._to_config(), merged)
        return type(plugin)(merged)

    @property
    def plugins(self) -> dict[str, BasePlugin]:
        """Get all registered plugins."""
        return self._plugins

    def list(self) -> list[dict[str, Any]]:
        """List all plugins with their metadata."""
        result = []
        for p in self._plugins.values():
            info = p.info
            info["source"] = getattr(p, "source", "builtin")
            result.append(info)
        return result

    def get_plugin_names(self) -> list[str]:
        """Get names of all registered plugins."""
        return list(self._plugins.keys())

    def is_custom(self, name: str) -> bool:
        """判断是否为自定义插件。"""
        return name in self._custom_names

    def add_custom(self, config: dict[str, Any]) -> BasePlugin:
        """添加自定义插件：创建 GenericPlugin 并写入 YAML 文件。"""
        from arguscaner.core.plugins.generic_plugin import GenericPlugin

        name = config.get("name", "")
        if not name:
            raise ValueError("插件名称不能为空")
        if name in self._plugins:
            raise ValueError(f"插件 '{name}' 已存在")

        plugin = GenericPlugin(config, self.settings)
        plugin.source = "custom"
        yaml_path = self.CUSTOM_PLUGINS_DIR / f"{name}.yaml"
        plugin.to_yaml_file(yaml_path)

        self._plugins[name] = plugin
        self._custom_names.add(name)
        return plugin

    def remove_custom(self, name: str) -> None:
        """删除自定义插件：移除 YAML 文件并从注册表清除。"""
        if name not in self._custom_names:
            raise ValueError(f"插件 '{name}' 不是自定义插件，无法删除")

        yaml_path = self.CUSTOM_PLUGINS_DIR / f"{name}.yaml"
        if yaml_path.exists():
            yaml_path.unlink()

        self._plugins.pop(name, None)
        self._custom_names.discard(name)


def get_plugin(name: str, settings: dict[str, Any] | None = None) -> BasePlugin:
    """Factory function to get a plugin instance by name."""
    return PluginRegistry(settings).get(name)


def list_plugins(settings: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """List all registered plugins with metadata."""
    return PluginRegistry(settings).list()
