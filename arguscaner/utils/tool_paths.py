"""Resolve external tool paths for built-in plugins.

Resolution order (highest priority first):

1. an explicit ``configured`` value (pipeline stage ``params``),
2. plugin settings (``plugins.<plugin>.<tool>_path``),
3. environment variables (e.g. ``HTTPX_PATH``),
4. a tool bundled with the application (``arguscaner/tools/...``),
5. the system ``PATH``,
6. the bare command name (last resort, reported as missing).

Explicit configuration is honoured even when the file does not exist so the
UI can report a broken override instead of silently falling back.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from arguscaner.core.tool_registry import (
    PROJECT_ROOT,
    TOOLS_DIR,
    TOOL_SPECS,
    get_spec,
)

SOURCE_LABELS = {
    "configured": "自定义路径",
    "env": "环境变量",
    "bundled": "内置",
    "path": "系统 PATH",
    "command": "命令名",
    "missing": "未找到",
}


def _lookup(settings: dict[str, Any] | None, dotted: str) -> Any:
    current: Any = settings or {}
    for part in dotted.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
        if current is None:
            return None
    return current


def _platform_names(names: list[str]) -> list[str]:
    """Return executable candidates valid on the current platform.

    Windows tries ``.exe`` entries first; other platforms skip them entirely so
    a bundled Windows binary is never selected on Linux/macOS.
    """
    if os.name == "nt":
        exe = [name for name in names if name.lower().endswith(".exe")]
        other = [name for name in names if not name.lower().endswith(".exe")]
        return exe + other
    native = [name for name in names if not name.lower().endswith(".exe")]
    return native or list(names)


def _expand(raw: Any) -> Path:
    text = os.path.expandvars(str(raw).strip())
    text = os.path.expanduser(text)
    path = Path(text)
    if path.is_absolute():
        return path
    # Relative paths are resolved against the project root first, then the
    # process working directory to keep CLI usage predictable.
    candidate = PROJECT_ROOT / path
    if candidate.exists():
        return candidate
    return path


def _pick_executable(path: Path, executables: list[str]) -> Path:
    """If ``path`` is a directory, return the expected executable inside it."""
    names = _platform_names(executables)
    if path.is_dir():
        for name in names:
            candidate = path / name
            if candidate.exists():
                return candidate
        # Report the first expected name inside the directory.
        if names:
            return path / names[0]
    return path


def _bundled_candidate(relative: str, executables: list[str]) -> Path | None:
    """Resolve a bundled tool, allowing nested directories (zip extraction)."""
    if os.name != "nt" and relative.lower().endswith(".exe"):
        return None
    candidate = TOOLS_DIR / relative
    if candidate.exists():
        return candidate
    parent = candidate.parent
    if not parent.exists():
        return None
    names = _platform_names([candidate.name] + executables)
    for name in names:
        for found in parent.rglob(name):
            if found.is_file():
                return found
    return None


@dataclass
class ToolResolution:
    """Result of resolving a tool key."""

    key: str
    label: str
    path: str
    configured: str
    source: str
    exists: bool
    is_dir: bool
    plugins: list[str] = field(default_factory=list)
    description: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "label": self.label,
            "description": self.description,
            "path": self.path,
            "configured": self.configured,
            "source": self.source,
            "source_label": SOURCE_LABELS.get(self.source, self.source),
            "exists": self.exists,
            "is_dir": self.is_dir,
            "plugins": list(self.plugins),
        }


def _resolution(
    key: str,
    spec: dict[str, Any],
    configured: str,
    path: Path,
    source: str,
) -> ToolResolution:
    exists = path.exists()
    return ToolResolution(
        key=key,
        label=spec["label"],
        path=str(path),
        configured=configured,
        source=source,
        exists=exists,
        is_dir=path.is_dir(),
        plugins=list(spec.get("plugins", [])),
        description=spec.get("description", ""),
    )


def resolve_tool(
    key: str,
    settings: dict[str, Any] | None = None,
    configured: Any = None,
    plugin: str | None = None,
) -> ToolResolution:
    """Resolve ``key`` to a concrete executable path.

    ``plugin`` makes that plugin's own setting key win over shared fallbacks
    (e.g. ``api_probe.httpx_path`` before ``httpx_probe.httpx_path``).
    """
    spec = get_spec(key)
    setting_keys = list(spec.get("setting_keys", []))
    if plugin:
        own_key = f"plugins.{plugin}.{key}_path"
        setting_keys.sort(key=lambda item: 0 if item == own_key else 1)

    # 1/2. Explicit value or first non-empty plugin setting.
    raw_configured = ""
    if configured not in (None, ""):
        raw_configured = str(configured)
    else:
        for setting_key in setting_keys:
            value = _lookup(settings, setting_key)
            if value not in (None, ""):
                raw_configured = str(value)
                break
    if raw_configured:
        path = _pick_executable(_expand(raw_configured), spec["executables"])
        return _resolution(key, spec, raw_configured, path, "configured")

    # 3. Environment variables.
    for env_name in spec.get("env", []):
        value = os.environ.get(env_name)
        if value:
            path = _pick_executable(_expand(value), spec["executables"])
            return _resolution(key, spec, value, path, "env")

    # 4. Bundled tool.
    for relative in spec.get("bundled", []):
        candidate = _bundled_candidate(relative, spec["executables"])
        if candidate is not None:
            return _resolution(key, spec, "", candidate, "bundled")

    # 5. System PATH.
    for executable in _platform_names(spec["executables"]):
        found = shutil.which(executable)
        if found:
            return _resolution(key, spec, "", Path(found), "path")

    # 6. Bare command (not found, but callable if it appears later on PATH).
    names = _platform_names(spec["executables"])
    bare = names[0] if names else key
    return _resolution(key, spec, "", Path(bare), "command")


def describe_tools(settings: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Return resolution metadata for every registered tool."""
    return [resolve_tool(key, settings).as_dict() for key in TOOL_SPECS]


def tools_by_plugin(
    settings: dict[str, Any] | None = None,
) -> dict[str, list[dict[str, Any]]]:
    """Group tool resolutions by the plugin that uses them."""
    grouped: dict[str, list[dict[str, Any]]] = {}
    for item in describe_tools(settings):
        for plugin in item["plugins"]:
            grouped.setdefault(plugin, []).append(item)
    return grouped


def _probe_version(path: Path, version_args: list[str], timeout: float = 6.0) -> str | None:
    if not version_args or not path.exists() or path.is_dir():
        return None
    command = [str(path), *version_args]
    kwargs: dict[str, Any] = {
        "capture_output": True,
        "text": True,
        "timeout": timeout,
    }
    if sys.platform == "win32":  # pragma: no cover - platform specific
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        result = subprocess.run(command, **kwargs)
    except (OSError, subprocess.SubprocessError):
        return None
    output = (result.stdout or "") + "\n" + (result.stderr or "")
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    pattern = re.compile(r"version[^0-9]*([0-9][\w.\-]*)", re.IGNORECASE)
    for line in lines:
        match = pattern.search(line)
        if match:
            return match.group(1)[:160]
    return lines[0][:160] if lines else None


def check_candidate(
    path_value: Any,
    key: str | None = None,
    *,
    probe_version: bool = True,
) -> dict[str, Any]:
    """Inspect an arbitrary candidate path (used by ``/api/tools/check``)."""
    spec = TOOL_SPECS.get(key or "", {})
    executables = spec.get("executables", [])
    raw = str(path_value).strip()
    path = _expand(raw)
    if executables:
        path = _pick_executable(path, executables)
    exists = path.exists()
    version = None
    if exists and probe_version:
        version = _probe_version(path, spec.get("version_args", []))
    return {
        "key": key or "",
        "path": str(path),
        "raw": raw,
        "exists": exists,
        "is_dir": path.is_dir(),
        "is_file": path.is_file(),
        "version": version,
    }


def python_executable() -> str:
    """Return the Python interpreter used for script-based tools."""
    return sys.executable