"""Tests for the cross-platform one-click setup script."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SETUP_PATH = ROOT / "scripts" / "setup.py"


def _load_setup():
    spec = importlib.util.spec_from_file_location("argus_setup", SETUP_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


setup = _load_setup()


def test_parse_args_defaults():
    args = setup.parse_args([])
    assert args.dev is False
    assert args.no_venv is False
    assert args.check is False
    assert args.host == "127.0.0.1"
    assert args.port == 5000
    assert args.install_optional_tools is False
    assert args.install_redis is False


def test_parse_args_flags():
    args = setup.parse_args(
        [
            "--dev",
            "--no-venv",
            "--check",
            "--fix-tool-paths",
            "--install-optional-tools",
            "--install-redis",
            "--test",
            "--run",
            "--host",
            "0.0.0.0",
            "--port",
            "8080",
            "--yes",
            "--recreate-venv",
        ]
    )
    assert args.dev is True
    assert args.no_venv is True
    assert args.check is True
    assert args.fix_tool_paths is True
    assert args.install_optional_tools is True
    assert args.install_redis is True
    assert args.test is True
    assert args.run is True
    assert args.host == "0.0.0.0"
    assert args.port == 8080
    assert args.yes is True
    assert args.recreate_venv is True


def test_python_version_check():
    assert setup.python_version_ok((3, 10)) is True
    assert setup.python_version_ok((3, 11, 4)) is True
    assert setup.python_version_ok((3, 12)) is True
    assert setup.python_version_ok((3, 9, 18)) is False
    assert setup.python_version_ok((2, 7)) is False


def test_venv_python_path_windows(monkeypatch, tmp_path):
    monkeypatch.setattr(setup.os, "name", "nt")
    assert setup.venv_python_path(tmp_path).name == "python.exe"
    assert "Scripts" in str(setup.venv_python_path(tmp_path))


def test_venv_python_path_posix(monkeypatch, tmp_path):
    monkeypatch.setattr(setup.os, "name", "posix")
    assert setup.venv_python_path(tmp_path).name == "python"
    assert "bin" in str(setup.venv_python_path(tmp_path))


def test_ensure_dirs(tmp_path):
    created = setup.ensure_dirs(tmp_path)
    assert (tmp_path / "workspace").is_dir()
    assert (tmp_path / "logs").is_dir()
    assert (tmp_path / "arguscaner" / "configs" / "custom_plugins").is_dir()
    assert (tmp_path / "arguscaner" / "configs" / "pipelines").is_dir()
    assert len(created) == 4
    # A second run creates nothing new.
    assert setup.ensure_dirs(tmp_path) == []


def test_ensure_gitignore(tmp_path):
    assert setup.ensure_gitignore(tmp_path) is True
    content = (tmp_path / ".gitignore").read_text(encoding="utf-8")
    assert ".venv/" in content
    assert "workspace/" in content
    # Idempotent.
    assert setup.ensure_gitignore(tmp_path) is False


def test_nested_get_set():
    data = {"plugins": {"httpx_probe": {"httpx_path": ""}}}
    assert setup._nested_get(data, "plugins.httpx_probe.httpx_path") == ""
    setup._nested_set(data, "plugins.nmap_scan.nmap_path", "/usr/bin/nmap")
    assert data["plugins"]["nmap_scan"]["nmap_path"] == "/usr/bin/nmap"


def test_detect_tools_returns_all():
    from arguscaner.core.tool_registry import TOOL_SPECS

    tools = setup.detect_tools({})
    keys = {tool["key"] for tool in tools}
    assert set(TOOL_SPECS) <= keys
    assert all("exists" in tool and "source_label" in tool for tool in tools)


def test_main_check_mode(capsys):
    code = setup.main(["--check"])
    captured = capsys.readouterr()
    assert code == 0
    assert "仅检查模式" in captured.out
    assert "外部工具" in captured.out


def test_fix_tool_paths_on_temp_settings(tmp_path):
    settings_path = tmp_path / "settings.yaml"
    settings_path.write_text(
        "plugins:\n"
        "  httpx_probe:\n"
        "    httpx_path: ''\n"
        "  nmap_scan:\n"
        "    nmap_path: ''\n",
        encoding="utf-8",
    )
    # Should not raise even when some tools are missing.
    setup.fix_tool_paths(settings_path)
    import yaml

    data = yaml.safe_load(settings_path.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    assert "plugins" in data


def test_platform_names_skips_windows_exe_on_posix(monkeypatch):
    from arguscaner.utils import tool_paths

    monkeypatch.setattr(tool_paths.os, "name", "posix")
    names = tool_paths._platform_names(["httpx.exe", "httpx"])
    assert names == ["httpx"]


def test_platform_names_prefers_exe_on_windows(monkeypatch):
    from arguscaner.utils import tool_paths

    monkeypatch.setattr(tool_paths.os, "name", "nt")
    names = tool_paths._platform_names(["httpx", "httpx.exe"])
    assert names[0] == "httpx.exe"
    assert "httpx" in names


def test_bundled_exe_ignored_on_posix(monkeypatch):
    from arguscaner.utils import tool_paths

    monkeypatch.setattr(tool_paths.os, "name", "posix")
    assert tool_paths._bundled_candidate("httpx/httpx.exe", ["httpx.exe"]) is None