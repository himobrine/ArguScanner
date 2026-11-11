"""Tests for external tool path resolution."""

from __future__ import annotations

from pathlib import Path

from arguscaner.core import tool_registry
from arguscaner.utils import tool_paths


def _clear_env(monkeypatch):
    for spec in tool_registry.TOOL_SPECS.values():
        for name in spec.get("env", []):
            monkeypatch.delenv(name, raising=False)


def test_bundled_tools_are_found(monkeypatch):
    _clear_env(monkeypatch)
    httpx = tool_paths.resolve_tool("httpx", {})
    urlfinder = tool_paths.resolve_tool("urlfinder", {})
    assert httpx.source == "bundled"
    assert httpx.exists is True
    assert httpx.path.endswith("httpx.exe") or httpx.path.endswith("httpx")
    assert urlfinder.source == "bundled"
    assert urlfinder.exists is True


def test_configured_file_wins(tmp_path, monkeypatch):
    _clear_env(monkeypatch)
    fake = tmp_path / "custom-httpx.exe"
    fake.write_bytes(b"")
    settings = {"plugins": {"httpx_probe": {"httpx_path": str(fake)}}}
    result = tool_paths.resolve_tool("httpx", settings)
    assert result.source == "configured"
    assert result.path == str(fake)
    assert result.exists is True


def test_configured_directory_finds_executable(tmp_path, monkeypatch):
    _clear_env(monkeypatch)
    tool_dir = tmp_path / "httpx"
    tool_dir.mkdir()
    exe = tool_dir / "httpx.exe"
    exe.write_bytes(b"")
    settings = {"plugins": {"httpx_probe": {"httpx_path": str(tool_dir)}}}
    result = tool_paths.resolve_tool("httpx", settings)
    assert result.path == str(exe)
    assert result.exists is True


def test_plugin_specific_setting_takes_priority(tmp_path, monkeypatch):
    _clear_env(monkeypatch)
    shared = tmp_path / "shared.exe"
    specific = tmp_path / "api.exe"
    shared.write_bytes(b"")
    specific.write_bytes(b"")
    settings = {
        "plugins": {
            "httpx_probe": {"httpx_path": str(shared)},
            "api_probe": {"httpx_path": str(specific)},
        }
    }
    assert tool_paths.resolve_tool("httpx", settings, plugin="httpx_probe").path == str(shared)
    assert tool_paths.resolve_tool("httpx", settings, plugin="api_probe").path == str(specific)


def test_missing_configured_path_is_reported(tmp_path, monkeypatch):
    _clear_env(monkeypatch)
    missing = tmp_path / "does-not-exist.exe"
    settings = {"plugins": {"nmap_scan": {"nmap_path": str(missing)}}}
    result = tool_paths.resolve_tool("nmap", settings, plugin="nmap_scan")
    assert result.source == "configured"
    assert result.exists is False


def test_environment_variable_fallback(tmp_path, monkeypatch):
    _clear_env(monkeypatch)
    exe = tmp_path / "env-httpx.exe"
    exe.write_bytes(b"")
    monkeypatch.setenv("HTTPX_PATH", str(exe))
    result = tool_paths.resolve_tool("httpx", {})
    assert result.source == "env"
    assert result.path == str(exe)


def test_pipeline_params_override(tmp_path, monkeypatch):
    _clear_env(monkeypatch)
    exe = tmp_path / "stage-httpx.exe"
    exe.write_bytes(b"")
    settings = {"plugins": {"httpx_probe": {"httpx_path": "ignored.exe"}}}
    result = tool_paths.resolve_tool("httpx", settings, configured=str(exe))
    assert result.source == "configured"
    assert result.path == str(exe)


def test_describe_tools_covers_all_specs(monkeypatch):
    _clear_env(monkeypatch)
    described = tool_paths.describe_tools({})
    assert {item["key"] for item in described} == set(tool_registry.TOOL_SPECS)
    assert all("source_label" in item for item in described)


def test_tools_grouped_by_plugin(monkeypatch):
    _clear_env(monkeypatch)
    grouped = tool_paths.tools_by_plugin({})
    assert "httpx_probe" in grouped and "api_probe" in grouped
    assert "nmap_scan" in grouped
    assert grouped["httpx_probe"][0]["key"] == "httpx"


def test_check_candidate_reports_existence(tmp_path):
    exe = tmp_path / "tool.exe"
    exe.write_bytes(b"")
    result = tool_paths.check_candidate(str(exe), None, probe_version=False)
    assert result["exists"] is True
    assert result["is_file"] is True

    missing = tool_paths.check_candidate(str(tmp_path / "nope.exe"), None, probe_version=False)
    assert missing["exists"] is False


def test_relative_configured_path_uses_project_root(monkeypatch):
    _clear_env(monkeypatch)
    relative = Path("arguscaner/tools/httpx/httpx.exe")
    result = tool_paths.resolve_tool("httpx", {"plugins": {"httpx_probe": {"httpx_path": str(relative)}}})
    assert result.exists is True
    assert result.path == str(tool_registry.PROJECT_ROOT / relative)