"""Tests for the plugin system."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from arguscaner.core.plugins.base_plugin import get_plugin, BasePlugin
from arguscaner.core.plugins.oneforall import OneForAllPlugin
from arguscaner.core.plugins.httpx_probe import HttpxProbePlugin
from arguscaner.core.plugins.nmap_scan import NmapScanPlugin
from arguscaner.core.plugins.api_probe import ApiProbePlugin


def _mock_run_command(self, cmd, workdir, timeout=3000):
    """Mock _run_command that creates the expected output file."""
    output_file = workdir / self.output_filename
    output_file.write_text("", encoding="utf-8")
    return MagicMock(returncode=0, stdout="", stderr="")


class TestArgvExecution:

    def test_to_argv_accepts_list(self):
        args = ["cmd", "--flag", "a b"]
        assert BasePlugin._to_argv(args) == args

    def test_to_argv_splits_quoted_string(self):
        args = BasePlugin._to_argv('"C:/Program Files/tool.exe" -u "a b"')
        assert args == ["C:/Program Files/tool.exe", "-u", "a b"]

    def test_no_shell_true_in_plugin_sources(self):
        import inspect

        from arguscaner.core.plugins import (
            base_plugin,
            httpx_probe,
            jsfinder,
            nmap_scan,
            oneforall,
            urlfinder,
        )

        for mod in (base_plugin, oneforall, jsfinder, urlfinder, httpx_probe, nmap_scan):
            assert "shell=True" not in inspect.getsource(mod), mod.__name__

    def test_run_command_executes_argv_without_shell(self, sample_settings, tmp_workdir):
        import sys

        plugin = HttpxProbePlugin(sample_settings)
        result = plugin._run_command(
            [sys.executable, "-c", "print('argv-ok')"], tmp_workdir
        )
        assert "argv-ok" in result.stdout

    def test_run_command_rejects_nonzero_with_exit_code(self, sample_settings, tmp_workdir):
        import sys

        from arguscaner.core.plugins.base_plugin import CommandError

        plugin = HttpxProbePlugin(sample_settings)
        with pytest.raises(CommandError) as exc:
            plugin._run_command(
                [sys.executable, "-c", "import sys; sys.exit(127)"], tmp_workdir
            )
        assert exc.value.returncode == 127


class TestPluginRegistry:
    def test_get_oneforall(self, sample_settings):
        plugin = get_plugin("oneforall", sample_settings)
        assert isinstance(plugin, OneForAllPlugin)
        assert plugin.name == "oneforall"

    def test_get_httpx_probe(self, sample_settings):
        plugin = get_plugin("httpx_probe", sample_settings)
        assert isinstance(plugin, HttpxProbePlugin)
        assert plugin.name == "httpx_probe"

    def test_get_nmap_scan(self, sample_settings):
        plugin = get_plugin("nmap_scan", sample_settings)
        assert isinstance(plugin, NmapScanPlugin)
        assert plugin.name == "nmap_scan"

    def test_unknown_plugin_raises(self, sample_settings):
        with pytest.raises(ValueError, match="未知插件"):
            get_plugin("nonexistent", sample_settings)


class TestOneForAllPlugin:

    @patch.object(BasePlugin, "_run_command", _mock_run_command)
    def test_execute(self, sample_settings, tmp_workdir):
        plugin = OneForAllPlugin(sample_settings)
        output = plugin.execute("example.com", tmp_workdir)
        assert output.exists()
        assert output.name == "oneforall_output.jsonl"

    @patch.object(BasePlugin, "_run_command", _mock_run_command)
    def test_parse_output(self, sample_settings, tmp_workdir):
        plugin = OneForAllPlugin(sample_settings)
        output = plugin.execute("example.com", tmp_workdir)
        records = plugin.parse_output(output)
        assert isinstance(records, list)

    @patch.object(BasePlugin, "_run_command")
    def test_command_and_raw_mapping(self, mock_run, sample_settings, tmp_workdir):
        captured = {}

        def _side_effect(cmd, workdir, timeout=3000):
            captured["cmd"] = cmd
            (workdir / "oneforall_raw.json").write_text(
                json.dumps([
                    {"subdomain": "a.example.com", "ip": "1.2.3.4"},
                    {"url": "https://b.example.com/x", "ip": "5.6.7.8"},
                ]),
                encoding="utf-8",
            )
            return MagicMock(returncode=0)

        mock_run.side_effect = _side_effect
        plugin = OneForAllPlugin(sample_settings)
        output = plugin.execute("example.com", tmp_workdir)
        records = plugin.parse_output(output)

        cmd = captured["cmd"]
        cmd_str = " ".join(cmd) if isinstance(cmd, (list, tuple)) else cmd
        assert " run" in f" {cmd_str}"
        assert "--fmt json" in cmd_str
        assert "--path" in cmd_str
        assert "--output" not in cmd_str
        assert isinstance(cmd, list)
        assert [r["domain"] for r in records] == ["a.example.com", "b.example.com"]
        assert records[0]["ip"] == "1.2.3.4"


class TestHttpxProbePlugin:

    @patch.object(BasePlugin, "_run_command", _mock_run_command)
    def test_execute(self, sample_settings, tmp_workdir):
        plugin = HttpxProbePlugin(sample_settings)
        output = plugin.execute("example.com", tmp_workdir)
        assert output.exists()

    @patch.object(BasePlugin, "_run_command", _mock_run_command)
    def test_parse_output(self, sample_settings, tmp_workdir):
        plugin = HttpxProbePlugin(sample_settings)
        output = plugin.execute("example.com", tmp_workdir)
        records = plugin.parse_output(output)
        assert isinstance(records, list)

    @patch.object(BasePlugin, "_run_command")
    def test_per_instance_params_reach_command(
        self, mock_run, sample_settings, tmp_workdir
    ):
        captured = {}

        def _side_effect(cmd, workdir, timeout=3000):
            captured["cmd"] = cmd
            return MagicMock(returncode=0)

        mock_run.side_effect = _side_effect
        settings = {
            **sample_settings,
            "plugins": {
                "httpx_probe": {
                    "threads": 42,
                    "rate_limit": 150,
                    "extra_args": ["-timeout", "7"],
                }
            },
        }
        plugin = HttpxProbePlugin(settings)
        plugin.bind_stage("probe_fast", scoped=True)
        plugin.execute("example.com", tmp_workdir)

        cmd = captured["cmd"]
        assert "-threads" in cmd and "42" in cmd
        assert "-rate-limit" in cmd and "150" in cmd
        assert "-timeout" in cmd and "7" in cmd
        assert any("httpx_output__probe_fast.jsonl" in str(part) for part in cmd)
        assert any("httpx_input__probe_fast.txt" in str(part) for part in cmd)

    @patch.object(BasePlugin, "_run_command", _mock_run_command)
    def test_falls_back_when_oneforall_output_empty(self, sample_settings, tmp_workdir):
        """An empty OneForAll output must not silently produce an empty probe."""
        (tmp_workdir / "oneforall_output.jsonl").write_text("", encoding="utf-8")
        plugin = HttpxProbePlugin(sample_settings)
        plugin.execute("example.com", tmp_workdir)
        fallback = tmp_workdir / "httpx_input.txt"
        assert fallback.exists()
        assert "example.com" in fallback.read_text(encoding="utf-8")


class TestNmapScanPlugin:

    @patch("arguscaner.core.plugins.nmap_scan.subprocess.Popen")
    def test_execute(self, mock_popen, sample_settings, tmp_workdir):
        # Mock Popen to simulate nmap output
        mock_proc = MagicMock()
        mock_proc.stdout = [
            "Starting Nmap 7.95",
            "Stats: 0:00:10 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan",
            "Nmap scan report for 93.184.216.34",
            "80/tcp  open  http",
        ]
        mock_proc.returncode = 0
        mock_proc.wait.return_value = 0
        mock_popen.return_value = mock_proc

        plugin = NmapScanPlugin(sample_settings)
        output = plugin.execute("example.com", tmp_workdir)
        assert output.exists()

    @patch("arguscaner.core.plugins.nmap_scan.subprocess.Popen")
    def test_parse_output(self, mock_popen, sample_settings, tmp_workdir):
        mock_proc = MagicMock()
        mock_proc.stdout = [
            "Starting Nmap 7.95",
            "Nmap scan report for 93.184.216.34",
            "80/tcp  open  http",
        ]
        mock_proc.returncode = 0
        mock_proc.wait.return_value = 0
        mock_popen.return_value = mock_proc

        plugin = NmapScanPlugin(sample_settings)
        output = plugin.execute("example.com", tmp_workdir)
        records = plugin.parse_output(output)
        assert isinstance(records, list)


class TestPluginsUrlTarget:

    @patch.object(BasePlugin, "_run_command", _mock_run_command)
    def test_oneforall_url_target(self, sample_settings, tmp_workdir):
        plugin = OneForAllPlugin(sample_settings)
        output = plugin.execute("https://www.baidu.com/", tmp_workdir)
        records = plugin.parse_output(output)
        assert isinstance(records, list)

    @patch.object(BasePlugin, "_run_command", _mock_run_command)
    def test_httpx_url_target(self, sample_settings, tmp_workdir):
        plugin = HttpxProbePlugin(sample_settings)
        output = plugin.execute("https://www.baidu.com/", tmp_workdir)
        records = plugin.parse_output(output)
        assert isinstance(records, list)


class TestPluginToolPaths:
    """Built-in plugins honour configurable tool paths."""

    def test_nmap_path_setting(self, sample_settings, tmp_path):
        exe = tmp_path / "nmap.exe"
        exe.write_bytes(b"")
        settings = {
            **sample_settings,
            "plugins": {"nmap_scan": {"nmap_path": str(exe)}},
        }
        assert NmapScanPlugin(settings)._nmap_bin == str(exe)

    def test_httpx_path_setting(self, sample_settings, tmp_path):
        exe = tmp_path / "httpx.exe"
        exe.write_bytes(b"")
        settings = {
            **sample_settings,
            "plugins": {"httpx_probe": {"httpx_path": str(exe)}},
        }
        assert HttpxProbePlugin(settings)._httpx_bin == str(exe)

    def test_api_probe_inherits_httpx_path(self, sample_settings, tmp_path):
        exe = tmp_path / "httpx.exe"
        exe.write_bytes(b"")
        settings = {
            **sample_settings,
            "plugins": {"httpx_probe": {"httpx_path": str(exe)}},
        }
        assert ApiProbePlugin(settings)._httpx_bin == str(exe)

    def test_api_probe_own_httpx_path_wins(self, sample_settings, tmp_path):
        shared = tmp_path / "shared.exe"
        own = tmp_path / "api.exe"
        shared.write_bytes(b"")
        own.write_bytes(b"")
        settings = {
            **sample_settings,
            "plugins": {
                "httpx_probe": {"httpx_path": str(shared)},
                "api_probe": {"httpx_path": str(own)},
            },
        }
        assert ApiProbePlugin(settings)._httpx_bin == str(own)
