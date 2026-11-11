"""Tests for CLI commands."""

from __future__ import annotations

import os

import pytest
from typer.testing import CliRunner

from arguscaner.entrypoint import app

runner = CliRunner()

# Real plugin execution needs external tools (OneForAll/httpx/nmap) and network.
# Opt in with RUN_INTEGRATION=1 to avoid slow/flaky default runs.
requires_integration = pytest.mark.skipif(
    os.environ.get("RUN_INTEGRATION") != "1",
    reason="integration test: requires external tools; set RUN_INTEGRATION=1",
)


class TestCLIHelp:

    def test_root_help(self):
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "auto-recon" in result.output

    def test_scan_help(self):
        result = runner.invoke(app, ["scan", "--help"])
        assert result.exit_code == 0

    def test_batch_help(self):
        result = runner.invoke(app, ["batch", "--help"])
        assert result.exit_code == 0

    def test_status_help(self):
        result = runner.invoke(app, ["status", "--help"])
        assert result.exit_code == 0

    def test_resume_help(self):
        result = runner.invoke(app, ["resume", "--help"])
        assert result.exit_code == 0

    def test_test_plugin_help(self):
        result = runner.invoke(app, ["test-plugin", "--help"])
        assert result.exit_code == 0

    def test_web_help(self):
        result = runner.invoke(app, ["web", "--help"])
        assert result.exit_code == 0


@requires_integration
class TestTestPluginCommand:

    def test_test_plugin_oneforall(self, tmp_path):
        result = runner.invoke(app, [
            "test-plugin", "-t", "example.com", "-p", "oneforall",
        ])
        assert result.exit_code == 0
        assert "记录数：" in result.output

    def test_test_plugin_httpx(self, tmp_path):
        result = runner.invoke(app, [
            "test-plugin", "-t", "example.com", "-p", "httpx_probe",
        ])
        assert result.exit_code == 0
        assert "记录数：" in result.output

    def test_test_plugin_nmap(self, tmp_path):
        result = runner.invoke(app, [
            "test-plugin", "-t", "example.com", "-p", "nmap_scan",
        ])
        assert result.exit_code == 0
        assert "记录数：" in result.output

    def test_test_plugin_no_plugin_specified(self):
        result = runner.invoke(app, ["test-plugin", "-t", "example.com"])
        assert result.exit_code == 1

    def test_test_plugin_unknown_plugin(self):
        result = runner.invoke(app, [
            "test-plugin", "-t", "example.com", "-p", "unknown",
        ])
        assert result.exit_code == 1


@requires_integration
class TestScanCommand:

    def test_scan_runs(self, tmp_path):
        result = runner.invoke(app, [
            "scan", "example.com", "--workspace", str(tmp_path),
        ])
        assert result.exit_code == 0
        assert "任务 ID：" in result.output
