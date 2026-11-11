"""Tests for test-plugin command (test_tester.py per README)."""

from __future__ import annotations

import os

import pytest
from typer.testing import CliRunner

from arguscaner.entrypoint import app

runner = CliRunner()

requires_integration = pytest.mark.skipif(
    os.environ.get("RUN_INTEGRATION") != "1",
    reason="integration test: requires external tools; set RUN_INTEGRATION=1",
)


class TestPluginTesterCommand:

    @requires_integration
    def test_verbose_output(self):
        result = runner.invoke(app, [
            "test-plugin", "-t", "example.com", "-p", "oneforall", "-v",
        ])
        assert result.exit_code == 0
        assert "记录数：" in result.output

    @requires_integration
    def test_limit_flag(self):
        result = runner.invoke(app, [
            "test-plugin", "-t", "example.com", "-p", "nmap_scan", "-l", "2",
        ])
        assert result.exit_code == 0

    def test_test_proxy_pool_no_sources(self):
        result = runner.invoke(app, [
            "test-plugin", "--test-proxy-pool", "-t", "example.com",
        ])
        assert result.exit_code == 0
        assert "代理" in result.output or "未配置" in result.output
