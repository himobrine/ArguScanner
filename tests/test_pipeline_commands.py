"""Tests for pipeline/plugins/config/proxy CLI commands."""

from __future__ import annotations

from pathlib import Path

import yaml
from typer.testing import CliRunner

from arguscaner.entrypoint import app, SETTINGS_YAML
from arguscaner.core.plugins.base_plugin import PluginRegistry

runner = CliRunner()


class TestPipelineCommands:

    def test_show(self):
        result = runner.invoke(app, ["pipeline", "show"])
        assert result.exit_code == 0
        assert "oneforall" in result.output
        assert "nmap_scan" in result.output

    def test_show_condition_display(self):
        result = runner.invoke(app, ["pipeline", "show"])
        assert result.exit_code == 0
        assert "target_type" in result.output or "types=" in result.output

    def test_list(self):
        result = runner.invoke(app, ["pipeline", "list"])
        assert result.exit_code == 0

    def test_list_plugins(self):
        result = runner.invoke(app, ["pipeline", "list-plugins"])
        assert result.exit_code == 0
        assert "oneforall" in result.output
        assert "nmap_scan" in result.output

    def test_unknown_action(self):
        result = runner.invoke(app, ["pipeline", "bogus"])
        assert result.exit_code == 1


class TestPluginsCommands:

    def test_list(self):
        result = runner.invoke(app, ["plugins", "list"])
        assert result.exit_code == 0
        assert "oneforall" in result.output
        assert "httpx_probe" in result.output

    def test_show(self):
        result = runner.invoke(app, ["plugins", "show", "oneforall"])
        assert result.exit_code == 0
        assert "oneforall" in result.output
        assert "命令模板" in result.output
        assert "支持类型" in result.output

    def test_show_unknown(self):
        result = runner.invoke(app, ["plugins", "show", "nonexistent"])
        assert result.exit_code == 1

    def test_enable_then_disable(self):
        # Enable
        result = runner.invoke(app, ["plugins", "enable", "nmap_scan"])
        assert result.exit_code == 0

        # Verify persisted in settings
        with open(SETTINGS_YAML, "r", encoding="utf-8") as f:
            settings = yaml.safe_load(f)
        assert settings["plugins"]["nmap_scan"]["enabled"] is True

        # Disable
        result = runner.invoke(app, ["plugins", "disable", "nmap_scan"])
        assert result.exit_code == 0
        with open(SETTINGS_YAML, "r", encoding="utf-8") as f:
            settings = yaml.safe_load(f)
        assert settings["plugins"]["nmap_scan"]["enabled"] is False

        # Restore enabled
        runner.invoke(app, ["plugins", "enable", "nmap_scan"])

    def test_add_and_remove_custom(self):
        result = runner.invoke(app, [
            "plugins", "add",
            "--name", "cli_test_plugin",
            "--command", "echo {{target}} > {{output}}",
            "--types", "domain,ip",
            "--description", "CLI test plugin",
        ])
        assert result.exit_code == 0
        assert "cli_test_plugin" in result.output

        # YAML file created
        yaml_path = PluginRegistry.CUSTOM_PLUGINS_DIR / "cli_test_plugin.yaml"
        assert yaml_path.exists()

        # Remove
        result = runner.invoke(app, ["plugins", "remove", "cli_test_plugin"])
        assert result.exit_code == 0
        assert not yaml_path.exists()

    def test_add_missing_name(self):
        result = runner.invoke(app, [
            "plugins", "add",
            "--command", "echo {{target}}",
        ])
        assert result.exit_code == 1

    def test_add_missing_command(self):
        result = runner.invoke(app, [
            "plugins", "add",
            "--name", "no_cmd",
        ])
        assert result.exit_code == 1

    def test_remove_builtin_fails(self):
        result = runner.invoke(app, ["plugins", "remove", "oneforall"])
        assert result.exit_code == 1
        assert "不是自定义插件" in result.output

    def test_list_shows_source(self):
        result = runner.invoke(app, ["plugins", "list"])
        assert result.exit_code == 0
        assert "builtin" in result.output


class TestConfigCommands:

    def test_show(self):
        result = runner.invoke(app, ["config", "show"])
        assert result.exit_code == 0
        assert "defaults.concurrency" in result.output

    def test_get(self):
        result = runner.invoke(app, ["config", "get", "--key", "defaults.concurrency"])
        assert result.exit_code == 0

    def test_set_and_restore(self):
        result = runner.invoke(app, ["config", "set", "--key", "defaults.timeout", "--value", "500"])
        assert result.exit_code == 0
        with open(SETTINGS_YAML, "r", encoding="utf-8") as f:
            settings = yaml.safe_load(f)
        assert settings["defaults"]["timeout"] == 500
        # restore
        runner.invoke(app, ["config", "set", "--key", "defaults.timeout", "--value", "300"])


class TestProxyCommands:

    def test_list_empty(self):
        result = runner.invoke(app, ["proxy", "list"])
        assert result.exit_code == 0

    def test_add_remove(self):
        result = runner.invoke(app, ["proxy", "add", "--url", "http://test-proxy:8080"])
        assert result.exit_code == 0
        with open(SETTINGS_YAML, "r", encoding="utf-8") as f:
            settings = yaml.safe_load(f)
        sources = settings["waf_aware"]["recovery"]["proxy_pool"]["sources"]
        assert "http://test-proxy:8080" in sources

        result = runner.invoke(app, ["proxy", "remove", "--url", "http://test-proxy:8080"])
        assert result.exit_code == 0
        with open(SETTINGS_YAML, "r", encoding="utf-8") as f:
            settings = yaml.safe_load(f)
        sources = settings["waf_aware"]["recovery"]["proxy_pool"]["sources"]
        assert "http://test-proxy:8080" not in sources

    def test_test(self):
        result = runner.invoke(app, ["proxy", "test"])
        assert result.exit_code == 0
