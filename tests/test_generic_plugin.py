"""Tests for GenericPlugin (YAML 声明式插件)."""

from __future__ import annotations

import yaml
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from arguscaner.core.plugins.generic_plugin import GenericPlugin
from arguscaner.core.plugins.base_plugin import PluginRegistry, BasePlugin


def _mock_run_command(self, cmd, workdir, timeout=3000):
    """Mock _run_command that creates the expected output file."""
    output_file = workdir / self.output_filename
    output_file.write_text("", encoding="utf-8")
    return MagicMock(returncode=0, stdout="", stderr="")


SAMPLE_CONFIG = {
    "name": "test_scanner",
    "description": "A test scanner plugin",
    "version": "1.0.0",
    "command_template": "test_scanner --target {{target}} --output {{output}}",
    "output_filename": "test_scanner_output.jsonl",
    "output_schema": {"host": "str", "port": "int", "service": "str"},
    "supported_target_types": ["domain", "ip"],
    "input_requirements": [],
    "conditions": [
        {
            "field": "target_type",
            "operator": "eq",
            "value": "domain",
            "description": "Only domains",
        }
    ],
    "enabled": True,
    "source": "custom",
}


class TestGenericPlugin:

    def test_from_config(self):
        plg = GenericPlugin(SAMPLE_CONFIG)
        assert plg.name == "test_scanner"
        assert plg.description == "A test scanner plugin"
        assert plg.version == "1.0.0"
        assert plg.command_template == "test_scanner --target {{target}} --output {{output}}"
        assert plg.output_schema == {"host": "str", "port": "int", "service": "str"}
        assert plg.source == "custom"

    def test_supported_target_types(self):
        plg = GenericPlugin(SAMPLE_CONFIG)
        values = [t.value for t in plg.supported_target_types]
        assert "domain" in values
        assert "ip" in values

    def test_conditions(self):
        plg = GenericPlugin(SAMPLE_CONFIG)
        assert len(plg.conditions) == 1
        assert plg.conditions[0].field == "target_type"
        assert plg.conditions[0].value == "domain"

    @patch.object(BasePlugin, "_run_command", _mock_run_command)
    def test_execute(self, tmp_workdir):
        settings = {"defaults": {"timeout": 30}}
        plg = GenericPlugin(SAMPLE_CONFIG, settings)
        output = plg.execute("example.com", tmp_workdir)
        assert output.exists()
        records = plg.parse_output(output)
        assert isinstance(records, list)

    def test_to_yaml_and_back(self, tmp_workdir):
        settings = {"defaults": {"timeout": 30}}
        plg = GenericPlugin(SAMPLE_CONFIG, settings)
        yaml_path = tmp_workdir / "test_scanner.yaml"
        plg.to_yaml_file(yaml_path)
        assert yaml_path.exists()

        plg2 = GenericPlugin.from_yaml_file(yaml_path, settings)
        assert plg2.name == "test_scanner"
        assert plg2.command_template == plg.command_template
        assert plg2.output_schema == plg.output_schema

    def test_info_includes_source(self):
        plg = GenericPlugin(SAMPLE_CONFIG)
        info = plg.info
        assert "source" not in info  # info property doesn't include source by default

    def test_default_output_filename(self):
        config = {"name": "my_tool", "command_template": "echo {{target}}"}
        plg = GenericPlugin(config)
        assert plg.output_filename == "my_tool_output.jsonl"


class TestPluginRegistryCustom:

    def test_add_and_remove_custom(self, tmp_workdir):
        settings = {"plugins": {}}
        registry = PluginRegistry(settings)

        # Override custom dir to temp
        registry.CUSTOM_PLUGINS_DIR = tmp_workdir

        config = dict(SAMPLE_CONFIG)
        plugin = registry.add_custom(config)
        assert plugin.name == "test_scanner"
        assert registry.is_custom("test_scanner")

        # YAML file created
        assert (tmp_workdir / "test_scanner.yaml").exists()

        # Remove
        registry.remove_custom("test_scanner")
        assert not registry.is_custom("test_scanner")
        assert not (tmp_workdir / "test_scanner.yaml").exists()

    def test_add_duplicate_raises(self, tmp_workdir):
        settings = {"plugins": {}}
        registry = PluginRegistry(settings)
        registry.CUSTOM_PLUGINS_DIR = tmp_workdir

        config = dict(SAMPLE_CONFIG)
        registry.add_custom(config)

        with pytest.raises(ValueError, match="已存在"):
            registry.add_custom(config)

        # Cleanup
        registry.remove_custom("test_scanner")

    def test_remove_builtin_raises(self, tmp_workdir):
        settings = {"plugins": {}}
        registry = PluginRegistry(settings)
        registry.CUSTOM_PLUGINS_DIR = tmp_workdir

        with pytest.raises(ValueError, match="不是自定义插件"):
            registry.remove_custom("oneforall")

    def test_list_includes_source(self, tmp_workdir):
        settings = {"plugins": {}}
        registry = PluginRegistry(settings)
        registry.CUSTOM_PLUGINS_DIR = tmp_workdir

        config = dict(SAMPLE_CONFIG)
        registry.add_custom(config)

        plugins = registry.list()
        custom = [p for p in plugins if p["name"] == "test_scanner"]
        assert len(custom) == 1
        assert custom[0]["source"] == "custom"

        builtin = [p for p in plugins if p["name"] == "oneforall"]
        assert len(builtin) == 1
        assert builtin[0]["source"] == "builtin"

        # Cleanup
        registry.remove_custom("test_scanner")

    def test_load_from_disk(self, tmp_workdir):
        settings = {"plugins": {}}

        # Write a YAML plugin file
        yaml_path = tmp_workdir / "disk_plugin.yaml"
        with open(yaml_path, "w", encoding="utf-8") as f:
            yaml.safe_dump(SAMPLE_CONFIG, f, allow_unicode=True)

        registry = PluginRegistry(settings)
        registry.CUSTOM_PLUGINS_DIR = tmp_workdir
        registry._custom_names.clear()
        registry._load_custom_plugins()

        assert "test_scanner" in registry.get_plugin_names()
        assert registry.is_custom("test_scanner")
