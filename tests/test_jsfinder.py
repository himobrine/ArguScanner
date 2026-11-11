"""Tests for JsFinderPlugin."""

from __future__ import annotations

from unittest.mock import patch, MagicMock

import pytest

from arguscaner.core.plugins.jsfinder import JsFinderPlugin
from arguscaner.core.plugins.base_plugin import PluginRegistry
from arguscaner.utils.target_classifier import TargetType


SAMPLE_SETTINGS = {
    "defaults": {"timeout": 30},
    "plugins": {
        "jsfinder": {
            "enabled": True,
            "jsfinder_path": "D:\\tools\\JSFinder-master\\JSFinder-master\\JSFinder.py",
            "timeout": 300,
            "retry": 2,
            "retry_delay": 5,
        }
    },
}


class TestJsFinderPlugin:

    def test_init(self):
        plugin = JsFinderPlugin(SAMPLE_SETTINGS)
        assert plugin.name == "jsfinder"
        assert plugin.description == "JSFinder JavaScript URL 和子域名提取"
        assert plugin.version == "1.0.0"
        assert plugin.enabled is True

    def test_supported_target_types(self):
        plugin = JsFinderPlugin(SAMPLE_SETTINGS)
        values = [t.value for t in plugin.supported_target_types]
        assert "domain" in values
        assert "ip" in values
        assert "cidr" not in values

    def test_conditions_empty(self):
        plugin = JsFinderPlugin(SAMPLE_SETTINGS)
        assert len(plugin.conditions) == 0

    @patch("arguscaner.core.plugins.base_plugin.subprocess.run")
    def test_execute_domain(self, mock_run, tmp_workdir):
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        plugin = JsFinderPlugin(SAMPLE_SETTINGS)
        output = plugin.execute("example.com", tmp_workdir)
        assert output.exists()
        assert output.name == "jsfinder_output.jsonl"
        mock_run.assert_called_once()

    @patch("arguscaner.core.plugins.base_plugin.subprocess.run")
    def test_execute_ip(self, mock_run, tmp_workdir):
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        plugin = JsFinderPlugin(SAMPLE_SETTINGS)
        output = plugin.execute("8.8.8.8", tmp_workdir)
        assert output.exists()
        mock_run.assert_called_once()

    def test_output_schema(self):
        plugin = JsFinderPlugin(SAMPLE_SETTINGS)
        schema = plugin.output_schema
        assert "type" in schema
        assert "data" in schema
        assert "source" in schema
        assert "timestamp" in schema

    def test_info_includes_metadata(self):
        plugin = JsFinderPlugin(SAMPLE_SETTINGS)
        info = plugin.info
        assert info["name"] == "jsfinder"
        assert "JSFinder" in info["description"]
        assert "domain" in info["supported_target_types"]
        assert "ip" in info["supported_target_types"]

    def test_disabled_plugin(self):
        settings = {
            "plugins": {"jsfinder": {"enabled": False}},
        }
        plugin = JsFinderPlugin(settings)
        assert plugin.enabled is False

        meets, reason = plugin.check_conditions({"target_type": "domain"})
        assert meets is False
        assert "已禁用" in reason

    def test_check_conditions_domain(self):
        plugin = JsFinderPlugin(SAMPLE_SETTINGS)
        meets, reason = plugin.check_conditions({"target_type": "domain"})
        assert meets is True

    def test_check_conditions_ip(self):
        plugin = JsFinderPlugin(SAMPLE_SETTINGS)
        meets, reason = plugin.check_conditions({"target_type": "ip"})
        assert meets is True

    def test_check_conditions_cidr_rejected(self):
        plugin = JsFinderPlugin(SAMPLE_SETTINGS)
        meets, reason = plugin.check_conditions({"target_type": "cidr"})
        assert meets is False
        assert "jsfinder" in reason
        assert "cidr" in reason


class TestJsFinderRegistry:

    def test_plugin_in_registry(self):
        settings = {"plugins": {}}
        registry = PluginRegistry(settings)
        assert "jsfinder" in registry.get_plugin_names()

    def test_plugin_is_builtin(self):
        settings = {"plugins": {}}
        registry = PluginRegistry(settings)
        plugins = registry.list()
        jsfinder = [p for p in plugins if p["name"] == "jsfinder"]
        assert len(jsfinder) == 1
        assert jsfinder[0]["source"] == "builtin"

    def test_plugin_info(self):
        settings = {"plugins": {}}
        registry = PluginRegistry(settings)
        plugin = registry.get("jsfinder")
        info = plugin.info
        assert "domain" in info["supported_target_types"]
        assert "ip" in info["supported_target_types"]
