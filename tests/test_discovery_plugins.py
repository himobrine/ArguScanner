"""Tests for IP discovery, API probing and batch crawl plugins."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from arguscaner.core.ip_inventory import IpInventory
from arguscaner.core.plugins.api_probe import ApiProbePlugin
from arguscaner.core.plugins.base_plugin import PluginSkipped
from arguscaner.core.plugins.ip_discovery import IpDiscoveryPlugin
from arguscaner.core.plugins.jsfinder import JsFinderPlugin
from arguscaner.core.plugins.nmap_scan import NmapScanPlugin
from arguscaner.core.plugins.urlfinder import UrlFinderPlugin


def _write_jsonl(path: Path, records: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for record in records:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")


class TestIpDiscovery:

    def test_resolves_ips_and_hosts(self, tmp_workdir):
        _write_jsonl(tmp_workdir / "round_targets.jsonl", [
            {"target": "1.2.3.4"},
            {"target": "5.6.7.8"},
        ])
        plugin = IpDiscoveryPlugin({"plugins": {"ip_discovery": {}}})
        output = plugin.execute("1.2.3.4", tmp_workdir)
        records = plugin.parse_output(output)
        pairs = {(r["host"], r["ip"]) for r in records}
        assert ("1.2.3.4", "1.2.3.4") in pairs
        assert ("5.6.7.8", "5.6.7.8") in pairs

    def test_skips_when_no_hosts(self, tmp_workdir):
        plugin = IpDiscoveryPlugin({"plugins": {"ip_discovery": {}}})
        with pytest.raises(PluginSkipped):
            plugin.execute("", tmp_workdir)

    def test_cidr_not_expanded_by_default(self, tmp_workdir):
        _write_jsonl(tmp_workdir / "round_targets.jsonl", [
            {"target": "10.0.0.0/30"},
        ])
        plugin = IpDiscoveryPlugin({"plugins": {"ip_discovery": {}}})
        # A /30 (without expansion) plus the resolvable root target "10.0.0.1".
        records = plugin.parse_output(plugin.execute("10.0.0.1", tmp_workdir))
        assert all(r["ip"] == "10.0.0.1" for r in records)


class TestNmapInventory:

    def _settings(self):
        return {
            "plugins": {"nmap_scan": {"enabled": True}},
            "recursive": {"skip_scanned_ips": True},
        }

    def test_collect_targets_skips_inventory(self, tmp_workdir):
        _write_jsonl(tmp_workdir / "ip_discovery.jsonl", [
            {"host": "a.example.com", "ip": "1.1.1.1"},
            {"host": "b.example.com", "ip": "2.2.2.2"},
        ])
        settings = self._settings()
        inventory = IpInventory.for_workdir(tmp_workdir, settings)
        inventory.mark_scanned("1.1.1.1")
        plugin = NmapScanPlugin(settings)

        targets, skipped = plugin._collect_targets(
            "example.com", tmp_workdir, inventory, skip_scanned=True
        )
        assert targets == ["2.2.2.2"]
        assert skipped == ["1.1.1.1"]

    def test_collect_targets_without_skip(self, tmp_workdir):
        _write_jsonl(tmp_workdir / "ip_discovery.jsonl", [
            {"ip": "1.1.1.1"},
            {"ip": "1.1.1.1"},
        ])
        inventory = IpInventory.for_workdir(tmp_workdir, self._settings())
        plugin = NmapScanPlugin(self._settings())
        targets, skipped = plugin._collect_targets(
            "example.com", tmp_workdir, inventory, skip_scanned=False
        )
        assert targets == ["1.1.1.1"]
        assert skipped == []

    def test_parse_output_open_ports_only(self, tmp_workdir):
        output = tmp_workdir / "nmap_output.txt"
        output.write_text(
            "Nmap scan report for a.example.com (1.1.1.1)\n"
            "22/tcp open ssh OpenSSH 8.9\n"
            "80/tcp closed http\n"
            "443/tcp open https nginx\n",
            encoding="utf-8",
        )
        records = NmapScanPlugin(self._settings()).parse_output(output)
        assert [r["port"] for r in records] == [22, 443]
        assert all(r["state"] == "open" for r in records)
        assert all(r["host"] == "a.example.com" for r in records)

    def test_parse_output_report_without_hostname(self, tmp_workdir):
        output = tmp_workdir / "nmap_output.txt"
        output.write_text(
            "Nmap scan report for 1.1.1.1\n"
            "22/tcp open ssh\n",
            encoding="utf-8",
        )
        records = NmapScanPlugin(self._settings()).parse_output(output)
        assert records[0]["host"] == ""
        assert records[0]["ip"] == "1.1.1.1"


class TestApiProbe:

    def _settings(self):
        return {"plugins": {"api_probe": {"max_origins": 100}}}

    def test_classify_known_api_families(self):
        assert ApiProbePlugin._classify(
            "https://a.example.com/swagger-ui.html", 200, "text/html", "Swagger UI"
        ) == "swagger/openapi"
        assert ApiProbePlugin._classify(
            "https://a.example.com/graphql", 200, "application/json", ""
        ) == "graphql"
        assert ApiProbePlugin._classify(
            "https://a.example.com/actuator/env", 200, "application/json", ""
        ) == "actuator"

    def test_classify_filters_non_api_responses(self):
        assert ApiProbePlugin._classify(
            "https://a.example.com/about", 200, "text/html", "About"
        ) is None
        assert ApiProbePlugin._classify(
            "https://a.example.com/login", 404, "text/html", ""
        ) is None

    def test_collect_origins_skips_probed(self, tmp_workdir):
        _write_jsonl(tmp_workdir / "http_probe.jsonl", [
            {"url": "https://a.example.com/x"},
            {"url": "https://a.example.com/y"},
            {"url": "https://b.example.com/"},
        ])
        (tmp_workdir / "api_probe_origins.txt").write_text(
            "https://b.example.com\n", encoding="utf-8"
        )
        plugin = ApiProbePlugin(self._settings())
        origins = plugin._collect_origins("example.com", tmp_workdir)
        assert origins == ["https://a.example.com"]

    def test_collect_origins_covers_scheme_less_round_hosts(self, tmp_workdir):
        _write_jsonl(tmp_workdir / "round_targets.jsonl", [
            {"target": "10.0.0.5", "host": "10.0.0.5"},
        ])
        plugin = ApiProbePlugin(self._settings())
        origins = plugin._collect_origins("example.com", tmp_workdir)
        assert origins == ["http://10.0.0.5", "https://10.0.0.5"]

    def test_wordlist_is_loaded(self):
        plugin = ApiProbePlugin(self._settings())
        paths = plugin._load_paths()
        assert "/swagger" in paths
        assert "/graphql" in paths
        assert all(p.startswith("/") for p in paths)


class TestBatchCrawlPlugins:

    @patch("arguscaner.core.plugins.base_plugin.subprocess.run")
    def test_jsfinder_runs_once_per_round_host(self, mock_run, tmp_workdir):
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        _write_jsonl(tmp_workdir / "round_targets.jsonl", [
            {"target": "a.example.com"},
            {"target": "b.example.com"},
        ])
        plugin = JsFinderPlugin({"plugins": {"jsfinder": {"max_targets": 50}}})
        output = plugin.execute("example.com", tmp_workdir)
        assert output.exists()
        assert mock_run.call_count == 2

        with pytest.raises(PluginSkipped):
            plugin.execute("example.com", tmp_workdir)

    @patch("arguscaner.core.plugins.base_plugin.subprocess.run")
    def test_urlfinder_runs_once_per_round_host(self, mock_run, tmp_workdir):
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        _write_jsonl(tmp_workdir / "round_targets.jsonl", [
            {"target": "a.example.com"},
        ])
        plugin = UrlFinderPlugin({"plugins": {"urlfinder": {"max_targets": 50}}})
        output = plugin.execute("example.com", tmp_workdir)
        assert output.exists()
        assert mock_run.call_count == 1
        assert (tmp_workdir / "urlfinder_output" / "a.example.com").exists()

        with pytest.raises(PluginSkipped):
            plugin.execute("example.com", tmp_workdir)
