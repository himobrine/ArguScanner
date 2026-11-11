"""Tests for the deduplication engine."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from arguscaner.core.dedup import DeduplicationEngine


class TestDeduplicationEngine:

    def test_l1_dedup(self, tmp_workdir):
        engine = DeduplicationEngine(tmp_workdir)
        records = [
            {"domain": "a.example.com", "ip": "1.1.1.1"},
            {"domain": "b.example.com", "ip": "2.2.2.2"},
            {"domain": "a.example.com", "ip": "3.3.3.3"},
        ]
        result = engine.l1_intra_phase(records, "subdomains")
        assert len(result) == 2
        assert result[0]["domain"] == "a.example.com"
        assert result[1]["domain"] == "b.example.com"

    def test_l2_global_merge(self, tmp_workdir):
        engine = DeduplicationEngine(tmp_workdir)
        all_records = {
            "subdomains": [
                {"domain": "a.example.com", "ip": "1.1.1.1"},
                {"domain": "b.example.com", "ip": "2.2.2.2"},
            ],
            "live_urls": [
                {"url": "https://a.example.com", "status": 200},
                {"url": "https://a.example.com", "status": 200},
            ],
        }
        result = engine.l2_global_merge(all_records)
        assert len(result["subdomains"]) == 2
        assert len(result["live_urls"]) == 1

    def test_l3_normalize_domain(self, tmp_workdir):
        engine = DeduplicationEngine(tmp_workdir)
        records = [{"domain": "  A.Example.COM  "}]
        result = engine.l3_normalize(records, "subdomains")
        assert result[0]["domain"] == "a.example.com"

    def test_l3_normalize_url(self, tmp_workdir):
        engine = DeduplicationEngine(tmp_workdir)
        records = [{"url": "example.com/path"}]
        result = engine.l3_normalize(records, "live_urls")
        assert result[0]["url"] == "http://example.com/path"

    def test_full_pipeline(self, tmp_workdir):
        # Write mock data files using stage filenames (scheduler outputs)
        (tmp_workdir / "subdomain_enum.jsonl").write_text(
            json.dumps({"domain": "a.example.com", "ip": "1.1.1.1"}) + "\n"
            + json.dumps({"domain": "a.example.com", "ip": "2.2.2.2"}) + "\n"
        )
        (tmp_workdir / "http_probe.jsonl").write_text(
            json.dumps({"url": "https://a.example.com", "status": 200}) + "\n"
        )

        engine = DeduplicationEngine(tmp_workdir)
        result = engine.deduplicate_all(tmp_workdir)
        assert "subdomains" in result
        assert len(result["subdomains"]) == 1
        assert result["subdomains"][0]["domain"] == "a.example.com"

    def test_recursive_rounds_are_included(self, tmp_workdir):
        (tmp_workdir / "subdomain_enum.jsonl").write_text(
            json.dumps({"domain": "a.example.com"}) + "\n", encoding="utf-8"
        )
        round_dir = tmp_workdir / "rounds" / "r001"
        round_dir.mkdir(parents=True)
        (round_dir / "http_probe.jsonl").write_text(
            json.dumps({"url": "https://b.example.com", "status": 200}) + "\n",
            encoding="utf-8",
        )
        # Internal files must be ignored.
        (round_dir / "round_targets.jsonl").write_text(
            json.dumps({"target": "b.example.com"}) + "\n", encoding="utf-8"
        )
        (round_dir / "run.jsonl").write_text(
            json.dumps({"event": "stage_end"}) + "\n", encoding="utf-8"
        )

        result = DeduplicationEngine(tmp_workdir).deduplicate_all(tmp_workdir)
        assert len(result["subdomains"]) == 1
        assert [r["url"] for r in result["live_urls"]] == ["https://b.example.com"]

    def test_ip_map_and_api_endpoints(self, tmp_workdir):
        round_dir = tmp_workdir / "rounds" / "r001"
        round_dir.mkdir(parents=True)
        (round_dir / "ip_discovery.jsonl").write_text(
            json.dumps({"host": "a.example.com", "ip": "1.1.1.1"}) + "\n"
            + json.dumps({"host": "a.example.com", "ip": "1.1.1.1"}) + "\n",
            encoding="utf-8",
        )
        (round_dir / "api_probe.jsonl").write_text(
            json.dumps({"url": "https://a.example.com/swagger.json", "status": 200}) + "\n",
            encoding="utf-8",
        )
        # Raw plugin outputs must not be treated as stage output.
        (round_dir / "api_probe_raw.jsonl").write_text(
            json.dumps({"url": "https://a.example.com/swagger.json"}) + "\n",
            encoding="utf-8",
        )

        result = DeduplicationEngine(tmp_workdir).deduplicate_all(tmp_workdir)
        assert len(result["ip_map"]) == 1
        assert result["ip_map"][0]["ip"] == "1.1.1.1"
        assert len(result["api_endpoints"]) == 1
        assert result["api_endpoints"][0]["url"].endswith("/swagger.json")

    def test_raw_outputs_are_ignored(self, tmp_workdir):
        (tmp_workdir / "oneforall_output.jsonl").write_text(
            json.dumps({"domain": "a.example.com"}) + "\n", encoding="utf-8"
        )
        (tmp_workdir / "subdomain_enum.jsonl").write_text(
            json.dumps({"domain": "a.example.com"}) + "\n", encoding="utf-8"
        )
        result = DeduplicationEngine(tmp_workdir).deduplicate_all(tmp_workdir)
        assert len(result["subdomains"]) == 1
