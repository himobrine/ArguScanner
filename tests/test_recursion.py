"""Tests for recursive scanning, asset catalog and PluginSkipped handling."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from arguscaner.core.plugins.base_plugin import PluginSkipped
from arguscaner.scheduler.recursion import (
    Asset,
    AssetCatalog,
    RecursiveScanner,
    collect_assets,
    normalize_host,
    prepare_round_dir,
)
from arguscaner.scheduler.scheduler_core import (
    PipelineScheduler,
    ScanResult,
    StageResult,
    TaskState,
    read_stage_marker,
)


class FakeScheduler:
    """Stands in for PipelineScheduler inside RecursiveScanner."""

    round_outputs: list[list[tuple[str, list[dict]]]] = []
    calls: list[dict] = []

    def __init__(self, pipeline, settings):
        self.pipeline = pipeline
        self.settings = settings

    def run(self, target, workdir, task_id, recursive=None, save_meta=True):
        index = len(FakeScheduler.calls)
        FakeScheduler.calls.append({
            "workdir": Path(workdir),
            "recursive": recursive,
            "save_meta": save_meta,
        })
        outputs = (
            FakeScheduler.round_outputs[index]
            if index < len(FakeScheduler.round_outputs)
            else []
        )
        for filename, records in outputs:
            path = Path(workdir) / filename
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                for record in records:
                    f.write(json.dumps(record, ensure_ascii=False) + "\n")

        result = ScanResult(task_id=task_id, target=target)
        result.stages["http_probe"] = StageResult(
            stage="http_probe", state=TaskState.DONE
        )
        return result


@pytest.fixture(autouse=True)
def reset_fake_scheduler():
    FakeScheduler.round_outputs = []
    FakeScheduler.calls = []
    yield
    FakeScheduler.round_outputs = []
    FakeScheduler.calls = []


def _write_jsonl(path: Path, records: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for record in records:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")


class TestAssetCatalog:

    def test_normalize_host(self):
        assert normalize_host("https://A.Example.com:8443/x") == "a.example.com"
        assert normalize_host("10.0.0.1:22") == "10.0.0.1"
        assert normalize_host("[2001:db8::1]:443") == "2001:db8::1"
        assert normalize_host("*.example.com") == "example.com"
        assert normalize_host("") == ""

    def test_registers_and_dedups(self):
        catalog = AssetCatalog()
        first = catalog.add_all([
            Asset("a.example.com", "host", "test", 1),
            Asset("https://a.example.com/x", "url", "test", 1),
            Asset("1.2.3.4", "ip", "test", 1),
        ])
        assert first == ["a.example.com", "1.2.3.4"]
        second = catalog.add_all([
            Asset("a.example.com", "host", "test", 2),
            Asset("https://b.example.com", "url", "test", 2),
        ])
        assert second == ["b.example.com"]
        assert catalog.summary()["hosts"] == 3
        assert catalog.summary()["urls"] == 2

    def test_targets_include_discovered_url(self):
        catalog = AssetCatalog()
        catalog.add(Asset("https://a.example.com/login", "url", "http_probe", 1))
        targets = catalog.targets_for(["a.example.com"], 2)
        assert targets[0]["target"] == "a.example.com"
        assert targets[0]["url"] == "https://a.example.com/login"


class TestCollectAssets:

    def test_collects_every_stage_type(self, tmp_workdir):
        _write_jsonl(tmp_workdir / "subdomain_enum.jsonl", [
            {"domain": "a.example.com"},
        ])
        _write_jsonl(tmp_workdir / "http_probe.jsonl", [
            {"url": "https://b.example.com", "ip": "2.2.2.2"},
        ])
        _write_jsonl(tmp_workdir / "js_url_extract.jsonl", [
            {"type": "url", "data": "https://c.example.com/app.js"},
            {"type": "subdomain", "data": "d.example.com"},
        ])
        _write_jsonl(tmp_workdir / "api_probe.jsonl", [
            {"url": "https://e.example.com/swagger.json"},
        ])
        _write_jsonl(tmp_workdir / "ip_discovery.jsonl", [
            {"host": "a.example.com", "ip": "1.1.1.1"},
        ])

        assets = collect_assets(tmp_workdir, 3)
        values = {(a.kind, a.value) for a in assets}
        assert ("host", "a.example.com") in values
        assert ("url", "https://b.example.com") in values
        assert ("ip", "2.2.2.2") in values
        assert ("url", "https://c.example.com/app.js") in values
        assert ("host", "d.example.com") in values
        assert ("api", "https://e.example.com/swagger.json") in values
        assert ("ip", "1.1.1.1") in values
        assert all(a.round_num == 3 for a in assets)


class TestRecursiveScanner:

    def _settings(self, **overrides):
        cfg = {
            "enabled": True,
            "max_rounds": 10,
            "max_assets_per_round": 100,
            "max_ips_per_round": 100,
        }
        cfg.update(overrides)
        return {"recursive": cfg}

    def test_runs_until_no_new_assets(self, tmp_workdir, monkeypatch):
        (tmp_workdir / "task.json").write_text('{"task_id": "t1"}', encoding="utf-8")
        _write_jsonl(tmp_workdir / "subdomain_enum.jsonl", [
            {"domain": "a.example.com"},
        ])
        FakeScheduler.round_outputs = [
            [("http_probe.jsonl", [{"url": "https://b.example.com"}])],
            [("js_url_extract.jsonl", [
                {"type": "subdomain", "data": "c.example.com"},
            ])],
            [],
        ]
        monkeypatch.setattr(
            "arguscaner.scheduler.recursion.PipelineScheduler", FakeScheduler
        )

        scanner = RecursiveScanner(
            tmp_workdir, "example.com", "domain", "t1", self._settings()
        )
        rounds = scanner.run()

        assert len(rounds) == 3
        assert rounds[0]["target_hosts"] == ["a.example.com"]
        assert rounds[0]["new_hosts"] == ["b.example.com"]
        assert rounds[1]["target_hosts"] == ["b.example.com"]
        assert rounds[1]["new_hosts"] == ["c.example.com"]
        assert rounds[2]["target_hosts"] == ["c.example.com"]
        assert rounds[2]["new_hosts"] == []

        assert len(FakeScheduler.calls) == 3
        for call in FakeScheduler.calls:
            assert call["recursive"] is False
            assert call["save_meta"] is False
            assert not (call["workdir"] / "task.json").exists()

    def test_max_rounds_is_total_passes(self, tmp_workdir, monkeypatch):
        (tmp_workdir / "task.json").write_text("{}", encoding="utf-8")
        _write_jsonl(tmp_workdir / "subdomain_enum.jsonl", [
            {"domain": "a.example.com"},
        ])
        FakeScheduler.round_outputs = [
            [("http_probe.jsonl", [{"url": "https://b.example.com"}])],
            [("http_probe.jsonl", [{"url": "https://c.example.com"}])],
        ]
        monkeypatch.setattr(
            "arguscaner.scheduler.recursion.PipelineScheduler", FakeScheduler
        )

        scanner = RecursiveScanner(
            tmp_workdir, "example.com", "domain", "t1",
            self._settings(max_rounds=2),
        )
        rounds = scanner.run()
        assert len(rounds) == 1
        assert len(FakeScheduler.calls) == 1

    def test_no_rounds_when_nothing_discovered(self, tmp_workdir, monkeypatch):
        (tmp_workdir / "task.json").write_text("{}", encoding="utf-8")
        monkeypatch.setattr(
            "arguscaner.scheduler.recursion.PipelineScheduler", FakeScheduler
        )
        scanner = RecursiveScanner(
            tmp_workdir, "example.com", "domain", "t1", self._settings()
        )
        assert scanner.run() == []
        assert FakeScheduler.calls == []

    def test_target_host_is_not_rescanned(self, tmp_workdir, monkeypatch):
        (tmp_workdir / "task.json").write_text("{}", encoding="utf-8")
        _write_jsonl(tmp_workdir / "http_probe.jsonl", [
            {"url": "https://example.com/"},
        ])
        monkeypatch.setattr(
            "arguscaner.scheduler.recursion.PipelineScheduler", FakeScheduler
        )
        scanner = RecursiveScanner(
            tmp_workdir, "example.com", "domain", "t1", self._settings()
        )
        assert scanner.run() == []

    def test_trackers_copied_into_first_round(self, tmp_workdir, monkeypatch):
        (tmp_workdir / "task.json").write_text("{}", encoding="utf-8")
        _write_jsonl(tmp_workdir / "subdomain_enum.jsonl", [
            {"domain": "a.example.com"},
        ])
        (tmp_workdir / "api_probe_origins.txt").write_text(
            "https://base.example.com\n", encoding="utf-8"
        )
        FakeScheduler.round_outputs = [
            [("http_probe.jsonl", [{"url": "https://b.example.com"}])],
            [],
        ]
        monkeypatch.setattr(
            "arguscaner.scheduler.recursion.PipelineScheduler", FakeScheduler
        )
        scanner = RecursiveScanner(
            tmp_workdir, "example.com", "domain", "t1", self._settings()
        )
        scanner.run()

        round1 = tmp_workdir / "rounds" / "r001" / "api_probe_origins.txt"
        assert round1.read_text(encoding="utf-8").strip() == (
            "https://base.example.com"
        )

    def test_prepare_round_dir_merges_trackers(self, tmp_workdir):
        previous = tmp_workdir / "previous"
        current = tmp_workdir / "current"
        previous.mkdir()
        (previous / "api_probe_origins.txt").write_text(
            "https://a.example.com\nhttps://b.example.com\n", encoding="utf-8"
        )
        current.mkdir()
        (current / "api_probe_origins.txt").write_text(
            "https://b.example.com\n", encoding="utf-8"
        )

        prepare_round_dir(
            current,
            [{"target": "a.example.com"}],
            previous_dir=previous,
        )
        content = (current / "api_probe_origins.txt").read_text(encoding="utf-8")
        assert content.splitlines() == [
            "https://b.example.com",
            "https://a.example.com",
        ]
        assert (current / "round_targets.jsonl").exists()


class TestPluginSkipped:

    def test_skipped_stage_is_not_a_failure(self, tmp_workdir, sample_settings):
        pipeline = {
            "pipeline": {
                "name": "skip-test",
                "stages": [
                    {"name": "subdomain_enum", "plugin": "oneforall", "depends_on": []},
                ],
            }
        }
        path = tmp_workdir / "pipeline_skip.yaml"
        path.write_text(yaml.dump(pipeline), encoding="utf-8")

        def _skip(self, target, workdir, proxy=None):
            raise PluginSkipped("nothing to do")

        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(
                "arguscaner.core.plugins.oneforall.OneForAllPlugin.execute", _skip
            )
            scheduler = PipelineScheduler(path, sample_settings)
            result = scheduler.run("example.com", tmp_workdir, "skip-001")

        assert result.stages["subdomain_enum"].state == TaskState.SKIPPED
        assert result.failed_stages == []
        marker = tmp_workdir / ".subdomain_enum.done"
        assert read_stage_marker(marker) == "skipped"
        assert json.loads(marker.read_text(encoding="utf-8"))["reason"] == "nothing to do"


class TestSchedulerRecursiveHook:

    def test_run_invokes_scanner_and_merges_rounds(
        self, tmp_workdir, sample_settings, monkeypatch
    ):
        pipeline = {
            "pipeline": {
                "name": "hook-test",
                "stages": [
                    {"name": "subdomain_enum", "plugin": "oneforall", "depends_on": []},
                ],
            }
        }
        path = tmp_workdir / "pipeline_hook.yaml"
        path.write_text(yaml.dump(pipeline), encoding="utf-8")

        def _ok(self, target, workdir, proxy=None):
            out = workdir / "oneforall_output.jsonl"
            out.write_text('{"domain": "a.example.com"}\n', encoding="utf-8")
            return out

        def _fake_rounds(self, logger=None):
            return [{                "round": 1,
                "dir": str(tmp_workdir / "rounds" / "r001"),
                "targets": 1,
                "new_hosts": [],
                "stage_results": {
                    "http_probe": StageResult(
                        stage="http_probe", state=TaskState.DONE
                    ),
                    "port_scan": StageResult(
                        stage="port_scan", state=TaskState.FAILED, error="boom"
                    ),
                },
                "duration": 0.1,
                "error": None,
            }]

        monkeypatch.setattr(
            "arguscaner.core.plugins.oneforall.OneForAllPlugin.execute", _ok
        )
        monkeypatch.setattr(RecursiveScanner, "run", _fake_rounds)

        settings = dict(sample_settings)
        settings["recursive"] = {"enabled": True}
        scheduler = PipelineScheduler(path, settings)
        result = scheduler.run("example.com", tmp_workdir, "hook-001")

        assert len(result.recursive_rounds) == 1
        assert "r1:http_probe" in result.stages
        assert result.stages["r1:port_scan"].state == TaskState.FAILED
        assert "r1:port_scan" in result.failed_stages

    def test_recursive_flag_false_disables_scanner(
        self, tmp_workdir, sample_settings, monkeypatch
    ):
        pipeline = {
            "pipeline": {
                "name": "hook-test",
                "stages": [
                    {"name": "subdomain_enum", "plugin": "oneforall", "depends_on": []},
                ],
            }
        }
        path = tmp_workdir / "pipeline_hook.yaml"
        path.write_text(yaml.dump(pipeline), encoding="utf-8")

        def _ok(self, target, workdir, proxy=None):
            out = workdir / "oneforall_output.jsonl"
            out.write_text('{"domain": "a.example.com"}\n', encoding="utf-8")
            return out

        calls = []

        def _fake_rounds(self, logger=None):
            calls.append(1)
            return []

        monkeypatch.setattr(
            "arguscaner.core.plugins.oneforall.OneForAllPlugin.execute", _ok
        )
        monkeypatch.setattr(RecursiveScanner, "run", _fake_rounds)

        settings = dict(sample_settings)
        settings["recursive"] = {"enabled": True}
        scheduler = PipelineScheduler(path, settings)
        scheduler.run("example.com", tmp_workdir, "hook-002", recursive=False)
        assert calls == []


class TestAfterOrdering:

    def test_after_stage_runs_when_ordered_stage_fails(
        self, tmp_workdir, sample_settings
    ):
        pipeline = {
            "pipeline": {
                "name": "after-test",
                "stages": [
                    {"name": "subdomain_enum", "plugin": "oneforall", "depends_on": []},
                    {
                        "name": "http_probe",
                        "plugin": "httpx_probe",
                        "depends_on": [],
                        "after": ["subdomain_enum"],
                    },
                ],
            }
        }
        path = tmp_workdir / "pipeline_after.yaml"
        path.write_text(yaml.dump(pipeline), encoding="utf-8")

        def _fail(self, target, workdir, proxy=None):
            from arguscaner.core.plugins.base_plugin import CommandError

            raise CommandError("boom", returncode=127)

        def _ok(self, target, workdir, proxy=None):
            out = workdir / "httpx_output.jsonl"
            out.write_text('{"url": "https://a.example.com"}\n', encoding="utf-8")
            return out

        settings = dict(sample_settings)
        settings["retry"] = {"max_attempts": 1, "backoff_seconds": 0}

        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(
                "arguscaner.core.plugins.oneforall.OneForAllPlugin.execute", _fail
            )
            mp.setattr(
                "arguscaner.core.plugins.httpx_probe.HttpxProbePlugin.execute", _ok
            )
            scheduler = PipelineScheduler(path, settings)
            result = scheduler.run("example.com", tmp_workdir, "after-001")

        assert result.stages["subdomain_enum"].state == TaskState.FAILED
        assert result.stages["http_probe"].state == TaskState.DONE, (
            result.stages["http_probe"].error
        )


class TestRealRoundPipeline:
    """Exercise the real recursive pipeline with stubbed plugin commands."""

    def test_multi_hop_rounds_with_real_scheduler(
        self, tmp_workdir, sample_settings, monkeypatch
    ):
        (tmp_workdir / "task.json").write_text(
            '{"task_id": "real-round"}', encoding="utf-8"
        )
        _write_jsonl(tmp_workdir / "subdomain_enum.jsonl", [
            {"domain": "a.example.com"},
        ])

        calls = {"ip": 0, "api": 0}

        def _ip_discovery(self, target, workdir, proxy=None):
            calls["ip"] += 1
            out = Path(workdir) / self.output_filename
            out.write_text(
                json.dumps({
                    "host": "a.example.com",
                    "ip": "10.0.0.5",
                    "source": "dns",
                }) + "\n",
                encoding="utf-8",
            )
            return out

        def _nmap(self, target, workdir, proxy=None):
            out = Path(workdir) / self.output_filename
            out.write_text(
                "Nmap scan report for 10.0.0.5\n80/tcp open http\n",
                encoding="utf-8",
            )
            return out

        def _httpx(self, target, workdir, proxy=None):
            out = Path(workdir) / self.output_filename
            out.write_text(
                json.dumps({
                    "url": "https://a.example.com/",
                    "status_code": 200,
                }) + "\n",
                encoding="utf-8",
            )
            return out

        def _skip(self, target, workdir, proxy=None):
            raise PluginSkipped("no hosts")

        def _api(self, target, workdir, proxy=None):
            calls["api"] += 1
            out = Path(workdir) / self.output_filename
            if calls["api"] == 1:
                out.write_text(
                    json.dumps({
                        "url": "https://api.internal.example/swagger.json",
                        "status": 200,
                        "api_type": "swagger/openapi",
                        "source": "api_probe",
                    }) + "\n",
                    encoding="utf-8",
                )
            else:
                out.write_text("", encoding="utf-8")
            return out

        monkeypatch.setattr(
            "arguscaner.core.plugins.ip_discovery.IpDiscoveryPlugin.execute",
            _ip_discovery,
        )
        monkeypatch.setattr(
            "arguscaner.core.plugins.nmap_scan.NmapScanPlugin.execute", _nmap
        )
        monkeypatch.setattr(
            "arguscaner.core.plugins.httpx_probe.HttpxProbePlugin.execute", _httpx
        )
        monkeypatch.setattr(
            "arguscaner.core.plugins.jsfinder.JsFinderPlugin.execute", _skip
        )
        monkeypatch.setattr(
            "arguscaner.core.plugins.urlfinder.UrlFinderPlugin.execute", _skip
        )
        monkeypatch.setattr(
            "arguscaner.core.plugins.api_probe.ApiProbePlugin.execute", _api
        )

        settings = dict(sample_settings)
        settings["retry"] = {"max_attempts": 1, "backoff_seconds": 0}
        settings["recursive"] = {
            "enabled": True,
            "max_rounds": 4,
            "max_assets_per_round": 100,
        }

        scanner = RecursiveScanner(
            tmp_workdir, "example.com", "domain", "real-round", settings
        )
        rounds = scanner.run()

        assert len(rounds) == 2
        assert set(rounds[0]["target_hosts"]) == {"a.example.com"}
        assert set(rounds[0]["new_hosts"]) == {"api.internal.example", "10.0.0.5"}
        assert set(rounds[1]["target_hosts"]) == {"api.internal.example", "10.0.0.5"}
        assert rounds[1]["new_hosts"] == []

        for index in (1, 2):
            round_dir = tmp_workdir / "rounds" / f"r{index:03d}"
            assert round_dir.exists()
            assert not (round_dir / "task.json").exists()
            assert (round_dir / "round_targets.jsonl").exists()
            assert read_stage_marker(round_dir / ".http_probe.done") == "done"
        # The version-blind stage markers are per round.
        assert read_stage_marker(
            tmp_workdir / "rounds" / "r001" / ".js_url_extract.done"
        ) == "skipped"
