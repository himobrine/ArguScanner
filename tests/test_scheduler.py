"""Tests for the DAG scheduler."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch, MagicMock

import networkx as nx
import pytest
import yaml

from arguscaner.scheduler.scheduler_core import (
    PipelineScheduler,
    TaskState,
    generate_task_id,
    read_stage_marker,
    write_stage_marker,
)
from arguscaner.core.plugins.base_plugin import CommandError


@pytest.fixture
def pipeline_yaml(tmp_workdir):
    config = {
        "pipeline": {
            "name": "test",
            "stages": [
                {"name": "subdomain_enum", "plugin": "oneforall", "depends_on": []},
                {"name": "http_probe", "plugin": "httpx_probe", "depends_on": ["subdomain_enum"]},
                {"name": "port_scan", "plugin": "nmap_scan", "depends_on": ["subdomain_enum"]},
            ],
        }
    }
    path = tmp_workdir / "pipeline.yaml"
    with open(path, "w") as f:
        yaml.dump(config, f)
    return path


@pytest.fixture
def mock_plugin_execute():
    """Mock plugin execute to create output files without running CLI tools."""
    def _mock_execute(target, workdir, proxy=None):
        output_file = workdir / "output.jsonl"
        output_file.write_text('{"mock": true}\n', encoding="utf-8")
        return output_file

    with patch(
        "arguscaner.core.plugins.oneforall.OneForAllPlugin.execute",
        side_effect=_mock_execute,
    ), patch(
        "arguscaner.core.plugins.httpx_probe.HttpxProbePlugin.execute",
        side_effect=_mock_execute,
    ), patch(
        "arguscaner.core.plugins.nmap_scan.NmapScanPlugin.execute",
        side_effect=_mock_execute,
    ):
        yield


class TestPipelineScheduler:

    def test_loads_dag(self, pipeline_yaml, sample_settings):
        scheduler = PipelineScheduler(pipeline_yaml, sample_settings)
        assert isinstance(scheduler.dag, nx.DiGraph)
        assert scheduler.dag.number_of_nodes() == 3

    def test_validate_valid_dag(self, pipeline_yaml, sample_settings):
        scheduler = PipelineScheduler(pipeline_yaml, sample_settings)
        assert scheduler.validate() is True

    def test_validate_cyclic_dag(self, tmp_workdir, sample_settings):
        config = {
            "pipeline": {
                "stages": [
                    {"name": "a", "plugin": "oneforall", "depends_on": ["c"]},
                    {"name": "b", "plugin": "httpx_probe", "depends_on": ["a"]},
                    {"name": "c", "plugin": "nmap_scan", "depends_on": ["b"]},
                ]
            }
        }
        path = tmp_workdir / "cyclic.yaml"
        with open(path, "w") as f:
            yaml.dump(config, f)

        scheduler = PipelineScheduler(path, sample_settings)
        with pytest.raises(ValueError, match="依赖循环"):
            scheduler.validate()

    def test_execution_levels(self, pipeline_yaml, sample_settings):
        scheduler = PipelineScheduler(pipeline_yaml, sample_settings)
        levels = scheduler.get_execution_levels()
        assert len(levels) == 2
        assert "subdomain_enum" in levels[0]

    def test_run(self, mock_plugin_execute, pipeline_yaml, sample_settings, tmp_workdir):
        scheduler = PipelineScheduler(pipeline_yaml, sample_settings)
        result = scheduler.run("example.com", tmp_workdir, "test-001")
        assert result.task_id == "test-001"
        assert result.total_duration > 0

    def test_done_markers_created(self, mock_plugin_execute, pipeline_yaml, sample_settings, tmp_workdir):
        scheduler = PipelineScheduler(pipeline_yaml, sample_settings)
        scheduler.run("example.com", tmp_workdir, "test-002")
        done_files = list(tmp_workdir.glob(".*.done"))
        assert len(done_files) == 3

    def test_ip_target_skips_domain_plugin(self, mock_plugin_execute, pipeline_yaml, sample_settings, tmp_workdir):
        scheduler = PipelineScheduler(pipeline_yaml, sample_settings)
        result = scheduler.run("8.8.8.8", tmp_workdir, "test-ip-001")
        assert result.stages["subdomain_enum"].state == TaskState.SKIPPED

    def test_ip_target_downstream_stages_run(self, mock_plugin_execute, pipeline_yaml, sample_settings, tmp_workdir):
        scheduler = PipelineScheduler(pipeline_yaml, sample_settings)
        result = scheduler.run("8.8.8.8", tmp_workdir, "test-ip-002")
        assert result.stages["subdomain_enum"].state == TaskState.SKIPPED
        assert result.stages["http_probe"].state == TaskState.DONE
        assert result.stages["port_scan"].state == TaskState.DONE
        done_files = list(tmp_workdir.glob(".*.done"))
        assert len(done_files) == 3

    def test_when_list_target_type(self, mock_plugin_execute, tmp_workdir, sample_settings):
        config = {
            "pipeline": {
                "name": "test",
                "stages": [
                    {"name": "subdomain_enum", "plugin": "oneforall", "depends_on": [],
                     "when": {"target_type": "domain"}},
                    {"name": "http_probe", "plugin": "httpx_probe", "depends_on": ["subdomain_enum"],
                     "when": {"target_type": ["domain", "ip"]}},
                    {"name": "port_scan", "plugin": "nmap_scan", "depends_on": ["subdomain_enum"]},
                ],
            }
        }
        path = tmp_workdir / "when_list.yaml"
        with open(path, "w") as f:
            yaml.dump(config, f)

        scheduler = PipelineScheduler(path, sample_settings)
        result = scheduler.run("8.8.8.8", tmp_workdir, "test-when-list")
        assert result.stages["subdomain_enum"].state == TaskState.SKIPPED
        assert result.stages["http_probe"].state == TaskState.DONE
        assert result.stages["port_scan"].state == TaskState.DONE

    def test_task_meta_saved(self, mock_plugin_execute, pipeline_yaml, sample_settings, tmp_workdir):
        scheduler = PipelineScheduler(pipeline_yaml, sample_settings)
        scheduler.run("example.com", tmp_workdir, "test-meta-001")
        meta_file = tmp_workdir / "task.json"
        assert meta_file.exists()
        meta = PipelineScheduler.load_task_meta(tmp_workdir)
        assert meta["target"] == "example.com"
        assert meta["target_type"] == "domain"
        assert meta["pipeline"] == "pipeline"
        assert [s["id"] for s in meta["pipeline_stages"]] == [
            "subdomain_enum", "http_probe", "port_scan",
        ]

    def test_duplicate_plugin_stages_get_isolated_instances(
        self, pipeline_yaml, sample_settings, tmp_workdir
    ):
        config = {
            "pipeline": {
                "name": "dupes",
                "stages": [
                    {"id": "enum_a", "plugin": "oneforall", "level": 1,
                     "params": {"suffix_a": True}},
                    {"id": "enum_b", "plugin": "oneforall", "level": 1,
                     "params": {"suffix_b": True}},
                ],
            }
        }
        path = tmp_workdir / "dupes.yaml"
        with open(path, "w") as handle:
            yaml.dump(config, handle)

        scheduler = PipelineScheduler(path, sample_settings)
        assert scheduler._plugin_usage["oneforall"] == 2

        first = scheduler._spawn_plugin("oneforall", {"suffix_a": True})
        second = scheduler._spawn_plugin("oneforall", {"suffix_b": True})
        assert first is not second
        assert first.settings["plugins"]["oneforall"]["suffix_a"] is True
        assert second.settings["plugins"]["oneforall"]["suffix_b"] is True

        first.bind_stage("enum_a", scoped=True)
        second.bind_stage("enum_b", scoped=True)
        assert first._stage_file(tmp_workdir, "out.jsonl").name == "out__enum_a.jsonl"
        assert second._stage_file(tmp_workdir, "out.jsonl").name == "out__enum_b.jsonl"

    def test_stage_settings_do_not_mutate_global_settings(
        self, pipeline_yaml, sample_settings
    ):
        scheduler = PipelineScheduler(pipeline_yaml, sample_settings)
        merged = scheduler._stage_settings("nmap_scan", {"ports": "80,443"})
        assert merged["plugins"]["nmap_scan"]["ports"] == "80,443"
        assert "plugins" not in sample_settings

    def test_stage_input_files_resolves_declared_sources(
        self, sample_settings, tmp_workdir
    ):
        config = {
            "pipeline": {
                "name": "inputs",
                "stages": [
                    {"id": "ip_discovery", "plugin": "ip_discovery", "level": 1},
                    {"id": "port_scan", "plugin": "nmap_scan", "level": 2,
                     "after": ["ip_discovery"],
                     "inputs": [
                         {"from": "round_targets", "data": "host"},
                         {"from": "ip_discovery", "data": "ip"},
                         {"from": "target", "data": "原始目标"},
                     ]},
                ],
            }
        }
        path = tmp_workdir / "inputs.yaml"
        with open(path, "w") as handle:
            yaml.dump(config, handle)

        scheduler = PipelineScheduler(path, sample_settings)
        node = scheduler.dag.nodes["port_scan"]
        files = PipelineScheduler._stage_input_files(node, tmp_workdir)
        assert [path.name for path in files] == [
            "round_targets.jsonl", "ip_discovery.jsonl",
        ]

    def test_pipeline_graph_includes_plugins(self, pipeline_yaml, sample_settings):
        scheduler = PipelineScheduler(pipeline_yaml, sample_settings)
        graph = scheduler.get_pipeline_graph()
        assert {node["id"] for node in graph["nodes"]} >= {
            "subdomain_enum", "http_probe", "port_scan",
        }
        assert "oneforall" in graph["plugins"]

    def test_same_plugin_runs_twice_with_separate_stage_outputs(
        self, mock_plugin_execute, sample_settings, tmp_workdir
    ):
        config = {
            "pipeline": {
                "name": "duplicate_run",
                "stages": [
                    {"id": "enum_a", "plugin": "oneforall", "level": 1},
                    {"id": "enum_b", "plugin": "oneforall", "level": 2,
                     "depends_on": ["enum_a"],
                     "params": {"max_targets": 1},
                     "inputs": [{"from": "enum_a", "data": "subdomain"}]},
                ],
            }
        }
        path = tmp_workdir / "duplicate_run.yaml"
        with open(path, "w") as handle:
            yaml.dump(config, handle)

        scheduler = PipelineScheduler(path, sample_settings)
        result = scheduler.run("example.com", tmp_workdir, "test-dup-run")

        assert result.stages["enum_a"].state == TaskState.DONE
        assert result.stages["enum_b"].state == TaskState.DONE
        assert (tmp_workdir / ".enum_a.done").exists()
        assert (tmp_workdir / ".enum_b.done").exists()
        assert (tmp_workdir / "enum_a.jsonl").exists()
        assert (tmp_workdir / "enum_b.jsonl").exists()

    def test_resume_recovers_target(self, mock_plugin_execute, pipeline_yaml, sample_settings, tmp_workdir):
        scheduler = PipelineScheduler(pipeline_yaml, sample_settings)
        scheduler.run("example.com", tmp_workdir, "test-res-001")
        result = scheduler.resume("test-res-001", tmp_workdir)
        assert result.target == "example.com"
        assert result.target_type == "domain"


class TestStageMarkers:
    """Four-state marker semantics and dependency gating."""

    def test_marker_roundtrip_json(self, tmp_workdir):
        marker = tmp_workdir / ".stage.done"
        write_stage_marker(marker, TaskState.FAILED.value, error="boom")
        assert read_stage_marker(marker) == "failed"

    def test_marker_reads_legacy_text(self, tmp_workdir):
        marker = tmp_workdir / ".stage.done"
        marker.write_text("done", encoding="utf-8")
        assert read_stage_marker(marker) == "done"

    def test_marker_absent_returns_none(self, tmp_workdir):
        assert read_stage_marker(tmp_workdir / ".missing.done") is None

    def test_failed_dependency_blocks_downstream(self, pipeline_yaml, sample_settings, tmp_workdir):
        settings = dict(sample_settings)
        settings["retry"] = {"max_attempts": 1, "backoff_seconds": 0}

        def _fail(target, workdir, proxy=None):
            raise CommandError("boom", returncode=127)

        def _ok(target, workdir, proxy=None):
            out = workdir / "output.jsonl"
            out.write_text('{"mock": true}\n', encoding="utf-8")
            return out

        with patch(
            "arguscaner.core.plugins.oneforall.OneForAllPlugin.execute",
            side_effect=_fail,
        ), patch(
            "arguscaner.core.plugins.httpx_probe.HttpxProbePlugin.execute",
            side_effect=_ok,
        ), patch(
            "arguscaner.core.plugins.nmap_scan.NmapScanPlugin.execute",
            side_effect=_ok,
        ):
            scheduler = PipelineScheduler(pipeline_yaml, settings)
            result = scheduler.run("example.com", tmp_workdir, "test-block")

        assert result.stages["subdomain_enum"].state == TaskState.FAILED
        assert result.stages["http_probe"].state == TaskState.BLOCKED
        assert result.stages["port_scan"].state == TaskState.BLOCKED
        assert result.stages["http_probe"].skip_reason
        assert result.failed_stages == ["subdomain_enum"]

    def test_resume_reruns_failed_but_skips_done(self, pipeline_yaml, sample_settings, tmp_workdir):
        settings = dict(sample_settings)
        settings["retry"] = {"max_attempts": 1, "backoff_seconds": 0}

        def _fail(target, workdir, proxy=None):
            raise CommandError("boom", returncode=127)

        def _ok(target, workdir, proxy=None):
            out = workdir / "output.jsonl"
            out.write_text('{"mock": true}\n', encoding="utf-8")
            return out

        with patch(
            "arguscaner.core.plugins.oneforall.OneForAllPlugin.execute",
            side_effect=_fail,
        ), patch(
            "arguscaner.core.plugins.httpx_probe.HttpxProbePlugin.execute",
            side_effect=_ok,
        ), patch(
            "arguscaner.core.plugins.nmap_scan.NmapScanPlugin.execute",
            side_effect=_ok,
        ):
            scheduler = PipelineScheduler(pipeline_yaml, settings)
            first = scheduler.run("example.com", tmp_workdir, "test-resume")
            assert first.stages["subdomain_enum"].state == TaskState.FAILED

        with patch(
            "arguscaner.core.plugins.oneforall.OneForAllPlugin.execute",
            side_effect=_ok,
        ), patch(
            "arguscaner.core.plugins.httpx_probe.HttpxProbePlugin.execute",
            side_effect=_ok,
        ), patch(
            "arguscaner.core.plugins.nmap_scan.NmapScanPlugin.execute",
            side_effect=_ok,
        ):
            scheduler = PipelineScheduler(pipeline_yaml, settings)
            second = scheduler.resume("test-resume", tmp_workdir)

        assert second.stages["subdomain_enum"].state == TaskState.DONE
        assert second.stages["http_probe"].state == TaskState.DONE
        assert second.stages["port_scan"].state == TaskState.DONE

    def test_should_retry_respects_exit_codes(self, pipeline_yaml, tmp_workdir):
        settings = {
            "retry": {
                "max_attempts": 3,
                "backoff_seconds": 0,
                "retryable_exit_codes": [1, 2],
                "non_retryable_exit_codes": [0, 127],
            }
        }
        scheduler = PipelineScheduler(pipeline_yaml, settings)
        assert scheduler._should_retry(CommandError("x", returncode=1)) is True
        assert scheduler._should_retry(CommandError("x", returncode=127)) is False
        assert scheduler._should_retry(CommandError("x", returncode=0)) is False
        assert scheduler._should_retry(CommandError("x", returncode=99)) is False
        assert scheduler._should_retry(RuntimeError("no exit code")) is True


class TestGenerateTaskId:
    def test_format(self):
        task_id = generate_task_id()
        assert task_id.startswith("hv-")
        parts = task_id.split("-")
        assert len(parts) == 5  # hv-YYYY-MM-DD-NNN
        assert parts[1].isdigit()  # year
        assert parts[4].isdigit()  # counter
