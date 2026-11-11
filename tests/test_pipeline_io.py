"""Tests for pipeline definition I/O, validation and graph building."""

from __future__ import annotations

import yaml

from arguscaner.scheduler import pipeline_io


def _definition(stages, name="test_pipeline"):
    return {"pipeline": {"name": name}, "stages": stages}


def _stage(stage_id, plugin="oneforall", **extra):
    data = {"id": stage_id, "plugin": plugin}
    data.update(extra)
    return data


def test_legacy_name_and_missing_levels_are_normalized():
    raw = {
        "pipeline": {
            "name": "legacy",
            "stages": [
                {"name": "enum", "plugin": "oneforall", "depends_on": []},
            ],
        }
    }
    definition = pipeline_io.normalize_definition(raw)
    stage = definition["stages"][0]
    assert stage["id"] == "enum"
    assert stage["label"] == "enum"
    assert stage["level"] is None
    assert stage["inputs"] == []


def test_inputs_accept_strings_and_dicts():
    definition = pipeline_io.normalize_definition(_definition([
        _stage("a", inputs=["target", {"from": "round_targets", "data": "host"}]),
    ]))
    inputs = definition["stages"][0]["inputs"]
    assert inputs[0] == {"from": "target", "data": "数据"}
    assert inputs[1] == {"from": "round_targets", "data": "host", "field": ""}


def test_serialize_drops_internal_order_and_roundtrips(tmp_path):
    definition = pipeline_io.normalize_definition(_definition([
        _stage("a", level=1, label="阶段 A"),
        _stage("b", plugin="httpx_probe", level=2, inputs=[{"from": "a", "data": "url"}]),
    ]))
    path = tmp_path / "pipeline.yaml"
    pipeline_io.save_definition(path, definition, backup=False)
    loaded = pipeline_io.load_definition(path)
    assert [s["id"] for s in loaded["stages"]] == ["a", "b"]
    assert "order" not in yaml.safe_load(path.read_text(encoding="utf-8"))["stages"][0]
    assert loaded["stages"][1]["inputs"][0]["data"] == "url"


def test_validate_rejects_duplicate_ids():
    definition = _definition([_stage("a"), _stage("a", plugin="httpx_probe")])
    errors = pipeline_io.validate_definition(definition, {"oneforall", "httpx_probe"})
    assert any("重复" in error for error in errors)


def test_validate_rejects_unknown_plugin():
    errors = pipeline_io.validate_definition(
        _definition([_stage("a", plugin="nope")]), {"oneforall"}
    )
    assert any("未知插件" in error for error in errors)


def test_validate_rejects_dangling_input():
    definition = _definition([_stage("a", inputs=[{"from": "missing"}])])
    errors = pipeline_io.validate_definition(definition)
    assert any("数据来源不存在" in error for error in errors)


def test_validate_rejects_cycle():
    definition = _definition([
        _stage("a", depends_on=["b"]),
        _stage("b", depends_on=["a"]),
    ])
    errors = pipeline_io.validate_definition(definition)
    assert any("循环" in error for error in errors)


def test_validate_rejects_mixed_levels():
    definition = _definition([
        _stage("a", level=1),
        _stage("b"),
    ])
    errors = pipeline_io.validate_definition(definition)
    assert any("层级字段必须为全部阶段设置" in error for error in errors)


def test_validate_rejects_dependency_level_conflict():
    definition = _definition([
        _stage("a", level=2),
        _stage("b", level=1, depends_on=["a"]),
    ])
    errors = pipeline_io.validate_definition(definition)
    assert any("更早层级" in error for error in errors)


def test_validate_allows_same_plugin_multiple_times():
    definition = _definition([
        _stage("a", level=1),
        _stage("b", level=2, inputs=[{"from": "a", "data": "url"}]),
    ])
    errors = pipeline_io.validate_definition(definition, {"oneforall"})
    assert errors == []


def test_compute_levels_uses_explicit_numbers():
    definition = _definition([
        _stage("a", level=1),
        _stage("b", level=2),
        _stage("c", level=2),
    ])
    assert pipeline_io.compute_levels(definition) == [["a"], ["b", "c"]]


def test_compute_levels_auto_from_dependencies():
    definition = _definition([
        _stage("a"),
        _stage("b", depends_on=["a"]),
        _stage("c", after=["a"]),
        _stage("d", inputs=[{"from": "b"}, {"from": "c"}]),
    ])
    levels = pipeline_io.compute_levels(definition)
    assert levels[0] == ["a"]
    assert sorted(levels[1]) == ["b", "c"]
    assert levels[2] == ["d"]


def test_build_graph_labels_data_and_order_edges():
    definition = _definition([
        _stage("a", level=1),
        _stage("b", plugin="httpx_probe", level=2,
               after=["a"], inputs=[{"from": "a", "data": "subdomain"}]),
    ])
    graph = pipeline_io.build_graph(definition)
    edges = {(edge["from"], edge["to"], edge["kind"]): edge for edge in graph["edges"]}
    assert edges[("a", "b", "data")]["label"] == "subdomain"
    assert edges[("a", "b", "order")]["label"] == "顺序"
    assert graph["levels"] == [["a"], ["b"]]


def test_build_graph_adds_pseudo_source_nodes():
    definition = _definition([
        _stage("a", level=1, inputs=[{"from": "round_targets", "data": "host"}]),
    ])
    graph = pipeline_io.build_graph(definition)
    source = [node for node in graph["nodes"] if node["kind"] == "source"]
    assert source and source[0]["id"] == "round_targets"
    assert any(edge["from"] == "round_targets" for edge in graph["edges"])


def test_stage_meta_records_computed_levels():
    definition = _definition([
        _stage("a"),
        _stage("b", depends_on=["a"]),
    ])
    meta = pipeline_io.stage_meta(definition)
    assert meta == [
        {"id": "a", "label": "a", "plugin": "oneforall", "level": 1},
        {"id": "b", "label": "b", "plugin": "oneforall", "level": 2},
    ]


def test_save_creates_backup_and_restore(tmp_path):
    path = tmp_path / "pipeline.yaml"
    original = _definition([_stage("a")])
    pipeline_io.save_definition(path, original, backup=False)
    pipeline_io.save_definition(path, _definition([_stage("b")]), backup=True)
    assert "id: b" in path.read_text(encoding="utf-8")
    assert pipeline_io.latest_backup(path) is not None
    backup = pipeline_io.restore_backup(path)
    assert backup is not None
    assert "id: a" in path.read_text(encoding="utf-8")


def test_save_retains_only_latest_backups(tmp_path):
    path = tmp_path / "pipeline.yaml"
    pipeline_io.save_definition(path, _definition([_stage("a")]), backup=False)
    for index in range(23):
        pipeline_io.save_definition(
            path, _definition([_stage(f"stage_{index}")]), backup=True
        )
    backups = list((tmp_path / ".history").glob("pipeline.*.yaml"))
    assert len(backups) == 20


def test_resolve_pipeline_falls_back_to_default():
    assert pipeline_io.resolve_pipeline(None) == pipeline_io.DEFAULT_PIPELINE
    assert pipeline_io.resolve_pipeline("default") == pipeline_io.DEFAULT_PIPELINE
    assert pipeline_io.pipeline_key(pipeline_io.DEFAULT_PIPELINE) == "default"
