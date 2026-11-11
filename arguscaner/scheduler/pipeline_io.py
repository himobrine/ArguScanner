"""Pipeline definition I/O: load, normalize, validate, graph and save.

The pipeline format is a small DAG description with an optional explicit
execution level.  The loader accepts the legacy layout (``name`` instead of
``id`` and no levels/inputs) so existing YAML files keep working.
"""

from __future__ import annotations

import copy
import json
import os
import time
from pathlib import Path
from typing import Any

import networkx as nx
import yaml

CONFIGS_DIR = Path(__file__).parent.parent / "configs"
DEFAULT_PIPELINE = CONFIGS_DIR / "pipeline.yaml"
CUSTOM_PIPELINES_DIR = CONFIGS_DIR / "pipelines"
HISTORY_DIRNAME = ".history"

#: Pseudo sources that are not stages but can feed a stage.
PSEUDO_SOURCES = {
    "target": "原始目标",
    "round_targets": "本轮资产",
}

DEFAULT_INPUT_DATA = "数据"


def resolve_pipeline(name: str | None) -> Path:
    """Resolve a pipeline name/file to a YAML path.

    ``default``/``None`` resolves to ``configs/pipeline.yaml``.  A bare name is
    looked up in ``configs/pipelines/`` and finally in the working directory.
    """
    if not name or name == "default":
        return DEFAULT_PIPELINE
    candidate = Path(str(name))
    if not candidate.suffix:
        candidate = candidate.with_suffix(".yaml")
    if candidate.exists() and candidate.is_file():
        return candidate
    named = CUSTOM_PIPELINES_DIR / candidate.name
    if named.exists():
        return named
    return DEFAULT_PIPELINE


def pipeline_key(path: Path) -> str:
    """Return the API name for a pipeline file."""
    path = Path(path)
    try:
        if path.resolve() == DEFAULT_PIPELINE.resolve():
            return "default"
    except OSError:
        pass
    return path.stem


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return list(value)
    return [value]


def _normalize_inputs(raw: Any) -> list[dict[str, str]]:
    inputs: list[dict[str, str]] = []
    for item in _as_list(raw):
        if isinstance(item, str):
            inputs.append({"from": item, "data": DEFAULT_INPUT_DATA})
        elif isinstance(item, dict) and item.get("from"):
            inputs.append({
                "from": str(item["from"]),
                "data": str(item.get("data") or DEFAULT_INPUT_DATA),
                "field": str(item.get("field") or ""),
            })
    return inputs


def normalize_definition(raw: dict[str, Any] | None) -> dict[str, Any]:
    """Return a canonical pipeline definition.

    Canonical shape::

        {"pipeline": {"name", "description", "version"},
         "stages": [{"id", "plugin", "label", "level", "depends_on",
                     "after", "when", "inputs", "outputs", "params",
                     "description"}]}
    """
    raw = raw or {}
    meta = dict(raw.get("pipeline") or {})
    stages_raw = raw.get("stages")
    if stages_raw is None:
        stages_raw = meta.get("stages") or []
    stages_raw = _as_list(stages_raw)

    stages: list[dict[str, Any]] = []
    for index, item in enumerate(stages_raw):
        if not isinstance(item, dict):
            continue
        stage_id = str(item.get("id") or item.get("name") or "").strip()
        if not stage_id:
            continue
        level = item.get("level")
        try:
            level = int(level) if level is not None else None
        except (TypeError, ValueError):
            level = None
        outputs = item.get("outputs")
        if not isinstance(outputs, dict):
            outputs = {}
        params = item.get("params")
        if not isinstance(params, dict):
            params = {}
        stages.append({
            "id": stage_id,
            "plugin": str(item.get("plugin") or "").strip(),
            "label": str(item.get("label") or stage_id).strip(),
            "level": level,
            "depends_on": [str(d) for d in _as_list(item.get("depends_on"))],
            "after": [str(d) for d in _as_list(item.get("after"))],
            "when": dict(item.get("when") or {}),
            "inputs": _normalize_inputs(item.get("inputs")),
            "outputs": dict(outputs),
            "params": dict(params),
            "description": str(item.get("description") or ""),
            "order": index,
        })

    return {
        "pipeline": {
            "name": str(meta.get("name") or "default_recon"),
            "description": str(meta.get("description") or ""),
            "version": int(meta.get("version") or 2),
        },
        "stages": stages,
    }


def load_definition(path: Path) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as handle:
        raw = yaml.safe_load(handle) or {}
    return normalize_definition(raw)


def serialize_definition(definition: dict[str, Any]) -> dict[str, Any]:
    """Return a YAML-friendly payload (drops internal ``order`` fields)."""
    definition = normalize_definition(definition)
    stages: list[dict[str, Any]] = []
    for stage in definition["stages"]:
        item: dict[str, Any] = {
            "id": stage["id"],
            "plugin": stage["plugin"],
        }
        if stage["label"] and stage["label"] != stage["id"]:
            item["label"] = stage["label"]
        if stage["level"] is not None:
            item["level"] = stage["level"]
        item["depends_on"] = list(stage["depends_on"])
        item["after"] = list(stage["after"])
        if stage["when"]:
            item["when"] = stage["when"]
        if stage["inputs"]:
            item["inputs"] = [
                {k: v for k, v in entry.items() if v}
                for entry in stage["inputs"]
            ]
        if stage["outputs"]:
            item["outputs"] = stage["outputs"]
        if stage["params"]:
            item["params"] = stage["params"]
        if stage["description"]:
            item["description"] = stage["description"]
        stages.append(item)
    return {
        "pipeline": dict(definition["pipeline"]),
        "stages": stages,
    }


def _stage_ids(definition: dict[str, Any]) -> set[str]:
    return {stage["id"] for stage in definition["stages"]}


def validate_definition(
    definition: dict[str, Any],
    plugin_names: set[str] | None = None,
) -> list[str]:
    """Validate a definition and return a list of human-readable errors."""
    definition = normalize_definition(definition)
    stages = definition["stages"]
    errors: list[str] = []
    ids: set[str] = set()

    if not stages:
        return ["流程至少需要一个阶段"]

    for stage in stages:
        if not stage["id"]:
            errors.append("存在缺少 id 的阶段")
            continue
        if stage["id"] in ids:
            errors.append(f"阶段 id 重复：{stage['id']}")
        ids.add(stage["id"])
        if not stage["plugin"]:
            errors.append(f"阶段 {stage['id']} 未指定插件")
        elif plugin_names is not None and stage["plugin"] not in plugin_names:
            errors.append(f"阶段 {stage['id']} 使用了未知插件：{stage['plugin']}")
        if stage["level"] is not None and stage["level"] < 1:
            errors.append(f"阶段 {stage['id']} 的层级必须 >= 1")

    for stage in stages:
        for dep in stage["depends_on"] + stage["after"]:
            if dep not in ids:
                errors.append(f"阶段 {stage['id']} 引用了不存在的阶段：{dep}")
        for entry in stage["inputs"]:
            source = entry["from"]
            if source in ids or source in PSEUDO_SOURCES:
                continue
            errors.append(f"阶段 {stage['id']} 的数据来源不存在：{source}")

    if errors:
        return errors

    def ordering_deps(stage: dict[str, Any]) -> list[str]:
        deps = list(stage["depends_on"]) + list(stage["after"])
        deps += [
            entry["from"]
            for entry in stage["inputs"]
            if entry["from"] in ids and entry["from"] not in deps
        ]
        return deps

    # Cycle detection (depends_on + after + declared data sources).
    graph = nx.DiGraph()
    graph.add_nodes_from(ids)
    for stage in stages:
        for dep in ordering_deps(stage):
            graph.add_edge(dep, stage["id"])
    if not nx.is_directed_acyclic_graph(graph):
        try:
            cycle = list(nx.find_cycle(graph))
            path = " -> ".join(edge[0] for edge in cycle)
            errors.append(f"检测到依赖循环：{path}")
        except nx.NetworkXNoCycle:  # pragma: no cover - defensive
            errors.append("检测到依赖循环")
        return errors

    # Explicit levels must place every predecessor in a strictly earlier level.
    if all(stage["level"] is not None for stage in stages):
        levels = {stage["id"]: stage["level"] for stage in stages}
        for stage in stages:
            for dep in ordering_deps(stage):
                if levels[dep] >= levels[stage["id"]]:
                    errors.append(
                        f"阶段 {stage['id']}（层级 {levels[stage['id']]}）依赖"
                        f" {dep}（层级 {levels[dep]}），依赖必须位于更早层级"
                    )
    elif any(stage["level"] is not None for stage in stages):
        errors.append("层级字段必须为全部阶段设置，或全部留空（自动推导）")

    return errors


def compute_levels(definition: dict[str, Any]) -> list[list[str]]:
    """Group stages into execution levels (explicit level wins)."""
    definition = normalize_definition(definition)
    stages = definition["stages"]
    if not stages:
        return []
    if all(stage["level"] is not None for stage in stages):
        grouped: dict[int, list[tuple[int, str]]] = {}
        for stage in stages:
            grouped.setdefault(int(stage["level"]), []).append(
                (stage["order"], stage["id"])
            )
        return [
            [stage_id for _, stage_id in sorted(items)]
            for _, items in sorted(grouped.items())
        ]

    graph = nx.DiGraph()
    for stage in stages:
        graph.add_node(stage["id"])
    for stage in stages:
        deps = list(stage["depends_on"]) + list(stage["after"])
        deps += [
            entry["from"]
            for entry in stage["inputs"]
            if entry["from"] in graph and entry["from"] not in deps
        ]
        for dep in deps:
            if dep in graph:
                graph.add_edge(dep, stage["id"])

    order = {stage["id"]: stage["order"] for stage in stages}
    levels: list[list[str]] = []
    assigned: set[str] = set()
    current = [node for node in graph.nodes if graph.in_degree(node) == 0]
    while current:
        current.sort(key=lambda node: order.get(node, 0))
        levels.append(current)
        assigned.update(current)
        next_level: list[str] = []
        for node in current:
            for successor in graph.successors(node):
                if successor in assigned or successor in next_level:
                    continue
                if all(pred in assigned for pred in graph.predecessors(successor)):
                    next_level.append(successor)
        current = next_level
    return levels


def build_graph(definition: dict[str, Any]) -> dict[str, Any]:
    """Build the node/edge payload used by the tree view."""
    definition = normalize_definition(definition)
    levels = compute_levels(definition)
    level_of = {
        stage_id: index + 1 for index, level in enumerate(levels) for stage_id in level
    }

    nodes: list[dict[str, Any]] = []
    for stage in definition["stages"]:
        nodes.append({
            "id": stage["id"],
            "kind": "stage",
            "label": stage["label"],
            "plugin": stage["plugin"],
            "level": level_of.get(stage["id"], stage["level"] or 0),
            "when": stage["when"],
            "inputs": stage["inputs"],
            "outputs": stage["outputs"],
            "params": stage["params"],
            "depends_on": stage["depends_on"],
            "after": stage["after"],
            "description": stage["description"],
        })

    used_sources = {
        entry["from"]
        for stage in definition["stages"]
        for entry in stage["inputs"]
        if entry["from"] in PSEUDO_SOURCES
    }
    for source in sorted(used_sources):
        nodes.insert(0, {
            "id": source,
            "kind": "source",
            "label": PSEUDO_SOURCES[source],
            "plugin": "",
            "level": 0,
            "when": {},
            "inputs": [],
            "outputs": {},
            "params": {},
            "depends_on": [],
            "after": [],
            "description": "",
        })

    edges: list[dict[str, Any]] = []
    for stage in definition["stages"]:
        input_labels = {
            entry["from"]: entry.get("data") or DEFAULT_INPUT_DATA
            for entry in stage["inputs"]
        }
        for dep in stage["depends_on"]:
            edges.append({
                "from": dep,
                "to": stage["id"],
                "kind": "data",
                "label": input_labels.get(dep, DEFAULT_INPUT_DATA),
            })
        for dep in stage["after"]:
            edges.append({
                "from": dep,
                "to": stage["id"],
                "kind": "order",
                "label": "顺序",
            })
        # Declared data sources that are not dependency edges (order-only or
        # pseudo sources) still need to be visible.
        for entry in stage["inputs"]:
            source = entry["from"]
            if source == "target":
                continue
            already = any(
                edge["from"] == source
                and edge["to"] == stage["id"]
                and edge["kind"] == "data"
                for edge in edges
            )
            if not already:
                edges.append({
                    "from": source,
                    "to": stage["id"],
                    "kind": "data",
                    "label": entry.get("data") or DEFAULT_INPUT_DATA,
                })

    return {
        "pipeline": dict(definition["pipeline"]),
        "levels": levels,
        "nodes": nodes,
        "edges": edges,
    }


def list_pipelines() -> list[dict[str, Any]]:
    """List the default pipeline and custom pipelines."""
    entries: list[dict[str, Any]] = []

    def _entry(path: Path, builtin: bool) -> dict[str, Any] | None:
        try:
            definition = load_definition(path)
        except (OSError, yaml.YAMLError, ValueError):
            return None
        return {
            "name": pipeline_key(path),
            "file": str(path),
            "builtin": builtin,
            "description": definition["pipeline"].get("description", ""),
            "stage_count": len(definition["stages"]),
            "stages": [stage["id"] for stage in definition["stages"]],
        }

    default_entry = _entry(DEFAULT_PIPELINE, True)
    if default_entry:
        entries.append(default_entry)
    if CUSTOM_PIPELINES_DIR.exists():
        for path in sorted(CUSTOM_PIPELINES_DIR.glob("*.yaml")):
            item = _entry(path, False)
            if item:
                entries.append(item)
    return entries


def _backup(path: Path) -> Path | None:
    if not path.exists():
        return None
    history = path.parent / HISTORY_DIRNAME
    history.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    backup = history / f"{path.stem}.{stamp}.yaml"
    suffix = 1
    while backup.exists():
        backup = history / f"{path.stem}.{stamp}-{suffix}.yaml"
        suffix += 1
    backup.write_bytes(path.read_bytes())
    backups = sorted(history.glob(f"{path.stem}.*.yaml"))
    for old in backups[:-20]:
        try:
            old.unlink()
        except OSError:
            pass
    return backup


def save_definition(
    path: Path,
    definition: dict[str, Any],
    *,
    backup: bool = True,
) -> Path:
    """Validate and atomically write a pipeline definition."""
    normalized = normalize_definition(definition)
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if backup:
        _backup(path)
    payload = serialize_definition(normalized)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    tmp.write_text(
        yaml.safe_dump(payload, allow_unicode=True, sort_keys=False),
        encoding="utf-8",
    )
    os.replace(tmp, path)
    return path


def latest_backup(path: Path) -> Path | None:
    history = Path(path).parent / HISTORY_DIRNAME
    if not history.exists():
        return None
    backups = sorted(history.glob(f"{Path(path).stem}.*.yaml"))
    return backups[-1] if backups else None


def restore_backup(path: Path) -> Path | None:
    backup = latest_backup(path)
    if backup is None:
        return None
    _backup(Path(path))
    Path(path).write_bytes(backup.read_bytes())
    return backup


def stage_meta(definition: dict[str, Any]) -> list[dict[str, Any]]:
    """Compact stage list stored in ``task.json`` for status derivation."""
    definition = normalize_definition(definition)
    levels = compute_levels(definition)
    level_of = {
        stage_id: index + 1 for index, level in enumerate(levels) for stage_id in level
    }
    return [
        {
            "id": stage["id"],
            "label": stage["label"],
            "plugin": stage["plugin"],
            "level": level_of.get(stage["id"], stage["level"] or 0),
        }
        for stage in definition["stages"]
    ]


def dumps(definition: dict[str, Any]) -> str:
    return json.dumps(serialize_definition(definition), ensure_ascii=False, indent=2)


def clone(definition: dict[str, Any]) -> dict[str, Any]:
    return copy.deepcopy(normalize_definition(definition))
