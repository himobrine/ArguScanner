"""PipelineScheduler - DAG-based task scheduler for the scan pipeline."""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import networkx as nx
import yaml

from arguscaner.core.plugins.base_plugin import PluginRegistry, PluginSkipped
from arguscaner.scheduler.logger import ScanLogger
from arguscaner.scheduler import pipeline_io
from arguscaner.utils.target_classifier import TargetClassifier, TargetType


class TaskState(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    SKIPPED = "skipped"
    BLOCKED = "blocked"
    PARTIAL = "partial"


#: Marker states that mean "this stage does not need to run again".
MARKER_COMPLETE_STATES = frozenset({TaskState.DONE.value, TaskState.SKIPPED.value})
#: Marker states that mean "this stage did not produce trustworthy output".
MARKER_FAILURE_STATES = frozenset({
    TaskState.FAILED.value,
    TaskState.BLOCKED.value,
    TaskState.PARTIAL.value,
})


def write_stage_marker(marker_path: Path, state: str, **extra: Any) -> None:
    """Write a stage completion marker as JSON.

    Format: {"state": "done", "ts": 123.0, ...}. Legacy plain-text markers
    ("done"/"failed"/"skipped") are still readable via read_stage_marker().
    """
    payload: dict[str, Any] = {"state": state, "ts": time.time()}
    payload.update(extra)
    marker_path.write_text(
        json.dumps(payload, ensure_ascii=False), encoding="utf-8"
    )


def read_stage_marker(marker_path: Path) -> str | None:
    """Return the recorded state of a stage marker, or None if absent.

    Supports both the JSON marker format and legacy plain-text markers.
    """
    if not marker_path.exists():
        return None
    try:
        raw = marker_path.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    if not raw:
        return None
    if raw.startswith("{"):
        try:
            return json.loads(raw).get("state")
        except json.JSONDecodeError:
            return None
    return raw


@dataclass
class StageResult:
    stage: str
    state: TaskState
    output_file: Path | None = None
    record_count: int = 0
    duration: float = 0.0
    error: str | None = None
    skip_reason: str | None = None


@dataclass
class ScanResult:
    task_id: str
    target: str
    target_type: str = ""
    stages: dict[str, StageResult] = field(default_factory=dict)
    started_at: float = 0.0
    finished_at: float = 0.0
    total_duration: float = 0.0
    interrupted_count: int = 0
    failed_stages: list[str] = field(default_factory=list)
    recursive_rounds: list[dict[str, Any]] = field(default_factory=list)


class PipelineScheduler:
    """DAG-based pipeline scheduler.

    Loads pipeline definition from YAML, validates the DAG,
    and executes stages in topological order with intra-stage parallelism.

    Stages are gated by:
    - plugin 'enabled' state (from settings)
    - plugin supported target types
    - per-stage 'when' conditions from pipeline.yaml
    - input requirements (depends_on stages must have produced data)
    """

    def __init__(self, pipeline_yaml: Path, settings: dict[str, Any]):
        self.settings = settings
        self.pipeline_yaml = Path(pipeline_yaml)
        self.definition = pipeline_io.load_definition(self.pipeline_yaml)
        self.dag = self._load_dag(self.definition)
        self.concurrency = settings.get("defaults", {}).get("concurrency", 100)
        self.timeout = settings.get("defaults", {}).get("timeout", 300)
        self.registry = PluginRegistry(settings)
        self._plugin_usage: dict[str, int] = {}
        for node in self.dag.nodes:
            plugin = self.dag.nodes[node].get("plugin", "")
            self._plugin_usage[plugin] = self._plugin_usage.get(plugin, 0) + 1

    def _load_dag(self, definition: dict[str, Any]) -> nx.DiGraph:
        """Load pipeline definition from YAML and build DAG.

        ``depends_on`` edges gate execution (a dependency that failed blocks
        the stage). ``after`` edges only order execution; they are useful for
        stages that can still work with partial/absent input (e.g. probing
        HTTP after subdomain enumeration, even if enumeration failed).
        Declared ``inputs`` also imply ordering but do not gate execution.
        """
        stages = definition.get("stages", [])
        G = nx.DiGraph()
        stage_names = {stage["id"] for stage in stages}

        for stage in stages:
            G.add_node(
                stage["id"],
                plugin=stage["plugin"],
                label=stage.get("label") or stage["id"],
                level=stage.get("level"),
                order=stage.get("order", 0),
                depends_on=stage.get("depends_on", []),
                after=stage.get("after", []),
                inputs=stage.get("inputs", []),
                outputs=stage.get("outputs", {}),
                params=stage.get("params", {}),
                description=stage.get("description", ""),
                when=stage.get("when", {}),
            )

        for stage in stages:
            for dep in stage.get("depends_on", []):
                G.add_edge(dep, stage["id"])
            for dep in stage.get("after", []):
                if dep in stage_names:
                    G.add_edge(dep, stage["id"])
            for entry in stage.get("inputs", []):
                dep = entry.get("from")
                if dep in stage_names and not G.has_edge(dep, stage["id"]):
                    G.add_edge(dep, stage["id"])

        return G

    def validate(self) -> bool:
        """Validate the DAG has no cycles."""
        if not nx.is_directed_acyclic_graph(self.dag):
            cycle = list(nx.find_cycle(self.dag))
            cycle_str = " -> ".join(f"{u}" for u, _ in cycle)
            raise ValueError(f"检测到依赖循环：{cycle_str}")
        return True

    def get_execution_levels(self) -> list[list[str]]:
        """Group stages into levels that can run in parallel."""
        return pipeline_io.compute_levels(self.definition)

    def get_pipeline_definition(self) -> list[dict[str, Any]]:
        """Return the pipeline definition for display in UI/CLI."""
        stages = []
        for node in nx.topological_sort(self.dag):
            data = self.dag.nodes[node]
            plugin = self.registry.get(data["plugin"])
            stages.append({
                "name": node,
                "id": node,
                "label": data.get("label", node),
                "plugin": data["plugin"],
                "description": data.get("description", plugin.description),
                "level": data.get("level"),
                "depends_on": data.get("depends_on", []),
                "after": data.get("after", []),
                "inputs": data.get("inputs", []),
                "outputs": data.get("outputs", {}),
                "params": data.get("params", {}),
                "when": data.get("when", {}),
                "plugin_info": plugin.info,
                "conditions_met_for": [
                    t.value for t in plugin.supported_target_types
                ] or ["all"],
            })
        return stages

    def get_pipeline_graph(self) -> dict[str, Any]:
        """Return nodes/edges for the tree view."""
        graph = pipeline_io.build_graph(self.definition)
        plugins = {}
        for stage in graph["nodes"]:
            if stage["kind"] == "stage" and stage["plugin"] not in plugins:
                try:
                    plugins[stage["plugin"]] = self.registry.get(stage["plugin"]).info
                except ValueError:
                    plugins[stage["plugin"]] = {}
        graph["plugins"] = plugins
        return graph

    def run(
        self,
        target: str,
        workdir: Path,
        task_id: str,
        recursive: bool | None = None,
        save_meta: bool = True,
    ) -> ScanResult:
        """Execute the full scan pipeline.

        Args:
            target: Scan target.
            workdir: Working directory for this task.
            task_id: Unique task identifier.
            recursive: Force recursion on/off. ``None`` uses
                ``settings.recursive.enabled``.
            save_meta: Write task.json. Disabled for recursive round
                directories so ``find_task_root`` still resolves to the task.

        Returns:
            ScanResult with all stage results.
        """
        self.validate()
        workdir.mkdir(parents=True, exist_ok=True)

        target_type = self._classify_target(target)
        if save_meta:
            self._save_task_meta(task_id, target, target_type, workdir)

        logger = ScanLogger(workdir, task_id)
        result = ScanResult(
            task_id=task_id,
            target=target,
            target_type=target_type,
            started_at=time.time(),
        )

        levels = self.get_execution_levels()

        for level in levels:
            stage_results = asyncio.run(
                self._execute_level(level, target, target_type, workdir, task_id, logger)
            )
            result.stages.update(stage_results)

            for stage_name, sr in stage_results.items():
                if sr.state == TaskState.FAILED:
                    result.failed_stages.append(stage_name)

        recursive_enabled = (
            recursive
            if recursive is not None
            else bool(self.settings.get("recursive", {}).get("enabled", False))
        )
        if recursive_enabled:
            from arguscaner.scheduler.recursion import RecursiveScanner

            scanner = RecursiveScanner(
                workdir, target, target_type, task_id, self.settings
            )
            rounds = scanner.run(logger=logger)
            result.recursive_rounds = rounds
            for round_info in rounds:
                prefix = f"r{round_info.get('round', 0)}:"
                for stage_name, sr in round_info.get("stage_results", {}).items():
                    result.stages[prefix + stage_name] = sr
                    if sr.state == TaskState.FAILED:
                        result.failed_stages.append(prefix + stage_name)

        result.finished_at = time.time()
        result.total_duration = result.finished_at - result.started_at
        result.interrupted_count = len(result.failed_stages)

        logger.log_task_complete(result)
        return result

    def _classify_target(self, target: str) -> str:
        """Classify the target type, defaulting to 'unknown' on error."""
        try:
            return TargetClassifier.classify(target).value
        except ValueError:
            return "unknown"

    def _save_task_meta(
        self, task_id: str, target: str, target_type: str, workdir: Path
    ) -> None:
        """Save task metadata (incl. original target) for resume recovery."""
        meta = {
            "task_id": task_id,
            "target": target,
            "target_type": target_type,
            "started_at": time.time(),
            "pipeline": pipeline_io.pipeline_key(self.pipeline_yaml),
            "pipeline_file": str(self.pipeline_yaml),
            "pipeline_stages": pipeline_io.stage_meta(self.definition),
        }
        with open(workdir / "task.json", "w", encoding="utf-8") as f:
            json.dump(meta, f, ensure_ascii=False, indent=2)

    async def _execute_level(
        self,
        level: list[str],
        target: str,
        target_type: str,
        workdir: Path,
        task_id: str,
        logger: ScanLogger,
    ) -> dict[str, StageResult]:
        """Execute all stages in a level concurrently."""
        semaphore = asyncio.Semaphore(self.concurrency)

        async def run_stage(stage_name: str) -> tuple[str, StageResult]:
            async with semaphore:
                return await self._execute_stage(stage_name, target, target_type, workdir, task_id, logger)

        tasks = [run_stage(name) for name in level]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Batch-log stage_end for failed stages (done stages log immediately)
        for item in results:
            if isinstance(item, StageResult) and item.state == TaskState.FAILED:
                logger.log_stage_end(
                    item.stage, "failed", item.duration or 0, error=item.error
                )

        stage_results = {}
        for item in results:
            if isinstance(item, Exception):
                # Preserve failed stage info instead of silently dropping
                stage_results[f"error_{len(stage_results)}"] = StageResult(
                    stage="unknown",
                    state=TaskState.FAILED,
                    error=str(item),
                )
            else:
                name, sr = item
                stage_results[name] = sr
        return stage_results

    def _stage_settings(self, plugin_name: str, params: dict[str, Any]) -> dict[str, Any]:
        """Merge per-stage ``params`` into the plugin settings section."""
        if not params:
            return self.settings
        import copy

        merged = copy.deepcopy(self.settings)
        plugins_cfg = merged.setdefault("plugins", {})
        entry = plugins_cfg.get(plugin_name)
        if not isinstance(entry, dict):
            entry = {}
        entry.update(params)
        plugins_cfg[plugin_name] = entry
        return merged

    def _spawn_plugin(self, plugin_name: str, params: dict[str, Any]):
        """Create an isolated plugin instance for a stage."""
        settings = self._stage_settings(plugin_name, params)
        return self.registry.spawn(plugin_name, settings)

    @staticmethod
    def _stage_input_files(node_data: dict[str, Any], workdir: Path) -> list[Path]:
        """Resolve declared inputs to concrete JSONL files."""
        files: list[Path] = []
        seen: set[str] = set()
        for entry in node_data.get("inputs") or []:
            source = str(entry.get("from") or "")
            if not source or source == "target":
                continue
            name = "round_targets.jsonl" if source == "round_targets" else f"{source}.jsonl"
            if name in seen:
                continue
            seen.add(name)
            files.append(workdir / name)
        return files

    async def _execute_stage(
        self,
        stage_name: str,
        target: str,
        target_type: str,
        workdir: Path,
        task_id: str,
        logger: ScanLogger,
    ) -> tuple[str, StageResult]:
        """Execute a single pipeline stage with condition gating."""
        node_data = self.dag.nodes[stage_name]
        plugin_name = node_data["plugin"]
        plugin = self._spawn_plugin(plugin_name, node_data.get("params") or {})
        scoped = self._plugin_usage.get(plugin_name, 1) > 1
        plugin.bind_stage(
            stage_name,
            input_files=self._stage_input_files(node_data, workdir),
            scoped=scoped,
        )

        done_marker = workdir / f".{stage_name}.done"
        marker_state = read_stage_marker(done_marker)
        if marker_state in MARKER_COMPLETE_STATES:
            logger.log_stage_skip(stage_name)
            return stage_name, StageResult(
                stage=stage_name,
                state=TaskState.SKIPPED,
                skip_reason="已完成",
            )
        if marker_state in MARKER_FAILURE_STATES:
            # A previous run failed/blocked: invalidate the marker and retry.
            try:
                done_marker.unlink()
            except OSError:
                pass

        # Check plugin conditions (enabled, target type support, built-in conditions)
        context = {"target_type": target_type, "target": target}
        meets, reason = plugin.check_conditions(context)
        if not meets:
            logger.log_stage_skip(stage_name, reason=reason)
            write_stage_marker(done_marker, TaskState.SKIPPED.value, reason=reason)
            return stage_name, StageResult(
                stage=stage_name,
                state=TaskState.SKIPPED,
                skip_reason=reason,
            )

        # Check per-stage 'when' conditions
        when = node_data.get("when", {})
        from_meta = self._check_when_conditions(when, target_type)
        if not from_meta["meets"]:
            logger.log_stage_skip(stage_name, reason=from_meta["reason"])
            write_stage_marker(done_marker, TaskState.SKIPPED.value, reason=from_meta["reason"])
            return stage_name, StageResult(
                stage=stage_name,
                state=TaskState.SKIPPED,
                skip_reason=from_meta["reason"],
            )

        # Check input requirements: a dependency must have completed successfully
        # (done/skipped). A failed/blocked/partial or missing dependency means
        # this stage would run against empty input, so mark it BLOCKED instead.
        for dep in node_data.get("depends_on", []):
            dep_state = read_stage_marker(workdir / f".{dep}.done")
            if dep_state not in MARKER_COMPLETE_STATES:
                reason = (
                    f"依赖 '{dep}' 未成功完成"
                    f"（状态：{dep_state or '缺失'}），跳过以避免空输入"
                )
                logger.log_stage_skip(stage_name, reason=reason)
                write_stage_marker(
                    done_marker,
                    TaskState.BLOCKED.value,
                    reason=reason,
                    blocked_by=dep,
                )
                return stage_name, StageResult(
                    stage=stage_name,
                    state=TaskState.BLOCKED,
                    skip_reason=reason,
                )

        logger.log_stage_start(stage_name)
        start_time = time.time()

        max_attempts = self.settings.get("retry", {}).get("max_attempts", 1)
        backoff_seconds = self.settings.get("retry", {}).get("backoff_seconds", 30)

        last_error: Exception | None = None
        for attempt in range(1, max_attempts + 1):
            try:
                output_file = await asyncio.to_thread(
                    plugin.execute, target, workdir
                )
                records = await asyncio.to_thread(plugin.parse_output, output_file)

                parsed_jsonl = workdir / f"{stage_name}.jsonl"
                with open(parsed_jsonl, "w", encoding="utf-8") as pf:
                    for rec in records:
                        pf.write(json.dumps(rec, ensure_ascii=False) + "\n")

                duration = time.time() - start_time

                write_stage_marker(
                    done_marker,
                    TaskState.DONE.value,
                    record_count=len(records),
                    duration=round(duration, 3),
                )
                logger.log_stage_end(stage_name, "done", duration, len(records))

                return stage_name, StageResult(
                    stage=stage_name,
                    state=TaskState.DONE,
                    output_file=output_file,
                    record_count=len(records),
                    duration=duration,
                )
            except PluginSkipped as e:
                # An intentional skip is not a failure: downstream stages may
                # still run and the marker records why nothing was produced.
                duration = time.time() - start_time
                reason = str(e) or "插件主动跳过"
                write_stage_marker(
                    done_marker,
                    TaskState.SKIPPED.value,
                    reason=reason,
                    duration=round(duration, 3),
                )
                logger.log_stage_skip(stage_name, reason=reason)
                return stage_name, StageResult(
                    stage=stage_name,
                    state=TaskState.SKIPPED,
                    duration=duration,
                    skip_reason=reason,
                )
            except Exception as e:
                last_error = e
                if attempt < max_attempts and self._should_retry(e):
                    await asyncio.sleep(backoff_seconds)
                else:
                    break

        duration = time.time() - start_time
        exit_code = getattr(last_error, "returncode", None)
        write_stage_marker(
            done_marker,
            TaskState.FAILED.value,
            error=str(last_error),
            exit_code=exit_code,
            duration=round(duration, 3),
        )
        # Defer stage_end failed log to _execute_level (after all parallel stages finish)
        return stage_name, StageResult(
            stage=stage_name,
            state=TaskState.FAILED,
            duration=duration,
            error=str(last_error),
        )

    def _should_retry(self, exc: Exception) -> bool:
        """Decide whether a failed attempt is worth retrying.

        Uses the configured exit-code policy. Errors without an exit code
        (timeouts, parse errors, plugin bugs) are retried by default.
        """
        rc = getattr(exc, "returncode", None)
        retry_cfg = self.settings.get("retry", {})
        if rc is None:
            return True
        if rc in retry_cfg.get("non_retryable_exit_codes", []):
            return False
        retryable = retry_cfg.get("retryable_exit_codes")
        if retryable:
            return rc in retryable
        return True

    def _check_when_conditions(self, when: dict, target_type: str) -> dict[str, Any]:
        """Evaluate per-stage 'when' conditions from pipeline.yaml.

        Supports: target_type (eq), enabled (bool).
        """
        if not when:
            return {"meets": True, "reason": ""}

        if "target_type" in when:
            expected = when["target_type"]
            if isinstance(expected, list):
                meets = target_type in expected
            else:
                meets = target_type == expected
            if not meets:
                return {
                    "meets": False,
                    "reason": f"条件要求目标类型为 {expected}，实际为 {target_type}",
                }

        if when.get("enabled") is False:
            return {"meets": False, "reason": "阶段已在流程中显式禁用"}

        return {"meets": True, "reason": ""}

    @staticmethod
    def load_task_meta(workdir: Path) -> dict[str, Any] | None:
        """Load task metadata from task.json for resume."""
        meta_file = workdir / "task.json"
        if not meta_file.exists():
            return None
        with open(meta_file, "r", encoding="utf-8") as f:
            return json.load(f)

    def resume(self, task_id: str, workdir: Path, target: str = "") -> ScanResult:
        """Resume an interrupted scan.

        Recovers the original target from task.json if not provided.
        Skips stages that already have .done markers.
        """
        meta = self.load_task_meta(workdir)
        if target:
            resume_target = target
        elif meta and meta.get("target"):
            resume_target = meta["target"]
            workdir = workdir  # same workdir
        else:
            raise ValueError(
                "无法恢复：未提供目标且无 task.json 元数据"
            )

        return self.run(resume_target, workdir, task_id)


def load_settings(settings_yaml: Path) -> dict[str, Any]:
    """Load settings from YAML file."""
    with open(settings_yaml, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def generate_task_id() -> str:
    """Generate a task ID in format hv-YYYY-MM-DD-NNN."""
    import datetime

    now = datetime.datetime.now()
    date_str = now.strftime("%Y-%m-%d")
    counter_file = Path("logs") / f"counter_{date_str}.json"

    counter = 1
    if counter_file.exists():
        with open(counter_file, "r") as f:
            data = json.load(f)
            counter = data.get("counter", 0) + 1

    counter_file.parent.mkdir(parents=True, exist_ok=True)
    with open(counter_file, "w") as f:
        json.dump({"counter": counter}, f)

    return f"hv-{date_str}-{counter:03d}"
