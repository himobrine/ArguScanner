"""Flask routes for ArguScanner Web UI."""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path

import yaml
from flask import Blueprint, jsonify, render_template, request, send_file

main_bp = Blueprint("main", __name__)
api_bp = Blueprint("api", __name__)


@api_bp.before_request
def _require_api_token():
    """Require X-API-Token on mutating requests when ARGUS_API_TOKEN is set.

    Opt-in: if the environment variable is unset, behaviour is unchanged
    (suitable for local development bound to 127.0.0.1).
    """
    token = os.environ.get("ARGUS_API_TOKEN", "")
    if not token:
        return None
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return None
    if request.headers.get("X-API-Token", "") != token:
        return jsonify({"error": "未授权：缺少或错误的 X-API-Token"}), 401
    return None

CONFIGS_DIR = Path(__file__).parent.parent / "configs"
WORKSPACE = Path(__file__).parent.parent.parent / "workspace"
CUSTOM_PIPELINES_DIR = CONFIGS_DIR / "pipelines"

# Stages in the default first-pass pipeline. Used to derive task status from
# stage markers when no in-memory/Celery state is available.
FIRST_PASS_STAGES = [
    "subdomain_enum",
    "http_probe",
    "port_scan",
    "js_url_extract",
    "urlfinder_extract",
    "api_probe",
]

# In-memory task tracking for threading fallback
_tasks: dict[str, dict] = {}
_tasks_lock = threading.Lock()


def _redis_available() -> bool:
    """Check if Redis is reachable (short timeout to avoid blocking)."""
    import socket
    try:
        s = socket.create_connection(("localhost", 6379), timeout=2)
        s.close()
        return True
    except (ConnectionRefusedError, OSError, socket.timeout):
        return False


def _load_settings() -> dict:
    with open(CONFIGS_DIR / "settings.yaml", "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def _save_settings(settings: dict) -> None:
    with open(CONFIGS_DIR / "settings.yaml", "w", encoding="utf-8") as f:
        yaml.safe_dump(settings, f, allow_unicode=True, sort_keys=False)


def _resolve_pipeline(name: str | None) -> Path:
    """Resolve a pipeline name to a YAML path."""
    from arguscaner.scheduler import pipeline_io

    return pipeline_io.resolve_pipeline(name)


def _plugin_names() -> set[str]:
    """Return the names of all currently registered plugins."""
    from arguscaner.core.plugins.base_plugin import PluginRegistry

    try:
        return set(PluginRegistry(_load_settings()).plugins)
    except Exception:  # pragma: no cover - defensive
        return set()


def _stage_state_map(workdir: Path) -> dict[str, str]:
    """Return {stage_name: state} for a task or round directory."""
    states: dict[str, str] = {}
    if not workdir.exists():
        return states
    try:
        from arguscaner.scheduler.scheduler_core import read_stage_marker
    except Exception:  # pragma: no cover - defensive
        return states
    for marker in workdir.glob(".*.done"):
        states[marker.name[1:-5]] = read_stage_marker(marker) or "unknown"
    return states


def _derive_status(
    stage_states: dict[str, str],
    expected_stages: list[str] | None = None,
) -> str:
    """Derive a task status from stage marker states.

    ``expected_stages`` comes from the task metadata (the pipeline that was
    actually executed).  Without it the historical first-pass list is used.
    """
    if not stage_states:
        return "pending"
    if any(state == "failed" for state in stage_states.values()):
        return "failed"
    expected = expected_stages or FIRST_PASS_STAGES
    if all(stage in stage_states for stage in expected):
        return "done"
    return "running"


def _expected_stages(meta: dict) -> list[str]:
    """Return the stage ids recorded in ``task.json`` (pipeline metadata)."""
    stages = meta.get("pipeline_stages")
    if isinstance(stages, list):
        ids = [
            str(stage.get("id"))
            for stage in stages
            if isinstance(stage, dict) and stage.get("id")
        ]
        if ids:
            return ids
    return list(FIRST_PASS_STAGES)


def _pipeline_meta(meta: dict) -> dict:
    """Extract pipeline-related fields from task metadata."""
    return {
        "pipeline": meta.get("pipeline", ""),
        "pipeline_file": meta.get("pipeline_file", ""),
        "pipeline_stages": meta.get("pipeline_stages", []),
    }


def _recursive_progress(workdir: Path) -> list[dict]:
    """Summarize recursive round directories for the status API."""
    rounds_dir = workdir / "rounds"
    if not rounds_dir.exists():
        return []
    expected_count = len(FIRST_PASS_STAGES)
    task_json = workdir / "task.json"
    if task_json.exists():
        try:
            meta = json.loads(task_json.read_text(encoding="utf-8"))
            stages = meta.get("pipeline_stages")
            if isinstance(stages, list) and stages:
                expected_count = len(stages)
        except (json.JSONDecodeError, OSError):
            pass
    progress: list[dict] = []
    for round_dir in sorted(rounds_dir.glob("r*")):
        if not round_dir.is_dir():
            continue
        stage_states = _stage_state_map(round_dir)
        targets = 0
        targets_file = round_dir / "round_targets.jsonl"
        if targets_file.exists():
            try:
                targets = sum(
                    1 for line in targets_file.read_text(
                        encoding="utf-8"
                    ).splitlines() if line.strip()
                )
            except OSError:
                targets = 0
        progress.append({
            "round": round_dir.name,
            "targets": targets,
            "stages_done": sorted(stage_states),
            "stage_states": stage_states,
            "running": bool(stage_states) and len(stage_states) < expected_count,
            "finished": len(stage_states) >= expected_count,
        })
    return progress


def _is_recursive_requested(value: object) -> bool | None:
    """Normalize the optional recursive flag from an API request."""
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "on")
    return bool(value)


# ---------------------------------------------------------------------------
# Main pages
# ---------------------------------------------------------------------------

@main_bp.route("/")
def index():
    """Home page - start a new scan."""
    return render_template("index.html")


@main_bp.route("/plugins")
def plugins_page():
    """Plugins management page."""
    settings = _load_settings()
    from arguscaner.core.plugins.base_plugin import PluginRegistry
    from arguscaner.utils.tool_paths import tools_by_plugin

    registry = PluginRegistry(settings)
    plugins = registry.list()
    return render_template(
        "plugins.html",
        plugins=plugins,
        tools_by_plugin=tools_by_plugin(settings),
    )


@main_bp.route("/pipeline")
def pipeline_page():
    """Pipeline view/editor page (``?name=`` selects a pipeline)."""
    from arguscaner.scheduler import pipeline_io

    settings = _load_settings()
    from arguscaner.scheduler.scheduler_core import PipelineScheduler

    name = request.args.get("name") or None
    path = pipeline_io.resolve_pipeline(name)
    scheduler = PipelineScheduler(path, settings)
    definition = pipeline_io.serialize_definition(scheduler.definition)
    stages = scheduler.get_pipeline_definition()
    levels = scheduler.get_execution_levels()
    stage_map = {stage["name"]: stage for stage in stages}
    graph = scheduler.get_pipeline_graph()
    return render_template(
        "pipeline.html",
        stages=stages,
        levels=levels,
        stage_map=stage_map,
        definition=definition,
        graph=graph,
        pipeline_name=pipeline_io.pipeline_key(path),
        pipeline_file=str(path),
        pipelines=pipeline_io.list_pipelines(),
        plugin_names=_plugin_names(),
    )


@main_bp.route("/settings")
def settings_page():
    """Settings management page."""
    from arguscaner.utils.tool_paths import describe_tools
    from arguscaner.web.settings_schema import schema_payload

    settings = _load_settings()
    return render_template(
        "settings.html",
        settings=settings,
        settings_schema=schema_payload(),
        tools=describe_tools(settings),
        settings_order={
            "sections": list(settings.keys()),
            "plugins": list((settings.get("plugins") or {}).keys()),
        },
    )


@main_bp.route("/proxy")
def proxy_page():
    """Proxy pool management page."""
    settings = _load_settings()
    sources = settings.get("waf_aware", {}).get("recovery", {}).get("proxy_pool", {}).get("sources", [])
    return render_template("proxy.html", sources=sources)


@main_bp.route("/batch")
def batch_page():
    """Batch scan results page."""
    return render_template("batch_results.html")


@main_bp.route("/status/<task_id>")
def status_page(task_id: str):
    """Task status page with live progress."""
    return render_template("status.html", task_id=task_id)


@main_bp.route("/results/<task_id>")
def results_page(task_id: str):
    """Results view page."""
    records = {}
    workdir = WORKSPACE / task_id
    if workdir.exists():
        from arguscaner.core.dedup import DeduplicationEngine
        dedup = DeduplicationEngine(workdir)
        records = dedup.deduplicate_all(workdir)
    return render_template("results.html", task_id=task_id, task={}, records=records)


@main_bp.route("/results/<task_id>/export")
def results_export(task_id: str):
    """Export scan results as Excel file."""
    workdir = WORKSPACE / task_id
    if not workdir.exists():
        return jsonify({"error": "任务不存在"}), 404

    from arguscaner.core.dedup import DeduplicationEngine
    from arguscaner.core.report_generator import ReportGenerator
    from arguscaner.scheduler.scheduler_core import TaskState, read_stage_marker
    from types import SimpleNamespace

    dedup = DeduplicationEngine(workdir)
    all_records = dedup.deduplicate_all(workdir)

    # Read task metadata
    task_meta = {}
    task_json = workdir / "task.json"
    if task_json.exists():
        import json as _json
        task_meta = _json.loads(task_json.read_text(encoding="utf-8"))

    # Read stage results from .done markers
    stages = {}
    failed_stages = []
    for marker in workdir.glob(".*.done"):
        stage_name = marker.name.lstrip(".")
        marker_state = read_stage_marker(marker)
        if marker_state == TaskState.DONE.value:
            state = TaskState.DONE
        elif marker_state == TaskState.SKIPPED.value:
            state = TaskState.SKIPPED
        else:
            state = TaskState.FAILED
        sr = SimpleNamespace(stage=stage_name, state=state, duration=0, error=None, record_count=0, output_file=None)
        stages[stage_name] = sr
        if state == TaskState.FAILED:
            failed_stages.append(stage_name)

    import time as _time
    scan_result = SimpleNamespace(
        task_id=task_id,
        target=task_meta.get("target", ""),
        target_type=task_meta.get("target_type", ""),
        stages=stages,
        started_at=task_meta.get("started_at", 0),
        finished_at=_time.time(),
        total_duration=_time.time() - task_meta.get("started_at", _time.time()),
        interrupted_count=len(failed_stages),
        failed_stages=failed_stages,
    )

    settings_path = CONFIGS_DIR / "settings.yaml"
    settings = {}
    if settings_path.exists():
        import yaml as _yaml
        settings = _yaml.safe_load(settings_path.read_text(encoding="utf-8")) or {}

    report_gen = ReportGenerator(workdir, task_id, settings)
    report_path = report_gen.generate(scan_result, all_records)

    return send_file(
        report_path,
        as_attachment=True,
        download_name=f"report_{task_id}.xlsx",
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )


@main_bp.route("/history")
def history_page():
    """Scan history page."""
    return render_template("history.html")


# ---------------------------------------------------------------------------
# API endpoints
# ---------------------------------------------------------------------------

def _try_celery_or_thread(func, *args, **kwargs):
    """Try to submit to Celery; fall back to threading if Redis is unavailable."""
    try:
        return func(*args, **kwargs), "celery"
    except Exception:
        # Celery broker unavailable, run in thread directly
        return None, "thread"


def _run_scan_in_thread(
    task_id: str,
    target: str,
    pipeline_name: str | None,
    recursive: bool | None = None,
):
    """Execute scan in a background thread (fallback when Celery is unavailable)."""
    from arguscaner.scheduler.scheduler_core import PipelineScheduler, load_settings

    settings = load_settings(CONFIGS_DIR / "settings.yaml")
    workdir = WORKSPACE / task_id
    workdir.mkdir(parents=True, exist_ok=True)

    from arguscaner.scheduler import pipeline_io

    pipeline_file = pipeline_io.resolve_pipeline(pipeline_name)

    with _tasks_lock:
        _tasks[task_id] = {
            "task_id": task_id,
            "target": target,
            "status": "running",
            "workdir": str(workdir),
            "recursive": recursive,
        }

    try:
        scheduler = PipelineScheduler(pipeline_file, settings)
        result = scheduler.run(
            target, workdir, task_id, recursive=recursive
        )
        with _tasks_lock:
            _tasks[task_id]["status"] = "done"
            _tasks[task_id]["result"] = {
                "total_duration": result.total_duration,
                "failed_stages": result.failed_stages,
                "recursive_rounds": len(result.recursive_rounds),
            }
    except Exception as e:
        with _tasks_lock:
            _tasks[task_id]["status"] = "failed"
            _tasks[task_id]["error"] = str(e)


@api_bp.route("/scan", methods=["POST"])
def create_scan():
    """Create and start a new scan task."""
    from arguscaner.scheduler.scheduler_core import generate_task_id
    from arguscaner.utils.target_classifier import TargetClassifier

    data = request.get_json() or {}
    target = data.get("target", "")
    if not target:
        return jsonify({"error": "目标不能为空"}), 400

    try:
        target_type = TargetClassifier.classify(target).value
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    task_id = generate_task_id()
    pipeline_name = data.get("pipeline")
    recursive = _is_recursive_requested(data.get("recursive"))

    # Try Celery first, fall back to threading
    if _redis_available():
        try:
            from arguscaner.web.tasks import run_single_scan
            run_single_scan.delay(task_id, target, pipeline_name, recursive)
            return jsonify({"task_id": task_id, "status": "started"})
        except Exception:
            pass

    # Celery unavailable, use threading
    thread = threading.Thread(
        target=_run_scan_in_thread,
        args=(task_id, target, pipeline_name, recursive),
        daemon=True,
    )
    thread.start()
    return jsonify({"task_id": task_id, "status": "started"})


@api_bp.route("/scan/batch", methods=["POST"])
def create_batch_scan():
    """Create multiple scan tasks."""
    from arguscaner.scheduler.scheduler_core import generate_task_id
    from arguscaner.utils.target_classifier import TargetClassifier

    data = request.get_json() or {}
    raw = data.get("targets", "")
    if not raw:
        return jsonify({"error": "目标不能为空"}), 400

    targets = TargetClassifier.parse_targets(raw)
    if not targets:
        return jsonify({"error": "目标不能为空"}), 400

    pipeline_name = data.get("pipeline")
    recursive = _is_recursive_requested(data.get("recursive"))
    task_ids = []
    errors = []

    # Try Celery first
    if _redis_available():
        try:
            from arguscaner.web.tasks import run_batch_scan
            result = run_batch_scan.delay(raw, pipeline_name, recursive)
            return jsonify({"celery_task_id": result.id, "status": "batch_started", "target_count": len(targets)})
        except Exception:
            pass

    # Fallback: spawn threads for each target
    for target in targets:
        try:
            TargetClassifier.classify(target)
        except ValueError as e:
            errors.append({"target": target, "error": str(e)})
            continue

        task_id = generate_task_id()
        thread = threading.Thread(
            target=_run_scan_in_thread,
            args=(task_id, target, pipeline_name, recursive),
            daemon=True,
        )
        thread.start()
        task_ids.append({"task_id": task_id, "target": target, "status": "started"})

    return jsonify({"tasks": task_ids, "errors": errors})


@api_bp.route("/status/<task_id>")
def api_status(task_id: str):
    """Get task status as JSON."""

    def _read_nmap_progress(wd: Path) -> dict | None:
        pf = wd / "nmap_progress.json"
        if not pf.exists():
            # Duplicate nmap stages write stage-scoped progress files.
            scoped = sorted(wd.glob("nmap_progress__*.json"))
            if not scoped:
                return None
            pf = scoped[0]
        try:
            return json.loads(pf.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None

    def _read_task_meta(wd: Path) -> dict:
        task_json = wd / "task.json"
        if task_json.exists():
            try:
                return json.loads(task_json.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                pass
        return {}

    def _with_recursive(resp: dict, wd: Path) -> dict:
        meta = _read_task_meta(wd)
        if meta.get("target") and not resp.get("target"):
            resp["target"] = meta["target"]
        if meta.get("target_type") and not resp.get("target_type"):
            resp["target_type"] = meta["target_type"]
        if meta.get("started_at") and not resp.get("started_at"):
            resp["started_at"] = meta["started_at"]
        pipeline_info = _pipeline_meta(meta)
        if meta.get("pipeline") or meta.get("pipeline_stages"):
            resp.update(pipeline_info)
        stage_states = _stage_state_map(wd)
        if stage_states:
            resp["stage_states"] = stage_states
            expected = _expected_stages(meta)
            resp["expected_stages"] = expected
            if resp.get("status") != "failed":
                resp["status"] = _derive_status(stage_states, expected)
            failed = sorted(
                name for name, state in stage_states.items() if state == "failed"
            )
            if failed:
                resp["failed_stages"] = failed
                resp["status"] = "failed"
        rounds = _recursive_progress(wd)
        if rounds:
            resp["recursive_rounds"] = rounds
            resp["recursive_enabled"] = True
        return resp

    # Check in-memory tasks (threading fallback)
    with _tasks_lock:
        task = _tasks.get(task_id)
    if task:
        workdir = Path(task.get("workdir", ""))
        stage_states = _stage_state_map(workdir)
        resp = {
            "task_id": task_id,
            "target": task.get("target", ""),
            "status": task.get("status", "unknown"),
            "stages_done": sorted(stage_states),
            "stage_states": stage_states,
        }
        nmap_progress = _read_nmap_progress(workdir)
        if nmap_progress:
            resp["nmap_progress"] = nmap_progress
        return jsonify(_with_recursive(resp, workdir))

    # Check Celery task status
    try:
        from arguscaner.celery_app import celery_app
        result = celery_app.AsyncResult(task_id)

        if result.state in ("PENDING", "UNKNOWN"):
            workdir = WORKSPACE / task_id
            if workdir.exists():
                done_markers = list(workdir.glob(".*.done"))
                if done_markers:
                    from arguscaner.scheduler.logger import ScanLogger
                    logger = ScanLogger(workdir, task_id)
                    logs = logger.get_logs()
                    stage_states = _stage_state_map(workdir)
                    resp = {
                        "task_id": task_id,
                        "status": _derive_status(stage_states),
                        "stages_done": sorted(stage_states),
                        "log_count": len(logs),
                    }
                    nmap_progress = _read_nmap_progress(workdir)
                    if nmap_progress:
                        resp["nmap_progress"] = nmap_progress
                    return jsonify(_with_recursive(resp, workdir))
            resp = {"task_id": task_id, "status": "pending"}
            nmap_progress = _read_nmap_progress(workdir)
            if nmap_progress:
                resp["nmap_progress"] = nmap_progress
            return jsonify(_with_recursive(resp, workdir))
        elif result.state == "STARTED":
            resp = {"task_id": task_id, "status": "running"}
            nmap_progress = _read_nmap_progress(WORKSPACE / task_id)
            if nmap_progress:
                resp["nmap_progress"] = nmap_progress
            return jsonify(_with_recursive(resp, WORKSPACE / task_id))
        elif result.state == "SUCCESS":
            resp = {"task_id": task_id, "status": "done", "result": result.result}
            return jsonify(_with_recursive(resp, WORKSPACE / task_id))
        elif result.state == "FAILURE":
            resp = {"task_id": task_id, "status": "failed", "error": str(result.info)}
            return jsonify(_with_recursive(resp, WORKSPACE / task_id))
        else:
            return jsonify({"task_id": task_id, "status": result.state})
    except Exception:
        pass

    # Fallback: check workdir for done markers
    workdir = WORKSPACE / task_id
    if workdir.exists():
        done_markers = list(workdir.glob(".*.done"))
        if done_markers:
            stage_states = _stage_state_map(workdir)
            resp = {
                "task_id": task_id,
                "status": _derive_status(stage_states),
                "stages_done": sorted(stage_states),
            }
            nmap_progress = _read_nmap_progress(workdir)
            if nmap_progress:
                resp["nmap_progress"] = nmap_progress
            return jsonify(_with_recursive(resp, workdir))
        task_meta = _read_task_meta(workdir)
        if task_meta:
            return jsonify(_with_recursive(
                {"task_id": task_id, "status": "pending"}, workdir
            ))
    return jsonify({"task_id": task_id, "status": "unknown"})


@api_bp.route("/logs/<task_id>")
def api_logs(task_id: str):
    """Get recent log entries as JSON."""
    workdir = WORKSPACE / task_id
    if not workdir.exists():
        return jsonify({"logs": []})

    from arguscaner.scheduler.logger import ScanLogger
    logger = ScanLogger(workdir, task_id)
    count = request.args.get("count", 50, type=int)
    logs = logger.get_recent_logs(count)
    return jsonify({"logs": logs})


@api_bp.route("/history")
def api_history():
    """List all scan tasks from workspace."""
    tasks = []
    if not WORKSPACE.exists():
        return jsonify(tasks)
    for task_dir in sorted(WORKSPACE.iterdir(), reverse=True):
        if not task_dir.is_dir():
            continue
        task_json = task_dir / "task.json"
        if not task_json.exists():
            continue
        try:
            meta = json.loads(task_json.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        stage_states = _stage_state_map(task_dir)
        stages_done = sorted(stage_states)
        failed_stages = sorted(
            name for name, state in stage_states.items() if state == "failed"
        )
        expected = _expected_stages(meta)
        status = _derive_status(stage_states, expected)
        rounds = _recursive_progress(task_dir)
        updated_at = meta.get("started_at", "")
        try:
            mtimes = [task_json.stat().st_mtime]
            mtimes.extend(m.stat().st_mtime for m in task_dir.glob(".*.done"))
            updated_at = max(mtimes)
        except OSError:
            pass
        entry = {
            "task_id": meta.get("task_id", task_dir.name),
            "target": meta.get("target", ""),
            "target_type": meta.get("target_type", ""),
            "started_at": meta.get("started_at", ""),
            "updated_at": updated_at,
            "status": status,
            "stages_done": stages_done,
            "stage_states": stage_states,
            "failed_stages": failed_stages,
            "recursive_rounds": len(rounds),
            "expected_stages": expected,
        }
        entry.update(_pipeline_meta(meta))
        tasks.append(entry)
    return jsonify(tasks)


# ---------------------------------------------------------------------------
# Management API
# ---------------------------------------------------------------------------

@api_bp.route("/plugins")
def api_plugins():
    """List plugins as JSON."""
    settings = _load_settings()
    from arguscaner.core.plugins.base_plugin import PluginRegistry
    registry = PluginRegistry(settings)
    return jsonify({"plugins": registry.list()})


@api_bp.route("/plugins", methods=["POST"])
def api_add_plugin():
    """添加自定义插件（YAML 声明式）。"""
    data = request.get_json() or {}
    name = data.get("name", "").strip()
    command = data.get("command_template", "").strip()
    if not name:
        return jsonify({"error": "名称不能为空"}), 400
    if not command:
        return jsonify({"error": "命令模板不能为空"}), 400

    settings = _load_settings()
    from arguscaner.core.plugins.base_plugin import PluginRegistry
    registry = PluginRegistry(settings)

    config = {
        "name": name,
        "description": data.get("description", f"自定义插件：{name}"),
        "version": data.get("version", "1.0.0"),
        "command_template": command,
        "output_filename": data.get("output_filename", f"{name}_output.jsonl"),
        "output_schema": data.get("output_schema", {}),
        "supported_target_types": data.get("supported_target_types", []),
        "input_requirements": data.get("input_requirements", []),
        "conditions": data.get("conditions", []),
        "enabled": data.get("enabled", True),
        "source": "custom",
    }

    try:
        plugin = registry.add_custom(config)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    return jsonify({"status": "ok", "plugin": plugin.info})


@api_bp.route("/plugins/<name>", methods=["DELETE"])
def api_remove_plugin(name: str):
    """删除自定义插件。"""
    settings = _load_settings()
    from arguscaner.core.plugins.base_plugin import PluginRegistry
    registry = PluginRegistry(settings)

    if not registry.is_custom(name):
        return jsonify({"error": f"'{name}' 不是自定义插件"}), 400

    try:
        registry.remove_custom(name)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    return jsonify({"status": "ok", "name": name})


@api_bp.route("/plugins/<name>/status", methods=["PUT"])
def api_plugin_status(name: str):
    """Enable/disable a plugin persistently (takes effect immediately)."""
    data = request.get_json() or {}
    enabled = bool(data.get("enabled"))
    settings = _load_settings()
    settings.setdefault("plugins", {}).setdefault(name, {})["enabled"] = enabled
    _save_settings(settings)
    return jsonify({"name": name, "enabled": enabled})


@api_bp.route("/settings")
def api_get_settings():
    """Return current settings as JSON."""
    return jsonify(_load_settings())


@api_bp.route("/settings", methods=["PUT"])
def api_set_settings():
    """Update settings (flattened keys) - applies immediately."""
    data = request.get_json() or {}
    settings = _load_settings()
    for key, value in data.items():
        cur = settings
        parts = key.split(".")
        for p in parts[:-1]:
            if p not in cur or not isinstance(cur[p], dict):
                cur[p] = {}
            cur = cur[p]
        cur[parts[-1]] = value
    _save_settings(settings)
    return jsonify({"status": "ok"})


@api_bp.route("/tools")
def api_tools():
    """Return resolved tool paths and their source."""
    from arguscaner.utils.tool_paths import describe_tools

    return jsonify({"tools": describe_tools(_load_settings())})


@api_bp.route("/tools/check", methods=["POST"])
def api_check_tool():
    """Validate a candidate tool path and (optionally) read its version."""
    from arguscaner.utils.tool_paths import check_candidate

    data = request.get_json() or {}
    path = str(data.get("path") or "").strip()
    key = str(data.get("key") or "").strip() or None
    if not path and key:
        from arguscaner.utils.tool_paths import resolve_tool

        resolution = resolve_tool(key, _load_settings())
        path = resolution.path
    if not path:
        return jsonify({"error": "路径不能为空", "exists": False}), 400

    result = check_candidate(path, key)
    result["ok"] = bool(result.get("exists"))
    return jsonify(result)


@api_bp.route("/proxy")
def api_get_proxies():
    """Return proxy pool as JSON."""
    settings = _load_settings()
    sources = settings.get("waf_aware", {}).get("recovery", {}).get("proxy_pool", {}).get("sources", [])
    return jsonify({"sources": sources})


@api_bp.route("/proxy", methods=["POST"])
def api_add_proxy():
    """Add a proxy URL."""
    data = request.get_json() or {}
    url = data.get("url", "")
    if not url:
        return jsonify({"error": "URL 不能为空"}), 400
    settings = _load_settings()
    pool = settings.setdefault("waf_aware", {}).setdefault("recovery", {}).setdefault("proxy_pool", {})
    sources = pool.setdefault("sources", [])
    if url in sources:
        return jsonify({"error": "已存在"}), 409
    sources.append(url)
    _save_settings(settings)
    return jsonify({"status": "ok", "sources": sources})


@api_bp.route("/proxy", methods=["DELETE"])
def api_remove_proxy():
    """Remove a proxy URL."""
    data = request.get_json() or {}
    url = data.get("url", "")
    settings = _load_settings()
    pool = settings.get("waf_aware", {}).get("recovery", {}).get("proxy_pool", {})
    sources = pool.get("sources", [])
    if url in sources:
        sources.remove(url)
        _save_settings(settings)
    return jsonify({"status": "ok", "sources": sources})


# ---------------------------------------------------------------------------
# Pipeline API
# ---------------------------------------------------------------------------

def _definition_payload(data: dict) -> dict:
    """Extract a pipeline definition from a request body.

    Accepts ``{"definition": {...}}``, a raw definition (``stages`` key) or a
    YAML string in ``yaml``/``definition``.
    """
    from arguscaner.scheduler import pipeline_io

    raw = data.get("definition")
    if raw is None:
        raw = data.get("yaml")
    if isinstance(raw, str):
        parsed = yaml.safe_load(raw) or {}
        return pipeline_io.normalize_definition(parsed)
    if isinstance(raw, dict):
        return pipeline_io.normalize_definition(raw)
    return pipeline_io.normalize_definition(data)


def _pipeline_payload(path: Path, settings: dict | None = None) -> dict:
    """Build the JSON payload used by the pipeline page and API."""
    from arguscaner.scheduler import pipeline_io
    from arguscaner.scheduler.scheduler_core import PipelineScheduler

    scheduler = PipelineScheduler(path, settings or _load_settings())
    graph = scheduler.get_pipeline_graph()
    return {
        "name": pipeline_io.pipeline_key(path),
        "file": str(path),
        "definition": pipeline_io.serialize_definition(scheduler.definition),
        "stages": scheduler.get_pipeline_definition(),
        "levels": scheduler.get_execution_levels(),
        "graph": graph,
        "pipelines": pipeline_io.list_pipelines(),
    }


def _custom_pipeline_path(name: str) -> Path | None:
    """Return the path for a custom pipeline, or ``None`` for the default."""
    name = (name or "").strip()
    if not name or name == "default":
        return None
    safe = Path(name).name
    if not safe or safe != name or safe in (".", ".."):
        return None
    if safe.endswith(".yaml"):
        safe = safe[:-5]
    if not safe:
        return None
    return CUSTOM_PIPELINES_DIR / f"{safe}.yaml"


@api_bp.route("/pipeline")
def api_pipeline():
    """Return pipeline definition/graph as JSON (``?name=`` selects one)."""
    from arguscaner.scheduler import pipeline_io

    path = pipeline_io.resolve_pipeline(request.args.get("name"))
    return jsonify(_pipeline_payload(path))


@api_bp.route("/pipeline/graph")
def api_pipeline_graph():
    """Return only the node/edge graph for a pipeline."""
    from arguscaner.scheduler import pipeline_io

    path = pipeline_io.resolve_pipeline(request.args.get("name"))
    definition = pipeline_io.load_definition(path)
    graph = pipeline_io.build_graph(definition)
    return jsonify(graph)


@api_bp.route("/pipelines")
def api_pipelines():
    """List the default and custom pipelines."""
    from arguscaner.scheduler import pipeline_io

    return jsonify({"pipelines": pipeline_io.list_pipelines()})


@api_bp.route("/pipeline/validate", methods=["POST"])
def api_pipeline_validate():
    """Validate a pipeline definition without saving it."""
    from arguscaner.scheduler import pipeline_io

    data = request.get_json() or {}
    definition = _definition_payload(data)
    errors = pipeline_io.validate_definition(definition, _plugin_names())
    payload = {
        "ok": not errors,
        "errors": errors,
        "levels": pipeline_io.compute_levels(definition),
    }
    if not errors:
        payload["graph"] = pipeline_io.build_graph(definition)
    return jsonify(payload), (200 if not errors else 400)


@api_bp.route("/pipelines", methods=["POST"])
def api_create_pipeline():
    """Create a custom pipeline."""
    from arguscaner.scheduler import pipeline_io

    data = request.get_json() or {}
    name = str(data.get("name") or "").strip()
    path = _custom_pipeline_path(name)
    if path is None:
        return jsonify({"error": "流程名称无效"}), 400
    if path.exists():
        return jsonify({"error": f"流程已存在：{path.stem}"}), 409

    definition = _definition_payload(data)
    errors = pipeline_io.validate_definition(definition, _plugin_names())
    if errors:
        return jsonify({"ok": False, "errors": errors}), 400

    pipeline_io.save_definition(path, definition, backup=False)
    return jsonify({"status": "ok", **_pipeline_payload(path)}), 201


@api_bp.route("/pipelines/<name>", methods=["PUT"])
def api_save_pipeline(name: str):
    """Save a pipeline (default is editable, custom pipelines are created)."""
    from arguscaner.scheduler import pipeline_io

    if name == "default":
        path = pipeline_io.DEFAULT_PIPELINE
    else:
        path = _custom_pipeline_path(name)
        if path is None:
            return jsonify({"error": "流程名称无效"}), 400

    data = request.get_json() or {}
    definition = _definition_payload(data)
    errors = pipeline_io.validate_definition(definition, _plugin_names())
    if errors:
        return jsonify({"ok": False, "errors": errors}), 400

    pipeline_io.save_definition(path, definition, backup=True)
    return jsonify({"status": "ok", **_pipeline_payload(path)})


@api_bp.route("/pipelines/<name>", methods=["DELETE"])
def api_delete_pipeline(name: str):
    """Delete a custom pipeline (the default cannot be deleted)."""
    path = _custom_pipeline_path(name)
    if path is None:
        return jsonify({"error": "默认流程不能删除"}), 400
    if not path.exists():
        return jsonify({"error": "流程不存在"}), 404
    try:
        path.unlink()
    except OSError as exc:
        return jsonify({"error": str(exc)}), 500
    return jsonify({"status": "ok", "name": name})


@api_bp.route("/pipelines/<name>/restore", methods=["POST"])
def api_restore_pipeline(name: str):
    """Restore the most recent backup of a pipeline."""
    from arguscaner.scheduler import pipeline_io

    if name == "default":
        path = pipeline_io.DEFAULT_PIPELINE
    else:
        path = _custom_pipeline_path(name)
        if path is None:
            return jsonify({"error": "流程名称无效"}), 400

    backup = pipeline_io.restore_backup(path)
    if backup is None:
        return jsonify({"error": "没有可恢复的历史版本"}), 404
    return jsonify({
        "status": "ok",
        "restored_from": str(backup),
        **_pipeline_payload(path),
    })
