"""Celery tasks for ArguScanner scan operations."""

from __future__ import annotations

from pathlib import Path

from arguscaner.celery_app import celery_app

CONFIGS_DIR = Path(__file__).parent.parent / "configs"
WORKSPACE = Path(__file__).parent.parent.parent / "workspace"


def _load_settings() -> dict:
    import yaml

    with open(CONFIGS_DIR / "settings.yaml", "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


@celery_app.task(bind=True, name="scan.run_single")
def run_single_scan(
    self,
    task_id: str,
    target: str,
    pipeline_name: str | None = None,
    recursive: bool | None = None,
):
    """Execute a single-target scan.

    Args:
        task_id: Unique task identifier (hv-YYYY-MM-DD-NNN).
        target: Scan target string.
        pipeline_name: Optional pipeline name or file path.
        recursive: Force multi-round recursion on/off (None = settings).
    """
    from arguscaner.scheduler.scheduler_core import PipelineScheduler

    settings = _load_settings()
    workdir = WORKSPACE / task_id
    workdir.mkdir(parents=True, exist_ok=True)

    from arguscaner.scheduler import pipeline_io

    pipeline_file = pipeline_io.resolve_pipeline(pipeline_name)

    scheduler = PipelineScheduler(pipeline_file, settings)
    result = scheduler.run(target, workdir, task_id, recursive=recursive)

    return {
        "task_id": task_id,
        "target": target,
        "status": "done",
        "total_duration": result.total_duration,
        "failed_stages": result.failed_stages,
        "recursive_rounds": len(result.recursive_rounds),
    }


@celery_app.task(bind=True, name="scan.run_batch")
def run_batch_scan(
    self,
    raw_targets: str,
    pipeline_name: str | None = None,
    recursive: bool | None = None,
):
    """Execute batch scan: spawn a child task for each target.

    Args:
        raw_targets: Comma/newline/semicolon separated target string.
        pipeline_name: Optional pipeline name or file path.
        recursive: Force multi-round recursion on/off (None = settings).
    """
    from arguscaner.scheduler.scheduler_core import generate_task_id
    from arguscaner.utils.target_classifier import TargetClassifier

    targets = TargetClassifier.parse_targets(raw_targets)
    results = []

    for target in targets:
        try:
            TargetClassifier.classify(target)
        except ValueError:
            results.append({"target": target, "error": "无效目标"})
            continue

        task_id = generate_task_id()
        run_single_scan.delay(task_id, target, pipeline_name, recursive)
        results.append({"task_id": task_id, "target": target, "status": "queued"})

    return {"tasks": results}
