"""Celery application instance for ArguScanner."""

from __future__ import annotations

from celery import Celery

celery_app = Celery("arguscanner")
celery_app.config_from_object(
    {
        "broker_url": "redis://localhost:6379/0",
        "result_backend": "redis://localhost:6379/1",
        "task_serializer": "json",
        "result_serializer": "json",
        "accept_content": ["json"],
        "task_track_started": True,
        "task_acks_late": True,
        "worker_prefetch_multiplier": 1,
        "task_soft_time_limit": 3600,
        "task_time_limit": 3660,
    }
)

celery_app.autodiscover_tasks(["arguscaner.web"])
