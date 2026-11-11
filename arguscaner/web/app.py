"""Flask application factory for ArguScanner Web UI."""

from __future__ import annotations

from flask import Flask


def create_app(config: dict | None = None) -> Flask:
    """Create and configure the Flask application.

    Args:
        config: Optional configuration overrides.

    Returns:
        Configured Flask app instance.
    """
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "arguscanner-dev-key"
    app.config["WORKSPACE"] = "workspace"
    # Keep Chinese text readable and preserve the settings.yaml key order.
    app.json.ensure_ascii = False
    app.json.sort_keys = False

    if config:
        app.config.update(config)

    from arguscaner.web.routes import main_bp, api_bp
    app.register_blueprint(main_bp)
    app.register_blueprint(api_bp, url_prefix="/api")

    # Ensure Celery tasks are registered
    from arguscaner.celery_app import celery_app  # noqa: F401

    return app
