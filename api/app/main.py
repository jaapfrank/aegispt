from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.staticfiles import StaticFiles

from api.app.config import Settings, get_settings
from api.app.db import configure_database, shutdown_database
from api.app.routers.artifacts import router as artifacts_router
from api.app.routers.auth import router as auth_router
from api.app.routers.codex import router as codex_router
from api.app.routers.custom_vulnerabilities import router as custom_vulnerabilities_router
from api.app.routers.dashboard import router as dashboard_router
from api.app.routers.engagements import router as engagements_router
from api.app.routers.findings import router as findings_router
from api.app.routers.health import router as health_router
from api.app.routers.integrations import router as integrations_router
from api.app.routers.inventory import router as inventory_router
from api.app.routers.internal_validations import router as internal_validations_router
from api.app.routers.mcp import router as mcp_router
from api.app.routers.packs import router as packs_router
from api.app.routers.problems import router as problems_router
from api.app.routers.relevance import router as relevance_router
from api.app.routers.runs import router as runs_router
from api.app.routers.settings import router as settings_router
from api.app.routers.tasks import router as tasks_router
from api.app.routers.threat_intel import router as threat_intel_router
from api.app.routers.triggers import router as triggers_router
from api.app.services.cve_sync_scheduler import start_cve_feed_scheduler, stop_cve_feed_scheduler
from api.app.services.gdpr_data import start_gdpr_retention_scheduler, stop_gdpr_retention_scheduler
from api.app.services.scheduled_runs import start_scheduled_run_scheduler, stop_scheduled_run_scheduler


logger = logging.getLogger(__name__)
DATABASE_UNENCRYPTED_WARNING = (
    "Database is NOT encrypted. Set AEGISPT_DB_KEY environment variable to enable encryption at rest."
)
DEVELOPMENT_ENVS = {"development", "dev", "local", "test", "testing"}


def warn_if_database_unencrypted(settings: Settings) -> None:
    if settings.aegispt_db_key:
        return
    if settings.app_env.strip().lower() in DEVELOPMENT_ENVS:
        return
    logger.warning(DATABASE_UNENCRYPTED_WARNING)


def create_app() -> FastAPI:
    settings = get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.runtime_state = "starting"
        warn_if_database_unencrypted(settings)
        configure_database(app, settings)
        start_cve_feed_scheduler(app, settings)
        start_gdpr_retention_scheduler(app)
        start_scheduled_run_scheduler(app, settings)
        app.state.runtime_state = "healthy"
        try:
            yield
        finally:
            app.state.runtime_state = "shutting_down"
            stop_scheduled_run_scheduler(app)
            stop_gdpr_retention_scheduler(app)
            stop_cve_feed_scheduler(app)
            shutdown_database(app)

    app = FastAPI(title=settings.app_name, version="0.1.0", lifespan=lifespan)

    @app.middleware("http")
    async def add_security_headers(request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        return response

    app.include_router(health_router)
    app.include_router(artifacts_router)
    app.include_router(auth_router)
    app.include_router(codex_router)
    app.include_router(custom_vulnerabilities_router)
    app.include_router(dashboard_router)
    app.include_router(engagements_router)
    app.include_router(findings_router)
    app.include_router(integrations_router)
    app.include_router(inventory_router)
    app.include_router(internal_validations_router)
    app.include_router(mcp_router)
    app.include_router(packs_router)
    app.include_router(problems_router)
    app.include_router(relevance_router)
    app.include_router(runs_router)
    app.include_router(settings_router)
    app.include_router(tasks_router)
    app.include_router(threat_intel_router)
    app.include_router(triggers_router)

    ui_dir = Path(__file__).resolve().parents[2] / "ui"
    if ui_dir.exists():
        app.mount("/app", StaticFiles(directory=str(ui_dir), html=True), name="app-ui")

    @app.get("/", tags=["meta"])
    def root() -> dict[str, str]:
        return {
            "name": settings.app_name,
            "environment": settings.app_env,
            "status": "bootstrap",
        }

    @app.get("/api/docs", include_in_schema=False)
    def api_docs():
        return get_swagger_ui_html(
            openapi_url=app.openapi_url or "/openapi.json",
            title=f"{settings.app_name} API Reference",
        )

    return app


app = create_app()
