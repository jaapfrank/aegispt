from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from api.app.config import get_settings
from api.app.db import configure_database, shutdown_database
from api.app.routers.codex import router as codex_router
from api.app.routers.artifacts import router as artifacts_router
from api.app.routers.engagements import router as engagements_router
from api.app.routers.findings import router as findings_router
from api.app.routers.health import router as health_router
from api.app.routers.inventory import router as inventory_router
from api.app.routers.internal_validations import router as internal_validations_router
from api.app.routers.packs import router as packs_router
from api.app.routers.relevance import router as relevance_router
from api.app.routers.runs import router as runs_router
from api.app.routers.tasks import router as tasks_router
from api.app.routers.threat_intel import router as threat_intel_router


def create_app() -> FastAPI:
    settings = get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        configure_database(app, settings)
        yield
        shutdown_database(app)

    app = FastAPI(title=settings.app_name, version="0.1.0", lifespan=lifespan)
    app.include_router(health_router)
    app.include_router(artifacts_router)
    app.include_router(codex_router)
    app.include_router(engagements_router)
    app.include_router(findings_router)
    app.include_router(inventory_router)
    app.include_router(internal_validations_router)
    app.include_router(packs_router)
    app.include_router(relevance_router)
    app.include_router(runs_router)
    app.include_router(tasks_router)
    app.include_router(threat_intel_router)

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

    return app


app = create_app()
