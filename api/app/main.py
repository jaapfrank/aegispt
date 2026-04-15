from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI

from api.app.config import get_settings
from api.app.db import configure_database, shutdown_database
from api.app.routers.artifacts import router as artifacts_router
from api.app.routers.engagements import router as engagements_router
from api.app.routers.findings import router as findings_router
from api.app.routers.health import router as health_router
from api.app.routers.internal_validations import router as internal_validations_router
from api.app.routers.runs import router as runs_router
from api.app.routers.tasks import router as tasks_router


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
    app.include_router(engagements_router)
    app.include_router(findings_router)
    app.include_router(internal_validations_router)
    app.include_router(runs_router)
    app.include_router(tasks_router)

    @app.get("/", tags=["meta"])
    def root() -> dict[str, str]:
        return {
            "name": settings.app_name,
            "environment": settings.app_env,
            "status": "bootstrap",
        }

    return app


app = create_app()
