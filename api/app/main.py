from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.cors import CORSMiddleware

from api.app.config import Settings, get_settings
from api.app.db import configure_database, shutdown_database
from api.app.routers.artifacts import router as artifacts_router
from api.app.routers.auth import router as auth_router
from api.app.routers.ai_research import router as ai_research_router
from api.app.routers.codex import router as codex_router
from api.app.routers.custom_vulnerabilities import router as custom_vulnerabilities_router
from api.app.routers.dashboard import router as dashboard_router
from api.app.routers.diagnostics import router as diagnostics_router
from api.app.routers.engagements import router as engagements_router
from api.app.routers.findings import router as findings_router
from api.app.routers.health import router as health_router
from api.app.routers.integrations import router as integrations_router
from api.app.routers.internal_validations import router as internal_validations_router
from api.app.routers.inventory import router as inventory_router
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
from api.app.services.rate_limit import InMemoryRateLimiter, client_identifier
from api.app.services.scheduled_runs import (
    start_scheduled_run_scheduler,
    stop_scheduled_run_scheduler,
)

logger = logging.getLogger(__name__)
DATABASE_UNENCRYPTED_WARNING = (
    "Database is NOT encrypted. Set AEGISPT_DB_KEY environment variable to enable encryption at rest."
)
DEVELOPMENT_ENVS = {"development", "dev", "local", "test", "testing"}
DEFAULT_ALLOWED_ORIGINS = ("http://localhost:8000", "http://127.0.0.1:8000")


class ReactAppStaticFiles(StaticFiles):
    async def get_response(self, path: str, scope):
        try:
            return await super().get_response(path, scope)
        except StarletteHTTPException as exc:
            if exc.status_code == 404:
                return await super().get_response("index.html", scope)
            raise


def effective_app_env(settings: Settings) -> str:
    return str(settings.aegispt_env or settings.app_env or "development").strip().lower()


def parse_allowed_origins(raw_origins: str | None) -> list[str]:
    raw = str(raw_origins or "").replace("\n", ",").replace(";", ",")
    origins = [origin.strip().rstrip("/") for origin in raw.split(",") if origin.strip()]
    return origins or list(DEFAULT_ALLOWED_ORIGINS)


def database_key_required(settings: Settings) -> bool:
    env = effective_app_env(settings)
    return env not in DEVELOPMENT_ENVS or not bool(settings.auto_create_tables)


def enforce_database_encryption_key(settings: Settings) -> None:
    if settings.aegispt_db_key:
        return
    if not database_key_required(settings):
        return
    raise RuntimeError(
        "AEGISPT_DB_KEY is required for production-style startup. "
        "Set AEGISPT_DB_KEY, or run only in development/test mode with AUTO_CREATE_TABLES=true."
    )


def warn_if_database_unencrypted(settings: Settings) -> None:
    if settings.aegispt_db_key:
        return
    env = effective_app_env(settings)
    if env in DEVELOPMENT_ENVS:
        return
    if database_key_required(settings):
        return
    logger.warning(DATABASE_UNENCRYPTED_WARNING)


def create_app() -> FastAPI:
    settings = get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.runtime_state = "starting"
        enforce_database_encryption_key(settings)
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
    app.state.rate_limiter = InMemoryRateLimiter()

    app.add_middleware(
        CORSMiddleware,
        allow_origins=parse_allowed_origins(settings.aegispt_allowed_origins),
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["*"],
    )

    @app.middleware("http")
    async def add_security_headers(request, call_next):
        limiter = getattr(request.app.state, "rate_limiter", None)
        rule = limiter.rule_for_request(request) if limiter is not None else None
        if rule is not None:
            allowed, retry_after, remaining = limiter.check(
                rule=rule,
                client_id=client_identifier(request),
            )
            if not allowed:
                return JSONResponse(
                    status_code=429,
                    content={
                        "detail": "Rate limit exceeded. Retry after the indicated number of seconds.",
                        "rate_limit": {
                            "scope": rule.name,
                            "limit": rule.max_requests,
                            "window_seconds": rule.window_seconds,
                        },
                    },
                    headers={
                        "Retry-After": str(retry_after),
                        "X-RateLimit-Limit": str(rule.max_requests),
                        "X-RateLimit-Remaining": "0",
                        "X-RateLimit-Reset": str(retry_after),
                    },
                )
        response = await call_next(request)
        if rule is not None:
            response.headers.setdefault("X-RateLimit-Limit", str(rule.max_requests))
            response.headers.setdefault("X-RateLimit-Remaining", str(remaining))
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        return response

    app.include_router(health_router)
    app.include_router(ai_research_router)
    app.include_router(artifacts_router)
    app.include_router(auth_router)
    app.include_router(codex_router)
    app.include_router(custom_vulnerabilities_router)
    app.include_router(dashboard_router)
    app.include_router(diagnostics_router)
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

    ui_v2_dir = Path(__file__).resolve().parents[2] / "ui-v2" / "dist"
    if ui_v2_dir.exists():
        @app.get("/app-v2/health", include_in_schema=False)
        def app_v2_health() -> dict[str, str]:
            return {"status": "ok", "version": "v2"}

        @app.get("/v2", include_in_schema=False)
        def legacy_app_v2_redirect() -> RedirectResponse:
            return RedirectResponse(url="/app-v2/")

        @app.get("/v2/{path:path}", include_in_schema=False)
        def legacy_app_v2_path_redirect(path: str) -> RedirectResponse:
            return RedirectResponse(url=f"/app-v2/{path}")

        app.mount("/app-v2", ReactAppStaticFiles(directory=str(ui_v2_dir), html=True), name="app-ui-v2")

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
