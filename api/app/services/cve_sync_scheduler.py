from __future__ import annotations

from typing import Any

from fastapi import FastAPI

from api.app.config import Settings
from api.app.services.cve_sync import sync_cve_feeds
from api.app.services.settings import tenant_scope_key


def start_cve_feed_scheduler(app: FastAPI, settings: Settings) -> dict[str, Any]:
    if not settings.cve_feed_sync_enabled:
        status = {"enabled": False, "status": "disabled", "reason": "cve_feed_sync_enabled=false"}
        app.state.cve_feed_scheduler_status = status
        return status
    try:
        from apscheduler.schedulers.background import BackgroundScheduler
        from apscheduler.triggers.cron import CronTrigger
    except ImportError:
        status = {"enabled": False, "status": "missing_dependency", "reason": "APScheduler is not installed"}
        app.state.cve_feed_scheduler_status = status
        return status

    session_factory = app.state.session_factory
    tenant_id = tenant_scope_key(settings.settings_tenant_id)

    def sync_job() -> None:
        session = session_factory()
        try:
            sync_cve_feeds(session, tenant_id=tenant_id, settings=settings, force=False)
            session.commit()
        except Exception:
            session.rollback()
        finally:
            session.close()

    scheduler = BackgroundScheduler()
    scheduler.add_job(
        sync_job,
        CronTrigger(hour=3, minute=0),
        id="cve-feed-auto-sync",
        replace_existing=True,
        max_instances=1,
        coalesce=True,
    )
    scheduler.start()
    app.state.cve_feed_scheduler = scheduler
    status = {"enabled": True, "status": "scheduled", "cron": "0 3 * * *", "tenant_id": tenant_id}
    app.state.cve_feed_scheduler_status = status
    return status


def stop_cve_feed_scheduler(app: FastAPI) -> None:
    scheduler = getattr(app.state, "cve_feed_scheduler", None)
    if scheduler is not None:
        scheduler.shutdown(wait=False)
        app.state.cve_feed_scheduler = None
