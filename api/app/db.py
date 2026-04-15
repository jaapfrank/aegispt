from __future__ import annotations

from collections.abc import Generator

from fastapi import FastAPI, Request
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from api.app.config import Settings
from api.app.models import Base


def build_engine(database_url: str) -> Engine:
    connect_args: dict[str, bool] = {}
    if database_url.startswith("sqlite"):
        connect_args["check_same_thread"] = False

    return create_engine(database_url, pool_pre_ping=True, future=True, connect_args=connect_args)


def configure_database(app: FastAPI, settings: Settings) -> None:
    engine = build_engine(settings.database_url)
    session_factory = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)

    app.state.engine = engine
    app.state.session_factory = session_factory

    if settings.auto_create_tables:
        Base.metadata.create_all(bind=engine)


def shutdown_database(app: FastAPI) -> None:
    engine: Engine | None = getattr(app.state, "engine", None)
    if engine is not None:
        engine.dispose()


def get_session(request: Request) -> Generator[Session, None, None]:
    session_factory: sessionmaker[Session] = request.app.state.session_factory
    session = session_factory()
    try:
        yield session
    finally:
        session.close()


def database_ready(session: Session) -> bool:
    session.execute(text("SELECT 1"))
    return True
