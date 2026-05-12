from __future__ import annotations

from collections.abc import Generator
from importlib import import_module
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.orm import Session, sessionmaker

from api.app.config import Settings
from api.app.models import Base


def _sqlcipher_driver() -> Any:
    try:
        return import_module("sqlcipher3.dbapi2")
    except ImportError as exc:
        raise RuntimeError(
            "AEGISPT_DB_KEY is set, but the sqlcipher3 Python package is not installed. "
            "Install requirements/base.txt or add sqlcipher3 before enabling database encryption."
        ) from exc


def _sqlite_database_path(database_url: str) -> str:
    url = make_url(database_url)
    if url.get_backend_name() != "sqlite":
        raise ValueError("SQLCipher encryption is only supported for SQLite database URLs.")

    database = url.database or ":memory:"
    if database == ":memory:":
        return database
    return str(Path(database).expanduser())


def _sqlcipher_key_literal(db_key: str) -> str:
    return "'" + db_key.replace("'", "''") + "'"


def _connect_sqlcipher_sqlite(database_url: str, db_key: str):
    driver = _sqlcipher_driver()
    connection = driver.connect(_sqlite_database_path(database_url))
    connection.execute(f"PRAGMA key = {_sqlcipher_key_literal(db_key)}")
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def build_engine(database_url: str, db_key: str | None = None) -> Engine:
    if db_key:
        return create_engine(
            "sqlite://",
            pool_pre_ping=True,
            future=True,
            creator=lambda: _connect_sqlcipher_sqlite(database_url, db_key),
        )

    connect_args: dict = {}
    if database_url.startswith("sqlite"):
        connect_args["check_same_thread"] = False
        # Enable WAL mode and busy timeout for concurrent access (AI analysis + loop)
        def _sqlite_connect():
            import sqlite3 as _sqlite3
            url_path = database_url.replace("sqlite+pysqlite:///", "").replace("sqlite:///", "")
            conn = _sqlite3.connect(url_path, check_same_thread=False)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA busy_timeout=5000")
            return conn
        return create_engine("sqlite://", pool_pre_ping=True, future=True, creator=_sqlite_connect)

    return create_engine(database_url, pool_pre_ping=True, future=True, connect_args=connect_args)


def configure_database(app: FastAPI, settings: Settings) -> None:
    engine = build_engine(settings.database_url, db_key=settings.aegispt_db_key)
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
