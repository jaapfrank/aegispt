from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from functools import lru_cache

from sqlalchemy.orm import Session, sessionmaker

from api.app.db import build_engine


@lru_cache
def get_session_factory(database_url: str) -> sessionmaker[Session]:
    engine = build_engine(database_url)
    return sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)


@contextmanager
def session_scope() -> Iterator[Session]:
    database_url = os.getenv("DATABASE_URL", "sqlite+pysqlite:///./aegispt.db")
    session = get_session_factory(database_url)()
    try:
        yield session
    finally:
        session.close()
