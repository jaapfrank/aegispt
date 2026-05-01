from __future__ import annotations

import sqlite3
import sys
from types import ModuleType

import pytest

from api.app.config import Settings
from api.app.main import DATABASE_UNENCRYPTED_WARNING, warn_if_database_unencrypted


class FakeSqlcipherConnection:
    def __init__(self) -> None:
        self.executed: list[tuple[str, tuple[object, ...] | None]] = []

    def execute(self, statement: str, parameters: tuple[object, ...] | None = None):
        self.executed.append((statement, parameters))
        return self


def _install_fake_sqlcipher(monkeypatch: pytest.MonkeyPatch, connection: FakeSqlcipherConnection):
    sqlcipher_package = ModuleType("sqlcipher3")
    sqlcipher_dbapi = ModuleType("sqlcipher3.dbapi2")
    sqlcipher_dbapi.connect = lambda path: connection  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "sqlcipher3", sqlcipher_package)
    monkeypatch.setitem(sys.modules, "sqlcipher3.dbapi2", sqlcipher_dbapi)


def test_sqlcipher_connection_applies_key_before_use(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    from api.app.db import _connect_sqlcipher_sqlite

    connection = FakeSqlcipherConnection()
    _install_fake_sqlcipher(monkeypatch, connection)

    returned = _connect_sqlcipher_sqlite(f"sqlite+pysqlite:///{tmp_path / 'encrypted.db'}", "secret")

    assert returned is connection
    assert connection.executed[0] == ("PRAGMA key = 'secret'", None)
    assert connection.executed[1] == ("PRAGMA foreign_keys = ON", None)


def test_sqlcipher_missing_dependency_is_actionable(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    from api.app import db

    monkeypatch.delitem(sys.modules, "sqlcipher3.dbapi2", raising=False)
    monkeypatch.delitem(sys.modules, "sqlcipher3", raising=False)
    monkeypatch.setattr(db, "import_module", lambda name: (_ for _ in ()).throw(ImportError(name)))

    with pytest.raises(RuntimeError, match="AEGISPT_DB_KEY is set"):
        db._connect_sqlcipher_sqlite(f"sqlite+pysqlite:///{tmp_path / 'encrypted.db'}", "secret")


def test_plain_sqlite_still_reads_and_writes_without_key(tmp_path) -> None:
    from api.app.db import build_engine

    engine = build_engine(f"sqlite+pysqlite:///{tmp_path / 'plain.db'}")
    with engine.begin() as connection:
        connection.exec_driver_sql("CREATE TABLE sample (id integer primary key, name text)")
        connection.exec_driver_sql("INSERT INTO sample (name) VALUES ('ok')")
        rows = connection.exec_driver_sql("SELECT name FROM sample").fetchall()

    assert rows == [("ok",)]


def test_production_startup_warns_when_database_key_missing(caplog) -> None:
    settings = Settings(app_env="production", aegispt_db_key=None)

    warn_if_database_unencrypted(settings)

    assert DATABASE_UNENCRYPTED_WARNING in caplog.text


def test_development_startup_does_not_warn_when_database_key_missing(caplog) -> None:
    settings = Settings(app_env="development", aegispt_db_key=None)

    warn_if_database_unencrypted(settings)

    assert DATABASE_UNENCRYPTED_WARNING not in caplog.text


def test_encrypt_existing_db_script_copies_plaintext_into_sqlcipher_target(monkeypatch, tmp_path) -> None:
    import scripts.encrypt_existing_db as encrypt_script

    source = tmp_path / "plain.db"
    output = tmp_path / "encrypted.db"
    with sqlite3.connect(source) as connection:
        connection.execute("CREATE TABLE sample (name text)")
        connection.execute("INSERT INTO sample (name) VALUES ('copied')")

    fake_driver = ModuleType("sqlcipher3.dbapi2")
    fake_driver.connect = lambda path: sqlite3.connect(path)  # type: ignore[attr-defined]
    monkeypatch.setattr(encrypt_script, "_sqlcipher_driver", lambda: fake_driver)

    encrypt_script.encrypt_existing_db(source=source, output=output, key="secret")

    with sqlite3.connect(output) as connection:
        rows = connection.execute("SELECT name FROM sample").fetchall()
    assert rows == [("copied",)]


def test_encrypt_existing_db_script_requires_key(tmp_path, monkeypatch) -> None:
    import scripts.encrypt_existing_db as encrypt_script

    monkeypatch.delenv("AEGISPT_DB_KEY", raising=False)

    assert encrypt_script.main(["--source", str(tmp_path / "a.db"), "--output", str(tmp_path / "b.db")]) == 2
