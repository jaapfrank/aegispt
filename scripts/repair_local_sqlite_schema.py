#!/usr/bin/env python3
from __future__ import annotations

import sqlite3
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from api.app.config import get_settings

HEAD_REVISION = "20260425_0023"
CVE_SYNC_REVISION = "20260426_0024"

REQUIRED_TABLES = {
    "instance_settings",
    "repo_integrations",
    "finding_repo_links",
    "cicd_triggers",
    "cicd_trigger_events",
    "finding_validation_records",
    "exposure_scores",
    "assessment_chains",
}

CVE_SYNC_TABLES = {
    "cve_product_watchlist_entries",
    "cve_feed_sync_logs",
}

REQUIRED_COLUMNS = {
    "runs": {
        "autonomous_mode": "ALTER TABLE runs ADD COLUMN autonomous_mode BOOLEAN NOT NULL DEFAULT 0",
        "autonomous_intrusive_allowed": (
            "ALTER TABLE runs ADD COLUMN autonomous_intrusive_allowed BOOLEAN NOT NULL DEFAULT 0"
        ),
        "assessment_chain_id": "ALTER TABLE runs ADD COLUMN assessment_chain_id CHAR(32)",
        "deleted_at": "ALTER TABLE runs ADD COLUMN deleted_at DATETIME",
    },
    "engagements": {
        "deleted_at": "ALTER TABLE engagements ADD COLUMN deleted_at DATETIME",
    },
    "findings": {
        "autofix_json": "ALTER TABLE findings ADD COLUMN autofix_json JSON",
        "validation_status": (
            "ALTER TABLE findings ADD COLUMN validation_status VARCHAR(50) NOT NULL DEFAULT 'unvalidated'"
        ),
    },
    "tasks": {
        "source_finding_id": "ALTER TABLE tasks ADD COLUMN source_finding_id CHAR(32)",
    },
}

REQUIRED_INDEXES = {
    "ix_runs_assessment_chain_id": "CREATE INDEX IF NOT EXISTS ix_runs_assessment_chain_id ON runs (assessment_chain_id)",
    "ix_instance_settings_tenant_id": "CREATE INDEX IF NOT EXISTS ix_instance_settings_tenant_id ON instance_settings (tenant_id)",
    "ix_instance_settings_setting_key": "CREATE INDEX IF NOT EXISTS ix_instance_settings_setting_key ON instance_settings (setting_key)",
    "ix_exposure_scores_engagement_id": "CREATE INDEX IF NOT EXISTS ix_exposure_scores_engagement_id ON exposure_scores (engagement_id)",
    "ix_exposure_scores_run_id": "CREATE INDEX IF NOT EXISTS ix_exposure_scores_run_id ON exposure_scores (run_id)",
    "ix_assessment_chains_engagement_id": (
        "CREATE INDEX IF NOT EXISTS ix_assessment_chains_engagement_id ON assessment_chains (engagement_id)"
    ),
    "ix_assessment_chains_current_run_id": (
        "CREATE INDEX IF NOT EXISTS ix_assessment_chains_current_run_id ON assessment_chains (current_run_id)"
    ),
    "ix_assessment_chains_last_completed_run_id": (
        "CREATE INDEX IF NOT EXISTS ix_assessment_chains_last_completed_run_id ON assessment_chains (last_completed_run_id)"
    ),
    "ix_engagements_deleted_at": "CREATE INDEX IF NOT EXISTS ix_engagements_deleted_at ON engagements (deleted_at)",
    "ix_runs_deleted_at": "CREATE INDEX IF NOT EXISTS ix_runs_deleted_at ON runs (deleted_at)",
}


def _sqlite_path() -> Path | None:
    database_url = str(get_settings().database_url or "").strip()
    if not database_url.startswith("sqlite"):
        return None
    if database_url.endswith(":memory:"):
        return None
    if ":///" not in database_url:
        return None
    raw_path = database_url.split(":///", 1)[1]
    if not raw_path:
        return None
    path = Path(raw_path)
    if not path.is_absolute():
        path = Path.cwd() / path
    return path


def _table_exists(cursor: sqlite3.Cursor, table: str) -> bool:
    cursor.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,))
    return cursor.fetchone() is not None


def _column_names(cursor: sqlite3.Cursor, table: str) -> set[str]:
    cursor.execute(f"PRAGMA table_info({table})")
    return {str(row[1]) for row in cursor.fetchall()}


def _index_names(cursor: sqlite3.Cursor) -> set[str]:
    cursor.execute("SELECT name FROM sqlite_master WHERE type='index'")
    return {str(row[0]) for row in cursor.fetchall()}


def _current_revision(cursor: sqlite3.Cursor) -> str | None:
    if not _table_exists(cursor, "alembic_version"):
        return None
    cursor.execute("SELECT version_num FROM alembic_version")
    row = cursor.fetchone()
    return str(row[0]) if row else None


def _has_drift_signature(cursor: sqlite3.Cursor) -> bool:
    current_revision = _current_revision(cursor)
    if current_revision == HEAD_REVISION and any(_table_exists(cursor, table) for table in CVE_SYNC_TABLES):
        return True
    if current_revision == HEAD_REVISION:
        return False
    if current_revision and current_revision >= CVE_SYNC_REVISION:
        return False
    return any(_table_exists(cursor, table) for table in REQUIRED_TABLES)


def _can_stamp_head(cursor: sqlite3.Cursor) -> bool:
    if not all(_table_exists(cursor, table) for table in REQUIRED_TABLES):
        return False
    for table, columns in REQUIRED_COLUMNS.items():
        if not _table_exists(cursor, table):
            return False
        if not set(columns).issubset(_column_names(cursor, table)):
            return False
    return True


def _can_stamp_cve_sync(cursor: sqlite3.Cursor) -> bool:
    if _current_revision(cursor) != HEAD_REVISION:
        return False
    return all(_table_exists(cursor, table) for table in CVE_SYNC_TABLES)


def _repair_schema(db_path: Path) -> list[str]:
    actions: list[str] = []
    connection = sqlite3.connect(str(db_path))
    try:
        cursor = connection.cursor()
        if not _has_drift_signature(cursor):
            return actions

        for table, columns in REQUIRED_COLUMNS.items():
            if not _table_exists(cursor, table):
                continue
            existing_columns = _column_names(cursor, table)
            for column, statement in columns.items():
                if column in existing_columns:
                    continue
                cursor.execute(statement)
                actions.append(f"added {table}.{column}")

        existing_indexes = _index_names(cursor)
        for index_name, statement in REQUIRED_INDEXES.items():
            if index_name in existing_indexes:
                continue
            cursor.execute(statement)
            actions.append(f"created index {index_name}")

        connection.commit()
        if _can_stamp_cve_sync(cursor):
            subprocess.run([sys.executable, "-m", "alembic", "stamp", CVE_SYNC_REVISION], check=True)
            actions.append(f"stamped {CVE_SYNC_REVISION}")
            return actions
        if _can_stamp_head(cursor):
            subprocess.run([sys.executable, "-m", "alembic", "stamp", HEAD_REVISION], check=True)
            actions.append(f"stamped {HEAD_REVISION}")
        return actions
    finally:
        connection.close()


def main() -> int:
    db_path = _sqlite_path()
    if db_path is None or not db_path.exists():
        print("No local SQLite database repair needed.")
        return 0
    actions = _repair_schema(db_path)
    if not actions:
        print(f"No SQLite schema drift repair needed for {db_path}.")
        return 0
    print(f"SQLite schema drift repaired for {db_path}:")
    for action in actions:
        print(f"- {action}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
