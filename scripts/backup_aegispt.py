#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy.engine import make_url

REPO_ROOT = Path(__file__).resolve().parents[1]
SECRET_KEY_MARKERS = (
    "SECRET",
    "TOKEN",
    "PASSWORD",
    "PRIVATE",
    "CREDENTIAL",
    "API_KEY",
    "ACCESS_KEY",
    "DB_KEY",
    "KEY",
)


def utc_now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def is_sensitive_key(key: str) -> bool:
    upper_key = key.upper()
    return any(marker in upper_key for marker in SECRET_KEY_MARKERS)


def redact_env_value(key: str, value: str) -> str:
    if value and is_sensitive_key(key):
        return "<redacted>"
    return value


def read_redacted_env_file(path: Path) -> list[dict[str, str]]:
    entries: list[dict[str, str]] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", maxsplit=1)
        key = key.strip()
        entries.append({"key": key, "value": redact_env_value(key, value.strip())})
    return entries


def sqlite_path_from_url(database_url: str) -> Path:
    url = make_url(database_url)
    if url.get_backend_name() != "sqlite":
        raise ValueError(
            "backup_aegispt.py currently performs file-level backups for SQLite URLs only; "
            "use the runbook pg_dump path for PostgreSQL/Compose database backups."
        )
    database = url.database
    if not database or database == ":memory:":
        raise ValueError("AegisPT backup requires a file-backed SQLite database, not :memory:.")
    path = Path(database).expanduser()
    if not path.is_absolute():
        path = (REPO_ROOT / path).resolve()
    return path


def read_sqlite_alembic_version(database_path: Path) -> str | None:
    if not database_path.exists():
        return None
    try:
        connection = sqlite3.connect(str(database_path))
        try:
            row = connection.execute("SELECT version_num FROM alembic_version LIMIT 1").fetchone()
        finally:
            connection.close()
    except sqlite3.Error:
        return None
    return str(row[0]) if row else None


def alembic_heads() -> list[str]:
    config = Config(str(REPO_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(REPO_ROOT / "migrations"))
    script = ScriptDirectory.from_config(config)
    return list(script.get_heads())


def copy_directory(source: Path, destination: Path) -> dict[str, Any]:
    if not source.exists():
        return {"source": str(source), "copied": False, "reason": "missing"}
    if source.is_file():
        raise ValueError(f"{source} is a file; expected a directory")
    if destination.exists():
        shutil.rmtree(destination)
    shutil.copytree(source, destination)
    files = [
        {
            "path": str(path.relative_to(destination)),
            "sha256": sha256_file(path),
            "bytes": path.stat().st_size,
        }
        for path in sorted(destination.rglob("*"))
        if path.is_file()
    ]
    return {
        "source": str(source),
        "destination": str(destination),
        "copied": True,
        "file_count": len(files),
        "files": files,
    }


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def create_backup(
    *,
    output_dir: Path,
    database_url: str,
    artifacts_dir: Path,
    reports_dir: Path,
    env_files: list[Path],
    config_files: list[Path],
) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    database_path = sqlite_path_from_url(database_url)
    if not database_path.exists():
        raise FileNotFoundError(f"database file not found: {database_path}")

    database_backup_dir = output_dir / "database"
    database_backup_dir.mkdir(parents=True, exist_ok=True)
    database_backup_path = database_backup_dir / "aegispt.sqlite3"
    shutil.copy2(database_path, database_backup_path)

    config_dir = output_dir / "config"
    config_dir.mkdir(parents=True, exist_ok=True)
    env_manifest: list[dict[str, Any]] = []
    for env_file in env_files:
        if not env_file.exists():
            env_manifest.append({"source": str(env_file), "copied": False, "reason": "missing"})
            continue
        redacted_path = config_dir / f"{env_file.name}.redacted.json"
        entries = read_redacted_env_file(env_file)
        write_json(
            redacted_path,
            {
                "source": str(env_file),
                "contains_plaintext_secrets": False,
                "entries": entries,
            },
        )
        env_manifest.append(
            {
                "source": str(env_file),
                "redacted_manifest": str(redacted_path.relative_to(output_dir)),
                "copied": True,
                "raw_values_included": False,
            }
        )

    config_manifest: list[dict[str, Any]] = []
    for config_file in config_files:
        if not config_file.exists():
            config_manifest.append({"source": str(config_file), "copied": False, "reason": "missing"})
            continue
        destination = config_dir / config_file.name
        shutil.copy2(config_file, destination)
        config_manifest.append(
            {
                "source": str(config_file),
                "destination": str(destination.relative_to(output_dir)),
                "sha256": sha256_file(destination),
                "bytes": destination.stat().st_size,
                "copied": True,
            }
        )

    manifest: dict[str, Any] = {
        "kind": "aegispt-backup",
        "created_at": utc_now_iso(),
        "database": {
            "source_url_backend": make_url(database_url).get_backend_name(),
            "source_path": str(database_path),
            "backup_path": str(database_backup_path.relative_to(output_dir)),
            "sha256": sha256_file(database_backup_path),
            "bytes": database_backup_path.stat().st_size,
            "alembic_current": read_sqlite_alembic_version(database_path),
            "alembic_heads": alembic_heads(),
        },
        "artifacts": copy_directory(artifacts_dir, output_dir / "artifacts" / "inline"),
        "reports": copy_directory(reports_dir, output_dir / "reports"),
        "env": env_manifest,
        "config": config_manifest,
        "secrets_policy": {
            "plaintext_secrets_in_manifest": False,
            "raw_env_values_included": False,
            "note": "Secret-looking env values are redacted; preserve real secret values in an external vault or encrypted operator backup.",
        },
    }
    write_json(output_dir / "backup-manifest.json", manifest)
    return manifest


def default_env_files() -> list[Path]:
    return [
        REPO_ROOT / ".env",
        Path("/srv/aegispt/env/aegispt-host.env"),
        REPO_ROOT / "infra" / "compose" / ".env",
    ]


def default_config_files() -> list[Path]:
    return [
        REPO_ROOT / "alembic.ini",
        REPO_ROOT / "infra" / "compose" / "docker-compose.yml",
    ]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Create a redacted local AegisPT backup bundle.")
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--database-url", default=os.getenv("DATABASE_URL", "sqlite+pysqlite:///./aegispt.db"))
    parser.add_argument("--artifacts-dir", default=os.getenv("ARTIFACTS_INLINE_DIR", ".aegispt-artifacts"), type=Path)
    parser.add_argument("--reports-dir", default=os.getenv("AEGISPT_REPORTS_DIR", "/srv/aegispt/reports"), type=Path)
    parser.add_argument("--env-file", action="append", default=[], type=Path)
    parser.add_argument("--config-file", action="append", default=[], type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    env_files = args.env_file or default_env_files()
    config_files = args.config_file or default_config_files()
    manifest = create_backup(
        output_dir=args.output_dir,
        database_url=args.database_url,
        artifacts_dir=args.artifacts_dir,
        reports_dir=args.reports_dir,
        env_files=env_files,
        config_files=config_files,
    )
    print(
        json.dumps(
            {
                "status": "ok",
                "backup_dir": str(args.output_dir),
                "database_sha256": manifest["database"]["sha256"],
                "alembic_current": manifest["database"]["alembic_current"],
                "plaintext_secrets_in_manifest": False,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
