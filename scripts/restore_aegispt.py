#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def utc_now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def copy_optional_tree(source: Path, destination: Path) -> dict[str, Any]:
    if not source.exists():
        return {"source": str(source), "restored": False, "reason": "missing"}
    if destination.exists():
        shutil.rmtree(destination)
    shutil.copytree(source, destination)
    return {
        "source": str(source),
        "destination": str(destination),
        "restored": True,
        "file_count": sum(1 for path in destination.rglob("*") if path.is_file()),
    }


def restore_backup(*, backup_dir: Path, restore_dir: Path, force: bool = False) -> dict[str, Any]:
    manifest_path = backup_dir / "backup-manifest.json"
    if not manifest_path.exists():
        raise FileNotFoundError(f"backup manifest not found: {manifest_path}")
    manifest = read_json(manifest_path)
    if manifest.get("kind") != "aegispt-backup":
        raise ValueError(f"unsupported backup manifest kind: {manifest.get('kind')}")
    if restore_dir.exists() and any(restore_dir.iterdir()) and not force:
        raise FileExistsError(f"restore directory is not empty: {restore_dir}")

    restore_dir.mkdir(parents=True, exist_ok=True)
    source_database = backup_dir / manifest["database"]["backup_path"]
    restored_database_dir = restore_dir / "database"
    restored_database_dir.mkdir(parents=True, exist_ok=True)
    restored_database = restored_database_dir / "aegispt.sqlite3"
    shutil.copy2(source_database, restored_database)

    restored_artifacts = copy_optional_tree(backup_dir / "artifacts" / "inline", restore_dir / ".aegispt-artifacts")
    restored_reports = copy_optional_tree(backup_dir / "reports", restore_dir / "reports")
    restored_config = copy_optional_tree(backup_dir / "config", restore_dir / "config-redacted")

    restore_manifest = {
        "kind": "aegispt-restore",
        "created_at": utc_now_iso(),
        "source_backup": str(backup_dir),
        "database_url": f"sqlite+pysqlite:///{restored_database}",
        "database_path": str(restored_database),
        "artifacts_dir": str(restore_dir / ".aegispt-artifacts"),
        "reports_dir": str(restore_dir / "reports"),
        "alembic_current_at_backup": manifest["database"].get("alembic_current"),
        "alembic_heads_at_backup": manifest["database"].get("alembic_heads", []),
        "restored_artifacts": restored_artifacts,
        "restored_reports": restored_reports,
        "restored_config": restored_config,
        "secrets_policy": {
            "plaintext_secrets_in_restore_manifest": False,
            "raw_env_values_included": False,
        },
    }
    write_json(restore_dir / "restore-manifest.json", restore_manifest)
    return restore_manifest


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Restore an AegisPT local backup into a separate directory.")
    parser.add_argument("--backup-dir", required=True, type=Path)
    parser.add_argument("--restore-dir", required=True, type=Path)
    parser.add_argument("--force", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    manifest = restore_backup(backup_dir=args.backup_dir, restore_dir=args.restore_dir, force=args.force)
    print(
        json.dumps(
            {
                "status": "ok",
                "restore_dir": str(args.restore_dir),
                "database_url": manifest["database_url"],
                "plaintext_secrets_in_restore_manifest": False,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
