#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from fastapi.testclient import TestClient
from sqlalchemy import select, text
from sqlalchemy.orm import sessionmaker

from api.app.config import get_settings
from api.app.db import build_engine
from api.app.models import (
    AuditEvent,
    Engagement,
    EvidenceArtifact,
    Finding,
    InstanceSetting,
    Run,
    RunProfile,
    SecretRef,
    Task,
    ToolExecution,
)
from api.app.services.artifact_storage import (
    ArtifactStorageConfig,
    load_artifact_content,
    store_artifact_bytes,
)
from scripts.backup_aegispt import create_backup, read_sqlite_alembic_version
from scripts.restore_aegispt import restore_backup

FIXTURE_SECRET_VALUE = "fixture-plaintext-secret-must-not-appear"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run_alembic(database_url: str, *args: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["DATABASE_URL"] = database_url
    env["AUTO_CREATE_TABLES"] = "false"
    return subprocess.run(
        [sys.executable, "-m", "alembic", *args],
        cwd=REPO_ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def require_alembic(database_url: str, *args: str) -> str:
    completed = run_alembic(database_url, *args)
    if completed.returncode != 0:
        raise RuntimeError(
            f"alembic {' '.join(args)} failed: {completed.stdout.strip()} {completed.stderr.strip()}"
        )
    return (completed.stdout + completed.stderr).strip()


def seed_safe_fixture(database_url: str, artifacts_dir: Path) -> dict[str, str]:
    engine = build_engine(database_url)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
    artifact_data = b"AegisPT safe restore drill evidence\n"
    artifact_digest = sha256_bytes(artifact_data)

    with SessionLocal() as session:
        engagement = Engagement(
            name="Safe Restore Drill Engagement",
            client="AegisPT Fixture",
            tenant_id="restore-drill",
            roe_ref="local-fixture-only",
            authorization_confirmed_by="restore-drill",
            status="active",
        )
        profile = RunProfile(name="Safe Restore Drill", run_class="passive", limits_json={"fixture": True})
        session.add_all([engagement, profile])
        session.flush()

        run = Run(
            engagement_id=engagement.id,
            profile_id=profile.id,
            requested_by="restore-drill",
            status="completed",
            configuration_json={"fixture": "safe-local", "target": "127.0.0.1"},
        )
        session.add(run)
        session.flush()

        task = Task(run_id=run.id, tool="restore-drill", target_id="127.0.0.1", status="completed")
        session.add(task)
        session.flush()

        execution = ToolExecution(
            task_id=task.id,
            runner_digest="restore-drill@sha256:fixture",
            tool_version="fixture-1.0",
            exit_code=0,
            stdout_text="safe restore drill completed",
        )
        session.add(execution)
        session.flush()

        storage_config = ArtifactStorageConfig(
            mode="inline",
            endpoint="",
            bucket="",
            access_key="",
            secret_key="",
            inline_dir=str(artifacts_dir),
        )
        stored = store_artifact_bytes(
            config=storage_config,
            artifact_name="restore-drill-output.txt",
            artifact_kind="stdout",
            artifact_digest=artifact_digest,
            content_type="text/plain",
            data=artifact_data,
            run_id=str(run.id),
            task_id=str(task.id),
            execution_id=str(execution.id),
        )
        artifact = EvidenceArtifact(
            tool_execution_id=execution.id,
            kind="stdout",
            uri=stored.uri,
            sha256=artifact_digest,
            redaction_state="redacted",
            metadata_json={
                **stored.metadata,
                "name": "restore-drill-output.txt",
                "fixture": "safe-local",
            },
        )
        session.add(artifact)
        session.flush()

        finding = Finding(
            run_id=run.id,
            title="Safe restore drill finding",
            severity="info",
            target_id="127.0.0.1",
            evidence_ref=stored.uri,
            status="open",
            summary="Fixture finding used only to prove backup and restore linkage.",
            methodology_tags=["evidence-handling"],
        )
        session.add(finding)

        session.add(
            SecretRef(
                engagement_id=engagement.id,
                vault_pointer="vault://aegispt/restore-drill/api-token",
                purpose="restore drill secret metadata",
                secret_kind="api_token",
                storage_backend="encrypted_local",
                display_label="Restore drill API token",
                encrypted_value="gAAAA-restored-fixture-ciphertext",
                metadata_json={"plaintext_available": False, "fixture": "safe-local"},
            )
        )
        session.add(
            InstanceSetting(
                tenant_id="restore-drill",
                setting_key="restore_drill.secret_marker",
                value_json={"configured": True},
                sensitive=True,
                storage_backend="encrypted_local",
                encrypted_value="gAAAA-instance-setting-fixture-ciphertext",
                display_label="Restore drill secret marker",
                metadata_json={"plaintext_available": False},
            )
        )
        session.add(
            AuditEvent(
                actor="restore-drill",
                action="restore_fixture_seeded",
                object_type="run",
                object_id=str(run.id),
                metadata_json={"fixture": "safe-local", "evidence_artifact": str(artifact.id)},
            )
        )
        session.commit()

        return {
            "engagement_id": str(engagement.id),
            "run_id": str(run.id),
            "task_id": str(task.id),
            "execution_id": str(execution.id),
            "artifact_id": str(artifact.id),
            "finding_id": str(finding.id),
            "artifact_sha256": artifact_digest,
            "artifact_uri": stored.uri,
        }


def assert_no_plaintext_secret(path: Path) -> None:
    for file_path in path.rglob("*"):
        if not file_path.is_file():
            continue
        if FIXTURE_SECRET_VALUE in file_path.read_text(encoding="utf-8", errors="ignore"):
            raise AssertionError(f"plaintext fixture secret leaked into {file_path}")


def verify_restored_database(restore_manifest: dict[str, Any], expected: dict[str, str]) -> dict[str, Any]:
    database_url = restore_manifest["database_url"]
    engine = build_engine(database_url)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
    with SessionLocal() as session:
        counts = {
            "engagements": session.query(Engagement).count(),
            "runs": session.query(Run).count(),
            "tasks": session.query(Task).count(),
            "executions": session.query(ToolExecution).count(),
            "artifacts": session.query(EvidenceArtifact).count(),
            "findings": session.query(Finding).count(),
            "audit_events": session.query(AuditEvent).count(),
            "secret_refs": session.query(SecretRef).count(),
            "sensitive_settings": session.query(InstanceSetting).filter(InstanceSetting.sensitive.is_(True)).count(),
        }
        artifact = session.scalar(select(EvidenceArtifact).where(EvidenceArtifact.id == uuid.UUID(expected["artifact_id"])))
        finding = session.scalar(select(Finding).where(Finding.id == uuid.UUID(expected["finding_id"])))
        audit_event = session.scalar(select(AuditEvent).where(AuditEvent.object_id == expected["run_id"]))
        secret = session.scalar(select(SecretRef).where(SecretRef.engagement_id == uuid.UUID(expected["engagement_id"])))
        session.execute(text("SELECT 1"))

    if artifact is None or finding is None or audit_event is None or secret is None:
        raise AssertionError("restored fixture is missing artifact, finding, audit event, or secret metadata")
    if finding.evidence_ref != expected["artifact_uri"]:
        raise AssertionError("restored finding evidence reference changed")
    if secret.encrypted_value == FIXTURE_SECRET_VALUE:
        raise AssertionError("restored secret metadata contains plaintext fixture secret")

    storage_config = ArtifactStorageConfig(
        mode="inline",
        endpoint="",
        bucket="",
        access_key="",
        secret_key="",
        inline_dir=restore_manifest["artifacts_dir"],
    )
    content = load_artifact_content(config=storage_config, uri=artifact.uri)
    if content is None:
        raise AssertionError("restored artifact content is unavailable")
    if sha256_bytes(content.data) != expected["artifact_sha256"]:
        raise AssertionError("restored artifact hash does not match metadata")

    return {
        "counts": counts,
        "artifact_hash_verified": True,
        "finding_evidence_ref_verified": True,
        "audit_event_verified": True,
        "secret_metadata_verified": True,
    }


def verify_api_read_paths(restore_manifest: dict[str, Any], expected: dict[str, str]) -> dict[str, Any]:
    previous_env = {
        "DATABASE_URL": os.environ.get("DATABASE_URL"),
        "AUTO_CREATE_TABLES": os.environ.get("AUTO_CREATE_TABLES"),
        "ARTIFACTS_INLINE_DIR": os.environ.get("ARTIFACTS_INLINE_DIR"),
        "ARTIFACTS_STORAGE_MODE": os.environ.get("ARTIFACTS_STORAGE_MODE"),
        "APP_ENV": os.environ.get("APP_ENV"),
    }
    os.environ["DATABASE_URL"] = restore_manifest["database_url"]
    os.environ["AUTO_CREATE_TABLES"] = "true"
    os.environ["ARTIFACTS_INLINE_DIR"] = restore_manifest["artifacts_dir"]
    os.environ["ARTIFACTS_STORAGE_MODE"] = "inline"
    os.environ["APP_ENV"] = "testing"
    get_settings.cache_clear()

    try:
        from api.app.main import create_app

        with TestClient(create_app()) as client:
            health = client.get("/health/live")
            engagements = client.get("/api/v1/engagements")
            run = client.get(f"/api/v1/runs/{expected['run_id']}")
            artifact = client.get(f"/api/v1/artifacts/{expected['artifact_id']}/content")
    finally:
        for key, value in previous_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        get_settings.cache_clear()

    if health.status_code != 200:
        raise AssertionError(f"health check failed after restore: {health.status_code}")
    if engagements.status_code != 200 or expected["engagement_id"] not in engagements.text:
        raise AssertionError("restored engagement is not readable through the API")
    if run.status_code != 200 or expected["run_id"] not in run.text:
        raise AssertionError("restored run is not readable through the API")
    if artifact.status_code != 200 or sha256_bytes(artifact.content) != expected["artifact_sha256"]:
        raise AssertionError("restored artifact is not readable through the API")
    return {
        "health_status": health.status_code,
        "engagements_status": engagements.status_code,
        "run_status": run.status_code,
        "artifact_status": artifact.status_code,
    }


def run_safe_local_restore_drill(base_dir: Path | None = None) -> dict[str, Any]:
    temp_context = tempfile.TemporaryDirectory(prefix="aegispt-restore-drill-") if base_dir is None else None
    root = Path(temp_context.name) if temp_context else base_dir
    assert root is not None
    try:
        source_dir = root / "source"
        backup_dir = root / "backup"
        restore_dir = root / "restore"
        source_dir.mkdir(parents=True, exist_ok=True)
        database_path = source_dir / "aegispt.sqlite3"
        artifacts_dir = source_dir / ".aegispt-artifacts"
        reports_dir = source_dir / "reports"
        env_file = source_dir / "aegispt-host.env"
        env_file.write_text(
            "\n".join(
                [
                    "APP_PUBLIC_BASE_URL=http://127.0.0.1:8000",
                    f"FIXTURE_SECRET={FIXTURE_SECRET_VALUE}",
                    "DATABASE_URL=sqlite+pysqlite:///./aegispt.db",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        reports_dir.mkdir(parents=True, exist_ok=True)
        (reports_dir / "README.txt").write_text("safe restore drill report placeholder\n", encoding="utf-8")

        database_url = f"sqlite+pysqlite:///{database_path}"
        require_alembic(database_url, "upgrade", "head")
        expected = seed_safe_fixture(database_url, artifacts_dir)
        backup_manifest = create_backup(
            output_dir=backup_dir,
            database_url=database_url,
            artifacts_dir=artifacts_dir,
            reports_dir=reports_dir,
            env_files=[env_file],
            config_files=[REPO_ROOT / "alembic.ini"],
        )
        restore_manifest = restore_backup(backup_dir=backup_dir, restore_dir=restore_dir)
        restored_database_url = restore_manifest["database_url"]
        current_output = require_alembic(restored_database_url, "current")
        heads_output = require_alembic(restored_database_url, "heads")
        database_checks = verify_restored_database(restore_manifest, expected)
        api_checks = verify_api_read_paths(restore_manifest, expected)
        assert_no_plaintext_secret(backup_dir)
        assert_no_plaintext_secret(restore_dir)

        return {
            "status": "ok",
            "fixture": "safe-local",
            "work_dir": str(root),
            "backup_dir": str(backup_dir),
            "restore_dir": str(restore_dir),
            "alembic_current": read_sqlite_alembic_version(Path(restore_manifest["database_path"])),
            "alembic_current_output": current_output,
            "alembic_heads_output": heads_output,
            "backup_database_sha256": backup_manifest["database"]["sha256"],
            "database_checks": database_checks,
            "api_checks": api_checks,
            "plaintext_secrets_exposed": False,
        }
    finally:
        if temp_context is not None:
            temp_context.cleanup()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Verify AegisPT backup/restore integrity.")
    parser.add_argument("--fixture", choices=["safe-local"])
    parser.add_argument("--work-dir", type=Path, default=None)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.fixture != "safe-local":
        raise SystemExit("--fixture safe-local is required for the built-in restore drill")
    result = run_safe_local_restore_drill(args.work_dir)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
