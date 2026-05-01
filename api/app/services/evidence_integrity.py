from __future__ import annotations

import hashlib
import subprocess
import tempfile
import urllib.request
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app.config import Settings
from api.app.models import AuditEvent, EvidenceArtifact, Finding, Run
from api.app.schemas.evidence_integrity import (
    EvidenceIntegrityResultRead,
    RunEvidenceIntegrityResultRead,
)
from api.app.services.artifact_storage import (
    ArtifactStorageConfig,
    artifact_storage_config_from_settings,
    load_artifact_content,
    store_artifact_bytes_with_fallback,
)
from api.app.services.audit import write_audit_event

HASH_UNAVAILABLE = "hash-unavailable"
TIMESTAMP_UNAVAILABLE = "timestamp-unavailable"
TIMESTAMP_DISABLED = "timestamp-disabled"
TIMESTAMP_VERIFIED = "timestamp-verified"
TIMESTAMP_FAILED = "timestamp-failed"


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def flag_artifact_hash_status(
    *,
    artifact: EvidenceArtifact,
    metadata: dict[str, Any] | None = None,
) -> None:
    artifact.metadata_json = {
        **dict(artifact.metadata_json or {}),
        "hash_status": "sha256-recorded" if artifact.sha256 != HASH_UNAVAILABLE else HASH_UNAVAILABLE,
        **dict(metadata or {}),
    }


def _store_timestamp_response(
    *,
    settings: Settings,
    storage_config: ArtifactStorageConfig,
    artifact_name: str,
    data: bytes,
    run_id: str,
    task_id: str,
    execution_id: str,
) -> dict[str, Any]:
    if not settings.evidence_timestamping_enabled:
        return {"timestamp_status": TIMESTAMP_DISABLED}

    tsa_url = settings.evidence_timestamp_authority_url.strip()
    if not tsa_url:
        return {"timestamp_status": TIMESTAMP_DISABLED}

    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            data_path = f"{tmpdir}/artifact.bin"
            query_path = f"{tmpdir}/artifact.tsq"
            with open(data_path, "wb") as handle:
                handle.write(data)
            subprocess.run(
                [
                    settings.evidence_timestamp_openssl_binary,
                    "ts",
                    "-query",
                    "-data",
                    data_path,
                    "-sha256",
                    "-cert",
                    "-out",
                    query_path,
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            with open(query_path, "rb") as handle:
                timestamp_query = handle.read()
        request = urllib.request.Request(
            tsa_url,
            data=timestamp_query,
            headers={
                "Content-Type": "application/timestamp-query",
                "Accept": "application/timestamp-reply",
            },
            method="POST",
        )
        with urllib.request.urlopen(
            request,
            timeout=max(0.1, float(settings.evidence_timestamp_timeout_seconds)),
        ) as response:
            timestamp_reply = response.read()
        if not timestamp_reply:
            raise RuntimeError("empty timestamp authority response")
        timestamp_digest = sha256_hex(timestamp_reply)
        sidecar = store_artifact_bytes_with_fallback(
            config=storage_config,
            artifact_name=f"{artifact_name}.tsr",
            artifact_kind="timestamp-response",
            artifact_digest=timestamp_digest,
            content_type="application/timestamp-reply",
            data=timestamp_reply,
            run_id=run_id,
            task_id=task_id,
            execution_id=execution_id,
        )
        return {
            "timestamp_status": "stored",
            "timestamp_authority_url": tsa_url,
            "timestamp_response_uri": sidecar.uri,
            "timestamp_response_sha256": timestamp_digest,
            "timestamp_requested_at": datetime.now(UTC).isoformat(),
            "timestamp_storage_backend": sidecar.metadata.get("storage_backend"),
            "timestamp_inline_object_key": sidecar.metadata.get("inline_object_key"),
            "timestamp_s3_object_key": sidecar.metadata.get("object_key"),
        }
    except Exception as exc:
        return {
            "timestamp_status": TIMESTAMP_UNAVAILABLE,
            "timestamp_authority_url": tsa_url,
            "timestamp_error": str(exc),
            "timestamp_requested_at": datetime.now(UTC).isoformat(),
        }


def apply_artifact_integrity_metadata(
    *,
    settings: Settings,
    storage_config: ArtifactStorageConfig,
    artifact_record: EvidenceArtifact,
    artifact_name: str,
    data: bytes,
    run_id: str,
    task_id: str,
    execution_id: str,
) -> None:
    metadata = dict(artifact_record.metadata_json or {})
    metadata["content_sha256"] = artifact_record.sha256
    metadata["hash_status"] = "sha256-recorded"
    timestamp_metadata = _store_timestamp_response(
        settings=settings,
        storage_config=storage_config,
        artifact_name=artifact_name,
        data=data,
        run_id=run_id,
        task_id=task_id,
        execution_id=execution_id,
    )
    metadata.update(timestamp_metadata)
    timestamp_uri = timestamp_metadata.get("timestamp_response_uri")
    artifact_record.timestamp_token_uri = (
        str(timestamp_uri).strip() if isinstance(timestamp_uri, str) and timestamp_uri.strip() else None
    )
    artifact_record.metadata_json = metadata


def _load_artifact_for_finding(session: Session, finding: Finding) -> EvidenceArtifact | None:
    if not finding.evidence_ref:
        return None
    return session.scalar(select(EvidenceArtifact).where(EvidenceArtifact.uri == finding.evidence_ref))


def _verify_timestamp(
    *,
    settings: Settings,
    storage_config: ArtifactStorageConfig,
    artifact_data: bytes,
    artifact: EvidenceArtifact,
) -> tuple[str, str | None]:
    metadata = dict(artifact.metadata_json or {})
    timestamp_uri = metadata.get("timestamp_response_uri") or artifact.timestamp_token_uri
    if not isinstance(timestamp_uri, str) or not timestamp_uri.strip():
        return str(metadata.get("timestamp_status") or TIMESTAMP_UNAVAILABLE), timestamp_uri

    timestamp_content = load_artifact_content(config=storage_config, uri=timestamp_uri)
    if timestamp_content is None:
        return TIMESTAMP_UNAVAILABLE, timestamp_uri

    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            data_path = f"{tmpdir}/artifact.bin"
            tsr_path = f"{tmpdir}/artifact.tsr"
            with open(data_path, "wb") as handle:
                handle.write(artifact_data)
            with open(tsr_path, "wb") as handle:
                handle.write(timestamp_content.data)
            result = subprocess.run(
                [
                    settings.evidence_timestamp_openssl_binary,
                    "ts",
                    "-verify",
                    "-in",
                    tsr_path,
                    "-data",
                    data_path,
                ],
                capture_output=True,
                text=True,
                check=False,
            )
        if result.returncode == 0:
            return TIMESTAMP_VERIFIED, timestamp_uri
        return TIMESTAMP_FAILED, timestamp_uri
    except Exception:
        return TIMESTAMP_UNAVAILABLE, timestamp_uri


def verify_finding_evidence(
    *,
    session: Session,
    finding: Finding,
    settings: Settings,
    actor: str,
) -> EvidenceIntegrityResultRead:
    verified_at = datetime.now(UTC)
    storage_config = artifact_storage_config_from_settings(settings)
    artifact = _load_artifact_for_finding(session, finding)
    status = "unavailable"
    detail = "No linked artifact record could be found for this finding."
    current_sha256: str | None = None
    timestamp_status = "not-available"
    timestamp_response_uri: str | None = None

    if artifact is not None:
        content = load_artifact_content(config=storage_config, uri=artifact.uri)
        if content is None:
            status = "hash-unavailable"
            detail = "Linked artifact content is not readable on this storage backend."
        else:
            current_sha256 = sha256_hex(content.data)
            if artifact.sha256 == current_sha256:
                status = "verified"
                detail = "Verified: stored SHA-256 matches the current artifact bytes."
            else:
                status = "integrity-failure"
                detail = "INTEGRITY FAILURE: stored SHA-256 does not match current artifact bytes."
            timestamp_status, timestamp_response_uri = _verify_timestamp(
                settings=settings,
                storage_config=storage_config,
                artifact_data=content.data,
                artifact=artifact,
            )
            if timestamp_response_uri and not artifact.timestamp_token_uri:
                artifact.timestamp_token_uri = timestamp_response_uri
            if timestamp_status == TIMESTAMP_VERIFIED:
                artifact.timestamp_verified_at = verified_at

    event = write_audit_event(
        session=session,
        actor=actor,
        action="finding.evidence_integrity.verified",
        object_type="finding",
        object_id=str(finding.id),
        metadata={
            "status": status,
            "artifact_id": str(artifact.id) if artifact is not None else None,
            "artifact_uri": artifact.uri if artifact is not None else None,
            "stored_sha256": artifact.sha256 if artifact is not None else None,
            "current_sha256": current_sha256,
            "timestamp_status": timestamp_status,
            "timestamp_response_uri": timestamp_response_uri,
            "verified_at": verified_at.isoformat(),
        },
    )
    session.flush()

    return _result_from_event(
        finding=finding,
        artifact=artifact,
        event=event,
        status=status,
        current_sha256=current_sha256,
        timestamp_status=timestamp_status,
        timestamp_response_uri=timestamp_response_uri,
        verified_at=verified_at,
        detail=detail,
    )


def _result_from_event(
    *,
    finding: Finding,
    artifact: EvidenceArtifact | None,
    event: AuditEvent,
    status: str,
    current_sha256: str | None,
    timestamp_status: str,
    timestamp_response_uri: str | None,
    verified_at: datetime,
    detail: str | None,
) -> EvidenceIntegrityResultRead:
    return EvidenceIntegrityResultRead(
        finding_id=finding.id,
        status=status,
        artifact_id=artifact.id if artifact is not None else None,
        artifact_uri=artifact.uri if artifact is not None else None,
        stored_sha256=artifact.sha256 if artifact is not None else None,
        current_sha256=current_sha256,
        timestamp_status=timestamp_status,
        timestamp_response_uri=timestamp_response_uri,
        verified_at=verified_at,
        audit_event_id=event.id,
        detail=detail,
    )


def verify_run_evidence(
    *,
    session: Session,
    run: Run,
    settings: Settings,
    actor: str,
) -> RunEvidenceIntegrityResultRead:
    findings = session.scalars(
        select(Finding).where(Finding.run_id == run.id).order_by(Finding.created_at, Finding.id)
    ).all()
    results = [
        verify_finding_evidence(
            session=session,
            finding=finding,
            settings=settings,
            actor=actor,
        )
        for finding in findings
    ]
    verified = sum(1 for result in results if result.status == "verified")
    integrity_failures = sum(1 for result in results if result.status == "integrity-failure")
    unavailable = sum(1 for result in results if result.status not in {"verified", "integrity-failure"})
    status = "verified" if results and verified == len(results) else "needs-review"
    if integrity_failures:
        status = "integrity-failure"
    elif unavailable and not integrity_failures:
        status = "partial"

    return RunEvidenceIntegrityResultRead(
        run_id=run.id,
        verified_at=datetime.now(UTC),
        status=status,
        total_findings=len(results),
        verified=verified,
        integrity_failures=integrity_failures,
        unavailable=unavailable,
        results=results,
        summary={
            "verified": verified,
            "integrity_failures": integrity_failures,
            "unavailable": unavailable,
        },
    )
