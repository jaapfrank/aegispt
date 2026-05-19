from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from api.app.config import Settings


@dataclass(slots=True, frozen=True)
class ArtifactStorageConfig:
    mode: str
    endpoint: str
    bucket: str
    access_key: str
    secret_key: str
    inline_dir: str
    enforce_sse: bool = False


@dataclass(slots=True, frozen=True)
class StoredArtifactReference:
    uri: str
    metadata: dict[str, Any]


@dataclass(slots=True, frozen=True)
class ArtifactContent:
    data: bytes
    content_type: str


def normalize_storage_mode(mode: str) -> str:
    normalized = mode.strip().lower()
    if normalized in {"", "inline"}:
        return "inline"
    if normalized == "s3":
        return normalized
    raise ValueError(f"unsupported artifact storage mode: {mode}")


def artifact_storage_config_from_settings(settings: Settings) -> ArtifactStorageConfig:
    return ArtifactStorageConfig(
        mode=normalize_storage_mode(settings.artifacts_storage_mode),
        endpoint=settings.artifacts_s3_endpoint,
        bucket=settings.artifacts_s3_bucket,
        access_key=settings.artifacts_s3_access_key,
        secret_key=settings.artifacts_s3_secret_key,
        inline_dir=settings.artifacts_inline_dir,
        enforce_sse=settings.artifacts_s3_enforce_sse,
    )


def artifact_storage_config_from_env() -> ArtifactStorageConfig:
    return ArtifactStorageConfig(
        mode=normalize_storage_mode(os.getenv("ARTIFACTS_STORAGE_MODE", "inline")),
        endpoint=os.getenv("ARTIFACTS_S3_ENDPOINT", "http://localhost:9000"),
        bucket=os.getenv("ARTIFACTS_S3_BUCKET", "aegispt-artifacts"),
        access_key=os.getenv("ARTIFACTS_S3_ACCESS_KEY", "minioadmin"),
        secret_key=os.getenv("ARTIFACTS_S3_SECRET_KEY", "change-me"),
        inline_dir=os.getenv("ARTIFACTS_INLINE_DIR", ".aegispt-artifacts"),
        enforce_sse=os.getenv("ARTIFACTS_S3_ENFORCE_SSE", "false").strip().lower()
        in {"1", "true", "yes", "on"},
    )


def build_s3_client(config: ArtifactStorageConfig):
    return boto3.client(
        "s3",
        endpoint_url=config.endpoint,
        aws_access_key_id=config.access_key,
        aws_secret_access_key=config.secret_key,
        region_name="us-east-1",
        config=Config(signature_version="s3v4", s3={"addressing_style": "path"}),
    )


def build_inline_artifact_uri(task_id: str, artifact_name: str) -> str:
    return f"inline://tasks/{task_id}/{artifact_name}"


def build_inline_stored_artifact_uri(
    *,
    run_id: str,
    task_id: str,
    execution_id: str,
    artifact_name: str,
    artifact_digest: str,
) -> str:
    object_key = build_artifact_object_key(
        run_id=run_id,
        task_id=task_id,
        execution_id=execution_id,
        artifact_name=artifact_name,
        artifact_digest=artifact_digest,
    )
    return f"inline://{object_key}"


def parse_inline_artifact_uri(uri: str) -> str:
    if not uri.startswith("inline://"):
        raise ValueError(f"unsupported inline artifact uri: {uri}")
    object_key = uri.removeprefix("inline://").lstrip("/")
    if not object_key or object_key.startswith("../") or "/../" in object_key:
        raise ValueError(f"invalid inline artifact uri: {uri}")
    return object_key


def parse_s3_artifact_uri(uri: str) -> tuple[str, str]:
    if not uri.startswith("s3://"):
        raise ValueError(f"unsupported artifact uri: {uri}")
    _, remainder = uri.split("s3://", maxsplit=1)
    bucket, _, key = remainder.partition("/")
    if not bucket or not key:
        raise ValueError(f"invalid s3 artifact uri: {uri}")
    return bucket, key


def sanitize_artifact_name(name: str) -> str:
    sanitized = re.sub(r"[^A-Za-z0-9._-]+", "-", name.strip())
    sanitized = sanitized.strip(".-")
    return sanitized or "artifact.bin"


def build_artifact_object_key(
    *,
    run_id: str,
    task_id: str,
    execution_id: str,
    artifact_name: str,
    artifact_digest: str,
) -> str:
    safe_name = sanitize_artifact_name(artifact_name)
    return (
        f"runs/{run_id}/tasks/{task_id}/executions/{execution_id}/"
        f"{artifact_digest[:16]}-{safe_name}"
    )


def ensure_bucket_exists(client, bucket: str) -> None:
    try:
        client.head_bucket(Bucket=bucket)
        return
    except ClientError as exc:
        error_code = str(exc.response.get("Error", {}).get("Code", "")).strip()
        if error_code not in {"404", "NoSuchBucket", "NotFound"}:
            raise

    try:
        client.create_bucket(Bucket=bucket)
    except ClientError as exc:
        error_code = str(exc.response.get("Error", {}).get("Code", "")).strip()
        if error_code not in {"BucketAlreadyOwnedByYou", "BucketAlreadyExists"}:
            raise


def store_artifact_bytes(
    *,
    config: ArtifactStorageConfig,
    artifact_name: str,
    artifact_kind: str,
    artifact_digest: str,
    content_type: str,
    data: bytes,
    run_id: str,
    task_id: str,
    execution_id: str,
) -> StoredArtifactReference:
    if config.mode != "s3":
        object_key = build_artifact_object_key(
            run_id=run_id,
            task_id=task_id,
            execution_id=execution_id,
            artifact_name=artifact_name,
            artifact_digest=artifact_digest,
        )
        inline_root = Path(config.inline_dir)
        inline_path = inline_root / object_key
        inline_path.parent.mkdir(parents=True, exist_ok=True)
        inline_path.write_bytes(data)
        return StoredArtifactReference(
            uri=f"inline://{object_key}",
            metadata={
                "storage_backend": "inline",
                "inline_object_key": object_key,
            },
        )

    client = build_s3_client(config)
    ensure_bucket_exists(client, config.bucket)

    object_key = build_artifact_object_key(
        run_id=run_id,
        task_id=task_id,
        execution_id=execution_id,
        artifact_name=artifact_name,
        artifact_digest=artifact_digest,
    )
    put_kwargs: dict[str, object] = {
        "Bucket": config.bucket,
        "Key": object_key,
        "Body": data,
        "ContentType": content_type,
        "Metadata": {
            "artifact-kind": artifact_kind,
            "sha256": artifact_digest,
            "run-id": run_id,
            "task-id": task_id,
            "execution-id": execution_id,
        },
    }
    if config.enforce_sse:
        put_kwargs["ServerSideEncryption"] = "AES256"
    client.put_object(**put_kwargs)

    return StoredArtifactReference(
        uri=f"s3://{config.bucket}/{object_key}",
        metadata={
            "storage_backend": "s3",
            "bucket": config.bucket,
            "object_key": object_key,
        },
    )


def store_artifact_bytes_with_fallback(
    *,
    config: ArtifactStorageConfig,
    artifact_name: str,
    artifact_kind: str,
    artifact_digest: str,
    content_type: str,
    data: bytes,
    run_id: str,
    task_id: str,
    execution_id: str,
) -> StoredArtifactReference:
    try:
        return store_artifact_bytes(
            config=config,
            artifact_name=artifact_name,
            artifact_kind=artifact_kind,
            artifact_digest=artifact_digest,
            content_type=content_type,
            data=data,
            run_id=run_id,
            task_id=task_id,
            execution_id=execution_id,
        )
    except Exception as exc:
        return StoredArtifactReference(
            uri=build_inline_artifact_uri(task_id=task_id, artifact_name=artifact_name),
            metadata={
                "storage_backend": "inline-fallback",
                "storage_error": str(exc),
            },
        )


def load_artifact_content(*, config: ArtifactStorageConfig, uri: str) -> ArtifactContent | None:
    if uri.startswith("inline://"):
        try:
            object_key = parse_inline_artifact_uri(uri)
        except ValueError:
            return None
        inline_path = Path(config.inline_dir) / object_key
        if not inline_path.is_file():
            return None
        return ArtifactContent(data=inline_path.read_bytes(), content_type="application/octet-stream")

    if not uri.startswith("s3://"):
        return None

    bucket, object_key = parse_s3_artifact_uri(uri)
    client = build_s3_client(config)
    response = client.get_object(Bucket=bucket, Key=object_key)
    body = response["Body"].read()
    content_type = str(response.get("ContentType") or "application/octet-stream")

    return ArtifactContent(data=body, content_type=content_type)
