from __future__ import annotations

from io import BytesIO

import pytest
from botocore.exceptions import ClientError


class FakeS3Client:
    def __init__(self) -> None:
        self.buckets: set[str] = set()
        self.objects: dict[tuple[str, str], dict[str, object]] = {}

    def head_bucket(self, *, Bucket: str) -> None:  # noqa: N803
        if Bucket not in self.buckets:
            raise ClientError({"Error": {"Code": "404"}}, "HeadBucket")

    def create_bucket(self, *, Bucket: str) -> None:  # noqa: N803
        self.buckets.add(Bucket)

    def put_object(
        self,
        *,
        Bucket: str,  # noqa: N803
        Key: str,  # noqa: N803
        Body: bytes,  # noqa: N803
        ContentType: str,  # noqa: N803
        Metadata: dict[str, str],  # noqa: N803
        ServerSideEncryption: str | None = None,  # noqa: N803
    ) -> None:
        self.buckets.add(Bucket)
        self.objects[(Bucket, Key)] = {
            "body": bytes(Body),
            "content_type": ContentType,
            "metadata": dict(Metadata),
            "server_side_encryption": ServerSideEncryption,
        }

    def get_object(self, *, Bucket: str, Key: str) -> dict[str, object]:  # noqa: N803
        stored = self.objects[(Bucket, Key)]
        return {
            "Body": BytesIO(stored["body"]),
            "ContentType": stored["content_type"],
            "Metadata": stored["metadata"],
        }


@pytest.fixture
def fake_s3_client(monkeypatch: pytest.MonkeyPatch) -> FakeS3Client:
    client = FakeS3Client()

    from api.app.services import artifact_storage

    monkeypatch.setattr(artifact_storage, "build_s3_client", lambda config: client)
    return client


def test_inline_dispatch_stores_artifact_in_s3_and_serves_content(
    inline_s3_client,
    probe_server: str,
    fake_s3_client: FakeS3Client,
) -> None:
    engagement_response = inline_s3_client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "tester"},
        json={
            "name": "S3 Artifact Validation",
            "client": "Acme Corp",
            "roe_ref": "ROE-2026-006",
        },
    )
    engagement_id = engagement_response.json()["id"]

    inline_s3_client.post(
        f"/api/v1/engagements/{engagement_id}/scope",
        headers={"X-Actor": "tester"},
        json={
            "allowlist_json": {
                "urls": [probe_server],
            },
            "denylist_json": {},
        },
    )

    run_response = inline_s3_client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "tester"},
        json={"profile_name": "passive-web-baseline"},
    )
    run_payload = run_response.json()
    task_id = run_payload["tasks"][0]["id"]

    dispatch_response = inline_s3_client.post(
        f"/api/v1/runs/{run_payload['id']}/dispatch",
        headers={"X-Actor": "dispatcher"},
    )

    assert dispatch_response.status_code == 200
    task_response = inline_s3_client.get(f"/api/v1/tasks/{task_id}")
    task_payload = task_response.json()
    artifact = task_payload["executions"][0]["artifacts"][0]

    assert artifact["uri"].startswith("s3://aegispt-artifacts/")
    assert artifact["metadata_json"]["storage_backend"] == "s3"
    assert len(fake_s3_client.objects) >= 1

    content_response = inline_s3_client.get(f"/api/v1/artifacts/{artifact['id']}/content")

    assert content_response.status_code == 200
    assert content_response.headers["content-type"].startswith("application/x-ndjson")
    assert b'"status_code": 200' in content_response.content


def test_s3_artifact_storage_can_enforce_sse(fake_s3_client: FakeS3Client) -> None:
    from api.app.services import artifact_storage
    from api.app.services.artifact_storage import ArtifactStorageConfig

    config = ArtifactStorageConfig(
        mode="s3",
        endpoint="http://localhost:9000",
        bucket="aegispt-artifacts",
        access_key="minioadmin",
        secret_key="change-me",
        inline_dir=".aegispt-artifacts",
        enforce_sse=True,
    )

    reference = artifact_storage.store_artifact_bytes(
        config=config,
        artifact_name="evidence.json",
        artifact_kind="evidence",
        artifact_digest="a" * 64,
        content_type="application/json",
        data=b"{}",
        run_id="run-1",
        task_id="task-1",
        execution_id="exec-1",
    )

    bucket, key = artifact_storage.parse_s3_artifact_uri(reference.uri)
    assert fake_s3_client.objects[(bucket, key)]["server_side_encryption"] == "AES256"
