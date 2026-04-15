from __future__ import annotations

import json
from io import BytesIO
from pathlib import Path

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
    ) -> None:
        self.buckets.add(Bucket)
        self.objects[(Bucket, Key)] = {
            "body": bytes(Body),
            "content_type": ContentType,
            "metadata": dict(Metadata),
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


@pytest.fixture
def fake_nuclei_binary(tmp_path: Path) -> str:
    binary_path = tmp_path / "fake-nuclei"
    binary_path.write_text(
        """#!/usr/bin/env python3
import json
import sys
from pathlib import Path

args = sys.argv[1:]
if "-version" in args:
    print("nuclei v-test")
    raise SystemExit(0)

targets_path = Path(args[args.index("-l") + 1])
output_path = Path(args[args.index("-jsonl-export") + 1])
targets = [line.strip() for line in targets_path.read_text(encoding="utf-8").splitlines() if line.strip()]
results = [
    {
        "template-id": "aegispt-http-status-200",
        "info": {"severity": "info"},
        "matched-at": target,
    }
    for target in targets
]
output_path.write_text("\\n".join(json.dumps(result) for result in results) + ("\\n" if results else ""), encoding="utf-8")
print(output_path.read_text(encoding="utf-8"), end="")
""",
        encoding="utf-8",
    )
    binary_path.chmod(0o755)
    return str(binary_path)


def test_inline_dispatch_executes_nuclei_task(
    inline_client,
    monkeypatch: pytest.MonkeyPatch,
    fake_nuclei_binary: str,
) -> None:
    monkeypatch.setenv("NUCLEI_BINARY", fake_nuclei_binary)

    engagement_response = inline_client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "tester"},
        json={
            "name": "Inline Nuclei Validation",
            "client": "Acme Corp",
            "roe_ref": "ROE-2026-004",
        },
    )
    engagement_id = engagement_response.json()["id"]

    inline_client.post(
        f"/api/v1/engagements/{engagement_id}/scope",
        headers={"X-Actor": "tester"},
        json={
            "allowlist_json": {
                "urls": ["https://example.com"],
            },
            "denylist_json": {},
        },
    )

    run_response = inline_client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "tester"},
        json={"profile_name": "passive-web-nuclei-audit"},
    )
    run_payload = run_response.json()
    task_id = run_payload["tasks"][0]["id"]

    dispatch_response = inline_client.post(
        f"/api/v1/runs/{run_payload['id']}/dispatch",
        headers={"X-Actor": "dispatcher"},
    )

    assert dispatch_response.status_code == 200
    dispatch_payload = dispatch_response.json()
    assert dispatch_payload["run"]["status"] == "completed"
    assert dispatch_payload["run"]["tasks"][0]["tool"] == "nuclei"
    assert dispatch_payload["run"]["tasks"][0]["status"] == "completed"
    assert dispatch_payload["run"]["findings"]["finding_count"] == 1
    assert dispatch_payload["run"]["findings"]["findings_by_severity"] == {"info": 1}

    task_response = inline_client.get(f"/api/v1/tasks/{task_id}")
    task_payload = task_response.json()

    assert task_payload["status"] == "completed"
    assert task_payload["executions"][0]["tool_version"] == "nuclei v-test"
    assert task_payload["executions"][0]["exit_code"] == 0
    assert task_payload["executions"][0]["artifacts"][0]["metadata_json"]["name"] == "nuclei-results.jsonl"
    assert task_payload["executions"][0]["artifacts"][0]["metadata_json"]["template_id"] == "aegispt-http-status-200"
    assert task_payload["executions"][0]["artifacts"][0]["metadata_json"]["template_source"] == "aegispt-curated"
    assert len(task_payload["executions"][0]["artifacts"][0]["metadata_json"]["template_sha256"]) == 64

    findings_response = inline_client.get(f"/api/v1/runs/{run_payload['id']}/findings")
    findings_payload = findings_response.json()

    assert findings_response.status_code == 200
    assert len(findings_payload) == 1
    assert findings_payload[0]["title"] == "Nuclei: aegispt-http-status-200"
    assert findings_payload[0]["severity"] == "info"
    assert findings_payload[0]["status"] == "open"
    assert findings_payload[0]["evidence_ref"] == task_payload["executions"][0]["artifacts"][0]["uri"]
    assert findings_payload[0]["ptes_phase"] == "vulnerability_analysis"
    assert findings_payload[0]["nist_phase"] == "discovery"
    assert findings_payload[0]["control_family"] == "configuration"
    assert "template-validation" in findings_payload[0]["methodology_tags"]


@pytest.fixture
def fake_nuclei_binary_with_secret(tmp_path: Path) -> str:
    binary_path = tmp_path / "fake-nuclei-secret"
    binary_path.write_text(
        """#!/usr/bin/env python3
import json
import sys
from pathlib import Path

args = sys.argv[1:]
if "-version" in args:
    print("nuclei v-test")
    raise SystemExit(0)

targets_path = Path(args[args.index("-l") + 1])
output_path = Path(args[args.index("-jsonl-export") + 1])
targets = [line.strip() for line in targets_path.read_text(encoding="utf-8").splitlines() if line.strip()]
results = [
    {
        "template-id": "aegispt-http-status-200",
        "info": {"severity": "info"},
        "matched-at": target,
        "request": {
            "headers": {
                "authorization": "Bearer super-secret-token",
                "x-api-key": "nuclei-top-secret",
            }
        }
    }
    for target in targets
]
rendered = "\\n".join(json.dumps(result) for result in results) + ("\\n" if results else "")
output_path.write_text(rendered, encoding="utf-8")
print(rendered, end="")
print("curl 'https://example.com?apikey=super-secret-token'", file=sys.stderr)
""",
        encoding="utf-8",
    )
    binary_path.chmod(0o755)
    return str(binary_path)


def test_nuclei_outputs_are_redacted_before_storage(
    inline_s3_client,
    monkeypatch: pytest.MonkeyPatch,
    fake_nuclei_binary_with_secret: str,
    fake_s3_client: FakeS3Client,
) -> None:
    monkeypatch.setenv("NUCLEI_BINARY", fake_nuclei_binary_with_secret)

    engagement_response = inline_s3_client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "tester"},
        json={
            "name": "Nuclei Redaction Validation",
            "client": "Acme Corp",
            "roe_ref": "ROE-2026-012",
        },
    )
    engagement_id = engagement_response.json()["id"]

    inline_s3_client.post(
        f"/api/v1/engagements/{engagement_id}/scope",
        headers={"X-Actor": "tester"},
        json={"allowlist_json": {"urls": ["https://example.com"]}, "denylist_json": {}},
    )

    run_response = inline_s3_client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "tester"},
        json={"profile_name": "passive-web-nuclei-audit"},
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
    execution = task_payload["executions"][0]
    artifact = execution["artifacts"][0]

    assert "super-secret-token" not in execution["stdout_text"]
    assert "super-secret-token" not in execution["stderr_text"]
    assert "[REDACTED]" in execution["stdout_text"]
    assert "[REDACTED]" in execution["stderr_text"]
    assert artifact["redaction_state"] == "redacted"
    assert artifact["metadata_json"]["redaction_count"] >= 2
    assert len(fake_s3_client.objects) == 1

    content_response = inline_s3_client.get(f"/api/v1/artifacts/{artifact['id']}/content")

    assert content_response.status_code == 200
    artifact_lines = [line for line in content_response.text.splitlines() if line.strip()]
    first_line = json.loads(artifact_lines[0])
    authorization_value = first_line["request"]["headers"]["authorization"]
    api_key_value = first_line["request"]["headers"]["x-api-key"]
    assert authorization_value == "[REDACTED]"
    assert api_key_value == "[REDACTED]"
    assert "super-secret-token" not in content_response.text
