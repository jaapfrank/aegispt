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
def semgrep_target_dir(tmp_path: Path) -> str:
    target_dir = tmp_path / "sample-repo"
    target_dir.mkdir()
    (target_dir / "app.py").write_text(
        'password = "super-secret-token"\nprint(password)\n',
        encoding="utf-8",
    )
    return str(target_dir)


@pytest.fixture
def fake_semgrep_binary(tmp_path: Path) -> str:
    binary_path = tmp_path / "fake-semgrep"
    binary_path.write_text(
        """#!/usr/bin/env python3
import json
import sys
from pathlib import Path

args = sys.argv[1:]
if "--version" in args:
    print("semgrep 1.test")
    raise SystemExit(0)

output_path = Path(args[args.index("--output") + 1])
target_path = Path(args[-1])
target_file = target_path / "app.py"
payload = {
    "version": "1.test",
    "results": [
        {
            "check_id": "tmp.aegispt-semgrep-rule.aegispt.python.hardcoded-secret",
            "path": str(target_file),
            "start": {"line": 1, "col": 1},
            "end": {"line": 1, "col": 31},
            "extra": {
                "message": "Hardcoded secret assignment",
                "severity": "ERROR",
                "lines": "password = \\"super-secret-token\\"",
            },
        }
    ],
    "errors": [],
    "paths": {"scanned": [str(target_path)], "skipped": []},
}
output_path.write_text(json.dumps(payload), encoding="utf-8")
""",
        encoding="utf-8",
    )
    binary_path.chmod(0o755)
    return str(binary_path)


def test_inline_dispatch_executes_semgrep_task(
    inline_s3_client,
    monkeypatch: pytest.MonkeyPatch,
    semgrep_target_dir: str,
    fake_semgrep_binary: str,
    fake_s3_client: FakeS3Client,
) -> None:
    monkeypatch.setenv("SEMGREP_BINARY", fake_semgrep_binary)

    engagement_response = inline_s3_client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "tester"},
        json={
            "name": "Inline Semgrep Validation",
            "client": "Acme Corp",
            "roe_ref": "ROE-2026-013",
        },
    )
    engagement_id = engagement_response.json()["id"]

    inline_s3_client.post(
        f"/api/v1/engagements/{engagement_id}/scope",
        headers={"X-Actor": "tester"},
        json={"allowlist_json": {"paths": [semgrep_target_dir]}, "denylist_json": {}},
    )

    run_response = inline_s3_client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "tester"},
        json={"profile_name": "passive-code-semgrep-audit"},
    )
    run_payload = run_response.json()
    task_id = run_payload["tasks"][0]["id"]

    dispatch_response = inline_s3_client.post(
        f"/api/v1/runs/{run_payload['id']}/dispatch",
        headers={"X-Actor": "dispatcher"},
    )

    assert dispatch_response.status_code == 200
    dispatch_payload = dispatch_response.json()
    assert dispatch_payload["run"]["status"] == "completed"
    assert dispatch_payload["run"]["tasks"][0]["tool"] == "semgrep"
    assert dispatch_payload["run"]["findings"]["finding_count"] == 1
    assert dispatch_payload["run"]["findings"]["findings_by_severity"] == {"high": 1}

    task_response = inline_s3_client.get(f"/api/v1/tasks/{task_id}")
    task_payload = task_response.json()
    execution = task_payload["executions"][0]
    artifact = execution["artifacts"][0]

    assert task_payload["status"] == "completed"
    assert execution["tool_version"] == "semgrep 1.test"
    assert execution["exit_code"] == 0
    assert artifact["metadata_json"]["name"] == "semgrep-results.json"
    assert artifact["metadata_json"]["rule_source"] == "aegispt-curated"
    assert len(artifact["metadata_json"]["rule_sha256"]) == 64
    assert artifact["redaction_state"] == "redacted"
    assert fake_s3_client.objects

    content_response = inline_s3_client.get(f"/api/v1/artifacts/{artifact['id']}/content")
    content_payload = content_response.json()

    assert content_response.status_code == 200
    assert "super-secret-token" not in content_response.text
    assert "[REDACTED]" in content_response.text
    assert content_payload["runs"][0]["results"][0]["check_id"] == "aegispt.python.hardcoded-secret"

    findings_response = inline_s3_client.get(f"/api/v1/runs/{run_payload['id']}/findings")
    findings_payload = findings_response.json()

    assert findings_response.status_code == 200
    assert len(findings_payload) == 1
    assert findings_payload[0]["title"] == "Hardcoded secret assignment"
    assert findings_payload[0]["severity"] == "high"
    assert findings_payload[0]["status"] == "open"
    assert (
        findings_payload[0]["summary"]
        == f"Semgrep rule aegispt.python.hardcoded-secret matched at {semgrep_target_dir}/app.py:1."
    )
    assert findings_payload[0]["target_id"].endswith("app.py")
    assert findings_payload[0]["ptes_phase"] == "vulnerability_analysis"
    assert findings_payload[0]["nist_phase"] == "discovery"
    assert findings_payload[0]["wstg_id"] is None
    assert findings_payload[0]["control_family"] == "secure_code_review"
    assert "static-analysis" in findings_payload[0]["methodology_tags"]
