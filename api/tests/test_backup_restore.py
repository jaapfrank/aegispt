from __future__ import annotations

import json

from scripts.backup_aegispt import is_sensitive_key, read_redacted_env_file
from scripts.verify_restore import FIXTURE_SECRET_VALUE, run_safe_local_restore_drill


def test_safe_local_restore_drill_preserves_evidence_and_audit(tmp_path) -> None:
    result = run_safe_local_restore_drill(tmp_path)

    assert result["status"] == "ok"
    assert result["database_checks"]["counts"]["engagements"] == 1
    assert result["database_checks"]["counts"]["runs"] == 1
    assert result["database_checks"]["counts"]["findings"] == 1
    assert result["database_checks"]["counts"]["artifacts"] == 1
    assert result["database_checks"]["counts"]["audit_events"] == 1
    assert result["database_checks"]["artifact_hash_verified"] is True
    assert result["database_checks"]["finding_evidence_ref_verified"] is True
    assert result["database_checks"]["secret_metadata_verified"] is True
    assert result["api_checks"]["health_status"] == 200
    assert result["api_checks"]["engagements_status"] == 200
    assert result["api_checks"]["run_status"] == 200
    assert result["api_checks"]["artifact_status"] == 200
    assert result["plaintext_secrets_exposed"] is False

    backup_manifest = json.loads((tmp_path / "backup" / "backup-manifest.json").read_text())
    assert backup_manifest["secrets_policy"]["plaintext_secrets_in_manifest"] is False
    assert FIXTURE_SECRET_VALUE not in (tmp_path / "backup" / "backup-manifest.json").read_text()


def test_backup_env_redaction_never_exposes_secret_values(tmp_path) -> None:
    env_file = tmp_path / "aegispt-host.env"
    env_file.write_text(
        "\n".join(
            [
                "APP_PUBLIC_BASE_URL=http://127.0.0.1:8000",
                "AEGISPT_DB_KEY=super-secret-db-key",
                "CHATGPT_OAUTH_CLIENT_ID=public-client-id",
                "CHATGPT_OAUTH_CLIENT_SECRET=super-secret-client-secret",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    redacted = read_redacted_env_file(env_file)
    by_key = {entry["key"]: entry["value"] for entry in redacted}

    assert is_sensitive_key("AEGISPT_DB_KEY")
    assert by_key["APP_PUBLIC_BASE_URL"] == "http://127.0.0.1:8000"
    assert by_key["AEGISPT_DB_KEY"] == "<redacted>"
    assert by_key["CHATGPT_OAUTH_CLIENT_ID"] == "public-client-id"
    assert by_key["CHATGPT_OAUTH_CLIENT_SECRET"] == "<redacted>"
