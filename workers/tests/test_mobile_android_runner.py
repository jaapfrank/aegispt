from __future__ import annotations

import json
from types import SimpleNamespace
import zipfile

from workers.orchestration.findings import extract_findings
from workers.runners.base.contracts import EvidenceArtifact
from workers.runners.mobile_android.runner import (
    MOBILE_ANDROID_INVENTORY_ARTIFACT_NAME,
    MOBILE_ANDROID_RESULTS_ARTIFACT_NAME,
    execute_mobile_android_static,
)


class ArtifactRecord:
    uri = "artifact://mobile-android/results"


def build_fixture_apk(path) -> None:
    manifest = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.vulnerable">
  <uses-sdk android:minSdkVersion="23" android:targetSdkVersion="35" />
  <uses-permission android:name="android.permission.READ_SMS" />
  <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE" />
  <application
      android:allowBackup="true"
      android:debuggable="true"
      android:usesCleartextTraffic="true"
      android:networkSecurityConfig="@xml/network_security_config">
    <activity android:name=".MainActivity" android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.MAIN" />
      </intent-filter>
    </activity>
    <provider android:name=".SecretsProvider" android:exported="true" />
  </application>
</manifest>
"""
    network_security = """<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
  <base-config cleartextTrafficPermitted="true">
    <trust-anchors>
      <certificates src="user" />
    </trust-anchors>
  </base-config>
</network-security-config>
"""
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", manifest)
        archive.writestr("res/xml/network_security_config.xml", network_security)
        archive.writestr("assets/config.properties", "api_key = abcdefghijklmnopqrstuvwxyz123456")
        archive.writestr("res/xml/prefs.xml", "<map><!-- SharedPreferences marker --></map>")


def test_mobile_android_static_apk_review_creates_evidence_backed_findings(tmp_path) -> None:
    apk_path = tmp_path / "vulnerable.apk"
    build_fixture_apk(apk_path)

    execution = execute_mobile_android_static(
        [str(apk_path)],
        scope_allowlist={"apk_paths": [str(apk_path)]},
        dynamic_prerequisites={"proxy_ready": True},
    )

    assert execution.exit_code == 0
    assert execution.tool == "mobile-android"
    assert execution.metadata["status"] == "completed"
    assert execution.metadata["package_name"] == "com.example.vulnerable"
    artifact_names = {artifact.name for artifact in execution.artifacts}
    assert MOBILE_ANDROID_RESULTS_ARTIFACT_NAME in artifact_names
    assert MOBILE_ANDROID_INVENTORY_ARTIFACT_NAME in artifact_names

    results_artifact = next(
        artifact for artifact in execution.artifacts if artifact.name == MOBILE_ANDROID_RESULTS_ARTIFACT_NAME
    )
    payload = json.loads(results_artifact.data.decode("utf-8"))
    assert payload["safety"]["emulator_orchestration"] is False
    assert payload["dynamic_preparation"]["executed"] is False
    assert "dynamic_analysis_not_run" in payload["unsupported_states"]
    finding_types = {finding["type"] for finding in payload["findings"]}
    assert "android_debuggable_enabled" in finding_types
    assert "android_backup_allowed" in finding_types
    assert "android_cleartext_transport_allowed" in finding_types
    assert "android_exported_component" in finding_types
    assert "android_embedded_secret_indicator" in finding_types
    assert any(
        "MASVS" in " ".join(finding["methodology_tags"])
        and "MASTG" in " ".join(finding["methodology_tags"])
        for finding in payload["findings"]
    )

    task = SimpleNamespace(tool="mobile-android", target_id=str(apk_path), params_json={})
    findings = extract_findings(
        task=task,
        artifact=EvidenceArtifact(
            name=MOBILE_ANDROID_RESULTS_ARTIFACT_NAME,
            content_type="application/json",
            data=results_artifact.data,
            kind="mobile-android-results",
        ),
        artifact_record=ArtifactRecord(),
    )
    assert {finding.evidence_ref for finding in findings} == {ArtifactRecord.uri}
    assert "Android application is debuggable" in {finding.title for finding in findings}


def test_mobile_android_rejects_out_of_scope_apk(tmp_path) -> None:
    apk_path = tmp_path / "vulnerable.apk"
    build_fixture_apk(apk_path)
    outside_path = tmp_path / "outside.apk"
    build_fixture_apk(outside_path)

    try:
        execute_mobile_android_static(
            [str(outside_path)],
            scope_allowlist={"apk_paths": [str(apk_path)]},
        )
    except ValueError as exc:
        assert "outside scope" in str(exc)
    else:
        raise AssertionError("out-of-scope APK artifact was accepted")


def test_mobile_android_unsupported_artifact_type_is_truthful(tmp_path) -> None:
    artifact_path = tmp_path / "sample.ipa"
    artifact_path.write_text("not an apk", encoding="utf-8")

    execution = execute_mobile_android_static(
        [str(artifact_path)],
        scope_allowlist={"mobile_artifacts": [str(artifact_path)]},
    )

    assert execution.exit_code == 0
    assert execution.metadata["status"] == "skipped"
    assert execution.metadata["reason"] == "unsupported_mobile_artifact_type"
    payload = json.loads(execution.artifacts[0].data.decode("utf-8"))
    assert payload["safety"]["ios_testing"] is False


def test_mobile_android_missing_artifact_is_truthful(tmp_path) -> None:
    apk_path = tmp_path / "missing.apk"

    execution = execute_mobile_android_static(
        [str(apk_path)],
        scope_allowlist={"apk_paths": [str(apk_path)]},
    )

    assert execution.exit_code == 0
    assert execution.metadata["status"] == "skipped"
    assert execution.metadata["reason"] == "missing_mobile_artifact"


def test_mobile_android_invalid_apk_archive_is_truthful(tmp_path) -> None:
    apk_path = tmp_path / "broken.apk"
    apk_path.write_text("not a zip", encoding="utf-8")

    execution = execute_mobile_android_static(
        [str(apk_path)],
        scope_allowlist={"apk_paths": [str(apk_path)]},
    )

    assert execution.exit_code == 0
    assert execution.metadata["status"] == "skipped"
    assert execution.metadata["reason"] == "invalid_apk_archive"
