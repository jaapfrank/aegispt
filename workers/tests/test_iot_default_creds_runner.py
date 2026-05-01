from __future__ import annotations

from base64 import b64encode
import json
from urllib.parse import parse_qs

from workers.runners.iot_default_creds.runner import (
    HttpResponse,
    IOT_DEFAULT_CREDS_ARTIFACT_NAME,
    execute_iot_default_credential_audit,
    load_default_credentials,
)
from workers.orchestration.findings import extract_iot_default_credential_findings


def _artifact_payload(execution):
    artifact = next(item for item in execution.artifacts if item.name == IOT_DEFAULT_CREDS_ARTIFACT_NAME)
    return json.loads(artifact.data.decode("utf-8"))


def test_default_credential_database_contains_required_breadth() -> None:
    credentials = load_default_credentials()

    assert len(credentials) >= 50
    assert any(item["vendor"] == "Ubiquiti" and item["username"] == "ubnt" for item in credentials)
    assert any(item["vendor"] == "Philips" and item["no_auth_expected"] for item in credentials)
    assert any(item["vendor"] == "QNAP" and item["username"] == "admin" for item in credentials)


def test_basic_auth_success_creates_critical_redacted_finding_from_inventory() -> None:
    expected_auth = "Basic " + b64encode(b"ubnt:ubnt").decode("ascii")

    def fake_http_client(url, method, headers, data, timeout_seconds):
        if headers.get("Authorization") == expected_auth:
            return HttpResponse(200, {}, "UniFi dashboard", url)
        return HttpResponse(401, {"www-authenticate": "Basic realm=\"UniFi\""}, "Unauthorized", url)

    execution = execute_iot_default_credential_audit(
        targets=["10.0.20.0/24"],
        scope_allowlist={"cidr_ranges": ["10.0.20.0/24"]},
        inventory={
            "http_endpoints": [{"url": "http://10.0.20.10/", "title": "UniFi Network"}],
            "vendor_product_fingerprints": [{"vendor": "Ubiquiti", "product": "UniFi"}],
        },
        http_client=fake_http_client,
        sleep_func=lambda seconds: None,
    )

    payload = _artifact_payload(execution)

    assert execution.exit_code == 0
    assert payload["analysis_findings"][0]["severity"] == "critical"
    assert payload["analysis_findings"][0]["title"] == "Default manufacturer credentials accepted"
    assert payload["targets"][0]["attempts"][0]["username"] == "ubnt"
    assert payload["targets"][0]["attempts"][0]["password"] == "[REDACTED]"
    assert "ubnt:ubnt" not in json.dumps(payload)


def test_no_auth_known_device_creates_high_finding_without_credential_attempt() -> None:
    calls = []

    def fake_http_client(url, method, headers, data, timeout_seconds):
        calls.append((method, headers, data))
        return HttpResponse(200, {}, "{\"name\":\"Philips hue\"}", url)

    execution = execute_iot_default_credential_audit(
        targets=["10.0.20.0/24"],
        scope_allowlist={"cidr_ranges": ["10.0.20.0/24"]},
        inventory={
            "devices": [
                {
                    "ip": "10.0.20.11",
                    "port": 80,
                    "presentation_url": "http://10.0.20.11/",
                    "manufacturer": "Philips",
                    "model_name": "Hue Bridge",
                    "device_type": "smart-lighting-bridge",
                }
            ]
        },
        http_client=fake_http_client,
    )
    payload = _artifact_payload(execution)

    assert len(calls) == 1
    assert payload["analysis_findings"][0]["severity"] == "high"
    assert payload["analysis_findings"][0]["title"] == "Management interface accessible without authentication"
    assert payload["targets"][0]["no_auth_accessible"] is True


def test_rate_limit_and_max_three_attempts_per_host_are_enforced() -> None:
    sleep_calls = []
    credentials = [
        {
            "vendor": f"Camera {index}",
            "model": "generic",
            "device_type": "camera",
            "match_tokens": ["camera"],
            "username": "admin",
            "password": str(index),
            "no_auth_expected": False,
        }
        for index in range(4)
    ]

    def fake_http_client(url, method, headers, data, timeout_seconds):
        return HttpResponse(401, {"www-authenticate": "Basic realm=\"camera\""}, "Unauthorized", url)

    execution = execute_iot_default_credential_audit(
        targets=["10.0.20.12"],
        scope_allowlist={"hosts": ["10.0.20.12"]},
        inventory={"http_endpoints": [{"url": "http://10.0.20.12/", "title": "camera"}]},
        credentials=credentials,
        http_client=fake_http_client,
        sleep_func=lambda seconds: sleep_calls.append(seconds),
        time_func=lambda: 0.0,
        max_attempts_per_host=3,
        rate_limit_per_second=1,
    )
    payload = _artifact_payload(execution)

    assert len(payload["targets"][0]["attempts"]) == 3
    assert len(sleep_calls) == 2
    assert all(seconds >= 1 for seconds in sleep_calls)


def test_form_login_success_posts_single_redacted_default_pair() -> None:
    def fake_http_client(url, method, headers, data, timeout_seconds):
        if method == "POST":
            parsed = parse_qs((data or b"").decode("utf-8"))
            assert parsed["user"] == ["admin"]
            assert parsed["pass"] == ["admin"]
            return HttpResponse(200, {}, "Dashboard", url)
        if headers.get("Authorization"):
            return HttpResponse(401, {}, "Still login", url)
        return HttpResponse(
            200,
            {},
            '<form action="/login"><input name="user"><input type="password" name="pass"></form>',
            url,
        )

    execution = execute_iot_default_credential_audit(
        targets=["10.0.20.13"],
        scope_allowlist={"hosts": ["10.0.20.13"]},
        inventory={"http_endpoints": [{"url": "http://10.0.20.13/", "title": "QNAP NAS"}]},
        http_client=fake_http_client,
        sleep_func=lambda seconds: None,
    )
    payload = _artifact_payload(execution)

    assert payload["targets"][0]["attempts"][0]["method"] == "form-post"
    assert payload["targets"][0]["attempts"][0]["result"] == "accepted"
    assert payload["analysis_findings"][0]["severity"] == "critical"
    assert "admin/admin" not in json.dumps(payload)


def test_orchestration_extracts_iot_default_credential_findings() -> None:
    execution = execute_iot_default_credential_audit(
        targets=["10.0.20.14"],
        scope_allowlist={"hosts": ["10.0.20.14"]},
        inventory={"http_endpoints": [{"url": "http://10.0.20.14/", "title": "Philips Hue"}]},
        http_client=lambda url, method, headers, data, timeout_seconds: HttpResponse(
            200,
            {},
            "Hue bridge API",
            url,
        ),
    )
    artifact = execution.artifacts[0]
    artifact_record = type(
        "ArtifactRecord",
        (),
        {"uri": "artifact://iot-default-creds", "id": "artifact-id", "sha256": artifact.digest},
    )()

    findings = extract_iot_default_credential_findings(
        target_id="10.0.20.14",
        artifact=artifact,
        artifact_record=artifact_record,
    )

    assert findings
    assert findings[0].title == "Management interface accessible without authentication"
    assert findings[0].severity == "high"
