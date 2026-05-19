from __future__ import annotations

import json
from types import SimpleNamespace

from api.app.services.inventory import smart_home_observation_from_json
from workers.orchestration.findings import extract_findings, extract_smart_home_findings
from workers.orchestration.tasks import SUPPORTED_TOOLS, dispatch_runner
from workers.runners.base.contracts import RunnerRequest
from workers.runners.smart_home.runner import (
    SMART_HOME_RESULTS_ARTIFACT_NAME,
    HttpProbeResponse,
    execute_smart_home_audit,
    parse_mqtt_publish_topic,
)


def _payload_from_execution(execution) -> dict:
    artifact = next(
        item for item in execution.artifacts if item.name == SMART_HOME_RESULTS_ARTIFACT_NAME
    )
    return json.loads(artifact.data.decode("utf-8"))


def _mqtt_publish(topic: str, value: str) -> bytes:
    topic_bytes = topic.encode("utf-8")
    value_bytes = value.encode("utf-8")
    remaining = len(topic_bytes) + 2 + len(value_bytes)
    return b"\x30" + bytes([remaining]) + len(topic_bytes).to_bytes(2, "big") + topic_bytes + value_bytes


def test_mqtt_publish_topic_parser_reads_topic_without_value() -> None:
    packet = _mqtt_publish("homeassistant/light/kitchen/state", '{"state":"on"}')

    assert parse_mqtt_publish_topic(packet) == "homeassistant/light/kitchen/state"


def test_smart_home_audit_detects_mqtt_and_home_assistant_without_storing_values() -> None:
    mqtt_calls: list[tuple[str, int, bool]] = []
    http_urls: list[str] = []

    def fake_mqtt_probe(host: str, port: int, use_tls: bool, timeout: float, listen: float) -> dict:
        mqtt_calls.append((host, port, use_tls))
        if port == 1883:
            return {
                "host": host,
                "port": port,
                "tls": use_tls,
                "accepted": True,
                "topics": ["homeassistant/light/kitchen/state", "devices/thermostat"],
                "values_redacted": True,
            }
        return {"host": host, "port": port, "tls": use_tls, "accepted": False, "topics": []}

    def fake_http_get(url: str, timeout_seconds: float) -> HttpProbeResponse:
        http_urls.append(url)
        if url.endswith(":8123/api/"):
            return HttpProbeResponse(url=url, status_code=200, headers={}, body='{"message":"API running"}')
        if url.endswith(":8123/api/config"):
            return HttpProbeResponse(
                url=url,
                status_code=200,
                headers={},
                body='{"components":["mqtt"],"access_token":"super-secret-token"}',
            )
        if url.endswith(":8123/frontend_latest/index.html"):
            return HttpProbeResponse(url=url, status_code=200, headers={}, body="<html>HA</html>")
        if url.endswith(":4357/supervisor/info"):
            return HttpProbeResponse(url=url, status_code=401, headers={}, body="")
        return HttpProbeResponse(url=url, status_code=404, headers={}, body="")

    execution = execute_smart_home_audit(
        ["10.0.20.44"],
        scope_allowlist={"cidr_ranges": ["10.0.20.0/24"]},
        timeout_seconds=1,
        mqtt_listen_seconds=0.1,
        mqtt_probe=fake_mqtt_probe,
        http_getter=fake_http_get,
    )
    payload = _payload_from_execution(execution)
    artifact_text = execution.artifacts[0].data.decode("utf-8")

    assert execution.exit_code == 0
    assert ("10.0.20.44", 1883, False) in mqtt_calls
    assert ("10.0.20.44", 8883, True) in mqtt_calls
    assert "http://10.0.20.44:9001/mqtt" in http_urls
    assert payload["read_only"] is True
    assert payload["mqtt_publish_performed"] is False
    assert payload["device_control_performed"] is False
    assert payload["mqtt"][0]["topics"] == [
        "homeassistant/light/kitchen/state",
        "devices/thermostat",
    ]
    assert "super-secret-token" not in artifact_text
    assert '"access_token"' in artifact_text
    titles = {finding["title"] for finding in payload["analysis_findings"]}
    assert "MQTT broker accepts anonymous connections" in titles
    assert "Home Assistant API accessible without authentication" in titles
    assert "Home Assistant configuration details accessible without authentication" in titles


def test_smart_home_inventory_and_findings_extract_from_artifact() -> None:
    execution = execute_smart_home_audit(
        ["10.0.20.44"],
        mqtt_probe=lambda host, port, use_tls, timeout, listen: {
            "host": host,
            "port": port,
            "tls": use_tls,
            "accepted": port == 1883,
            "topics": ["home/garage/door"] if port == 1883 else [],
            "values_redacted": True,
        },
        http_getter=lambda url, timeout_seconds: HttpProbeResponse(
            url=url,
            status_code=200 if url.endswith(":8123/api/") else 404,
            headers={},
            body="{}",
        ),
        mqtt_listen_seconds=0.1,
    )
    artifact = execution.artifacts[0]
    artifact_record = type("ArtifactRecord", (), {"uri": "artifact://smart-home/results"})()

    observation = smart_home_observation_from_json(json_bytes=artifact.data, target_id="10.0.20.44")
    direct_findings = extract_smart_home_findings(
        target_id="10.0.20.44",
        artifact=artifact,
        artifact_record=artifact_record,
    )
    task = SimpleNamespace(tool="smart-home", target_id="10.0.20.44", params_json={})
    routed_findings = extract_findings(
        task=task,
        artifact=artifact,
        artifact_record=artifact_record,
    )

    assert observation["tool"] == "smart-home"
    assert observation["data"]["services"]
    assert any(finding.severity == "critical" for finding in direct_findings)
    assert [finding.title for finding in routed_findings] == [
        finding.title for finding in direct_findings
    ]
    assert all("smart-home" in finding.methodology_tags for finding in routed_findings)


def test_smart_home_dispatch_is_supported_and_safe_with_empty_targets() -> None:
    assert "smart-home" in SUPPORTED_TOOLS

    execution = dispatch_runner(
        RunnerRequest(
            tool="smart-home",
            targets=[],
            params={"timeout_seconds": 0.1, "mqtt_listen_seconds": 0.1},
            scope_allowlist={"cidr_ranges": ["10.0.20.0/24"]},
        )
    )

    payload = _payload_from_execution(execution)
    assert execution.tool == "smart-home"
    assert payload["hosts"] == []
    assert payload["mqtt_publish_performed"] is False
    assert payload["device_control_performed"] is False
