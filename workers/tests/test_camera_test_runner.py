from __future__ import annotations

import json
from types import SimpleNamespace

from api.app.services.inventory import camera_test_observation_from_json
from workers.orchestration.findings import extract_camera_test_findings
from workers.runners.base.contracts import EvidenceArtifact
from workers.runners.camera_test.runner import (
    CAMERA_TEST_RESULTS_ARTIFACT_NAME,
    HttpProbeResponse,
    execute_camera_test,
    parse_onvif_device_information,
    parse_onvif_probe_matches,
)


PROBE_MATCH = b"""<?xml version="1.0" encoding="UTF-8"?>
<Envelope xmlns="http://www.w3.org/2003/05/soap-envelope">
  <Body>
    <ProbeMatches xmlns="http://schemas.xmlsoap.org/ws/2005/04/discovery">
      <ProbeMatch>
        <EndpointReference xmlns="http://schemas.xmlsoap.org/ws/2004/08/addressing">
          <Address>urn:uuid:camera-1</Address>
        </EndpointReference>
        <Scopes>onvif://www.onvif.org/name/front-door onvif://www.onvif.org/Profile/Streaming</Scopes>
        <XAddrs>http://10.0.20.50/onvif/device_service</XAddrs>
      </ProbeMatch>
    </ProbeMatches>
  </Body>
</Envelope>"""


DEVICE_INFO = b"""<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
  xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
  <s:Body>
    <tds:GetDeviceInformationResponse>
      <tds:Manufacturer>Axis</tds:Manufacturer>
      <tds:Model>P1448</tds:Model>
      <tds:FirmwareVersion>11.9</tds:FirmwareVersion>
      <tds:SerialNumber>ABC123</tds:SerialNumber>
      <tds:HardwareId>HW1</tds:HardwareId>
    </tds:GetDeviceInformationResponse>
  </s:Body>
</s:Envelope>"""


def test_onvif_probe_matches_and_device_info_are_parsed() -> None:
    matches = parse_onvif_probe_matches(PROBE_MATCH)

    assert matches == [
        {
            "xaddrs": ["http://10.0.20.50/onvif/device_service"],
            "scopes": [
                "onvif://www.onvif.org/name/front-door",
                "onvif://www.onvif.org/Profile/Streaming",
            ],
            "endpoint_reference": "urn:uuid:camera-1",
        }
    ]
    assert parse_onvif_device_information(DEVICE_INFO) == {
        "manufacturer": "Axis",
        "model": "P1448",
        "firmware_version": "11.9",
        "serial_number": "ABC123",
        "hardware_id": "HW1",
    }


def test_camera_audit_detects_exposures_without_storing_frames() -> None:
    def ws_discovery(_hosts: list[str], _timeout: float) -> list[dict[str, object]]:
        return parse_onvif_probe_matches(PROBE_MATCH)

    def http_getter(url: str, _timeout: float) -> HttpProbeResponse:
        if "onvif/device_service" in url:
            return HttpProbeResponse(
                url=url,
                status_code=200,
                headers={"content-type": "application/soap+xml"},
                body=DEVICE_INFO,
            )
        if url.endswith("/snapshot.jpg"):
            return HttpProbeResponse(
                url=url,
                status_code=200,
                headers={"content-type": "image/jpeg"},
                body=b"\xff\xd8camera-bytes\xff\xd9",
            )
        return HttpProbeResponse(url=url, status_code=404, headers={}, body=b"")

    def http_poster(url: str, _body: bytes, _timeout: float) -> HttpProbeResponse:
        return HttpProbeResponse(
            url=url,
            status_code=200,
            headers={"content-type": "application/soap+xml"},
            body=DEVICE_INFO,
        )

    def rtsp_probe(host: str, path: str, _timeout: float) -> dict[str, object]:
        return {
            "host": host,
            "port": 554,
            "path": path,
            "uri": f"rtsp://{host}:554{path}",
            "options": {"method": "OPTIONS", "status_code": 200},
            "describe": {
                "method": "DESCRIBE",
                "status_code": 200 if path == "/Streaming/Channels/1" else 401,
                "response_sha256": "abc123",
            },
            "setup_performed": False,
            "play_performed": False,
            "media_captured": False,
        }

    def credential_tester(
        url: str,
        _credentials: tuple[tuple[str, str], ...],
        _timeout: float,
    ) -> list[dict[str, object]]:
        return [
            {
                "url": url,
                "auth_scheme": "basic",
                "username": "admin",
                "password_redacted": "[REDACTED]",
                "status_code": 200,
                "accepted": True,
            }
        ]

    execution = execute_camera_test(
        ["10.0.20.50"],
        ws_discovery_client=ws_discovery,
        rtsp_probe=rtsp_probe,
        http_getter=http_getter,
        http_poster=http_poster,
        credential_tester=credential_tester,
    )

    assert execution.tool == "camera-test"
    assert execution.exit_code == 0
    payload = json.loads(execution.artifacts[0].data)
    assert execution.artifacts[0].name == CAMERA_TEST_RESULTS_ARTIFACT_NAME
    assert payload["rtsp_play_performed"] is False
    assert payload["rtsp_setup_performed"] is False
    assert payload["video_frame_stored"] is False
    assert payload["ptz_control_performed"] is False
    assert payload["configuration_changed"] is False
    assert all(snapshot["frame_stored"] is False for snapshot in payload["snapshots"])
    assert b"camera-bytes" not in execution.artifacts[0].data
    titles = {finding["title"] for finding in payload["analysis_findings"]}
    assert "RTSP stream describes without authentication" in titles
    assert "Camera snapshot accessible without authentication" in titles
    assert "Camera management interface accepted default credentials" in titles
    assert "ONVIF device service accessible without authentication" in titles


def test_camera_inventory_and_finding_extraction() -> None:
    execution = execute_camera_test(
        ["10.0.20.50"],
        ws_discovery_client=lambda _hosts, _timeout: parse_onvif_probe_matches(PROBE_MATCH),
        http_getter=lambda url, _timeout: (
            HttpProbeResponse(
                url=url,
                status_code=200,
                headers={"content-type": "application/soap+xml"},
                body=DEVICE_INFO,
            )
            if "onvif/device_service" in url
            else HttpProbeResponse(url=url, status_code=404, headers={}, body=b"")
        ),
        http_poster=lambda url, _body, _timeout: HttpProbeResponse(
            url=url,
            status_code=200,
            headers={"content-type": "application/soap+xml"},
            body=DEVICE_INFO,
        ),
        rtsp_probe=lambda host, path, _timeout: {
            "host": host,
            "port": 554,
            "path": path,
            "uri": f"rtsp://{host}:554{path}",
            "options": {"status_code": 200},
            "describe": {"status_code": 401},
            "setup_performed": False,
            "play_performed": False,
            "media_captured": False,
        },
        credential_tester=lambda _url, _credentials, _timeout: [],
    )
    artifact = execution.artifacts[0]
    observation = camera_test_observation_from_json(
        json_bytes=artifact.data,
        target_id="10.0.20.50",
    )
    findings = extract_camera_test_findings(
        target_id="10.0.20.50",
        artifact=EvidenceArtifact(
            name=artifact.name,
            content_type=artifact.content_type,
            data=artifact.data,
            kind=artifact.kind,
        ),
        artifact_record=SimpleNamespace(uri="artifact://camera-test"),
    )

    assert observation["tool"] == "camera-test"
    assert observation["data"]["hosts"][0]["device_type"] == "ip-camera"
    assert observation["data"]["services"][0]["service"] == "onvif-device-service"
    assert [finding.title for finding in findings] == [
        "ONVIF device service accessible without authentication"
    ]


def test_camera_audit_empty_targets_is_safe() -> None:
    execution = execute_camera_test(
        [],
        ws_discovery_client=lambda _hosts, _timeout: [],
        http_getter=lambda url, _timeout: HttpProbeResponse(url=url, status_code=0, headers={}),
        http_poster=lambda url, _body, _timeout: HttpProbeResponse(
            url=url,
            status_code=0,
            headers={},
        ),
        rtsp_probe=lambda host, path, _timeout: {"host": host, "path": path},
        credential_tester=lambda _url, _credentials, _timeout: [],
    )
    payload = json.loads(execution.artifacts[0].data)

    assert payload["hosts"] == []
    assert payload["analysis_findings"] == []
    assert payload["rtsp_play_performed"] is False
    assert payload["video_frame_stored"] is False
