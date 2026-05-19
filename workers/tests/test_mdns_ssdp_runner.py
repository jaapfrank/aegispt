from __future__ import annotations

import json

from workers.runners.mdns_ssdp.runner import (
    MDNS_SSDP_ARTIFACT_NAME,
    build_mdns_ssdp_payload,
    execute_mdns_ssdp_discovery,
    identify_device_type,
    normalize_ssdp_device,
    parse_ssdp_response,
    parse_upnp_device_description,
)


def test_ssdp_response_and_upnp_description_are_normalized() -> None:
    headers = parse_ssdp_response(
        "HTTP/1.1 200 OK\r\n"
        "LOCATION: http://10.0.20.55:80/rootDesc.xml\r\n"
        "ST: urn:schemas-upnp-org:device:MediaServer:1\r\n"
        "USN: uuid:device-1\r\n"
        "SERVER: Linux/5 UPnP/1.0\r\n\r\n"
    )
    description = parse_upnp_device_description(
        """
        <root xmlns="urn:schemas-upnp-org:device-1-0">
          <device>
            <deviceType>urn:schemas-upnp-org:device:MediaServer:1</deviceType>
            <friendlyName>Living Room Speaker</friendlyName>
            <manufacturer>Sonos</manufacturer>
            <modelName>One</modelName>
            <presentationURL>/status</presentationURL>
          </device>
        </root>
        """,
        location_url=headers["location"],
    )

    device = normalize_ssdp_device(headers, description=description)

    assert device is not None
    assert device["ip"] == "10.0.20.55"
    assert device["presentation_url"] == "http://10.0.20.55:80/status"
    assert device["device_type"] == "consumer-iot"
    assert device["manufacturer"] == "Sonos"


def test_mdns_payload_builds_inventory_and_http_finding() -> None:
    payload = build_mdns_ssdp_payload(
        targets=["10.0.20.0/24"],
        scope_allowlist={"cidr_ranges": ["10.0.20.0/24"]},
        mdns_records=[
            {
                "name": "hue-bridge.local.",
                "service_type": "_hue._tcp.local.",
                "addresses": ["10.0.20.44"],
                "port": 80,
                "txt": {"model": "Hue Bridge"},
            }
        ],
        ssdp_devices=[],
    )

    assert payload["devices"][0]["device_type"] == "iot-gateway"
    assert payload["inventory"]["hosts"][0]["host"] == "10.0.20.44"
    assert payload["inventory"]["hosts"][0]["device_type"] == "iot-gateway"
    assert payload["inventory"]["services"][0]["service"] == "http"
    assert payload["analysis_findings"][0]["title"] == (
        "IoT management interface advertised over HTTP"
    )


def test_execute_mdns_ssdp_discovery_accepts_injected_records_without_network() -> None:
    execution = execute_mdns_ssdp_discovery(
        ["10.0.20.0/24"],
        scope_allowlist={"cidr_ranges": ["10.0.20.0/24"]},
        mdns_records=[
            {
                "name": "front-camera.local.",
                "service_type": "_rtsp._tcp.local.",
                "addresses": ["10.0.20.77"],
                "port": 554,
            }
        ],
        ssdp_devices=[],
    )

    assert execution.tool == "mdns-ssdp"
    assert execution.exit_code == 0
    assert execution.metadata["device_count"] == 1
    artifact = next(item for item in execution.artifacts if item.name == MDNS_SSDP_ARTIFACT_NAME)
    payload = json.loads(artifact.data.decode("utf-8"))
    assert payload["devices"][0]["device_type"] == "ip-camera"
    assert payload["inventory"]["hosts"][0]["device_type"] == "ip-camera"


def test_device_type_identifies_common_iot_services() -> None:
    assert identify_device_type(service_type="_homekit._tcp.local.") == "smart-home-hub"
    assert identify_device_type(service_type="_mqtt._tcp.local.") == "smart-home-hub"
    assert identify_device_type(port=8123, name="Home Assistant") == "smart-home-hub"
