from __future__ import annotations

import json

import pytest

from workers.runners.wifi_survey.runner import (
    WIFI_SURVEY_RESULTS_ARTIFACT_NAME,
    execute_wifi_survey,
    parse_airodump_csv,
    parse_iw_scan,
)

IW_SCAN_FIXTURE = """
BSS aa:bb:cc:dd:ee:ff(on wlan0)
    signal: -42.00 dBm
    SSID: CorpWiFi
    DS Parameter set: channel 6
    RSN:     * Version: 1
             * Group cipher: CCMP
             * Pairwise ciphers: CCMP
             * Authentication suites: PSK
BSS 11:22:33:44:55:66(on wlan0)
    signal: -70.00 dBm
    SSID: GuestWiFi
    DS Parameter set: channel 11
    capability: ESS Privacy
    WPS:
""".strip()


AIRODUMP_FIXTURE = """
BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key
AA:BB:CC:DD:EE:FF, 2026-05-01 10:00:00, 2026-05-01 10:00:05, 6, 54, WPA2, CCMP, PSK, -41, 10, 0, 0.0.0.0, 8, CorpWiFi,
11:22:33:44:55:66, 2026-05-01 10:00:00, 2026-05-01 10:00:05, 11, 54, OPN, , , -70, 4, 0, 0.0.0.0, 9, GuestWiFi,
Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs
""".strip()


def _payload_from_execution(execution) -> dict:
    artifact = next(item for item in execution.artifacts if item.name == WIFI_SURVEY_RESULTS_ARTIFACT_NAME)
    data = artifact.data.decode("utf-8") if isinstance(artifact.data, bytes) else artifact.data
    return json.loads(data)


def test_iw_and_airodump_parsers_normalize_access_points() -> None:
    iw_access_points = parse_iw_scan(IW_SCAN_FIXTURE)
    airodump_access_points = parse_airodump_csv(AIRODUMP_FIXTURE)

    assert iw_access_points[0]["bssid"] == "aa:bb:cc:dd:ee:ff"
    assert iw_access_points[0]["ssid"] == "CorpWiFi"
    assert iw_access_points[0]["channel"] == 6
    assert iw_access_points[0]["encryption"] == "wpa2"
    assert airodump_access_points[1]["ssid"] == "GuestWiFi"
    assert airodump_access_points[1]["encryption"] == "open"


def test_wifi_survey_fixture_produces_inventory_findings_and_no_intrusive_flags() -> None:
    execution = execute_wifi_survey(
        ["HQ-Amsterdam"],
        site="HQ-Amsterdam",
        adapter="wlan0",
        approved_ssids=["CorpWiFi"],
        approved_bssids=["aa:bb:cc:dd:ee:ff"],
        iw_scan_text=IW_SCAN_FIXTURE,
        timeout_seconds=1.0,
    )
    payload = _payload_from_execution(execution)

    assert execution.tool == "wifi-survey"
    assert execution.exit_code == 0
    assert execution.metadata["access_point_count"] == 2
    assert payload["rf_disruptive_actions"] is False
    assert payload["handshake_capture"] is False
    assert payload["credential_harvesting"] is False
    assert payload["wps_pin_testing"] is False
    assert payload["inventory"]["wireless_access_points"]
    assert payload["inventory"]["wireless_networks"]
    assert any(finding["title"] == "Unexpected wireless SSID observed" for finding in payload["analysis_findings"])


def test_wifi_survey_requires_site_adapter_and_allowlist() -> None:
    with pytest.raises(ValueError, match="site/location"):
        execute_wifi_survey([], site="", adapter="wlan0", approved_ssids=["CorpWiFi"])
    with pytest.raises(ValueError, match="adapter/interface"):
        execute_wifi_survey(["HQ"], site="HQ", adapter="", approved_ssids=["CorpWiFi"])
    with pytest.raises(ValueError, match="approved SSID or BSSID"):
        execute_wifi_survey(["HQ"], site="HQ", adapter="wlan0", approved_ssids=[])
