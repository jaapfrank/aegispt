from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
WIZARD_MODULE = REPO_ROOT / "ui/assets/modules/wizard.js"


def test_wizard_exposes_smart_home_lan_tile_and_full_lan_iot_chain_preview() -> None:
    wizard_source = WIZARD_MODULE.read_text(encoding="utf-8")

    assert "smart-home-lan" in wizard_source
    assert "Smart Home / IoT LAN" in wizard_source
    assert "🏠🔒" in wizard_source
    assert "FULL-LAN-IOT" in wizard_source
    assert "Full LAN + IoT" in wizard_source
    assert "passive-lan-iot-discovery" in wizard_source
    assert "passive-lan-nse-full" in wizard_source
    assert "passive-lan-snmp-enum" in wizard_source
    assert "passive-lan-smart-home-audit" in wizard_source
    assert "active-lan-camera-audit" in wizard_source
    assert "active-lan-default-creds-audit" in wizard_source
    assert "passive-lan-segmentation-check" in wizard_source
    assert "passive-lan-ipv6-discovery" in wizard_source
    assert "compatibleAssessmentModesForSelection" in wizard_source


def test_wizard_exposes_governed_nmap_scan_depth_control() -> None:
    wizard_source = WIZARD_MODULE.read_text(encoding="utf-8")

    assert "wizard-nmap-scan-depth" in wizard_source
    assert "top-10000" in wizard_source
    assert "all-ports" in wizard_source
    assert "nmapConfigurationFromSafety" in wizard_source
