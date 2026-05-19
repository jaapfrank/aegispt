from __future__ import annotations

import csv
import json
import re
from collections import Counter
from collections.abc import Iterable
from datetime import UTC, datetime
from io import StringIO
from typing import Any

from workers.runners.base.contracts import EvidenceArtifact, RunnerExecution

WIFI_SURVEY_RESULTS_ARTIFACT_NAME = "wifi-survey-results.json"
WIFI_SURVEY_RUNNER_DIGEST = "workers.wifi_survey.runner:v1"


def _normalized_string_list(values: Iterable[object] | None) -> list[str]:
    normalized: list[str] = []
    seen: set[str] = set()
    for value in values or []:
        candidate = str(value or "").strip()
        if candidate and candidate.lower() not in seen:
            seen.add(candidate.lower())
            normalized.append(candidate)
    return normalized


def _normalized_bssid(value: object) -> str:
    candidate = str(value or "").strip().lower()
    if not candidate:
        return ""
    if re.fullmatch(r"[0-9a-f]{12}", candidate):
        return ":".join(candidate[index : index + 2] for index in range(0, 12, 2))
    return candidate


def _band_for_channel(channel: object) -> str | None:
    try:
        channel_number = int(channel)
    except (TypeError, ValueError):
        return None
    if 1 <= channel_number <= 14:
        return "2.4GHz"
    if 32 <= channel_number <= 177:
        return "5/6GHz"
    return None


def _channel_number(channel: object) -> int | None:
    try:
        return int(channel)
    except (TypeError, ValueError):
        return None


def _auth_from_privacy(privacy: str, cipher: str = "", auth: str = "") -> dict[str, Any]:
    haystack = " ".join([privacy, cipher, auth]).upper()
    encryption = "open"
    if "WEP" in haystack:
        encryption = "wep"
    elif "WPA3" in haystack or "SAE" in haystack:
        encryption = "wpa3"
    elif "WPA2" in haystack or "CCMP" in haystack or "PSK" in haystack or "MGT" in haystack:
        encryption = "wpa2"
    elif "WPA" in haystack or "TKIP" in haystack:
        encryption = "wpa"
    auth_mode = "open"
    if "MGT" in haystack or "802.1X" in haystack or "EAP" in haystack:
        auth_mode = "enterprise"
    elif encryption != "open":
        auth_mode = "psk"
    return {
        "encryption": encryption,
        "auth_mode": auth_mode,
        "cipher": cipher.strip() or None,
        "wpa_versions": [
            version
            for version in ("WPA", "WPA2", "WPA3")
            if version in haystack or (version == "WPA3" and "SAE" in haystack)
        ],
        "pmf": "required" if "MFPR" in haystack else ("capable" if "MFPC" in haystack else "unknown"),
        "wps": "WPS" in haystack,
    }


def parse_airodump_csv(text: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    ap_section = []
    for raw_line in str(text or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.lower().startswith("station mac"):
            break
        ap_section.append(raw_line)
    reader = csv.DictReader(StringIO("\n".join(ap_section)), skipinitialspace=True)
    for row in reader:
        if not isinstance(row, dict):
            continue
        bssid = _normalized_bssid(row.get("BSSID"))
        if not bssid or bssid == "bssid":
            continue
        channel = str(row.get("channel") or row.get("Channel") or "").strip()
        signal = str(row.get("Power") or "").strip()
        auth = _auth_from_privacy(
            str(row.get("Privacy") or ""),
            str(row.get("Cipher") or ""),
            str(row.get("Authentication") or ""),
        )
        rows.append(
            {
                "ssid": str(row.get("ESSID") or "").strip() or "<hidden>",
                "bssid": bssid,
                "channel": _channel_number(channel),
                "band": _band_for_channel(channel),
                "signal_dbm": int(signal) if signal.lstrip("-").isdigit() else None,
                "source": "airodump-ng csv",
                "first_seen": str(row.get("First time seen") or "").strip() or None,
                "last_seen": str(row.get("Last time seen") or "").strip() or None,
                "confidence": 0.86,
                **auth,
            }
        )
    return rows


def parse_iw_scan(text: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    privacy_chunks: list[str] = []

    def flush() -> None:
        nonlocal current, privacy_chunks
        if not current:
            return
        auth = _auth_from_privacy(" ".join(privacy_chunks))
        current.setdefault("ssid", "<hidden>")
        current.setdefault("channel", None)
        current.setdefault("band", _band_for_channel(current.get("channel")))
        current.update(auth)
        current.setdefault("source", "iw scan")
        current.setdefault("confidence", 0.78)
        rows.append(current)
        current = None
        privacy_chunks = []

    for raw_line in str(text or "").splitlines():
        line = raw_line.strip()
        bss_match = re.match(r"BSS\s+([0-9A-Fa-f:]{17})", line)
        if bss_match:
            flush()
            current = {"bssid": _normalized_bssid(bss_match.group(1))}
            continue
        if current is None:
            continue
        if line.startswith("SSID:"):
            current["ssid"] = line.split(":", 1)[1].strip() or "<hidden>"
        elif line.startswith("signal:"):
            signal_match = re.search(r"(-?\d+(?:\.\d+)?)", line)
            if signal_match:
                current["signal_dbm"] = int(float(signal_match.group(1)))
        elif "DS Parameter set:" in line and "channel" in line:
            channel_match = re.search(r"channel\s+(\d+)", line)
            if channel_match:
                current["channel"] = _channel_number(channel_match.group(1))
                current["band"] = _band_for_channel(channel_match.group(1))
        elif line.startswith(("capability:", "WPA:", "RSN:", "* Authentication suites:", "* Pairwise ciphers:", "* Group cipher:", "* Capabilities:")):
            privacy_chunks.append(line)
        elif "WPS:" in line or line.startswith("* Version:"):
            privacy_chunks.append("WPS")
    flush()
    return rows


def _dedupe_access_points(rows: Iterable[dict[str, Any]], *, observed_at: str, site: str, adapter: str) -> list[dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    for row in rows:
        bssid = _normalized_bssid(row.get("bssid"))
        if not bssid:
            continue
        existing = merged.setdefault(
            bssid,
            {
                "bssid": bssid,
                "ssid": str(row.get("ssid") or "<hidden>").strip() or "<hidden>",
                "site": site,
                "adapter": adapter,
                "observed_at": observed_at,
                "sources": [],
            },
        )
        for field in (
            "ssid",
            "channel",
            "band",
            "encryption",
            "auth_mode",
            "cipher",
            "pmf",
            "wps",
            "signal_dbm",
            "first_seen",
            "last_seen",
            "confidence",
        ):
            value = row.get(field)
            if value not in (None, "", []):
                existing[field] = value
        source = str(row.get("source") or "").strip()
        if source and source not in existing["sources"]:
            existing["sources"].append(source)
    return sorted(merged.values(), key=lambda item: (str(item.get("ssid")), str(item.get("bssid"))))


def _network_summary(access_points: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_ssid: dict[str, list[dict[str, Any]]] = {}
    for ap in access_points:
        by_ssid.setdefault(str(ap.get("ssid") or "<hidden>"), []).append(ap)
    networks: list[dict[str, Any]] = []
    for ssid, aps in sorted(by_ssid.items()):
        encryptions = sorted({str(ap.get("encryption") or "unknown") for ap in aps})
        auth_modes = sorted({str(ap.get("auth_mode") or "unknown") for ap in aps})
        networks.append(
            {
                "ssid": ssid,
                "bssid_count": len(aps),
                "bssids": [str(ap.get("bssid")) for ap in aps if ap.get("bssid")],
                "channels": sorted({str(ap.get("channel")) for ap in aps if ap.get("channel")}),
                "encryption": encryptions[0] if len(encryptions) == 1 else "mixed",
                "auth_modes": auth_modes,
                "wps": any(bool(ap.get("wps")) for ap in aps),
                "pmf": sorted({str(ap.get("pmf") or "unknown") for ap in aps}),
                "confidence": max(float(ap.get("confidence") or 0.5) for ap in aps),
            }
        )
    return networks


def _finding(
    *,
    title: str,
    severity: str,
    target_id: str,
    summary: str,
    tags: Iterable[str],
) -> dict[str, Any]:
    return {
        "title": title,
        "severity": severity,
        "target_id": target_id,
        "summary": summary,
        "methodology_tags": list(dict.fromkeys(["wireless", "wifi", *tags])),
        "ptes_phase": "intelligence_gathering",
        "nist_phase": "discovery",
        "control_family": "network_security",
    }


def _analysis_findings(
    access_points: list[dict[str, Any]],
    networks: list[dict[str, Any]],
    *,
    approved_ssids: list[str],
    approved_bssids: list[str],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    approved_ssid_set = {ssid.lower() for ssid in approved_ssids}
    approved_bssid_set = {_normalized_bssid(bssid) for bssid in approved_bssids}
    for ap in access_points:
        ssid = str(ap.get("ssid") or "<hidden>")
        bssid = str(ap.get("bssid") or "")
        target = f"{ssid} ({bssid})" if bssid else ssid
        encryption = str(ap.get("encryption") or "unknown").lower()
        cipher = str(ap.get("cipher") or "").upper()
        if encryption == "open":
            findings.append(
                _finding(
                    title="Open wireless network observed",
                    severity="medium",
                    target_id=target,
                    summary=f"SSID {ssid} was observed without link-layer encryption in the passive survey.",
                    tags=("open_network",),
                )
            )
        if encryption in {"wep", "wpa"} or "TKIP" in cipher:
            findings.append(
                _finding(
                    title="Legacy wireless security observed",
                    severity="high" if encryption == "wep" else "medium",
                    target_id=target,
                    summary=f"SSID {ssid} advertised legacy wireless security ({encryption.upper()}{' / TKIP' if 'TKIP' in cipher else ''}).",
                    tags=("legacy_crypto",),
                )
            )
        if ap.get("wps"):
            findings.append(
                _finding(
                    title="WPS advertised on wireless network",
                    severity="low",
                    target_id=target,
                    summary=f"SSID {ssid} advertised WPS metadata. This foundation only records the signal and does not attempt PIN testing.",
                    tags=("wps",),
                )
            )
        if encryption in {"wpa2", "wpa3"} and str(ap.get("pmf") or "unknown") == "unknown":
            findings.append(
                _finding(
                    title="Wireless PMF posture not confirmed",
                    severity="info",
                    target_id=target,
                    summary=f"SSID {ssid} did not provide enough passive evidence to confirm protected management frame posture.",
                    tags=("pmf",),
                )
            )
        if approved_ssid_set or approved_bssid_set:
            ssid_allowed = ssid.lower() in approved_ssid_set
            bssid_allowed = bssid.lower() in approved_bssid_set
            if approved_ssid_set and not ssid_allowed and not bssid_allowed:
                findings.append(
                    _finding(
                        title="Unexpected wireless SSID observed",
                        severity="low",
                        target_id=target,
                        summary=f"SSID {ssid} was observed at the authorized site but was not in the approved SSID/BSSID allowlist.",
                        tags=("rogue_ap_review",),
                    )
                )
            elif ssid_allowed and approved_bssid_set and not bssid_allowed:
                findings.append(
                    _finding(
                        title="Unknown BSSID advertising approved SSID",
                        severity="medium",
                        target_id=target,
                        summary=f"SSID {ssid} is approved, but BSSID {bssid} was not in the approved BSSID allowlist.",
                        tags=("evil_twin_like", "rogue_ap_review"),
                    )
                )
    ssid_counts = Counter(str(ap.get("ssid") or "<hidden>").lower() for ap in access_points)
    for network in networks:
        ssid = str(network.get("ssid") or "<hidden>")
        if ssid_counts[ssid.lower()] > 1 and approved_bssids:
            findings.append(
                _finding(
                    title="Multiple BSSIDs observed for wireless SSID",
                    severity="info",
                    target_id=ssid,
                    summary=f"SSID {ssid} appeared on {ssid_counts[ssid.lower()]} BSSIDs. Validate this against the approved AP inventory before treating it as rogue.",
                    tags=("duplicate_ssid",),
                )
            )
        if "guest" in ssid.lower() and network.get("encryption") == "open":
            findings.append(
                _finding(
                    title="Guest WiFi appears open",
                    severity="medium",
                    target_id=ssid,
                    summary=f"Guest-looking SSID {ssid} appeared open in passive survey evidence.",
                    tags=("guest_network", "open_network"),
                )
            )
    deduped: dict[tuple[str, str], dict[str, Any]] = {}
    for item in findings:
        deduped.setdefault((item["title"].lower(), item["target_id"].lower()), item)
    return list(deduped.values())


def execute_wifi_survey(
    targets: list[str],
    *,
    scope_allowlist: dict[str, Any] | None = None,
    site: str | None = None,
    adapter: str | None = None,
    approved_ssids: list[str] | None = None,
    approved_bssids: list[str] | None = None,
    excluded_ssids: list[str] | None = None,
    excluded_bssids: list[str] | None = None,
    iw_scan_text: str | None = None,
    airodump_csv_text: str | None = None,
    observed_at: str | None = None,
    timeout_seconds: float = 10.0,
) -> RunnerExecution:
    del timeout_seconds
    site_name = str(site or (targets[0] if targets else "")).strip()
    adapter_name = str(adapter or "").strip()
    approved_ssid_list = _normalized_string_list(approved_ssids)
    approved_bssid_list = [_normalized_bssid(value) for value in _normalized_string_list(approved_bssids)]
    if not site_name:
        raise ValueError("wifi-survey requires an explicit site/location identifier")
    if not adapter_name:
        raise ValueError("wifi-survey requires a wireless adapter/interface context")
    if not approved_ssid_list and not approved_bssid_list:
        raise ValueError("wifi-survey requires at least one approved SSID or BSSID")

    observed = observed_at or datetime.now(tz=UTC).isoformat()
    rows: list[dict[str, Any]] = []
    rows.extend(parse_iw_scan(iw_scan_text or ""))
    rows.extend(parse_airodump_csv(airodump_csv_text or ""))
    excluded_ssid_set = {value.lower() for value in _normalized_string_list(excluded_ssids)}
    excluded_bssid_set = {_normalized_bssid(value) for value in _normalized_string_list(excluded_bssids)}
    rows = [
        row
        for row in rows
        if str(row.get("ssid") or "").lower() not in excluded_ssid_set
        and _normalized_bssid(row.get("bssid")) not in excluded_bssid_set
    ]
    access_points = _dedupe_access_points(rows, observed_at=observed, site=site_name, adapter=adapter_name)
    networks = _network_summary(access_points)
    findings = _analysis_findings(
        access_points,
        networks,
        approved_ssids=approved_ssid_list,
        approved_bssids=approved_bssid_list,
    )
    data_source_count = int(bool(iw_scan_text)) + int(bool(airodump_csv_text))
    payload = {
        "tool": "wifi-survey",
        "mode": "passive_observation",
        "site": site_name,
        "adapter": adapter_name,
        "approved_ssids": approved_ssid_list,
        "approved_bssids": approved_bssid_list,
        "excluded_ssids": _normalized_string_list(excluded_ssids),
        "excluded_bssids": [_normalized_bssid(value) for value in _normalized_string_list(excluded_bssids)],
        "observed_at": observed,
        "rf_disruptive_actions": False,
        "handshake_capture": False,
        "credential_harvesting": False,
        "wps_pin_testing": False,
        "inventory": {
            "wireless_access_points": access_points,
            "wireless_networks": networks,
            "confidence": 0.84 if access_points else 0.2,
        },
        "analysis_findings": findings,
        "coverage": {
            "data_source_count": data_source_count,
            "access_point_count": len(access_points),
            "network_count": len(networks),
        },
        "limitations": [
            "Foundation slice consumes passive survey evidence only; it does not enable monitor mode, deauthenticate clients, capture handshakes, brute-force WPS, jam RF, or create rogue access points.",
            "Unknown/rogue AP signals require operator review against the authorized site inventory before conclusion.",
        ],
    }
    stdout = (
        f"wifi-survey: passive evidence imported for site {site_name} using adapter context {adapter_name}\n"
        f"wifi-survey: {len(access_points)} access points, {len(networks)} networks, {len(findings)} conservative findings\n"
    )
    if not access_points:
        stdout += "wifi-survey: no fixture/capture access points were provided; live RF scanning is intentionally unavailable in this foundation slice\n"
    return RunnerExecution(
        tool="wifi-survey",
        exit_code=0,
        stdout=stdout,
        stderr="",
        metadata={
            "status": "completed",
            "tool_version": "wifi-survey-passive-v1",
            "runner_digest": WIFI_SURVEY_RUNNER_DIGEST,
            "passive_only": True,
            "rf_disruptive_actions": False,
            "access_point_count": len(access_points),
            "network_count": len(networks),
            "finding_count": len(findings),
        },
        artifacts=[
            EvidenceArtifact(
                name=WIFI_SURVEY_RESULTS_ARTIFACT_NAME,
                content_type="application/json",
                data=json.dumps(payload, indent=2, sort_keys=True).encode("utf-8"),
                kind="wifi-survey-results",
            )
        ],
    )
