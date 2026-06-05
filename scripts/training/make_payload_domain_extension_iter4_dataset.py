"""Generate AD/cloud/LAN/IoT payload-domain extension examples for AegisPT.

This is a lab-only payload capability dataset for domains that were not covered
deeply by the first web/API payload curriculum. It focuses on controlled proof
selection, read-only checks, simulators, and marker evidence.
"""

from __future__ import annotations

import argparse
import json
import random
from collections import Counter
from collections.abc import Callable
from pathlib import Path
from typing import Any

DEFAULT_OUT_DIR = Path.home() / ".aegispt-tools" / "training"
DEFAULT_PREFIX = "aegispt_payload_domain_extension_iter4"
DEFAULT_COUNTS = {"train": 6400, "eval": 800, "test": 800}
SEED = 20260604

SYSTEM = (
    "You are AegisPT in an authorized lab. Return EXACTLY one JSON object with "
    "keys: reasoning, tool, args, payload, preconditions, expected_evidence, "
    "cleanup, finding, safety, done. Use only read-only checks, simulators, "
    "disposable lab objects, or marker topics. Do not dump credentials, crack "
    "hashes, relay authentication, touch real cloud metadata, persist access, "
    "or change production devices."
)

CLASSES = (
    "ad_ldap_filter_injection_marker",
    "ad_kerberos_preauth_config_query",
    "ad_bloodhound_path_query_lab",
    "ad_smb_signing_relay_simulation",
    "cloud_iam_policy_simulation",
    "cloud_storage_public_list_marker",
    "cloud_kube_rbac_selfsubjectreview",
    "cloud_imds_mock_token_requirement",
    "lan_snmp_readonly_oid",
    "lan_segmentation_tcp_marker",
    "lan_mdns_ssdp_discovery_marker",
    "lan_smb_signing_config_probe",
    "iot_mqtt_test_topic_marker",
    "iot_upnp_ssdp_probe",
    "iot_rtsp_options_probe",
    "iot_modbus_read_device_id",
)

DOMAIN = {
    **{klass: "active_directory" for klass in CLASSES if klass.startswith("ad_")},
    **{klass: "cloud" for klass in CLASSES if klass.startswith("cloud_")},
    **{klass: "lan" for klass in CLASSES if klass.startswith("lan_")},
    **{klass: "iot" for klass in CLASSES if klass.startswith("iot_")},
}

SEVERITY = {
    "ad_ldap_filter_injection_marker": "high",
    "ad_kerberos_preauth_config_query": "medium",
    "ad_bloodhound_path_query_lab": "medium",
    "ad_smb_signing_relay_simulation": "medium",
    "cloud_iam_policy_simulation": "high",
    "cloud_storage_public_list_marker": "high",
    "cloud_kube_rbac_selfsubjectreview": "high",
    "cloud_imds_mock_token_requirement": "medium",
    "lan_snmp_readonly_oid": "low",
    "lan_segmentation_tcp_marker": "high",
    "lan_mdns_ssdp_discovery_marker": "low",
    "lan_smb_signing_config_probe": "medium",
    "iot_mqtt_test_topic_marker": "high",
    "iot_upnp_ssdp_probe": "low",
    "iot_rtsp_options_probe": "medium",
    "iot_modbus_read_device_id": "medium",
}


def marker(rng: random.Random) -> str:
    return f"AEGISPT_DOMAIN_{rng.randint(1000, 9999)}"


def lab_host(rng: random.Random, prefix: str) -> str:
    return f"{prefix}-lab-{rng.randint(100, 999)}.example"


def lab_ip(rng: random.Random) -> str:
    return f"192.0.2.{rng.randint(10, 240)}"


def assistant_json(
    *,
    klass: str,
    reasoning: str,
    tool: str,
    args: dict[str, Any],
    payload: dict[str, Any],
    preconditions: list[str],
    expected_evidence: dict[str, Any],
    cleanup: list[str],
    finding: dict[str, Any],
) -> str:
    return json.dumps(
        {
            "args": args,
            "cleanup": cleanup,
            "done": True,
            "expected_evidence": expected_evidence,
            "finding": finding,
            "payload": payload,
            "preconditions": preconditions,
            "reasoning": reasoning,
            "safety": {
                "blocked_if": [
                    "not_lab",
                    "not_in_scope",
                    "approval_missing",
                    "would_collect_credentials",
                    "would_modify_production_state",
                ],
                "dataset_family": DEFAULT_PREFIX,
                "lab_only": True,
                "runtime_execution": False,
                "vulnerability_class": klass,
            },
            "tool": tool,
        },
        sort_keys=True,
    )


def finding(klass: str, ev: str, title: str, impact: str, remediation: str) -> dict[str, Any]:
    return {
        "confidence": "high",
        "evidence_ref": ev,
        "impact": impact,
        "remediation": remediation,
        "severity": SEVERITY[klass],
        "standards": ["NIST SP 800-115", "MITRE ATT&CK", "CIS Controls"],
        "title": title,
    }


def row(
    *,
    split: str,
    idx: int,
    klass: str,
    payload_family: str,
    prompt: str,
    content: str,
) -> dict[str, Any]:
    return {
        "messages": [
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content": prompt},
            {"role": "assistant", "content": content},
        ],
        "metadata": {
            "case_id": f"domain-extension-{klass}-{split}-{idx:05d}",
            "dataset_family": DEFAULT_PREFIX,
            "domain": DOMAIN[klass],
            "payload_family": payload_family,
            "safety_tags": ["lab_only", "payload_domain_extension", "no_credential_dumping", "no_state_change"],
            "split": split,
            "vulnerability_class": klass,
        },
    }


def make_ad_ldap(rng: random.Random, split: str, idx: int) -> dict[str, Any]:
    klass = "ad_ldap_filter_injection_marker"
    ev = f"domain-{klass}-{idx:05d}"
    proof = marker(rng)
    target = lab_host(rng, "ldap")
    payload = f"*)(description={proof})(uid=*"
    content = assistant_json(
        klass=klass,
        reasoning="Use a marker-only LDAP filter injection proof against the lab search endpoint, not against a real directory.",
        tool="lab_ldap_app_check",
        args={"parameter": "username", "target": target},
        payload={"family": "ldap_filter_injection_marker", "value": payload},
        preconditions=["lab app proxy", "synthetic directory", "read-only search"],
        expected_evidence={"evidence_ref": ev, "marker_seen_in_filter_result": proof},
        cleanup=["reset synthetic directory fixture"],
        finding=finding(klass, ev, "LDAP filter injection accepted a marker", "Directory-backed search may allow filter manipulation.", "Use parameterized LDAP filters and escape assertion values."),
    )
    prompt = f"AD lab app {target} searches LDAP by username. Prove filter injection with marker {proof}; no real directory."
    return row(split=split, idx=idx, klass=klass, payload_family="ldap_filter_injection_marker", prompt=prompt, content=content)


def make_ad_preauth(rng: random.Random, split: str, idx: int) -> dict[str, Any]:
    klass = "ad_kerberos_preauth_config_query"
    ev = f"domain-{klass}-{idx:05d}"
    dc = lab_host(rng, "dc")
    content = assistant_json(
        klass=klass,
        reasoning="Use LDAP configuration query only. Do not request tickets, collect hashes, or crack material.",
        tool="lab_ldap_readonly",
        args={"attributes": ["samAccountName", "userAccountControl"], "target": dc},
        payload={"family": "kerberos_preauth_disabled_filter", "value": "userAccountControl:preauth_not_required"},
        preconditions=["lab domain", "read-only LDAP approval", "no ticket capture"],
        expected_evidence={"accounts_counted": True, "evidence_ref": ev, "ticket_capture": False},
        cleanup=["none; read-only query"],
        finding=finding(klass, ev, "Kerberos pre-auth disabled on lab accounts", "Accounts with pre-auth disabled are exposed to offline attack workflows if abused.", "Require Kerberos pre-auth and review exceptions."),
    )
    prompt = f"Lab domain controller {dc} is in scope. Identify pre-auth disabled accounts without ticket capture."
    return row(split=split, idx=idx, klass=klass, payload_family="kerberos_preauth_disabled_filter", prompt=prompt, content=content)


def make_ad_bloodhound(rng: random.Random, split: str, idx: int) -> dict[str, Any]:
    klass = "ad_bloodhound_path_query_lab"
    ev = f"domain-{klass}-{idx:05d}"
    content = assistant_json(
        klass=klass,
        reasoning="Query the offline lab attack graph for shortest path evidence; do not touch live AD.",
        tool="lab_graph_query",
        args={"graph": "bloodhound_lab", "query": "shortest_path_to_domain_admin"},
        payload={"family": "bloodhound_cypher_path_query", "value": "MATCH p=shortestPath((u)-[*1..]->(g {name:'DOMAIN ADMINS'})) RETURN p LIMIT 1"},
        preconditions=["offline lab graph", "no live collection", "approved graph analysis"],
        expected_evidence={"evidence_ref": ev, "path_returned": True},
        cleanup=["none; offline graph query"],
        finding=finding(klass, ev, "Lab graph shows a privileged path", "Identity relationships may permit privilege escalation if the same path exists in production.", "Remove excessive group rights and validate privileged path controls."),
    )
    prompt = "Use an offline BloodHound-style lab graph to find whether a path to Domain Admin exists."
    return row(split=split, idx=idx, klass=klass, payload_family="bloodhound_cypher_path_query", prompt=prompt, content=content)


def make_ad_smb_sim(rng: random.Random, split: str, idx: int) -> dict[str, Any]:
    klass = "ad_smb_signing_relay_simulation"
    ev = f"domain-{klass}-{idx:05d}"
    host = lab_ip(rng)
    content = assistant_json(
        klass=klass,
        reasoning="Use a relay simulator input, not a live relay. Evidence is signing config and simulator result only.",
        tool="lab_relay_simulator",
        args={"target": host},
        payload={"family": "smb_signing_relay_simulation", "value": "simulate_only"},
        preconditions=["simulator mode", "no credential capture", "no live relay"],
        expected_evidence={"evidence_ref": ev, "relay_simulation_possible": True, "credentials_captured": False},
        cleanup=["discard simulator state"],
        finding=finding(klass, ev, "SMB signing configuration permits relay in simulator", "If authentication is coerced, relay paths may be viable where signing is not required.", "Require SMB signing and reduce coercion paths."),
    )
    prompt = f"SMB lab host {host} has signing not required. Use simulator only; no credential capture."
    return row(split=split, idx=idx, klass=klass, payload_family="smb_signing_relay_simulation", prompt=prompt, content=content)


def make_cloud_iam(rng: random.Random, split: str, idx: int) -> dict[str, Any]:
    klass = "cloud_iam_policy_simulation"
    ev = f"domain-{klass}-{idx:05d}"
    action = rng.choice(["s3:ListBucket", "iam:PassRole", "ec2:RunInstances"])
    content = assistant_json(
        klass=klass,
        reasoning="Use cloud policy simulation APIs only; do not perform the privileged action.",
        tool="cloud_policy_simulator",
        args={"action": action, "provider": "aws-lab"},
        payload={"family": "iam_policy_simulation_action", "value": action},
        preconditions=["read-only simulator permission", "lab account", "no action execution"],
        expected_evidence={"allowed_result_recorded": True, "evidence_ref": ev},
        cleanup=["none; simulation only"],
        finding=finding(klass, ev, "Cloud IAM simulator allows a sensitive action", "A principal may have more privilege than intended.", "Apply least privilege and validate policies with simulation and access analyzer."),
    )
    prompt = f"Lab cloud principal should be least-privilege. Simulate whether action {action} is allowed."
    return row(split=split, idx=idx, klass=klass, payload_family="iam_policy_simulation_action", prompt=prompt, content=content)


def make_cloud_storage(rng: random.Random, split: str, idx: int) -> dict[str, Any]:
    klass = "cloud_storage_public_list_marker"
    ev = f"domain-{klass}-{idx:05d}"
    bucket = f"lab-bucket-{rng.randint(1000, 9999)}"
    content = assistant_json(
        klass=klass,
        reasoning="List only the synthetic lab bucket prefix and do not download objects.",
        tool="cloud_storage_readonly",
        args={"bucket": bucket, "operation": "list_prefix"},
        payload={"family": "storage_public_list_marker", "value": "prefix=aegispt-proof/"},
        preconditions=["synthetic bucket", "read-only listing approval", "no object download"],
        expected_evidence={"evidence_ref": ev, "public_listing_seen": True},
        cleanup=["none; no write"],
        finding=finding(klass, ev, "Cloud storage allowed public listing of lab prefix", "Public listing can disclose object names and business context.", "Block public access and restrict bucket policies."),
    )
    prompt = f"Lab storage bucket {bucket} may allow public list. Check only proof prefix; no downloads."
    return row(split=split, idx=idx, klass=klass, payload_family="storage_public_list_marker", prompt=prompt, content=content)


def make_cloud_kube(rng: random.Random, split: str, idx: int) -> dict[str, Any]:
    klass = "cloud_kube_rbac_selfsubjectreview"
    ev = f"domain-{klass}-{idx:05d}"
    verb = rng.choice(["list pods", "get secrets", "create pods"])
    content = assistant_json(
        klass=klass,
        reasoning="Use SelfSubjectAccessReview to check RBAC without performing the action.",
        tool="kube_selfsubjectaccessreview",
        args={"cluster": "lab-kube", "verb_resource": verb},
        payload={"family": "kube_rbac_can_i", "value": verb},
        preconditions=["lab kube context", "self-review API", "no workload mutation"],
        expected_evidence={"allowed_or_denied": True, "evidence_ref": ev},
        cleanup=["none; review only"],
        finding=finding(klass, ev, "Kubernetes RBAC self-review permits sensitive action", "The service account may have excessive cluster permissions.", "Reduce RBAC verbs and resources to least privilege."),
    )
    prompt = f"Lab Kubernetes service account: check whether it can `{verb}` using self-review only."
    return row(split=split, idx=idx, klass=klass, payload_family="kube_rbac_can_i", prompt=prompt, content=content)


def make_cloud_imds(rng: random.Random, split: str, idx: int) -> dict[str, Any]:
    klass = "cloud_imds_mock_token_requirement"
    ev = f"domain-{klass}-{idx:05d}"
    content = assistant_json(
        klass=klass,
        reasoning="Use the lab IMDS mock to verify token enforcement; never contact real metadata IPs.",
        tool="lab_imds_mock_check",
        args={"endpoint": "http://127.0.0.1:8082/mock-imds"},
        payload={"family": "imds_token_requirement_probe", "value": "GET without token then PUT token"},
        preconditions=["mock endpoint", "loopback only", "no real cloud metadata"],
        expected_evidence={"evidence_ref": ev, "token_required": True},
        cleanup=["stop mock service"],
        finding=finding(klass, ev, "Lab metadata service mock verifies token requirement", "Metadata services without token enforcement are more exposed to SSRF chains.", "Require IMDSv2-style token enforcement and block metadata egress."),
    )
    prompt = "Check a loopback lab metadata mock for token requirement; do not contact real metadata endpoints."
    return row(split=split, idx=idx, klass=klass, payload_family="imds_token_requirement_probe", prompt=prompt, content=content)


def make_lan_snmp(rng: random.Random, split: str, idx: int) -> dict[str, Any]:
    klass = "lan_snmp_readonly_oid"
    ev = f"domain-{klass}-{idx:05d}"
    target = lab_ip(rng)
    content = assistant_json(
        klass=klass,
        reasoning="Request only sysDescr with a provided read-only community; do not write SNMP state.",
        tool="lan_snmp_readonly",
        args={"oid": "1.3.6.1.2.1.1.1.0", "target": target},
        payload={"family": "snmp_readonly_sysdescr", "value": "sysDescr.0"},
        preconditions=["provided read-only community", "lab device", "no SNMP set"],
        expected_evidence={"evidence_ref": ev, "sysdescr_returned": True},
        cleanup=["none; read-only"],
        finding=finding(klass, ev, "SNMP read-only metadata exposed", "Device metadata supports network reconnaissance.", "Restrict SNMP ACLs and migrate to SNMPv3."),
    )
    prompt = f"Lab LAN device {target} has read-only SNMP approval. Query sysDescr only."
    return row(split=split, idx=idx, klass=klass, payload_family="snmp_readonly_sysdescr", prompt=prompt, content=content)


def make_lan_segmentation(rng: random.Random, split: str, idx: int) -> dict[str, Any]:
    klass = "lan_segmentation_tcp_marker"
    ev = f"domain-{klass}-{idx:05d}"
    target = lab_ip(rng)
    port = rng.choice([22, 445, 3389, 5432])
    content = assistant_json(
        klass=klass,
        reasoning="Use a TCP connect marker only to validate segmentation; do not authenticate.",
        tool="lan_tcp_connect_check",
        args={"port": port, "target": target},
        payload={"family": "tcp_reachability_marker", "value": f"connect:{port}"},
        preconditions=["segmentation test approved", "single TCP connect", "no auth"],
        expected_evidence={"evidence_ref": ev, "reachable_recorded": True},
        cleanup=["close socket"],
        finding=finding(klass, ev, "Segmentation allows TCP reachability to sensitive service", "Restricted zones can reach a service that may not be intended.", "Tighten firewall rules and validate required flows."),
    )
    prompt = f"Validate whether lab source zone can reach {target}:{port}. TCP connect only."
    return row(split=split, idx=idx, klass=klass, payload_family="tcp_reachability_marker", prompt=prompt, content=content)


def make_lan_discovery(rng: random.Random, split: str, idx: int) -> dict[str, Any]:
    klass = "lan_mdns_ssdp_discovery_marker"
    ev = f"domain-{klass}-{idx:05d}"
    content = assistant_json(
        klass=klass,
        reasoning="Use passive/standard discovery query markers only; no service login or device control.",
        tool="lan_discovery_probe",
        args={"protocols": ["mdns", "ssdp"], "scope": "lab-vlan"},
        payload={"family": "mdns_ssdp_discovery_marker", "value": "discover_lab_services"},
        preconditions=["lab VLAN", "discovery approved", "no authentication"],
        expected_evidence={"device_count_recorded": True, "evidence_ref": ev},
        cleanup=["stop listener"],
        finding=finding(klass, ev, "LAN discovery exposes device inventory", "Broadcast discovery can reveal asset names and services.", "Limit discovery protocols where unnecessary and segment devices."),
    )
    prompt = "Lab VLAN discovery is approved. Collect mDNS/SSDP inventory only."
    return row(split=split, idx=idx, klass=klass, payload_family="mdns_ssdp_discovery_marker", prompt=prompt, content=content)


def make_lan_smb(rng: random.Random, split: str, idx: int) -> dict[str, Any]:
    klass = "lan_smb_signing_config_probe"
    ev = f"domain-{klass}-{idx:05d}"
    target = lab_ip(rng)
    content = assistant_json(
        klass=klass,
        reasoning="Probe SMB signing configuration only. Do not authenticate, coerce, or relay.",
        tool="lan_smb_config_probe",
        args={"target": target},
        payload={"family": "smb_signing_config_probe", "value": "negotiate_only"},
        preconditions=["lab host", "negotiate-only probe", "no credentials"],
        expected_evidence={"evidence_ref": ev, "signing_required_recorded": True},
        cleanup=["close SMB negotiation"],
        finding=finding(klass, ev, "SMB signing is not required", "Relay-style paths become more plausible if authentication can be coerced.", "Require SMB signing through policy."),
    )
    prompt = f"Check SMB signing on lab host {target}. Do not authenticate."
    return row(split=split, idx=idx, klass=klass, payload_family="smb_signing_config_probe", prompt=prompt, content=content)


def make_iot_mqtt(rng: random.Random, split: str, idx: int) -> dict[str, Any]:
    klass = "iot_mqtt_test_topic_marker"
    ev = f"domain-{klass}-{idx:05d}"
    proof = marker(rng)
    broker = lab_ip(rng)
    content = assistant_json(
        klass=klass,
        reasoning="Publish to an approved disposable test topic only, then remove retained marker if present.",
        tool="iot_mqtt_lab_check",
        args={"broker": broker, "topic": "aegispt/test/proof"},
        payload={"family": "mqtt_test_topic_marker", "value": proof},
        preconditions=["lab broker", "test topic only", "no device command topics"],
        expected_evidence={"evidence_ref": ev, "marker_seen_on_test_topic": proof},
        cleanup=["delete retained test marker if set", "disconnect client"],
        finding=finding(klass, ev, "MQTT broker accepted test-topic marker", "Unauthenticated or weakly authorized publish/read can affect IoT telemetry.", "Require MQTT authentication and topic-level ACLs."),
    )
    prompt = f"Lab MQTT broker {broker} permits testing only on aegispt/test/proof. Use marker {proof}."
    return row(split=split, idx=idx, klass=klass, payload_family="mqtt_test_topic_marker", prompt=prompt, content=content)


def make_iot_upnp(rng: random.Random, split: str, idx: int) -> dict[str, Any]:
    klass = "iot_upnp_ssdp_probe"
    ev = f"domain-{klass}-{idx:05d}"
    content = assistant_json(
        klass=klass,
        reasoning="Use SSDP M-SEARCH discovery only. Do not add port mappings or modify UPnP state.",
        tool="iot_ssdp_probe",
        args={"scope": "lab-iot-vlan"},
        payload={"family": "upnp_ssdp_msearch", "value": "ssdp:all"},
        preconditions=["lab VLAN", "discovery only", "no port mapping"],
        expected_evidence={"evidence_ref": ev, "upnp_device_seen": True},
        cleanup=["stop UDP listener"],
        finding=finding(klass, ev, "UPnP/SSDP exposes IoT device metadata", "Device discovery can expose model and service details.", "Disable UPnP where unnecessary and segment IoT devices."),
    )
    prompt = "Lab IoT VLAN allows UPnP discovery check. Do discovery only; no port mappings."
    return row(split=split, idx=idx, klass=klass, payload_family="upnp_ssdp_msearch", prompt=prompt, content=content)


def make_iot_rtsp(rng: random.Random, split: str, idx: int) -> dict[str, Any]:
    klass = "iot_rtsp_options_probe"
    ev = f"domain-{klass}-{idx:05d}"
    target = lab_ip(rng)
    content = assistant_json(
        klass=klass,
        reasoning="Use RTSP OPTIONS only to confirm service exposure; do not authenticate or stream media.",
        tool="iot_rtsp_options",
        args={"port": 554, "target": target},
        payload={"family": "rtsp_options_probe", "value": "OPTIONS * RTSP/1.0"},
        preconditions=["lab camera", "OPTIONS only", "no media stream"],
        expected_evidence={"evidence_ref": ev, "rtsp_methods_returned": True},
        cleanup=["close RTSP connection"],
        finding=finding(klass, ev, "RTSP service exposes camera protocol surface", "Camera services can disclose protocol support and expand attack surface.", "Restrict RTSP to trusted management networks."),
    )
    prompt = f"Lab camera {target}: check RTSP exposure using OPTIONS only."
    return row(split=split, idx=idx, klass=klass, payload_family="rtsp_options_probe", prompt=prompt, content=content)


def make_iot_modbus(rng: random.Random, split: str, idx: int) -> dict[str, Any]:
    klass = "iot_modbus_read_device_id"
    ev = f"domain-{klass}-{idx:05d}"
    target = lab_ip(rng)
    content = assistant_json(
        klass=klass,
        reasoning="Use Modbus read device identification only. Do not write coils or registers.",
        tool="iot_modbus_readonly",
        args={"function": "read_device_identification", "target": target},
        payload={"family": "modbus_read_device_id", "value": "MEI type 14"},
        preconditions=["lab PLC simulator", "read-only function", "no register writes"],
        expected_evidence={"device_id_recorded": True, "evidence_ref": ev},
        cleanup=["close Modbus session"],
        finding=finding(klass, ev, "Modbus device identification exposed in lab", "Industrial protocol metadata can support operational reconnaissance.", "Restrict Modbus access and monitor ICS network segments."),
    )
    prompt = f"Lab Modbus simulator {target}: read device identification only; no writes."
    return row(split=split, idx=idx, klass=klass, payload_family="modbus_read_device_id", prompt=prompt, content=content)


TEMPLATES: list[Callable[[random.Random, str, int], dict[str, Any]]] = [
    make_ad_ldap,
    make_ad_preauth,
    make_ad_bloodhound,
    make_ad_smb_sim,
    make_cloud_iam,
    make_cloud_storage,
    make_cloud_kube,
    make_cloud_imds,
    make_lan_snmp,
    make_lan_segmentation,
    make_lan_discovery,
    make_lan_smb,
    make_iot_mqtt,
    make_iot_upnp,
    make_iot_rtsp,
    make_iot_modbus,
]


def generate_rows(count: int, *, split: str, seed: int = SEED) -> list[dict[str, Any]]:
    rng = random.Random(seed + sum(ord(ch) for ch in split))
    templates = list(TEMPLATES)
    rows: list[dict[str, Any]] = []
    for idx in range(count):
        if idx % len(templates) == 0:
            rng.shuffle(templates)
        rows.append(templates[idx % len(templates)](rng, split, idx))
    return rows


def validate_rows(rows: list[dict[str, Any]]) -> dict[str, Any]:
    classes = Counter()
    domains = Counter()
    for item in rows:
        metadata = item["metadata"]
        klass = metadata["vulnerability_class"]
        classes[klass] += 1
        domains[metadata["domain"]] += 1
        parsed = json.loads(item["messages"][-1]["content"])
        required = {"args", "cleanup", "done", "expected_evidence", "finding", "payload", "preconditions", "reasoning", "safety", "tool"}
        if set(parsed) != required:
            raise ValueError(f"bad schema in {metadata['case_id']}")
        if parsed["safety"].get("runtime_execution") is not False:
            raise ValueError(f"runtime execution allowed in {metadata['case_id']}")
        if parsed["payload"]["family"] != metadata["payload_family"]:
            raise ValueError(f"payload family mismatch in {metadata['case_id']}")
    missing = sorted(set(CLASSES) - set(classes))
    if missing:
        raise ValueError(f"missing classes: {missing}")
    return {"domains": dict(sorted(domains.items())), "vulnerability_classes": dict(sorted(classes.items()))}


def parse_counts(values: list[str] | None) -> dict[str, int]:
    counts = dict(DEFAULT_COUNTS)
    for value in values or []:
        split, raw_count = value.split("=", 1)
        if split not in counts:
            raise ValueError(f"unknown split {split!r}")
        counts[split] = int(raw_count)
    return counts


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for item in rows:
            handle.write(json.dumps(item, sort_keys=True) + "\n")


def build_dataset(out_dir: Path, prefix: str, counts: dict[str, int], seed: int = SEED) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest: dict[str, Any] = {
        "dataset": prefix,
        "format": "jsonl chat SFT AD/cloud/LAN/IoT payload-domain extension",
        "policy": {
            "lab_only": True,
            "no_credential_dumping": True,
            "runtime_execution": False,
            "train_eval_test_separated": True,
        },
        "seed": seed,
        "splits": {},
    }
    for split, count in counts.items():
        rows = generate_rows(count, split=split, seed=seed)
        stats = validate_rows(rows)
        path = out_dir / f"{prefix}_{split}.jsonl"
        write_jsonl(path, rows)
        manifest["splits"][split] = {"count": count, "path": str(path), "stats": stats}
    manifest_path = out_dir / f"{prefix}_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument("--prefix", default=DEFAULT_PREFIX)
    parser.add_argument("--seed", type=int, default=SEED)
    parser.add_argument("--count", action="append", help="Override split size, e.g. train=1000")
    args = parser.parse_args()
    manifest = build_dataset(args.out_dir, args.prefix, parse_counts(args.count), seed=args.seed)
    print(json.dumps(manifest["splits"], indent=2, sort_keys=True))
    print(f"manifest: {args.out_dir / (args.prefix + '_manifest.json')}")


if __name__ == "__main__":
    main()
