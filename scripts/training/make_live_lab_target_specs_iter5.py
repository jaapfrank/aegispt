"""Generate iter-5 live-lab target specifications for dataset-class coverage.

This is a data-lane artifact only. It maps every positive payload curriculum
class to a future disposable lab target contract so the runner lane can later
test the same classes in real lab services instead of text-only prompts.

No service is started, no runtime binding is enabled, and no capability pack is
installed by this script.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.training.make_payload_capability_iter4_dataset import (
    DOMAINS as PAYLOAD_DOMAINS,
)
from scripts.training.make_payload_capability_iter4_dataset import (
    VULN_CLASSES as PAYLOAD_CLASSES,
)
from scripts.training.make_payload_domain_extension_iter4_dataset import (
    CLASSES as DOMAIN_CLASSES,
)
from scripts.training.make_payload_domain_extension_iter4_dataset import (
    DOMAIN as EXTENSION_DOMAINS,
)

DEFAULT_OUT_DIR = Path.home() / ".aegispt-tools" / "training"
DEFAULT_PREFIX = "aegispt_live_lab_target_specs_iter5"
DEFAULT_VARIANTS = 3
SEED = 20260605

SOURCE_FAMILIES = {
    "payload_capability": "aegispt_payload_capability_iter4",
    "payload_domain_extension": "aegispt_payload_domain_extension_iter4",
}

ALL_CLASSES = tuple(PAYLOAD_CLASSES) + tuple(DOMAIN_CLASSES)

SERVICE_HINTS: dict[str, dict[str, Any]] = {
    "api_mass_assignment": {
        "entrypoint": {"method": "PATCH", "parameter": "role", "path": "/api/lab/profile"},
        "payload_family": "mass_assignment_disposable_account",
        "service_kind": "rest_api_lab",
        "surface": "api",
    },
    "command_injection_echo": {
        "entrypoint": {"method": "POST", "parameter": "host", "path": "/lab/ping"},
        "payload_family": "command_injection_echo_marker",
        "service_kind": "web_command_adapter_lab",
        "surface": "web",
    },
    "file_upload_benign_polyglot": {
        "entrypoint": {"method": "POST", "parameter": "file", "path": "/lab/upload"},
        "payload_family": "benign_svg_upload_marker",
        "service_kind": "file_upload_lab",
        "surface": "web",
    },
    "graphql_introspection": {
        "entrypoint": {"method": "POST", "parameter": "query", "path": "/graphql"},
        "payload_family": "graphql_introspection_minimal",
        "service_kind": "graphql_api_lab",
        "surface": "api",
    },
    "idor_object_switch": {
        "entrypoint": {"method": "GET", "parameter": "object_id", "path": "/api/lab/orders/{id}"},
        "payload_family": "idor_object_switch",
        "service_kind": "rest_api_lab",
        "surface": "api",
    },
    "jwt_unsigned_token_lab": {
        "entrypoint": {"method": "GET", "parameter": "Authorization", "path": "/api/lab/admin"},
        "payload_family": "unsigned_jwt_toy_lab_negative",
        "service_kind": "jwt_auth_lab",
        "surface": "api",
    },
    "open_redirect_marker": {
        "entrypoint": {"method": "GET", "parameter": "next", "path": "/lab/redirect"},
        "payload_family": "open_redirect_example_invalid",
        "service_kind": "redirect_lab",
        "surface": "web",
    },
    "path_traversal_lab_file": {
        "entrypoint": {"method": "GET", "parameter": "file", "path": "/lab/download"},
        "payload_family": "path_traversal_seeded_file",
        "service_kind": "file_read_lab",
        "surface": "web",
    },
    "sqli_boolean": {
        "entrypoint": {"method": "GET", "parameter": "q", "path": "/lab/search"},
        "payload_family": "boolean_sqli",
        "service_kind": "sql_lab",
        "surface": "web",
    },
    "sqli_union_marker": {
        "entrypoint": {"method": "GET", "parameter": "category", "path": "/lab/products"},
        "payload_family": "union_sqli_marker",
        "service_kind": "sql_lab",
        "surface": "web",
    },
    "ssrf_loopback_probe": {
        "entrypoint": {"method": "POST", "parameter": "url", "path": "/lab/fetch"},
        "payload_family": "ssrf_loopback_probe",
        "service_kind": "ssrf_lab",
        "surface": "web",
    },
    "ssti_arithmetic_marker": {
        "entrypoint": {"method": "GET", "parameter": "name", "path": "/lab/render"},
        "payload_family": "ssti_arithmetic_marker",
        "service_kind": "template_lab",
        "surface": "web",
    },
    "xss_reflected_marker": {
        "entrypoint": {"method": "GET", "parameter": "q", "path": "/lab/reflect"},
        "payload_family": "reflected_xss_marker",
        "service_kind": "xss_lab",
        "surface": "web",
    },
    "xss_stored_marker": {
        "entrypoint": {"method": "POST", "parameter": "comment", "path": "/lab/comments"},
        "payload_family": "stored_xss_marker",
        "service_kind": "xss_lab",
        "surface": "web",
    },
    "xxe_lab_file_read": {
        "entrypoint": {"method": "POST", "parameter": "xml", "path": "/lab/xml"},
        "payload_family": "xxe_seeded_lab_file",
        "service_kind": "xml_parser_lab",
        "surface": "web",
    },
}


def class_domain(dataset_class: str) -> str:
    if dataset_class in PAYLOAD_DOMAINS:
        return PAYLOAD_DOMAINS[dataset_class]
    return EXTENSION_DOMAINS[dataset_class]


def source_family(dataset_class: str) -> str:
    if dataset_class in PAYLOAD_DOMAINS:
        return SOURCE_FAMILIES["payload_capability"]
    return SOURCE_FAMILIES["payload_domain_extension"]


def extension_hint(dataset_class: str) -> dict[str, Any]:
    domain = class_domain(dataset_class)
    if dataset_class.startswith("ad_"):
        return {
            "entrypoint": {"operation": dataset_class.removeprefix("ad_"), "protocol": "ldap/smb/graph"},
            "payload_family": dataset_class.removeprefix("ad_"),
            "service_kind": "active_directory_simulator",
            "surface": "identity",
        }
    if dataset_class.startswith("cloud_kube"):
        return {
            "entrypoint": {"operation": "self_subject_review", "protocol": "kubernetes_api"},
            "payload_family": dataset_class.removeprefix("cloud_"),
            "service_kind": "kubernetes_rbac_lab",
            "surface": "cloud",
        }
    if dataset_class.startswith("cloud_"):
        return {
            "entrypoint": {"operation": dataset_class.removeprefix("cloud_"), "protocol": "cloud_api"},
            "payload_family": dataset_class.removeprefix("cloud_"),
            "service_kind": "cloud_control_plane_simulator",
            "surface": "cloud",
        }
    if dataset_class.startswith("lan_"):
        return {
            "entrypoint": {"operation": dataset_class.removeprefix("lan_"), "protocol": "tcp/udp"},
            "payload_family": dataset_class.removeprefix("lan_"),
            "service_kind": "lan_service_simulator",
            "surface": "network",
        }
    if dataset_class.startswith("iot_"):
        return {
            "entrypoint": {"operation": dataset_class.removeprefix("iot_"), "protocol": "iot_protocol"},
            "payload_family": dataset_class.removeprefix("iot_"),
            "service_kind": "iot_device_simulator",
            "surface": "iot",
        }
    raise ValueError(f"missing hint for {dataset_class!r} in domain {domain!r}")


def class_hint(dataset_class: str) -> dict[str, Any]:
    if dataset_class in SERVICE_HINTS:
        return SERVICE_HINTS[dataset_class]
    return extension_hint(dataset_class)


def stable_marker(dataset_class: str, variant: int) -> str:
    digest = hashlib.sha1(f"{SEED}:{dataset_class}:{variant}".encode()).hexdigest()[:10]
    return f"AEGISPT_LAB_{digest.upper()}"


def materialization_hint(dataset_class: str, variant: int, hint: dict[str, Any]) -> dict[str, Any]:
    return {
        "container_profile": f"aegispt-{hint['service_kind']}",
        "fixture_seed": f"{dataset_class}:{variant}:{SEED}",
        "healthcheck": {
            "expected_status": "ready",
            "mode": "runner_port_poll",
            "path": "/healthz",
        },
        "initial_state": [
            "seed baseline object",
            "seed marker evidence",
            "record cleanup snapshot",
        ],
        "network": "isolated_aegispt_lab",
        "runner_lane_owner": "future_runner_lane",
    }


def lab_target_spec(dataset_class: str, variant: int) -> dict[str, Any]:
    hint = class_hint(dataset_class)
    service_name = dataset_class.replace("_", "-")
    lab_host = f"{service_name}-v{variant}.aegispt-lab.internal"
    marker = stable_marker(dataset_class, variant)
    return {
        "approval_level": "lab_payload_approved",
        "blocked_if": [
            "runtime_binding_requested_before_runner_lane_materialization",
            "target_not_disposable_lab",
            "target_not_in_written_scope",
            "cleanup_hook_missing",
            "baseline_snapshot_missing",
            "evidence_capture_missing",
        ],
        "cleanup": {
            "required": True,
            "steps": [
                "restore baseline snapshot",
                "delete seeded marker objects",
                "remove disposable lab account or topic",
                "archive request and response hashes",
            ],
        },
        "data_lane_only": True,
        "dataset_class": dataset_class,
        "domain": class_domain(dataset_class),
        "entrypoint": hint["entrypoint"],
        "expected_evidence": {
            "baseline_required": True,
            "evidence_ref_template": f"live-lab-{dataset_class}-{{run_id}}",
            "marker": marker,
            "must_capture": [
                "scope id",
                "request hash",
                "response hash",
                "marker observation",
                "cleanup receipt",
            ],
        },
        "lab_target_id": f"live-lab-{service_name}-v{variant}",
        "materialization_hint": materialization_hint(dataset_class, variant, hint),
        "payload_family": hint["payload_family"],
        "runner_contract": {
            "allowed_network": "isolated_aegispt_lab",
            "data_lane_only": True,
            "manual_approval_required": True,
            "must_be_materialized_before_execution": True,
            "runtime_binding": False,
            "scope_enforced": True,
        },
        "scope": {
            "allowed_hosts": [lab_host],
            "allowed_ports": [8000 + variant],
            "blocked_hosts": [
                "169.254.169.254",
                "metadata.google.internal",
                "localhost outside the lab namespace",
            ],
            "scope_id": f"SCOPE-LIVE-LAB-{service_name.upper()}-V{variant}",
        },
        "seeded_marker": marker,
        "service_kind": hint["service_kind"],
        "source_dataset_family": source_family(dataset_class),
        "surface": hint["surface"],
    }


def generate_specs(*, variants: int = DEFAULT_VARIANTS) -> list[dict[str, Any]]:
    specs: list[dict[str, Any]] = []
    for dataset_class in ALL_CLASSES:
        for variant in range(1, variants + 1):
            specs.append(lab_target_spec(dataset_class, variant))
    return specs


def validate_specs(specs: list[dict[str, Any]]) -> dict[str, Any]:
    classes = Counter(spec["dataset_class"] for spec in specs)
    domains = Counter(spec["domain"] for spec in specs)
    source_families = Counter(spec["source_dataset_family"] for spec in specs)
    target_ids = [spec["lab_target_id"] for spec in specs]
    if len(target_ids) != len(set(target_ids)):
        raise ValueError("duplicate live lab target ids")
    missing = sorted(set(ALL_CLASSES) - set(classes))
    if missing:
        raise ValueError(f"missing live lab specs for classes: {missing}")
    for spec in specs:
        if spec["runner_contract"].get("runtime_binding") is not False:
            raise ValueError(f"runtime binding enabled for {spec['lab_target_id']}")
        if spec.get("data_lane_only") is not True:
            raise ValueError(f"not data-lane only: {spec['lab_target_id']}")
        if not spec["expected_evidence"].get("must_capture"):
            raise ValueError(f"missing evidence contract: {spec['lab_target_id']}")
        if not spec["cleanup"].get("required"):
            raise ValueError(f"missing cleanup contract: {spec['lab_target_id']}")
        if any(host.endswith(".example.com") for host in spec["scope"]["allowed_hosts"]):
            raise ValueError(f"real-looking host in scope: {spec['lab_target_id']}")
    return {
        "classes": dict(sorted(classes.items())),
        "domains": dict(sorted(domains.items())),
        "source_families": dict(sorted(source_families.items())),
        "target_count": len(specs),
    }


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")


def build_dataset(out_dir: Path, prefix: str, *, variants: int = DEFAULT_VARIANTS) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    specs = generate_specs(variants=variants)
    stats = validate_specs(specs)
    path = out_dir / f"{prefix}.jsonl"
    write_jsonl(path, specs)
    manifest = {
        "dataset": prefix,
        "format": "jsonl live-lab target specs",
        "path": str(path),
        "policy": {
            "data_lane_only": True,
            "materializes_targets": False,
            "runtime_binding": False,
            "runtime_execution": False,
        },
        "seed": SEED,
        "stats": stats,
    }
    manifest_path = out_dir / f"{prefix}_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument("--prefix", default=DEFAULT_PREFIX)
    parser.add_argument("--variants", type=int, default=DEFAULT_VARIANTS)
    args = parser.parse_args()
    manifest = build_dataset(args.out_dir, args.prefix, variants=args.variants)
    print(json.dumps(manifest["stats"], indent=2, sort_keys=True))
    print(f"manifest: {args.out_dir / (args.prefix + '_manifest.json')}")


if __name__ == "__main__":
    main()
