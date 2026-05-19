from __future__ import annotations

import re
from typing import Any
from uuid import UUID

from sqlalchemy.orm import Session

from api.app.models import InventorySnapshot, Scope
from api.app.services.runs import derive_targets_from_target_map, target_value_is_allowed

WARGAMING_PROFILE_NAME = "wargaming-lab-simulation"
LAB_CLASSIFICATIONS = {"isolated_digital_twin", "local_lab"}
SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")


def validate_wargaming_sandbox_configuration(
    session: Session,
    *,
    engagement_id: UUID,
    source_inventory_snapshot_id: UUID | None,
    scope: Scope,
    configuration: dict[str, Any] | None,
) -> dict[str, Any]:
    if source_inventory_snapshot_id is None:
        raise ValueError("wargaming simulation requires a verified isolated-lab inventory snapshot")

    snapshot = session.get(InventorySnapshot, source_inventory_snapshot_id)
    if snapshot is None or snapshot.engagement_id != engagement_id:
        raise ValueError("wargaming simulation inventory snapshot is not available for this engagement")

    verification = _snapshot_wargaming_verification(snapshot)
    if not verification:
        raise ValueError("wargaming simulation requires inventory evidence flagged as an isolated lab or digital twin")

    config = configuration if isinstance(configuration, dict) else {}
    requested = config.get("wargaming_sandbox")
    if not isinstance(requested, dict):
        raise ValueError("wargaming simulation requires a wargaming_sandbox configuration block")

    if not bool(requested.get("operator_acknowledged_lab_only")):
        raise ValueError("operator must acknowledge that wargaming simulation is lab-only")
    if bool(requested.get("disable_approval_gates")) or bool(requested.get("bypass_choke_points")):
        raise ValueError("wargaming simulation cannot disable approval gates or choke points")
    if bool(requested.get("production_target")):
        raise ValueError("wargaming simulation rejects production targets")

    classification = str(verification.get("target_classification") or "").strip().lower()
    evidence_ref = str(verification.get("verification_evidence_ref") or "").strip()
    verification_hash = str(verification.get("sandbox_verification_sha256") or "").strip()
    if classification not in LAB_CLASSIFICATIONS:
        raise ValueError("wargaming simulation target must be classified as isolated_digital_twin or local_lab")
    if not evidence_ref:
        raise ValueError("wargaming simulation requires a verification evidence ref")
    if not SHA256_RE.fullmatch(verification_hash):
        raise ValueError("wargaming simulation requires a SHA256 verification hash for the lab snapshot")

    _validate_requested_targets_match_verified_lab(scope=scope, configuration=config, verification=verification)

    return {
        "mode": "lab_only_simulation",
        "profile_name": WARGAMING_PROFILE_NAME,
        "verified_isolated_lab": True,
        "target_classification": classification,
        "verification_evidence_ref": evidence_ref,
        "sandbox_verification_sha256": verification_hash.lower(),
        "source_inventory_snapshot_id": str(snapshot.id),
        "simulation_only": True,
        "approval_gates_bypassed": False,
        "choke_points_disabled": False,
        "automatic_live_execution": False,
        "production_target": False,
        "runtime_dispatch_created": False,
        "kill_switch_bypassed": False,
        "operator_acknowledged_lab_only": True,
    }


def _snapshot_wargaming_verification(snapshot: InventorySnapshot) -> dict[str, Any]:
    candidates = []
    for payload in (
        snapshot.summary_json,
        snapshot.normalized_inventory_json,
        snapshot.raw_inputs_json,
    ):
        if isinstance(payload, dict):
            candidates.append(payload.get("wargaming_sandbox"))
            candidates.append(payload.get("sandbox_verification"))
            candidates.append(payload.get("digital_twin_verification"))

    for candidate in candidates:
        if isinstance(candidate, dict) and bool(candidate.get("verified_isolated_lab")):
            return dict(candidate)
    return {}


def _validate_requested_targets_match_verified_lab(
    *,
    scope: Scope,
    configuration: dict[str, Any],
    verification: dict[str, Any],
) -> None:
    verified_targets = {
        str(value).strip()
        for value in verification.get("verified_targets", [])
        if isinstance(value, str) and value.strip()
    }
    configured_targets = derive_targets_from_target_map(
        configuration.get("targets") if isinstance(configuration.get("targets"), dict) else scope.allowlist_json
    )
    if not configured_targets:
        raise ValueError("wargaming simulation requires at least one configured or scoped lab target")
    for target in configured_targets:
        value = str(target.get("value") or "").strip()
        if target.get("kind") == "path":
            continue
        if not target_value_is_allowed(scope.allowlist_json, value):
            raise ValueError(f"wargaming simulation target {value} is outside approved scope")
        if verified_targets and value not in verified_targets:
            raise ValueError(f"wargaming simulation target {value} is not in the verified lab snapshot")
