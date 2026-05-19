"""Runner-emitted structured entity observation ingestion.

Runners do not have DB access — they return a RunnerExecution with metadata
and artifacts. To let a runner emit structured graph entities (asset, api,
identity, credential_ref, etc.) without changing the RunnerExecution contract,
this module defines:

1. `make_observation()` — runner-side helper that constructs a typed dict.
   The runner appends these to `metadata["observations"]` (additive — existing
   runners that don't opt in continue to work).

2. `persist_runner_observations()` — orchestrator-side helper called after a
   task completes. Reads `execution.metadata["observations"]` and writes
   EvidenceObservation rows.

3. `load_run_observations()` — graph-side helper called by
   build_normalized_evidence_graph to load observations as normalized nodes.

Validation: only the entity types in :data:`ACCEPTED_ENTITY_TYPES` are
accepted. Per backlog-372 scope (#322) we did not add new node types;
backlog-384 (#334) extends the set with ``captured_value`` for cross-target
provenance tracking.

See `docs/evidence_graph_adoption_plan.md` for the full design context.
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from typing import Any, Iterable

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app.models import EvidenceObservation, Run, Task

logger = logging.getLogger(__name__)

# Entity types accepted. ``captured_value`` added in #334 (backlog-384)
# for cross-target provenance: captured values from exec_plan steps
# (JWT, cookie, internal hostname, etc.) become first-class graph
# entities with origin_task_id + origin_step_name in attributes.
ACCEPTED_ENTITY_TYPES: frozenset[str] = frozenset(
    {
        "asset",  # host, service, endpoint
        "api",  # API endpoint
        "identity",  # user, role, group, service_account
        "credential_ref",  # captured credential
        "permission",  # role/permission grant
        "saas_connector",  # SaaS integration
        "captured_value",  # cross-target captured value (#334)
    }
)

# Known value-kind subtypes for captured_value. Free-form; this list is
# documentation only — the schema accepts any subtype string.
CAPTURED_VALUE_KINDS: frozenset[str] = frozenset(
    {"token", "cookie", "hostname", "credential_ref", "url", "other"}
)

# Bytes preserved verbatim in the redacted preview for token-like values.
REDACT_TAIL_CHARS = 4
# Max length below which a non-sensitive value is kept full.
VALUE_KEEP_FULL_MAX = 64

MAX_LABEL_LEN = 480
MAX_SOURCE_ID_LEN = 240
MAX_ATTRIBUTES_BYTES = 8 * 1024  # 8 KB per row cap
MAX_OBSERVATIONS_PER_TASK = 200  # defense against runaway runners


def make_observation(
    *,
    entity_type: str,
    entity_source_id: str,
    entity_label: str,
    entity_subtype: str | None = None,
    attributes: dict[str, Any] | None = None,
    confidence: float = 0.7,
    evidence_refs: list[str] | None = None,
) -> dict[str, Any]:
    """Runner-side constructor for a typed observation dict.

    Runners call this and append the result to
    ``RunnerExecution.metadata["observations"]``. The orchestrator picks them
    up after the task completes.

    Raises ValueError on obviously invalid input so a bad runner fails loudly
    rather than silently corrupting the graph.
    """
    if entity_type not in ACCEPTED_ENTITY_TYPES:
        raise ValueError(
            f"entity_type {entity_type!r} not in ACCEPTED_ENTITY_TYPES "
            f"{sorted(ACCEPTED_ENTITY_TYPES)}"
        )
    if not entity_source_id or not isinstance(entity_source_id, str):
        raise ValueError("entity_source_id must be a non-empty string")
    if not entity_label or not isinstance(entity_label, str):
        raise ValueError("entity_label must be a non-empty string")
    if not isinstance(confidence, (int, float)) or not 0.0 <= float(confidence) <= 1.0:
        raise ValueError("confidence must be a float in [0.0, 1.0]")
    return {
        "entity_type": str(entity_type),
        "entity_source_id": str(entity_source_id)[:MAX_SOURCE_ID_LEN],
        "entity_label": str(entity_label)[:MAX_LABEL_LEN],
        "entity_subtype": (str(entity_subtype)[:64] if entity_subtype else None),
        "attributes": dict(attributes) if attributes else {},
        "confidence": float(confidence),
        "evidence_refs": list(evidence_refs) if evidence_refs else [],
    }


def persist_runner_observations(
    session: Session,
    *,
    run: Run,
    task: Task | None,
    tool: str,
    observations: Iterable[dict[str, Any]] | None,
) -> int:
    """Persist observations emitted by a runner to evidence_observations.

    Returns count of rows written. Silently skips invalid rows (logged at
    debug). Caps total emissions per call to prevent runaway runners.

    Idempotency: this function does NOT dedupe — callers must not invoke it
    twice for the same task execution. The orchestrator should call it exactly
    once per completed task.
    """
    if not observations:
        return 0

    rows_to_add: list[EvidenceObservation] = []
    rejected = 0
    for raw in list(observations)[:MAX_OBSERVATIONS_PER_TASK]:
        if not isinstance(raw, dict):
            rejected += 1
            continue
        entity_type = str(raw.get("entity_type") or "").strip()
        if entity_type not in ACCEPTED_ENTITY_TYPES:
            rejected += 1
            continue
        entity_source_id = str(raw.get("entity_source_id") or "").strip()
        entity_label = str(raw.get("entity_label") or "").strip()
        if not entity_source_id or not entity_label:
            rejected += 1
            continue
        try:
            confidence = float(raw.get("confidence", 0.7))
        except (TypeError, ValueError):
            confidence = 0.7
        confidence = max(0.0, min(1.0, confidence))

        attributes = raw.get("attributes") or {}
        if not isinstance(attributes, dict):
            attributes = {}

        evidence_refs = raw.get("evidence_refs") or []
        if not isinstance(evidence_refs, list):
            evidence_refs = []
        evidence_refs = [str(r) for r in evidence_refs if r]

        entity_subtype = raw.get("entity_subtype")
        if entity_subtype is not None:
            entity_subtype = str(entity_subtype)[:64]

        rows_to_add.append(
            EvidenceObservation(
                run_id=run.id,
                task_id=task.id if task is not None else None,
                entity_type=entity_type,
                entity_source_id=entity_source_id[:MAX_SOURCE_ID_LEN],
                entity_label=entity_label[:MAX_LABEL_LEN],
                entity_subtype=entity_subtype,
                attributes_json=attributes,
                evidence_refs_json=evidence_refs,
                confidence=confidence,
                emitted_by_tool=str(tool or "")[:100] or None,
            )
        )

    if not rows_to_add:
        if rejected:
            logger.debug(
                "evidence_ingest: persisted 0 observations (rejected=%d) for run=%s tool=%s",
                rejected, run.id, tool,
            )
        return 0

    session.add_all(rows_to_add)
    session.flush()
    if rejected:
        logger.info(
            "evidence_ingest: persisted %d observations (rejected=%d) for run=%s tool=%s",
            len(rows_to_add), rejected, run.id, tool,
        )
    else:
        logger.info(
            "evidence_ingest: persisted %d observations for run=%s tool=%s",
            len(rows_to_add), run.id, tool,
        )
    return len(rows_to_add)


def load_run_observations(
    session: Session,
    *,
    run_id: uuid.UUID,
) -> list[EvidenceObservation]:
    """Read all EvidenceObservation rows for a run. Used by
    build_normalized_evidence_graph to merge runner emissions into the graph."""
    stmt = (
        select(EvidenceObservation)
        .where(EvidenceObservation.run_id == run_id)
        .order_by(EvidenceObservation.created_at.asc())
    )
    return list(session.scalars(stmt))


# ---------------------------------------------------------------------------
# #334 — Cross-target provenance: captured-value observations
# ---------------------------------------------------------------------------


def _redact_value(value: str, *, value_kind: str) -> tuple[str, str]:
    """Return ``(redacted_preview, sha256_hex)`` for a captured value.

    Redaction policy:
    - ``token`` / ``cookie`` → ``"…<last 4 chars>"`` + sha256
    - ``credential_ref`` → sha256 only; preview is ``"<redacted>"``
    - ``hostname`` / ``url`` → full value if ≤ VALUE_KEEP_FULL_MAX chars,
      else ``"<first 32>…<last 4>"`` + sha256
    - ``other`` → full value if ≤ VALUE_KEEP_FULL_MAX chars else sha256

    The preview is what callers display in graph projections; the sha256 is
    a stable identity key for cache/dedup. Full values stay in run_credential_vault
    (existing mechanism) — never in this entity's attributes.
    """
    if not isinstance(value, str):
        value = str(value)
    digest = hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()
    kind = (value_kind or "other").lower()

    if kind == "credential_ref":
        return "<redacted>", digest
    if kind in {"token", "cookie"}:
        tail = value[-REDACT_TAIL_CHARS:] if len(value) > REDACT_TAIL_CHARS else value
        return f"…{tail}", digest
    if kind in {"hostname", "url"}:
        if len(value) <= VALUE_KEEP_FULL_MAX:
            return value, digest
        tail = value[-REDACT_TAIL_CHARS:]
        return f"{value[:32]}…{tail}", digest
    # other
    if len(value) <= VALUE_KEEP_FULL_MAX:
        return value, digest
    return digest[:16], digest


def make_captured_value_observation(
    *,
    var_name: str,
    value: str,
    value_kind: str,
    origin_step_name: str,
    source_url: str | None = None,
    confidence: float = 0.85,
) -> dict[str, Any]:
    """Runner-side constructor for a ``captured_value`` observation (#334).

    Composes the entity_label as ``"{var_name} ({value_kind})"`` and uses
    the sha256 of the full value as ``entity_source_id`` so repeated
    captures of the same value dedupe across tasks. The full value is
    redacted per :func:`_redact_value` before going into attributes.

    Callers:
    - ``var_name``: the name the runner gave the captured value
      (e.g. ``"session_cookie"``, ``"csrf_token"``).
    - ``value``: the raw captured value.
    - ``value_kind``: one of CAPTURED_VALUE_KINDS (free-form string; the
      known list is for documentation, not validation).
    - ``origin_step_name``: the exec_plan step that produced the value
      (so the picker can trace "this token came from step X").
    - ``source_url``: optional URL the value was observed at; used by the
      graph projection to show provenance.

    Returns the dict shape expected by :func:`make_observation`. Note: the
    orchestrator's ``persist_runner_observations`` stamps ``task_id`` from
    its DB-side ``Task`` context — the runner does not need to set it.
    """
    if not var_name or not isinstance(var_name, str):
        raise ValueError("var_name must be a non-empty string")
    if not origin_step_name or not isinstance(origin_step_name, str):
        raise ValueError("origin_step_name must be a non-empty string")
    if value is None:
        value = ""
    preview, digest = _redact_value(str(value), value_kind=value_kind)
    attributes: dict[str, Any] = {
        "var_name": str(var_name)[:120],
        "value_kind": str(value_kind or "other")[:32],
        "origin_step_name": str(origin_step_name)[:120],
        "redacted_preview": preview,
        "value_sha256": digest,
    }
    if source_url:
        attributes["source_url"] = str(source_url)[:480]
    return make_observation(
        entity_type="captured_value",
        entity_source_id=digest[:MAX_SOURCE_ID_LEN],
        entity_label=f"{var_name} ({value_kind or 'other'})"[:MAX_LABEL_LEN],
        entity_subtype=str(value_kind or "other")[:64],
        attributes=attributes,
        confidence=float(confidence),
    )
