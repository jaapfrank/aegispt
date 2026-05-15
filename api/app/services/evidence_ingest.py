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

Validation: only the entity types already supported by
build_normalized_evidence_graph are accepted. Per backlog-372 scope, we do not
add new node types in this task — observations augment existing taxonomy.

See `docs/evidence_graph_adoption_plan.md` for the full design context.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, Iterable

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app.models import EvidenceObservation, Run, Task

logger = logging.getLogger(__name__)

# Entity types accepted by this task. These are the existing types that
# build_normalized_evidence_graph already understands; we are NOT introducing
# new types in #322. Future tasks may extend this set.
ACCEPTED_ENTITY_TYPES: frozenset[str] = frozenset(
    {
        "asset",  # host, service, endpoint
        "api",  # API endpoint
        "identity",  # user, role, group, service_account
        "credential_ref",  # captured credential
        "permission",  # role/permission grant
        "saas_connector",  # SaaS integration
    }
)

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
