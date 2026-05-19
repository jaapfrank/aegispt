"""Dynamic path augmentation driven by target_intel's emergent observations.

Replaces the static per-stack registries from #337/#338 (deleted in backlog-402
per `feedback_live_proof_must_be_diverse_real_targets`). The smart-system
contract is that target_intel reads the actual response at runtime and emits
`attack_candidates` — concrete (path, vuln_class, evidence_basis) tuples — that
downstream probes consume directly. No pre-baked stack→paths table.

Data flow::

    target_intel (Claude)  →  EvidenceObservation.attributes_json["attack_candidates"]
                              [{"path": "/some-path", "vuln_class": "info-leak",
                                "evidence_basis": "...", "suggested_runner_or_primitive": "..."}]

    workers/orchestration/tasks.py  →  attack_candidates_for_run(session, run_id)

    probe runner (info_disclosure / file_upload / stored_xss / param_pollution /
                  cookie_tamper) → paths_for_category(candidates, "info-leak")
                                 → augmented_PROBE_PATHS

Categories the probes consume (matched against ``vuln_class`` from target_intel):

  - ``info-leak`` / ``info-disclosure`` / ``debug-dump``  →  info_disclosure_probe
  - ``file-upload`` / ``file-upload-target``              →  file_upload_probe
  - ``register-action`` / ``auth-bypass``                  →  param_pollution_probe / cookie_tamper_probe
  - ``stored-xss`` / ``xss-stored``                        →  stored_xss_probe

Per ``feedback_no_prescriptive_recipes`` + ``feedback_live_proof_must_be_diverse_real_targets``:
this module is a READER over target_intel output. It contains NO seed data,
NO per-stack tables, NO per-target paths. The grep-guard test in
``tests/test_multi_target_validation_grep_guard.py`` will fail if any
target-hostname literal leaks in here.
"""
from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

# Vuln-class → category mapping. Probes filter target_intel candidates by
# category. We accept a generous synonym set because target_intel's Claude is
# free to phrase vuln classes naturally — the smart-system contract is that
# the model reasons about WHAT the path is for, not which keyword we expect.

_CATEGORY_INFO_LEAK = "info-leak"
_CATEGORY_FILE_UPLOAD = "file-upload"
_CATEGORY_REGISTER_ACTION = "register-action"
_CATEGORY_STORED_XSS = "stored-xss"

_VULN_CLASS_SYNONYMS: dict[str, str] = {
    # info-leak / debug-dump family
    "info-leak": _CATEGORY_INFO_LEAK,
    "info-disclosure": _CATEGORY_INFO_LEAK,
    "info_disclosure": _CATEGORY_INFO_LEAK,
    "information-disclosure": _CATEGORY_INFO_LEAK,
    "debug-dump": _CATEGORY_INFO_LEAK,
    "debug_dump": _CATEGORY_INFO_LEAK,
    "config-leak": _CATEGORY_INFO_LEAK,
    "secret-exposure": _CATEGORY_INFO_LEAK,
    "data-exposure": _CATEGORY_INFO_LEAK,
    # file-upload family
    "file-upload": _CATEGORY_FILE_UPLOAD,
    "file_upload": _CATEGORY_FILE_UPLOAD,
    "unrestricted-upload": _CATEGORY_FILE_UPLOAD,
    "upload-bypass": _CATEGORY_FILE_UPLOAD,
    # auth / register family
    "register-action": _CATEGORY_REGISTER_ACTION,
    "register_action": _CATEGORY_REGISTER_ACTION,
    "auth-bypass": _CATEGORY_REGISTER_ACTION,
    "auth_bypass": _CATEGORY_REGISTER_ACTION,
    "mass-assignment": _CATEGORY_REGISTER_ACTION,
    "mass_assignment": _CATEGORY_REGISTER_ACTION,
    "privilege-escalation": _CATEGORY_REGISTER_ACTION,
    "identity-forgery": _CATEGORY_REGISTER_ACTION,
    # stored-xss family
    "stored-xss": _CATEGORY_STORED_XSS,
    "stored_xss": _CATEGORY_STORED_XSS,
    "xss-stored": _CATEGORY_STORED_XSS,
    "persistent-xss": _CATEGORY_STORED_XSS,
}

KNOWN_CATEGORIES: frozenset[str] = frozenset({
    _CATEGORY_INFO_LEAK,
    _CATEGORY_FILE_UPLOAD,
    _CATEGORY_REGISTER_ACTION,
    _CATEGORY_STORED_XSS,
})


def _normalize_vuln_class(vuln_class: Any) -> str | None:
    """Map a free-text vuln_class to a category, or None if unknown."""
    if not isinstance(vuln_class, str):
        return None
    key = vuln_class.strip().lower().replace(" ", "-")
    return _VULN_CLASS_SYNONYMS.get(key)


def attack_candidates_for_run(session: Any, run_id: Any) -> list[dict[str, Any]]:
    """Read target_intel's emitted ``attack_candidates`` from EvidenceObservation rows.

    Returns a flat list of candidate dicts with shape::

        {"path": str, "vuln_class": str, "evidence_basis": str,
         "suggested_runner_or_primitive": str | None,
         "source_url": str | None}

    Best-effort: any exception (missing table, malformed attributes_json) is
    swallowed and returns []. The probes already handle an empty/None candidates
    list gracefully — their baseline catalogs continue to drive discovery.
    """
    if run_id is None:
        return []
    try:
        from sqlalchemy import select as _select

        from api.app.models import EvidenceObservation  # type: ignore

        rows = session.scalars(
            _select(EvidenceObservation).where(EvidenceObservation.run_id == run_id)
        ).all()
        out: list[dict[str, Any]] = []
        for row in rows:
            attrs = (row.attributes_json or {}) if hasattr(row, "attributes_json") else {}
            if not isinstance(attrs, dict):
                continue
            raw_candidates = attrs.get("attack_candidates")
            if not isinstance(raw_candidates, list):
                continue
            for item in raw_candidates:
                if not isinstance(item, dict):
                    continue
                path = item.get("path")
                vuln_class = item.get("vuln_class")
                if not isinstance(path, str) or not path.strip():
                    continue
                if not isinstance(vuln_class, str) or not vuln_class.strip():
                    continue
                out.append({
                    "path": path.strip(),
                    "vuln_class": vuln_class.strip(),
                    "evidence_basis": str(item.get("evidence_basis", "")).strip() or None,
                    "suggested_runner_or_primitive": (
                        str(item.get("suggested_runner_or_primitive", "")).strip() or None
                    ),
                    "source_url": str(item.get("source_url", "")).strip() or None,
                })
        return out
    except Exception as exc:  # best-effort; never block dispatch
        logger.debug("attack_candidates_for_run: skipped (%s)", exc)
        return []


def observed_paths_for_run(session: Any, run_id: Any) -> list[dict[str, Any]]:
    """Read target_intel's emitted ``observed_paths`` from EvidenceObservation rows.

    Returns a flat list of observed-path dicts with shape::

        {"url": str, "source": str, "hypothesis": str | None,
         "confidence": float | None}

    Used primarily by auth_discoverer to thread register/login candidate paths.
    """
    if run_id is None:
        return []
    try:
        from sqlalchemy import select as _select

        from api.app.models import EvidenceObservation  # type: ignore

        rows = session.scalars(
            _select(EvidenceObservation).where(EvidenceObservation.run_id == run_id)
        ).all()
        out: list[dict[str, Any]] = []
        for row in rows:
            attrs = (row.attributes_json or {}) if hasattr(row, "attributes_json") else {}
            if not isinstance(attrs, dict):
                continue
            raw_paths = attrs.get("observed_paths")
            if not isinstance(raw_paths, list):
                continue
            for item in raw_paths:
                if not isinstance(item, dict):
                    continue
                url = item.get("url")
                if not isinstance(url, str) or not url.strip():
                    continue
                out.append({
                    "url": url.strip(),
                    "source": str(item.get("source", "")).strip() or "unknown",
                    "hypothesis": str(item.get("hypothesis", "")).strip() or None,
                    "confidence": (
                        float(item["confidence"])
                        if isinstance(item.get("confidence"), (int, float))
                        else None
                    ),
                })
        return out
    except Exception as exc:
        logger.debug("observed_paths_for_run: skipped (%s)", exc)
        return []


def paths_for_category(
    attack_candidates: list[dict[str, Any]] | None,
    category: str,
) -> list[tuple[str, str]]:
    """Filter ``attack_candidates`` to ``category`` and return (path, label) tuples.

    ``category`` is one of :data:`KNOWN_CATEGORIES`. The ``vuln_class`` field on
    each candidate is matched against the synonym table — so a candidate
    declaring ``vuln_class="information-disclosure"`` matches category
    ``"info-leak"`` because both normalize to ``info-leak``.

    The label is the candidate's `vuln_class` (as emitted by target_intel),
    propagated to the probe's finding output so operators can trace which
    detection bucket a path landed in.

    Returns [] when ``attack_candidates`` is None / empty / category unknown.
    Deduplicates on path string. Order: registry-order from target_intel.
    """
    if not attack_candidates:
        return []
    cat_normalized = (category or "").strip().lower()
    if cat_normalized not in KNOWN_CATEGORIES:
        return []
    seen: set[str] = set()
    out: list[tuple[str, str]] = []
    for cand in attack_candidates:
        if not isinstance(cand, dict):
            continue
        cand_category = _normalize_vuln_class(cand.get("vuln_class"))
        if cand_category != cat_normalized:
            continue
        path = cand.get("path")
        if not isinstance(path, str) or not path.strip():
            continue
        path = path.strip()
        if path in seen:
            continue
        seen.add(path)
        label = str(cand.get("vuln_class", cat_normalized)).strip() or cat_normalized
        out.append((path, label))
    return out


__all__ = [
    "KNOWN_CATEGORIES",
    "attack_candidates_for_run",
    "observed_paths_for_run",
    "paths_for_category",
]
