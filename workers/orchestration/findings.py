from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, replace

from api.app.methodology import derive_finding_methodology
from api.app.models import EvidenceArtifact as EvidenceArtifactRecord
from api.app.models import Finding, Task
from workers.runners.base.contracts import EvidenceArtifact
from workers.runners.semgrep.runner import normalize_semgrep_rule_id


@dataclass(slots=True, frozen=True)
class NormalizedFinding:
    title: str
    severity: str
    target_id: str
    evidence_ref: str
    summary: str | None
    methodology_tags: tuple[str, ...] = ()
    ptes_phase: str | None = None
    nist_phase: str | None = None
    wstg_id: str | None = None
    wstg_version: str | None = None
    asvs_reference: str | None = None
    control_family: str | None = None
    finding_origin: str = "standard"
    source_pack_id: uuid.UUID | None = None
    source_pack_artifact_id: uuid.UUID | None = None
    source_inventory_snapshot_id: uuid.UUID | None = None
    source_relevance_decision_id: uuid.UUID | None = None
    source_pack_version: str | None = None


SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
    "unknown": 5,
}


def normalize_severity(raw_severity: str | None) -> str:
    normalized = (raw_severity or "").strip().lower()
    mapping = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "moderate": "medium",
        "low": "low",
        "info": "info",
        "informational": "info",
    }
    return mapping.get(normalized, "unknown")


def severity_rank(severity: str) -> int:
    return SEVERITY_ORDER.get(severity, SEVERITY_ORDER["unknown"])


def finding_signature(*, title: str, target_id: str) -> tuple[str, str]:
    return (title.strip().lower(), target_id.strip().lower())


def _uuid_or_none(value: object) -> uuid.UUID | None:
    if isinstance(value, uuid.UUID):
        return value
    if isinstance(value, str) and value.strip():
        try:
            return uuid.UUID(value.strip())
        except ValueError:
            return None
    return None


def merge_finding(existing: Finding, incoming: NormalizedFinding) -> bool:
    changed = False

    if severity_rank(incoming.severity) < severity_rank(existing.severity):
        existing.severity = incoming.severity
        changed = True
    if existing.evidence_ref != incoming.evidence_ref:
        existing.evidence_ref = incoming.evidence_ref
        changed = True
    if incoming.summary and existing.summary != incoming.summary:
        existing.summary = incoming.summary
        changed = True
    existing_tags = [tag for tag in (existing.methodology_tags or []) if isinstance(tag, str) and tag.strip()]
    incoming_tags = [tag for tag in incoming.methodology_tags if isinstance(tag, str) and tag.strip()]
    merged_tags = list(dict.fromkeys([*existing_tags, *incoming_tags]))
    if merged_tags != existing_tags:
        existing.methodology_tags = merged_tags
        changed = True
    for field_name in (
        "ptes_phase",
        "nist_phase",
        "wstg_id",
        "wstg_version",
        "asvs_reference",
        "control_family",
        "source_pack_version",
    ):
        existing_value = getattr(existing, field_name)
        incoming_value = getattr(incoming, field_name)
        if incoming_value and not existing_value:
            setattr(existing, field_name, incoming_value)
            changed = True
    for field_name in (
        "source_pack_id",
        "source_pack_artifact_id",
        "source_inventory_snapshot_id",
        "source_relevance_decision_id",
    ):
        existing_value = getattr(existing, field_name)
        incoming_value = getattr(incoming, field_name)
        if incoming_value is not None and existing_value is None:
            setattr(existing, field_name, incoming_value)
            changed = True
    if incoming.finding_origin == "adaptive_pack" and existing.finding_origin != "adaptive_pack":
        existing.finding_origin = incoming.finding_origin
        changed = True
    if existing.status == "resolved":
        existing.status = "reopened"
        changed = True

    return changed


def enrich_finding_with_methodology(*, finding: NormalizedFinding, task: Task) -> NormalizedFinding:
    pack_context = task.params_json.get("capability_pack", {})
    if not isinstance(pack_context, dict):
        pack_context = {}
    methodology = derive_finding_methodology(
        title=finding.title,
        summary=finding.summary,
        tool=task.tool,
        run_class=str(task.params_json.get("run_class") or ""),
    )
    pack_tags = [
        tag
        for tag in pack_context.get("methodology_tags", [])
        if isinstance(tag, str) and tag.strip()
    ]
    derived_tags = [
        tag
        for tag in methodology.get("methodology_tags", [])
        if isinstance(tag, str) and tag.strip()
    ]
    artifact_refs = pack_context.get("artifact_refs", [])
    first_artifact_id = None
    if isinstance(artifact_refs, list):
        for artifact_ref in artifact_refs:
            if not isinstance(artifact_ref, dict):
                continue
            first_artifact_id = _uuid_or_none(artifact_ref.get("artifact_id"))
            if first_artifact_id is not None:
                break
    return replace(
        finding,
        methodology_tags=tuple(dict.fromkeys([*finding.methodology_tags, *pack_tags, *derived_tags])),
        ptes_phase=str(methodology.get("ptes_phase") or "") or None,
        nist_phase=str(methodology.get("nist_phase") or "") or None,
        wstg_id=str(methodology.get("wstg_id") or "") or None,
        wstg_version=str(methodology.get("wstg_version") or "") or None,
        asvs_reference=str(methodology.get("asvs_reference") or "") or None,
        control_family=str(methodology.get("control_family") or "") or None,
        finding_origin="adaptive_pack" if pack_context.get("pack_id") else finding.finding_origin,
        source_pack_id=_uuid_or_none(pack_context.get("pack_id")),
        source_pack_artifact_id=first_artifact_id,
        source_inventory_snapshot_id=_uuid_or_none(pack_context.get("source_inventory_snapshot_id")),
        source_relevance_decision_id=_uuid_or_none(pack_context.get("relevance_decision_id")),
        source_pack_version=str(pack_context.get("version") or "") or None,
    )


def extract_findings(
    *,
    task: Task,
    artifact: EvidenceArtifact,
    artifact_record: EvidenceArtifactRecord,
) -> list[NormalizedFinding]:
    if task.tool == "nuclei":
        return extract_nuclei_findings(
            target_id=task.target_id,
            artifact=artifact,
            artifact_record=artifact_record,
        )
    if task.tool == "zap":
        return extract_zap_findings(
            target_id=task.target_id,
            artifact=artifact,
            artifact_record=artifact_record,
        )
    if task.tool == "semgrep":
        return extract_semgrep_findings(
            target_id=task.target_id,
            artifact=artifact,
            artifact_record=artifact_record,
        )

    return []


def extract_nuclei_findings(
    *,
    target_id: str,
    artifact: EvidenceArtifact,
    artifact_record: EvidenceArtifactRecord,
) -> list[NormalizedFinding]:
    if artifact.name != "nuclei-results.jsonl":
        return []

    findings: list[NormalizedFinding] = []
    for raw_line in artifact.data.decode("utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        result = json.loads(line)
        if not isinstance(result, dict):
            continue

        info = result.get("info", {})
        template_id = str(result.get("template-id") or "unknown-template").strip()
        severity = normalize_severity(info.get("severity") if isinstance(info, dict) else None)
        title = str(
            info.get("name") if isinstance(info, dict) and info.get("name") else f"Nuclei: {template_id}"
        ).strip()
        matched_at = str(result.get("matched-at") or target_id).strip()
        summary = f"Template {template_id} matched at {matched_at}."

        findings.append(
            NormalizedFinding(
                title=title,
                severity=severity,
                target_id=matched_at or target_id,
                evidence_ref=artifact_record.uri,
                summary=summary,
            )
        )

    return findings


def extract_zap_findings(
    *,
    target_id: str,
    artifact: EvidenceArtifact,
    artifact_record: EvidenceArtifactRecord,
) -> list[NormalizedFinding]:
    if artifact.name != "zap-results.json":
        return []

    payload = json.loads(artifact.data.decode("utf-8", errors="replace"))
    if not isinstance(payload, dict):
        return []

    results = payload.get("results", [])
    if not isinstance(results, list):
        return []

    findings: list[NormalizedFinding] = []
    seen_keys: set[tuple[str, str]] = set()

    for result in results:
        if not isinstance(result, dict):
            continue
        alerts = result.get("alerts", [])
        if not isinstance(alerts, list):
            continue

        for alert in alerts:
            if not isinstance(alert, dict):
                continue
            title = str(alert.get("alert") or "ZAP Alert").strip()
            matched_target = str(alert.get("url") or result.get("target") or target_id).strip() or target_id
            dedupe_key = (title.lower(), matched_target.lower())
            if dedupe_key in seen_keys:
                continue
            seen_keys.add(dedupe_key)

            severity = normalize_severity(str(alert.get("risk") or "info"))
            description = str(alert.get("description") or "").strip()
            summary = description or f"ZAP reported {title} for {matched_target}."

            findings.append(
                NormalizedFinding(
                    title=title,
                    severity=severity,
                    target_id=matched_target,
                    evidence_ref=artifact_record.uri,
                    summary=summary,
                )
            )

    return findings


def extract_semgrep_findings(
    *,
    target_id: str,
    artifact: EvidenceArtifact,
    artifact_record: EvidenceArtifactRecord,
) -> list[NormalizedFinding]:
    if artifact.name != "semgrep-results.json":
        return []

    payload = json.loads(artifact.data.decode("utf-8", errors="replace"))
    if not isinstance(payload, dict):
        return []

    runs = payload.get("runs", [])
    if not isinstance(runs, list):
        return []

    findings: list[NormalizedFinding] = []
    seen_keys: set[tuple[str, str]] = set()
    severity_mapping = {
        "error": "high",
        "warning": "medium",
        "info": "info",
        "inventory": "info",
    }

    for run_payload in runs:
        if not isinstance(run_payload, dict):
            continue
        results = run_payload.get("results", [])
        if not isinstance(results, list):
            continue

        for result in results:
            if not isinstance(result, dict):
                continue

            check_id = normalize_semgrep_rule_id(str(result.get("check_id") or "semgrep-rule"))
            path = str(result.get("path") or target_id).strip() or target_id
            extra = result.get("extra", {})
            severity_raw = ""
            message = ""
            if isinstance(extra, dict):
                severity_raw = str(extra.get("severity") or "").strip().lower()
                message = str(extra.get("message") or "").strip()

            severity = severity_mapping.get(severity_raw, normalize_severity(severity_raw))
            title = message or f"Semgrep: {check_id}"
            dedupe_key = (title.lower(), path.lower())
            if dedupe_key in seen_keys:
                continue
            seen_keys.add(dedupe_key)

            start = result.get("start", {})
            line = None
            if isinstance(start, dict):
                line = start.get("line")
            line_suffix = f":{line}" if isinstance(line, int) else ""
            summary = f"Semgrep rule {check_id} matched at {path}{line_suffix}."

            findings.append(
                NormalizedFinding(
                    title=title,
                    severity=severity,
                    target_id=path,
                    evidence_ref=artifact_record.uri,
                    summary=summary,
                )
            )

    return findings


def store_findings(
    *,
    session,
    task: Task,
    artifact_pairs: list[tuple[EvidenceArtifact, EvidenceArtifactRecord]],
) -> int:
    if task.run_id is None:
        return 0

    existing_findings = {
        finding_signature(title=finding.title, target_id=finding.target_id): finding
        for finding in task.run.findings
    }
    created_count = 0
    for artifact, artifact_record in artifact_pairs:
        for extracted_finding in extract_findings(task=task, artifact=artifact, artifact_record=artifact_record):
            finding = enrich_finding_with_methodology(finding=extracted_finding, task=task)
            signature = finding_signature(title=finding.title, target_id=finding.target_id)
            existing = existing_findings.get(signature)
            if existing is not None:
                merge_finding(existing, finding)
                continue

            created_finding = Finding(
                run_id=task.run_id,
                source_pack_id=finding.source_pack_id,
                source_pack_artifact_id=finding.source_pack_artifact_id,
                source_inventory_snapshot_id=finding.source_inventory_snapshot_id,
                source_relevance_decision_id=finding.source_relevance_decision_id,
                source_pack_version=finding.source_pack_version,
                finding_origin=finding.finding_origin,
                title=finding.title,
                severity=finding.severity,
                target_id=finding.target_id,
                evidence_ref=finding.evidence_ref,
                summary=finding.summary,
                methodology_tags=list(finding.methodology_tags),
                ptes_phase=finding.ptes_phase,
                nist_phase=finding.nist_phase,
                wstg_id=finding.wstg_id,
                wstg_version=finding.wstg_version,
                asvs_reference=finding.asvs_reference,
                control_family=finding.control_family,
                status="open",
            )
            session.add(created_finding)
            existing_findings[signature] = created_finding
            created_count += 1

    return created_count
