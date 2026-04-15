from __future__ import annotations

import hashlib
import json
from collections import Counter
from html import escape
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from api.app.methodology import (
    ASVS_STABLE_VERSION,
    WSTG_STABLE_VERSION,
    control_family_label,
    default_nist_phase_for_run_class,
    default_ptes_phase_for_run_class,
    default_remediation_detail,
    default_remediation_summary,
    format_wstg_reference,
    nist_phase_label,
    operator_workflow_stage_for_run_class,
    ptes_phase_label,
    tool_wstg_areas,
    wstg_area_for_identifier,
)
from api.app.models import Approval, Engagement, EvidenceArtifact, Finding, Run, Scope, Task, ToolExecution
from api.app.schemas.report_center import RunReportCatalogItemRead

SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
    "unknown": 5,
}

REMEDIATION_PRIORITY = {
    "critical": "Immediate",
    "high": "High",
    "medium": "Planned",
    "low": "Routine",
    "info": "Advisory",
    "unknown": "Review",
}

REPORT_VARIANT_LABELS = {
    "executive": "Executive Report",
    "technical": "Technical Report",
    "evidence": "Evidence Appendix",
    "retest": "Retest / Verification Report",
}

REPORT_VARIANT_DESCRIPTIONS = {
    "executive": "Leadership-ready summary of scope, outcomes, risk posture, and next steps.",
    "technical": "Full technical narrative with methodology, findings, evidence, and remediation detail.",
    "evidence": "Artifact-oriented appendix for replay, validation, and operator review.",
    "retest": "Verification-focused output tracking open, fixed, and still-unverified items.",
}


def load_run_report(session: Session, run_id: UUID | str) -> Run | None:
    return session.scalar(
        select(Run)
        .options(
            selectinload(Run.engagement).selectinload(Engagement.scopes),
            selectinload(Run.profile),
            selectinload(Run.bound_pack),
            selectinload(Run.bound_pack_deployment),
            selectinload(Run.approvals),
            selectinload(Run.findings),
            selectinload(Run.tasks)
            .selectinload(Task.executions)
            .selectinload(ToolExecution.artifacts),
        )
        .where(Run.id == run_id)
    )


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda finding: (
            SEVERITY_ORDER.get(finding.severity, SEVERITY_ORDER["unknown"]),
            finding.title.lower(),
            finding.target_id.lower(),
        ),
    )


def sort_tasks(tasks: list[Task]) -> list[Task]:
    return sorted(tasks, key=lambda task: (task.tool, task.target_id, task.created_at, task.id.hex))


def sort_approvals(approvals: list[Approval]) -> list[Approval]:
    return sorted(approvals, key=lambda approval: (approval.created_at, approval.id.hex))


def sort_artifacts(artifacts: list[EvidenceArtifact]) -> list[EvidenceArtifact]:
    return sorted(
        artifacts,
        key=lambda artifact: (
            str(artifact.metadata_json.get("name", "")),
            artifact.created_at,
            artifact.id.hex,
        ),
    )


def artifact_download_path(artifact_id: UUID) -> str:
    return f"/api/v1/artifacts/{artifact_id}/content"


def task_targets_display(task: Task) -> str:
    configured_targets = task.params_json.get("targets")
    if isinstance(configured_targets, list):
        normalized_targets = [target.strip() for target in configured_targets if isinstance(target, str) and target.strip()]
        if normalized_targets:
            return ", ".join(normalized_targets)

    return task.target_id


def findings_summary(findings: list[Finding]) -> tuple[dict[str, int], dict[str, int]]:
    by_severity = dict(Counter(finding.severity for finding in findings))
    by_status = dict(Counter(finding.status for finding in findings))
    return by_severity, by_status


def latest_scope_for_engagement(engagement: Engagement | None) -> Scope | None:
    if engagement is None:
        return None
    if not engagement.scopes:
        return None
    return sorted(engagement.scopes, key=lambda scope: (scope.created_at, scope.id.hex), reverse=True)[0]


def format_json_block(payload: dict[str, object] | None) -> str:
    return json.dumps(payload or {}, indent=2, sort_keys=True)


def methodology_context_for_run(run: Run) -> dict[str, str]:
    run_class = run.profile.run_class if run.profile is not None else None
    ptes_phase = default_ptes_phase_for_run_class(run_class)
    nist_phase = default_nist_phase_for_run_class(run_class)
    return {
        "operator_stage": operator_workflow_stage_for_run_class(run_class),
        "ptes_phase": ptes_phase,
        "ptes_phase_label": ptes_phase_label(ptes_phase) or ptes_phase,
        "nist_phase": nist_phase,
        "nist_phase_label": nist_phase_label(nist_phase) or nist_phase,
    }


def adaptive_pack_context(run: Run) -> dict[str, object]:
    if run.bound_pack is None:
        return {
            "active": False,
            "label": "Standard baseline coverage only",
            "manifest": {},
            "deployment_target": None,
            "deployment_status": None,
        }

    deployment = run.bound_pack_deployment
    return {
        "active": True,
        "label": f"{run.bound_pack.name} {run.bound_pack.version}",
        "manifest": dict(run.bound_pack.manifest_json or {}),
        "deployment_target": deployment.deployment_target if deployment is not None else None,
        "deployment_status": deployment.status if deployment is not None else None,
    }


def methodology_coverage_summary(findings: list[Finding], tasks: list[Task]) -> dict[str, list[str]]:
    wstg_areas = {
        area
        for area in (
            wstg_area_for_identifier(finding.wstg_id)
            for finding in findings
        )
        if area
    }
    if not wstg_areas:
        for task in tasks:
            wstg_areas.update(tool_wstg_areas(task.tool))

    control_families = {
        label
        for label in (
            control_family_label(finding.control_family)
            for finding in findings
        )
        if label
    }
    methodology_tags = {
        tag
        for finding in findings
        for tag in (finding.methodology_tags or [])
        if isinstance(tag, str) and tag.strip()
    }

    return {
        "wstg_areas": sorted(wstg_areas),
        "control_families": sorted(control_families),
        "methodology_tags": sorted(methodology_tags),
        "tools": sorted({task.tool for task in tasks}),
    }


def remediation_priority_for_finding(finding: Finding) -> str:
    return REMEDIATION_PRIORITY.get(finding.severity, REMEDIATION_PRIORITY["unknown"])


def replay_status_for_finding(finding: Finding) -> str:
    return "evidence-linked" if finding.evidence_ref else "not-linked"


def remediation_priority_counts(findings: list[Finding]) -> dict[str, int]:
    return dict(Counter(remediation_priority_for_finding(finding) for finding in findings))


def finding_methodology_lines(finding: Finding) -> list[str]:
    lines = [
        f"- PTES Phase: {ptes_phase_label(finding.ptes_phase) or 'Not Assigned'}",
        f"- NIST Phase: {nist_phase_label(finding.nist_phase) or 'Not Assigned'}",
        f"- WSTG Reference: {format_wstg_reference(finding.wstg_id, finding.wstg_version) or 'Not Assigned'}",
        f"- WSTG Area: {wstg_area_for_identifier(finding.wstg_id) or 'Not Assigned'}",
        f"- ASVS Reference: {finding.asvs_reference or 'Not Assigned'}",
        f"- Control Family: {control_family_label(finding.control_family) or 'Not Assigned'}",
        f"- Methodology Tags: {', '.join(finding.methodology_tags or []) or 'None'}",
        f"- Finding Origin: {finding.finding_origin}",
        f"- Source Pack Version: {finding.source_pack_version or 'Standard Coverage'}",
    ]
    return lines


def _humanize_key(value: str) -> str:
    return value.replace("_", " ").replace("-", " ").title()


def run_configuration_context(run: Run) -> dict[str, object]:
    configuration = dict(run.configuration_json or {})
    raw_modules = configuration.get("modules", {})
    enabled_modules = []
    if isinstance(raw_modules, dict):
        enabled_modules = sorted(
            _humanize_key(module)
            for module, enabled in raw_modules.items()
            if isinstance(module, str) and bool(enabled)
        )

    raw_targets = configuration.get("targets", {})
    normalized_targets: dict[str, list[str]] = {}
    if isinstance(raw_targets, dict):
        for key, values in raw_targets.items():
            if isinstance(key, str) and isinstance(values, list):
                normalized_targets[key] = [value for value in values if isinstance(value, str) and value.strip()]

    access = configuration.get("access", {})
    accounts_summary: list[str] = []
    if isinstance(access, dict):
        accounts = access.get("accounts", [])
        if isinstance(accounts, list):
            for account in accounts:
                if not isinstance(account, dict):
                    continue
                label = str(account.get("label") or account.get("username") or "Account").strip()
                role = str(account.get("role") or "role not set").strip()
                accounts_summary.append(f"{label} ({role})")

    eta = configuration.get("eta", {})
    if not isinstance(eta, dict):
        eta = {}
    safety = configuration.get("safety", {})
    if not isinstance(safety, dict):
        safety = {}

    return {
        "assessment_type": str(configuration.get("assessment_type") or "Not recorded"),
        "test_profile": str(configuration.get("test_profile") or (run.profile.name if run.profile is not None else "Not recorded")),
        "targets": normalized_targets,
        "enabled_modules": enabled_modules,
        "accounts_summary": accounts_summary,
        "safety": safety,
        "eta": eta,
    }


def report_methodology_references(run: Run) -> list[str]:
    references = [
        "PTES",
        f"OWASP WSTG {WSTG_STABLE_VERSION}",
        "NIST SP 800-115",
    ]
    if any(finding.asvs_reference for finding in run.findings):
        references.append(f"OWASP ASVS {ASVS_STABLE_VERSION}")
    return references


def report_context(run: Run) -> dict[str, object]:
    findings = sort_findings(list(run.findings))
    tasks = sort_tasks(list(run.tasks))
    approvals = sort_approvals(list(run.approvals))
    findings_by_severity, findings_by_status = findings_summary(findings)
    return {
        "profile_name": run.profile.name if run.profile is not None else "unknown-profile",
        "engagement_name": run.engagement.name if run.engagement is not None else "unknown-engagement",
        "client_name": run.engagement.client if run.engagement is not None and run.engagement.client else "unknown-client",
        "findings": findings,
        "tasks": tasks,
        "approvals": approvals,
        "findings_by_severity": findings_by_severity,
        "findings_by_status": findings_by_status,
        "methodology": methodology_context_for_run(run),
        "adaptive_pack": adaptive_pack_context(run),
        "coverage": methodology_coverage_summary(findings, tasks),
        "latest_scope": latest_scope_for_engagement(run.engagement),
        "remediation_counts": remediation_priority_counts(findings),
        "configuration": run_configuration_context(run),
    }


def _render_configuration_markdown(context: dict[str, object]) -> list[str]:
    configuration = context["configuration"]
    assert isinstance(configuration, dict)
    eta = configuration.get("eta", {})
    safety = configuration.get("safety", {})
    targets = configuration.get("targets", {})
    return [
        "## Run Configuration",
        "",
        f"- Assessment Type: {configuration.get('assessment_type') or 'Not Recorded'}",
        f"- Test Profile: {configuration.get('test_profile') or 'Not Recorded'}",
        f"- Enabled Modules: {', '.join(configuration.get('enabled_modules', [])) or 'Not Recorded'}",
        f"- Active Accounts / Roles: {', '.join(configuration.get('accounts_summary', [])) or 'None Recorded'}",
        f"- Target Inputs: {targets or {}}",
        f"- Safety Settings: {safety or {}}",
        f"- ETA Model: {eta or {}}",
        "",
    ]


def _render_configuration_html(context: dict[str, object]) -> str:
    configuration = context["configuration"]
    assert isinstance(configuration, dict)
    return (
        "<ul>"
        f"<li><strong>Assessment Type:</strong> {escape(str(configuration.get('assessment_type') or 'Not Recorded'))}</li>"
        f"<li><strong>Test Profile:</strong> {escape(str(configuration.get('test_profile') or 'Not Recorded'))}</li>"
        f"<li><strong>Enabled Modules:</strong> {escape(', '.join(configuration.get('enabled_modules', [])) or 'Not Recorded')}</li>"
        f"<li><strong>Active Accounts / Roles:</strong> {escape(', '.join(configuration.get('accounts_summary', [])) or 'None Recorded')}</li>"
        f"<li><strong>Target Inputs:</strong> {escape(str(configuration.get('targets') or {}))}</li>"
        f"<li><strong>Safety Settings:</strong> {escape(str(configuration.get('safety') or {}))}</li>"
        f"<li><strong>ETA Model:</strong> {escape(str(configuration.get('eta') or {}))}</li>"
        "</ul>"
    )


def _render_executive_markdown(run: Run, context: dict[str, object]) -> str:
    findings = context["findings"]
    methodology = context["methodology"]
    adaptive_pack = context["adaptive_pack"]
    remediation_counts = context["remediation_counts"]
    return "\n".join(
        [
            f"# AegisPT Executive Report: {run.id}",
            "",
            "## Mission Snapshot",
            "",
            f"- Engagement: {context['engagement_name']}",
            f"- Client: {context['client_name']}",
            f"- Run Profile: {context['profile_name']}",
            f"- Run Status: {run.status}",
            f"- Adaptive Coverage: {adaptive_pack['label']}",
            f"- Findings by Severity: {context['findings_by_severity'] or {}}",
            f"- Findings by Status: {context['findings_by_status'] or {}}",
            "",
            *_render_configuration_markdown(context),
            "## Methodology",
            "",
            f"- PTES Lifecycle Mapping: {methodology['ptes_phase_label']}",
            f"- NIST Mapping: {methodology['nist_phase_label']}",
            f"- OWASP WSTG Baseline: {WSTG_STABLE_VERSION}",
            "",
            "## Risk Highlights",
            "",
            f"- Remediation Priorities: {remediation_counts or {}}",
            *(
                [f"- {finding.severity.upper()}: {finding.title}" for finding in findings[:5]]
                if findings
                else ["- No confirmed findings recorded."]
            ),
            "",
            "## Recommended Next Steps",
            "",
            "- Validate remediation order with the customer owner and retain the evidence-backed run as the baseline.",
            "- Use the Technical Report for analyst detail and the Evidence Appendix for replay artifacts.",
            "- Schedule retest coverage for any item that remains open after remediation.",
            "",
        ]
    ).rstrip() + "\n"


def _render_evidence_markdown(run: Run, context: dict[str, object]) -> str:
    findings = context["findings"]
    tasks = context["tasks"]
    lines = [
        f"# AegisPT Evidence Appendix: {run.id}",
        "",
        *_render_configuration_markdown(context),
        "## Methodology References",
        "",
        *[f"- {reference}" for reference in report_methodology_references(run)],
        "",
        "## Findings Evidence Map",
        "",
    ]
    if findings:
        for finding in findings:
            lines.extend(
                [
                    f"### {finding.title}",
                    "",
                    f"- Evidence Ref: {finding.evidence_ref}",
                    f"- Severity: {finding.severity}",
                    f"- Status: {finding.status}",
                    *finding_methodology_lines(finding),
                    "",
                ]
            )
    else:
        lines.extend(["- No findings recorded.", ""])

    lines.extend(["## Task Evidence", ""])
    if tasks:
        for task in tasks:
            lines.extend(
                [
                    f"### Task {task.id}",
                    "",
                    f"- Tool: {task.tool}",
                    f"- Target: {task_targets_display(task)}",
                    f"- Status: {task.status}",
                ]
            )
            for execution in task.executions:
                lines.append(
                    f"- Execution {execution.id}: exit_code={execution.exit_code}, tool_version={execution.tool_version}"
                )
                for artifact in sort_artifacts(list(execution.artifacts)):
                    lines.append(
                        f"  artifact: {artifact.metadata_json.get('name', artifact.id)} download={artifact_download_path(artifact.id)}"
                    )
            lines.append("")
    else:
        lines.extend(["- No task evidence recorded.", ""])

    return "\n".join(lines).rstrip() + "\n"


def _render_retest_markdown(run: Run, context: dict[str, object]) -> str:
    findings = context["findings"]
    lines = [
        f"# AegisPT Retest / Verification Report: {run.id}",
        "",
        "## Verification Summary",
        "",
        f"- Run Status: {run.status}",
        f"- Verification Status Counts: {context['findings_by_status'] or {}}",
        f"- Resolved Findings: {sum(1 for finding in findings if finding.status == 'resolved')}",
        f"- Still Open: {sum(1 for finding in findings if finding.status in {'open', 'triaged', 'in_progress', 'reopened'})}",
        "",
        *_render_configuration_markdown(context),
        "## Findings Verification State",
        "",
    ]
    if findings:
        for finding in findings:
            lines.extend(
                [
                    f"### {finding.title}",
                    "",
                    f"- Severity: {finding.severity}",
                    f"- Status: {finding.status}",
                    f"- Replay Status: {replay_status_for_finding(finding)}",
                    f"- Remediation Summary: {default_remediation_summary(finding.control_family)}",
                    "",
                ]
            )
    else:
        lines.extend(["- No findings recorded.", ""])
    lines.extend(
        [
            "## Retest Guidance",
            "",
            "- Re-run validated checks after remediation and attach new evidence under the same engagement dossier.",
            "- Update finding status only after replay confirms the fix or the customer accepts residual risk.",
            "",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def build_report_catalog(run: Run) -> list[RunReportCatalogItemRead]:
    context = report_context(run)
    linked_evidence = sum(1 for finding in context["findings"] if finding.evidence_ref)
    catalog: list[RunReportCatalogItemRead] = []
    for variant, title in REPORT_VARIANT_LABELS.items():
        markdown_content = render_markdown_report(run, variant=variant)
        catalog.append(
            RunReportCatalogItemRead(
                variant=variant,
                title=title,
                description=REPORT_VARIANT_DESCRIPTIONS[variant],
                source_run_id=run.id,
                generated_at=run.created_at,
                available_formats=["markdown", "html"],
                methodology_references=report_methodology_references(run),
                source_scope_profile={
                    "run_profile": context["profile_name"],
                    "assessment_type": context["configuration"].get("assessment_type"),
                    "enabled_modules": context["configuration"].get("enabled_modules", []),
                    "targets": context["configuration"].get("targets", {}),
                },
                included_findings={
                    "count": len(context["findings"]),
                    "by_severity": context["findings_by_severity"],
                    "by_status": context["findings_by_status"],
                },
                evidence_status={
                    "linked_findings": linked_evidence,
                    "total_findings": len(context["findings"]),
                    "completeness_ratio": (linked_evidence / len(context["findings"])) if context["findings"] else 0.0,
                },
                version_label=f"{variant}-{run.created_at:%Y%m%dT%H%M%S}",
                content_sha256=hashlib.sha256(markdown_content.encode("utf-8")).hexdigest(),
                export_paths={
                    "markdown": f"/api/v1/runs/{run.id}/report?format=markdown&variant={variant}",
                    "html": f"/api/v1/runs/{run.id}/report?format=html&variant={variant}",
                },
            )
        )
    return catalog


def render_markdown_report(run: Run, *, variant: str = "technical") -> str:
    context = report_context(run)
    if variant == "executive":
        return _render_executive_markdown(run, context)
    if variant == "evidence":
        return _render_evidence_markdown(run, context)
    if variant == "retest":
        return _render_retest_markdown(run, context)

    profile_name = context["profile_name"]
    engagement_name = context["engagement_name"]
    client_name = context["client_name"]
    findings = context["findings"]
    tasks = context["tasks"]
    approvals = context["approvals"]
    findings_by_severity = context["findings_by_severity"]
    findings_by_status = context["findings_by_status"]
    methodology = context["methodology"]
    adaptive_pack = context["adaptive_pack"]
    coverage = context["coverage"]
    latest_scope = context["latest_scope"]
    remediation_counts = context["remediation_counts"]

    lines = [
        f"# AegisPT Run Report: {run.id}",
        "",
        "## Executive Summary",
        "",
        f"- Engagement: {engagement_name}",
        f"- Client: {client_name}",
        f"- Run Profile: {profile_name}",
        f"- Run Status: {run.status}",
        f"- Requested By: {run.requested_by}",
        f"- Created At: {run.created_at.isoformat()}",
        f"- Operator Workflow Stage: {methodology['operator_stage']}",
        f"- PTES Mapping for This Run: {methodology['ptes_phase_label']}",
        f"- NIST Mapping for This Run: {methodology['nist_phase_label']}",
        f"- Adaptive Coverage: {adaptive_pack['label']}",
        f"- Finding Count: {len(findings)}",
        "",
        "## Scope",
        "",
    ]

    if latest_scope is not None:
        lines.extend(
            [
                "### Allowlist",
                "",
                "```json",
                format_json_block(latest_scope.allowlist_json),
                "```",
                "",
                "### Denylist",
                "",
                "```json",
                format_json_block(latest_scope.denylist_json),
                "```",
                "",
            ]
        )
    else:
        lines.extend(["- No scope snapshot loaded for this run.", ""])

    lines.extend(_render_configuration_markdown(context))

    lines.extend(
        [
            "## Rules of Engagement Summary",
            "",
            f"- ROE Reference: {run.engagement.roe_ref if run.engagement is not None and run.engagement.roe_ref else 'Not Recorded'}",
            f"- Approval Records: {len(approvals)}",
            "- Guardrails: evidence-first collection, replayable artifacts, and approval-gated active validation where applicable.",
            "",
            "## Methodology",
            "",
            "- Assessment lifecycle: PTES",
            f"- Web/API technical coverage model: OWASP WSTG {WSTG_STABLE_VERSION}",
            "- Structured testing and reporting discipline: NIST SP 800-115",
            f"- Optional control-verification layer: OWASP ASVS {ASVS_STABLE_VERSION} when a precise reference is assigned",
            "",
            "### PTES Lifecycle Alignment",
            "",
            "- Pre-Engagement -> engagement definition, scope, and rules of engagement setup",
            "- Intelligence Gathering -> reconnaissance and target discovery activities",
            "- Analysis / Validation -> passive validation and evidence-backed issue confirmation",
            "- Controlled Exploitation / Verification -> approval-gated active validation and internal adversary simulation steps",
            "- Reporting -> executive and technical reporting with linked evidence",
            "- Retest -> rerun and verification-state updates after remediation",
            "",
            "### NIST SP 800-115 Alignment",
            "",
            "- Planning -> scope, logistics, approvals, and rules of engagement",
            "- Discovery -> reconnaissance, identification, and technical analysis",
            "- Attack -> controlled validation of exploitable weaknesses",
            "- Reporting -> structured findings, evidence, remediation, and verification output",
            "- Post-Testing -> remediation follow-up and retest handling",
            "",
            "## Coverage Summary",
            "",
            f"- Tools Executed: {', '.join(coverage['tools']) or 'None'}",
            f"- WSTG Areas Covered: {', '.join(coverage['wstg_areas']) or 'Not Assigned'}",
            f"- Control Families Seen: {', '.join(coverage['control_families']) or 'Not Assigned'}",
            f"- Methodology Tags Seen: {', '.join(coverage['methodology_tags']) or 'Not Assigned'}",
            f"- By Severity: {findings_by_severity or {}}",
            f"- By Status: {findings_by_status or {}}",
            "",
            "## Adaptive Coverage",
            "",
            f"- Runtime Pack: {adaptive_pack['label']}",
            f"- Deployment Target: {adaptive_pack['deployment_target'] or 'Not Bound'}",
            f"- Deployment Status: {adaptive_pack['deployment_status'] or 'Not Bound'}",
            f"- Inventory Snapshot Used: {adaptive_pack['manifest'].get('inventory_snapshot_id') or 'Not Assigned'}",
            f"- Relevance Decision: {adaptive_pack['manifest'].get('relevance_decision_id') or 'Not Assigned'}",
            f"- Threat Intel References: {', '.join(adaptive_pack['manifest'].get('threat_intel_refs', [])) or 'None'}",
            f"- Generation Reason: {adaptive_pack['manifest'].get('generation_reason') or 'Standard coverage only'}",
            "",
            "## Remediation Priorities",
            "",
            f"- Priority Counts: {remediation_counts or {}}",
        ]
    )

    if findings:
        for finding in findings[:5]:
            lines.append(f"- {remediation_priority_for_finding(finding)}: {finding.title}")
    else:
        lines.append("- No confirmed findings recorded.")

    lines.extend(["", "## Confirmed Findings", ""])
    if findings:
        for index, finding in enumerate(findings, start=1):
            lines.extend(
                [
                    f"### {index}. {finding.title}",
                    "",
                    f"- Severity: {finding.severity}",
                    f"- Status: {finding.status}",
                    f"- Verification Status: {finding.status}",
                    f"- Remediation Priority: {remediation_priority_for_finding(finding)}",
                    f"- Target: {finding.target_id}",
                    f"- Evidence Ref: {finding.evidence_ref}",
                    f"- Replay Status: {replay_status_for_finding(finding)}",
                ]
            )
            lines.extend(finding_methodology_lines(finding))
            if finding.summary:
                lines.append(f"- Summary: {finding.summary}")
            lines.append(f"- Remediation Summary: {default_remediation_summary(finding.control_family)}")
            lines.append(f"- Remediation Detail: {default_remediation_detail(finding.control_family)}")
            lines.append("")
    else:
        lines.extend(["No findings recorded.", ""])

    lines.extend(["## Evidence and Reproduction", ""])
    if tasks:
        for task in tasks:
            target_label = task_targets_display(task)
            lines.extend(
                [
                    f"### Task {task.id}",
                    "",
                    f"- Tool: {task.tool}",
                    f"- Target: {target_label}",
                    f"- Status: {task.status}",
                ]
            )
            if task.executions:
                for execution in task.executions:
                    lines.extend(
                        [
                            f"- Execution {execution.id}: exit_code={execution.exit_code}, tool_version={execution.tool_version}",
                        ]
                    )
                    for artifact in sort_artifacts(list(execution.artifacts)):
                        artifact_name = str(artifact.metadata_json.get("name", artifact.id))
                        lines.append(
                            f"  artifact: {artifact_name} ({artifact.uri}) download={artifact_download_path(artifact.id)}"
                        )
            else:
                lines.append("- No executions recorded")
            lines.append("")
    else:
        lines.extend(["No tasks recorded.", ""])

    lines.extend(
        [
            "## Retest and Verification",
            "",
            f"- Verification Status Counts: {findings_by_status or {}}",
            f"- Resolved Findings: {sum(1 for finding in findings if finding.status == 'resolved')}",
            f"- Findings Requiring Further Validation: {sum(1 for finding in findings if finding.status in {'open', 'triaged', 'in_progress', 'reopened'})}",
            "",
        ]
    )

    return "\n".join(lines).rstrip() + "\n"


def render_html_report(run: Run, *, variant: str = "technical") -> str:
    context = report_context(run)
    profile_name = context["profile_name"]
    engagement_name = context["engagement_name"]
    client_name = context["client_name"]
    findings = context["findings"]
    tasks = context["tasks"]
    approvals = context["approvals"]
    findings_by_severity = context["findings_by_severity"]
    findings_by_status = context["findings_by_status"]
    methodology = context["methodology"]
    adaptive_pack = context["adaptive_pack"]
    coverage = context["coverage"]
    latest_scope = context["latest_scope"]
    remediation_counts = context["remediation_counts"]

    summary_rows = [
        ("Engagement", engagement_name),
        ("Client", client_name),
        ("Run Profile", profile_name),
        ("Run Status", run.status),
        ("Requested By", run.requested_by),
        ("Created At", run.created_at.isoformat()),
        ("Operator Workflow Stage", methodology["operator_stage"]),
        ("PTES Mapping", methodology["ptes_phase_label"]),
        ("NIST Mapping", methodology["nist_phase_label"]),
        ("Adaptive Coverage", str(adaptive_pack["label"])),
        ("Finding Count", str(len(findings))),
    ]
    summary_html = "".join(
        f"<tr><th>{escape(label)}</th><td>{escape(value)}</td></tr>" for label, value in summary_rows
    )

    approvals_html = "".join(
        "<li>"
        f"{escape(approval.step_id)}: {escape(approval.decision)} by {escape(approval.approver_id)} "
        f"at {escape(approval.created_at.isoformat())}"
        "</li>"
        for approval in approvals
    ) or "<li>No approvals recorded</li>"

    scope_html = (
        "<div class='scope-grid'>"
        f"<section><h3>Allowlist</h3><pre>{escape(format_json_block(latest_scope.allowlist_json))}</pre></section>"
        f"<section><h3>Denylist</h3><pre>{escape(format_json_block(latest_scope.denylist_json))}</pre></section>"
        "</div>"
        if latest_scope is not None
        else "<p>No scope snapshot loaded for this run.</p>"
    )

    methodology_html = (
        "<ul>"
        "<li>PTES governs the assessment lifecycle and operator workflow alignment.</li>"
        f"<li>OWASP WSTG {escape(WSTG_STABLE_VERSION)} governs web and API technical coverage references.</li>"
        "<li>NIST SP 800-115 governs technical testing discipline, evidence handling, and reporting structure.</li>"
        f"<li>OWASP ASVS {escape(ASVS_STABLE_VERSION)} remains an optional control-reference layer when analysts assign precise references.</li>"
        "</ul>"
    )

    coverage_html = (
        "<ul>"
        f"<li><strong>Tools Executed:</strong> {escape(', '.join(coverage['tools']) or 'None')}</li>"
        f"<li><strong>WSTG Areas Covered:</strong> {escape(', '.join(coverage['wstg_areas']) or 'Not Assigned')}</li>"
        f"<li><strong>Control Families Seen:</strong> {escape(', '.join(coverage['control_families']) or 'Not Assigned')}</li>"
        f"<li><strong>Priority Counts:</strong> {escape(str(remediation_counts or {}))}</li>"
        "</ul>"
    )

    adaptive_pack_html = (
        "<ul>"
        f"<li><strong>Runtime Pack:</strong> {escape(str(adaptive_pack['label']))}</li>"
        f"<li><strong>Deployment Target:</strong> {escape(str(adaptive_pack['deployment_target'] or 'Not Bound'))}</li>"
        f"<li><strong>Deployment Status:</strong> {escape(str(adaptive_pack['deployment_status'] or 'Not Bound'))}</li>"
        f"<li><strong>Inventory Snapshot Used:</strong> {escape(str(adaptive_pack['manifest'].get('inventory_snapshot_id') or 'Not Assigned'))}</li>"
        f"<li><strong>Relevance Decision:</strong> {escape(str(adaptive_pack['manifest'].get('relevance_decision_id') or 'Not Assigned'))}</li>"
        f"<li><strong>Threat Intel References:</strong> {escape(', '.join(adaptive_pack['manifest'].get('threat_intel_refs', [])) or 'None')}</li>"
        f"<li><strong>Generation Reason:</strong> {escape(str(adaptive_pack['manifest'].get('generation_reason') or 'Standard coverage only'))}</li>"
        "</ul>"
    )

    findings_html = "".join(
        "<article class='finding'>"
        f"<div class='finding-header'><h3>{escape(finding.title)}</h3><span class='priority'>{escape(remediation_priority_for_finding(finding))}</span></div>"
        f"<p><strong>Severity:</strong> {escape(finding.severity)} | "
        f"<strong>Status:</strong> {escape(finding.status)} | "
        f"<strong>Target:</strong> {escape(finding.target_id)}</p>"
        f"<p><strong>Evidence Ref:</strong> <code>{escape(finding.evidence_ref)}</code></p>"
        f"<p><strong>Methodology:</strong> PTES {escape(ptes_phase_label(finding.ptes_phase) or 'Not Assigned')} | "
        f"NIST {escape(nist_phase_label(finding.nist_phase) or 'Not Assigned')} | "
        f"WSTG {escape(format_wstg_reference(finding.wstg_id, finding.wstg_version) or 'Not Assigned')}</p>"
        f"<p><strong>Control Family:</strong> {escape(control_family_label(finding.control_family) or 'Not Assigned')}</p>"
        f"<p><strong>Finding Origin:</strong> {escape(finding.finding_origin)} | "
        f"<strong>Source Pack Version:</strong> {escape(finding.source_pack_version or 'Standard Coverage')}</p>"
        + (f"<p>{escape(finding.summary)}</p>" if finding.summary else "")
        + f"<p><strong>Remediation Summary:</strong> {escape(default_remediation_summary(finding.control_family))}</p>"
        + "</article>"
        for finding in findings
    ) or "<p>No findings recorded.</p>"

    task_sections: list[str] = []
    for task in tasks:
        target_label = task_targets_display(task)
        execution_lines: list[str] = []
        for execution in task.executions:
            artifact_lines = "".join(
                "<li>"
                f"{escape(str(artifact.metadata_json.get('name', artifact.id)))} - "
                f"<code>{escape(artifact.uri)}</code> - "
                f"<a href=\"{escape(artifact_download_path(artifact.id))}\">download</a>"
                "</li>"
                for artifact in sort_artifacts(list(execution.artifacts))
            )
            execution_lines.append(
                "<li>"
                f"Execution {escape(str(execution.id))}: exit_code={execution.exit_code}, "
                f"tool_version={escape(execution.tool_version)}"
                + (f"<ul>{artifact_lines}</ul>" if artifact_lines else "")
                + "</li>"
            )
        task_sections.append(
            "<article class='task'>"
            f"<h3>Task {escape(str(task.id))}</h3>"
            f"<p><strong>Tool:</strong> {escape(task.tool)} | "
            f"<strong>Target:</strong> {escape(target_label)} | "
            f"<strong>Status:</strong> {escape(task.status)}</p>"
            + (f"<ul>{''.join(execution_lines)}</ul>" if execution_lines else "<p>No executions recorded.</p>")
            + "</article>"
        )

    tasks_html = "".join(task_sections) or "<p>No tasks recorded.</p>"

    configuration_html = _render_configuration_html(context)

    executive_panel = f"""
    <section class="panel">
      <h2>Risk Highlights</h2>
      <p><strong>Priority Counts:</strong> {escape(str(remediation_counts or {}))}</p>
      <ul class="meta-list">{"".join(f"<li>{escape(finding.severity.upper())}: {escape(finding.title)}</li>" for finding in findings[:5]) or "<li>No confirmed findings recorded.</li>"}</ul>
    </section>
    """

    if variant == "executive":
        findings_section = executive_panel
        evidence_section = ""
        verification_section = """
        <section class="panel">
          <h2>Recommended Next Steps</h2>
          <ul class="meta-list">
            <li>Use the Technical Report for analyst detail and the Evidence Appendix for replay artifacts.</li>
            <li>Prioritize remediation in the order shown above and schedule retest coverage for remaining open items.</li>
          </ul>
        </section>
        """
        title = "AegisPT Executive Report"
    elif variant == "evidence":
        findings_section = f"""
        <section class="panel">
          <h2>Findings Evidence Map</h2>
          {findings_html}
        </section>
        """
        evidence_section = f"""
        <section class="panel">
          <h2>Task Evidence</h2>
          {tasks_html}
        </section>
        """
        verification_section = ""
        title = "AegisPT Evidence Appendix"
    elif variant == "retest":
        findings_section = f"""
        <section class="panel">
          <h2>Findings Verification State</h2>
          {findings_html}
        </section>
        """
        evidence_section = ""
        verification_section = f"""
        <section class="panel">
          <h2>Retest and Verification</h2>
          <p><strong>Verification Status Counts:</strong> {escape(str(findings_by_status or {}))}</p>
          <p><strong>Resolved Findings:</strong> {sum(1 for finding in findings if finding.status == 'resolved')}</p>
          <p><strong>Findings Requiring Further Validation:</strong> {sum(1 for finding in findings if finding.status in {'open', 'triaged', 'in_progress', 'reopened'})}</p>
        </section>
        """
        title = "AegisPT Retest / Verification Report"
    else:
        findings_section = f"""
        <section class="panel">
          <h2>Confirmed Findings</h2>
          {findings_html}
        </section>
        """
        evidence_section = f"""
        <section class="panel">
          <h2>Evidence and Reproduction</h2>
          {tasks_html}
        </section>
        """
        verification_section = f"""
        <section class="panel">
          <h2>Retest and Verification</h2>
          <p><strong>Verification Status Counts:</strong> {escape(str(findings_by_status or {}))}</p>
          <p><strong>Resolved Findings:</strong> {sum(1 for finding in findings if finding.status == 'resolved')}</p>
          <p><strong>Findings Requiring Further Validation:</strong> {sum(1 for finding in findings if finding.status in {'open', 'triaged', 'in_progress', 'reopened'})}</p>
        </section>
        """
        title = "AegisPT Run Report"

    return f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>{escape(title)} {escape(str(run.id))}</title>
    <style>
      :root {{
        --ink: #1f2937;
        --muted: #4b5563;
        --line: #d1d5db;
        --panel: #ffffff;
        --panel-alt: #f8fafc;
        --accent: #9a3412;
      }}
      body {{
        font-family: "Segoe UI", "Helvetica Neue", sans-serif;
        margin: 2rem;
        color: var(--ink);
        background: linear-gradient(180deg, #fffaf5 0%, #ffffff 10rem);
      }}
      h1, h2, h3 {{
        color: #111827;
      }}
      h1 {{
        margin-bottom: 0.25rem;
      }}
      .lede {{
        color: var(--muted);
        margin-bottom: 2rem;
      }}
      table {{
        border-collapse: collapse;
        width: 100%;
        margin-bottom: 1.5rem;
        background: var(--panel);
      }}
      th, td {{
        border: 1px solid var(--line);
        padding: 0.65rem 0.75rem;
        text-align: left;
      }}
      th {{
        width: 16rem;
        background: #fcfcfd;
      }}
      .panel {{
        border: 1px solid var(--line);
        padding: 1rem 1.25rem;
        margin-bottom: 1rem;
        border-radius: 0.75rem;
        background: var(--panel);
        box-shadow: 0 8px 24px rgba(15, 23, 42, 0.04);
      }}
      .scope-grid {{
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(18rem, 1fr));
        gap: 1rem;
      }}
      .finding, .task {{
        border: 1px solid var(--line);
        padding: 1rem 1.25rem;
        margin-bottom: 1rem;
        border-radius: 0.75rem;
        background: var(--panel);
      }}
      .finding-header {{
        display: flex;
        align-items: baseline;
        justify-content: space-between;
        gap: 1rem;
      }}
      .priority {{
        color: var(--accent);
        font-weight: 600;
      }}
      code, pre {{
        background: var(--panel-alt);
        border-radius: 0.5rem;
      }}
      code {{
        padding: 0.1rem 0.3rem;
      }}
      pre {{
        padding: 0.85rem;
        overflow-x: auto;
      }}
      .meta-list li {{
        margin-bottom: 0.35rem;
      }}
    </style>
  </head>
  <body>
    <h1>{escape(title)}</h1>
    <p class="lede">Evidence-first assessment output aligned to PTES, OWASP WSTG, and NIST SP 800-115 without changing the core execution model.</p>

    <section class="panel">
      <h2>Summary</h2>
      <table>{summary_html}</table>
      <p><strong>By Severity:</strong> {escape(str(findings_by_severity or {}))}</p>
      <p><strong>By Status:</strong> {escape(str(findings_by_status or {}))}</p>
    </section>

    <section class="panel">
      <h2>Scope</h2>
      {scope_html}
    </section>

    <section class="panel">
      <h2>Run Configuration</h2>
      {configuration_html}
    </section>

    <section class="panel">
      <h2>Rules of Engagement Summary</h2>
      <p><strong>ROE Reference:</strong> {escape(run.engagement.roe_ref if run.engagement is not None and run.engagement.roe_ref else "Not Recorded")}</p>
      <ul class="meta-list">{approvals_html}</ul>
    </section>

    <section class="panel">
      <h2>Methodology Summary</h2>
      {methodology_html}
    </section>

    <section class="panel">
      <h2>Coverage Summary</h2>
      {coverage_html}
    </section>

    <section class="panel">
      <h2>Adaptive Coverage</h2>
      {adaptive_pack_html}
    </section>

    {findings_section}
    {evidence_section}
    {verification_section}
  </body>
</html>
"""
