from __future__ import annotations

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


def load_run_report(session: Session, run_id: UUID | str) -> Run | None:
    return session.scalar(
        select(Run)
        .options(
            selectinload(Run.engagement).selectinload(Engagement.scopes),
            selectinload(Run.profile),
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
    ]
    return lines


def render_markdown_report(run: Run) -> str:
    profile_name = run.profile.name if run.profile is not None else "unknown-profile"
    engagement_name = run.engagement.name if run.engagement is not None else "unknown-engagement"
    client_name = run.engagement.client if run.engagement is not None and run.engagement.client else "unknown-client"
    findings = sort_findings(list(run.findings))
    tasks = sort_tasks(list(run.tasks))
    approvals = sort_approvals(list(run.approvals))
    findings_by_severity, findings_by_status = findings_summary(findings)
    methodology = methodology_context_for_run(run)
    coverage = methodology_coverage_summary(findings, tasks)
    latest_scope = latest_scope_for_engagement(run.engagement)
    remediation_counts = remediation_priority_counts(findings)

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


def render_html_report(run: Run) -> str:
    profile_name = run.profile.name if run.profile is not None else "unknown-profile"
    engagement_name = run.engagement.name if run.engagement is not None else "unknown-engagement"
    client_name = run.engagement.client if run.engagement is not None and run.engagement.client else "unknown-client"
    findings = sort_findings(list(run.findings))
    tasks = sort_tasks(list(run.tasks))
    approvals = sort_approvals(list(run.approvals))
    findings_by_severity, findings_by_status = findings_summary(findings)
    methodology = methodology_context_for_run(run)
    coverage = methodology_coverage_summary(findings, tasks)
    latest_scope = latest_scope_for_engagement(run.engagement)
    remediation_counts = remediation_priority_counts(findings)

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

    return f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>AegisPT Run Report {escape(str(run.id))}</title>
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
    <h1>AegisPT Run Report</h1>
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
      <h2>Confirmed Findings</h2>
      {findings_html}
    </section>

    <section class="panel">
      <h2>Evidence and Reproduction</h2>
      {tasks_html}
    </section>

    <section class="panel">
      <h2>Retest and Verification</h2>
      <p><strong>Verification Status Counts:</strong> {escape(str(findings_by_status or {}))}</p>
      <p><strong>Resolved Findings:</strong> {sum(1 for finding in findings if finding.status == 'resolved')}</p>
      <p><strong>Findings Requiring Further Validation:</strong> {sum(1 for finding in findings if finding.status in {'open', 'triaged', 'in_progress', 'reopened'})}</p>
    </section>
  </body>
</html>
"""
