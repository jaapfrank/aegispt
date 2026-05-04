#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
SUPPORTED_STATUSES = {"supported", "supported-with-gap", "blocked", "unsupported"}


@dataclass(frozen=True)
class EvidenceRule:
    path: str
    label: str
    signals: tuple[str, ...] = ()


def _now_iso() -> str:
    return datetime.now(tz=UTC).isoformat()


def _read_text(repo_root: Path, relative_path: str) -> str:
    path = repo_root / relative_path
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def _read_json(repo_root: Path, relative_path: str) -> dict[str, Any]:
    text = _read_text(repo_root, relative_path)
    if not text:
        return {}
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return {"_parse_error": True}
    return payload if isinstance(payload, dict) else {"_payload": payload}


def _evidence(repo_root: Path, rules: list[EvidenceRule]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for rule in rules:
        text = _read_text(repo_root, rule.path)
        missing_signals = [signal for signal in rule.signals if signal not in text]
        items.append(
            {
                "path": rule.path,
                "label": rule.label,
                "exists": bool(text),
                "required_signals": list(rule.signals),
                "missing_signals": missing_signals,
                "satisfied": bool(text) and not missing_signals,
            }
        )
    return items


def _evidence_satisfied(items: list[dict[str, Any]]) -> bool:
    return all(item["satisfied"] for item in items)


def _any_evidence(items: list[dict[str, Any]]) -> bool:
    return any(item["exists"] for item in items)


def _claim(
    *,
    claim_id: str,
    title: str,
    status: str,
    category: str,
    critical: bool,
    summary: str,
    evidence: list[dict[str, Any]],
    gaps: list[str] | None = None,
    next_task_refs: list[str] | None = None,
    support_boundary: str | None = None,
    metrics: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if status not in SUPPORTED_STATUSES:
        raise ValueError(f"unsupported claim status {status!r}")
    if status == "supported" and not [item for item in evidence if item.get("exists")]:
        raise ValueError(f"supported claim {claim_id} must link to existing evidence")
    if status == "blocked" and not next_task_refs:
        raise ValueError(f"blocked claim {claim_id} must include a concrete next task reference")
    return {
        "id": claim_id,
        "title": title,
        "category": category,
        "status": status,
        "critical": critical,
        "summary": summary,
        "support_boundary": support_boundary or summary,
        "evidence": evidence,
        "gaps": gaps or [],
        "next_task_refs": next_task_refs or [],
        "metrics": metrics or {},
    }


def _count_full_system_defects(payload: dict[str, Any]) -> dict[str, Any]:
    defects = payload.get("defects") if isinstance(payload.get("defects"), list) else []
    severity_counts: dict[str, int] = {}
    for defect in defects:
        if not isinstance(defect, dict):
            continue
        severity = str(defect.get("severity") or "unknown").lower()
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    return {"total": len(defects), "severity_counts": severity_counts}


def _validation_matrix_summary(payload: dict[str, Any]) -> dict[str, Any]:
    scenarios = payload.get("scenarios") if isinstance(payload.get("scenarios"), list) else []
    statuses: dict[str, int] = {}
    for scenario in scenarios:
        if not isinstance(scenario, dict):
            continue
        status = str(scenario.get("status") or "unknown")
        statuses[status] = statuses.get(status, 0) + 1
    return {
        "status": str(payload.get("status") or "missing"),
        "scenario_status_counts": statuses,
        "scenario_count": len(scenarios),
    }


def _target_catalog_summary(payload: dict[str, Any]) -> dict[str, Any]:
    targets = payload.get("targets") if isinstance(payload.get("targets"), list) else []
    scenarios = payload.get("real_run_scenarios") if isinstance(payload.get("real_run_scenarios"), list) else []
    enabled_targets = [item for item in targets if isinstance(item, dict) and item.get("enabled", True) is True]
    enabled_scenarios = [item for item in scenarios if isinstance(item, dict) and item.get("enabled", True) is True]
    blocked_targets = [
        item
        for item in targets
        if isinstance(item, dict)
        and (item.get("enabled", True) is not True or item.get("authorized", True) is not True)
    ]
    return {
        "target_count": len(targets),
        "enabled_target_count": len(enabled_targets),
        "real_run_scenario_count": len(scenarios),
        "enabled_real_run_scenario_count": len(enabled_scenarios),
        "blocked_or_template_target_count": len(blocked_targets),
    }


def _product_matrix_summary(payload: dict[str, Any]) -> dict[str, Any]:
    scenarios = payload.get("scenarios") if isinstance(payload.get("scenarios"), list) else []
    lanes: dict[str, int] = {}
    for scenario in scenarios:
        if not isinstance(scenario, dict) or scenario.get("enabled", True) is not True:
            continue
        lane = str(scenario.get("lane") or "unknown")
        lanes[lane] = lanes.get(lane, 0) + 1
    return {"enabled_scenario_count": sum(lanes.values()), "enabled_lanes": lanes}


def build_release_readiness_report(repo_root: Path | None = None) -> dict[str, Any]:
    root = repo_root or REPO_ROOT
    product_matrix = _read_json(root, "codex/tasks/product_acceptance_matrix.json")
    target_catalog = _read_json(root, "codex/tasks/target_lab_matrix.json")
    validation_matrix = _read_json(root, "codex/results/validation-matrix-latest.json")
    full_audit = _read_json(root, "codex/results/backlog-181-full-system-audit.json")
    ia_audit = _read_json(root, "codex/results/backlog-181-ia-audit.json")

    product_metrics = _product_matrix_summary(product_matrix)
    target_metrics = _target_catalog_summary(target_catalog)
    validation_metrics = _validation_matrix_summary(validation_matrix)
    full_audit_metrics = _count_full_system_defects(full_audit)
    ia_metrics = {
        "page_count": len(ia_audit.get("pages") or []) if isinstance(ia_audit.get("pages"), list) else 0,
        "failure_notes": ia_audit.get("failure_notes") if isinstance(ia_audit.get("failure_notes"), list) else [],
        "partial": bool(ia_audit.get("partial", False)),
    }

    claims: list[dict[str, Any]] = []

    operator_evidence = _evidence(
        root,
        [
            EvidenceRule("docs/operator_product_operational_assurance.md", "Operational assurance matrix", ("Status Legend",)),
            EvidenceRule("codex/tasks/product_acceptance_matrix.json", "Product acceptance matrix", ("product_acceptance_matrix_v1",)),
            EvidenceRule("codex/results/backlog-181-full-system-audit.json", "Full-system acceptance audit"),
        ],
    )
    operator_gaps = []
    if full_audit_metrics["total"]:
        operator_gaps.append(f"Latest full-system audit records {full_audit_metrics['total']} product defects.")
    claims.append(
        _claim(
            claim_id="operator_product_acceptance",
            title="Operator product acceptance",
            status="supported-with-gap" if operator_gaps else ("supported" if _evidence_satisfied(operator_evidence) else "blocked"),
            category="product_acceptance",
            critical=True,
            summary="Operator journeys have matrix and audit coverage, but release claims must account for recorded product defects.",
            evidence=operator_evidence,
            gaps=operator_gaps,
            next_task_refs=["codex/tasks/backlog-149-full-system-acceptance-harness-and-defect-inventory.json"] if operator_gaps else [],
            metrics={"product_matrix": product_metrics, "full_system_audit": full_audit_metrics},
        )
    )

    wizard_evidence = _evidence(
        root,
        [
            EvidenceRule("codex/tasks/product_acceptance_matrix.json", "Wizard/profile acceptance scenarios", ("ui-wizard-profile-matrix",)),
            EvidenceRule("codex/results/backlog-151-wizard-input-prediction-matrix-20260430.json", "Wizard matrix evidence"),
        ],
    )
    claims.append(
        _claim(
            claim_id="wizard_profile_matrix",
            title="Wizard/profile matrix",
            status="supported" if _evidence_satisfied(wizard_evidence) else "supported-with-gap",
            category="product_acceptance",
            critical=True,
            summary="Wizard assessment, profile, access, and safety matrix evidence is present.",
            evidence=wizard_evidence,
            gaps=[] if _evidence_satisfied(wizard_evidence) else ["Wizard matrix evidence is incomplete."],
            next_task_refs=[] if _evidence_satisfied(wizard_evidence) else ["codex/tasks/backlog-151-wizard-input-prediction-and-assessment-matrix.json"],
            metrics={"product_matrix": product_metrics},
        )
    )

    tool_evidence = _evidence(
        root,
        [
            EvidenceRule("api/tests/test_settings.py", "Settings/readiness API coverage", ("tool", "readiness")),
            EvidenceRule("codex/results/backlog-184-observability-support-diagnostics-bundle-20260502.md", "Diagnostics evidence", ("tool readiness",)),
            EvidenceRule("codex/results/backlog-164-wifi-readiness-20260501.md", "WiFi readiness evidence"),
        ],
    )
    claims.append(
        _claim(
            claim_id="runner_tool_readiness",
            title="Runner and tool readiness",
            status="supported-with-gap" if _any_evidence(tool_evidence) else "blocked",
            category="runtime_readiness",
            critical=True,
            summary="Readiness surfaces expose tool availability, but actual enterprise hosts remain environment-dependent.",
            evidence=tool_evidence,
            gaps=["Tool availability depends on installed host binaries, adapters, and worker/inline mode."],
            next_task_refs=["codex/tasks/backlog-154-settings-environment-and-tool-readiness-control-plane.json"],
            metrics={},
        )
    )

    lab_evidence = _evidence(
        root,
        [
            EvidenceRule("codex/tasks/target_lab_matrix.json", "Safe target catalog", ("safe_target_catalog_v2",)),
            EvidenceRule("docs/operator_product_operational_assurance.md", "Safe real-run coverage", ("Real-Run Safe Target Coverage",)),
        ],
    )
    lab_gap = []
    if target_metrics["blocked_or_template_target_count"]:
        lab_gap.append(f"{target_metrics['blocked_or_template_target_count']} safe target entries are disabled/templates/documentation-only.")
    claims.append(
        _claim(
            claim_id="safe_lab_and_real_run_catalog",
            title="Safe lab and real-run catalog",
            status="supported-with-gap" if lab_gap else ("supported" if _evidence_satisfied(lab_evidence) else "blocked"),
            category="lab_truth",
            critical=True,
            summary="The catalog distinguishes runnable safe targets from disabled templates and documentation-only references.",
            evidence=lab_evidence,
            gaps=lab_gap,
            next_task_refs=["codex/tasks/backlog-107-benchmark-lab-expansion-foundation.json"] if lab_gap else [],
            metrics={"target_catalog": target_metrics},
        )
    )

    detection_evidence = _evidence(
        root,
        [
            EvidenceRule("codex/results/validation-matrix-latest.json", "Known-vulnerability validation matrix result", ("known_vulnerability_validation_v1",)),
            EvidenceRule("scripts/run_validation_matrix.py", "Validation matrix runner", ("detection_rate", "false_positive_rate")),
        ],
    )
    validation_ready = validation_metrics["status"] == "passed"
    claims.append(
        _claim(
            claim_id="known_vulnerability_detection_accuracy",
            title="Known-vulnerability detection accuracy",
            status="supported" if validation_ready and _evidence_satisfied(detection_evidence) else "blocked",
            category="accuracy",
            critical=True,
            summary="Release claims require executed expected-vs-actual validation, not catalog-only evidence.",
            evidence=detection_evidence,
            gaps=[] if validation_ready else [f"Validation matrix status is `{validation_metrics['status']}`, not `passed`."],
            next_task_refs=[] if validation_ready else ["codex/tasks/backlog-99-known-vulnerability-validation-matrix.json"],
            metrics={"validation_matrix": validation_metrics},
        )
    )

    claims.append(
        _claim(
            claim_id="false_positive_false_negative_posture",
            title="False-positive and false-negative posture",
            status="supported" if validation_ready and _evidence_satisfied(detection_evidence) else "blocked",
            category="accuracy",
            critical=True,
            summary="False-positive/negative posture must be based on executed validation scenarios with expected and forbidden findings.",
            evidence=detection_evidence,
            gaps=[] if validation_ready else ["Current validation matrix has no executed pass/fail accuracy verdict."],
            next_task_refs=[] if validation_ready else ["codex/tasks/backlog-99-known-vulnerability-validation-matrix.json"],
            metrics={"validation_matrix": validation_metrics},
        )
    )

    evidence_integrity = _evidence(
        root,
        [
            EvidenceRule("api/tests/test_backup_restore.py", "Backup/restore evidence linkage tests", ("artifact_hash_verified",)),
            EvidenceRule("api/tests/test_diagnostics.py", "Support bundle redaction tests", ("raw_evidence_payloads",)),
            EvidenceRule("docs/operator_product_operational_assurance.md", "Evidence and report path support matrix", ("Evidence Replay",)),
        ],
    )
    claims.append(
        _claim(
            claim_id="evidence_integrity",
            title="Evidence integrity and chain custody",
            status="supported-with-gap",
            category="evidence",
            critical=True,
            summary="Evidence hash/linkage and support redaction are validated, while full RFC 3161 chain completeness remains future work.",
            evidence=evidence_integrity,
            gaps=["Full evidence-chain completeness and timestamping are still tracked separately."],
            next_task_refs=["codex/tasks/backlog-119-evidence-chain-completeness.json"],
            metrics={},
        )
    )

    report_evidence = _evidence(
        root,
        [
            EvidenceRule("docs/operator_product_operational_assurance.md", "Report/export support matrix", ("Export and Report Paths",)),
            EvidenceRule("codex/tasks/product_acceptance_matrix.json", "Report download acceptance scenario", ("ui-report-downloads",)),
        ],
    )
    claims.append(
        _claim(
            claim_id="report_quality_and_exports",
            title="Report quality and exports",
            status="supported-with-gap" if _any_evidence(report_evidence) else "blocked",
            category="reporting",
            critical=True,
            summary="Current report/export paths are documented and tested, but enterprise assurance packages and external attestations are not complete.",
            evidence=report_evidence,
            gaps=["Evidence-backed assurance, ISO 27001, and PCI DSS report packages remain future slices."],
            next_task_refs=["codex/tasks/backlog-20-evidence-backed-assurance-package-foundation.json", "codex/tasks/backlog-29-compliance-framework-expansion-foundation.json"],
            metrics={},
        )
    )

    ai_evidence = _evidence(
        root,
        [
            EvidenceRule("api/tests/test_settings.py", "AI provider/settings coverage", ("AI",)),
            EvidenceRule("codex/results/backlog-161-ai-signal-global-chatgpt-no-run-validation-20260501.md", "AI Signal state evidence"),
            EvidenceRule("DECISIONS.md", "AI repair operator contract", ("AI repair", "AI Signal")),
        ],
    )
    claims.append(
        _claim(
            claim_id="ai_feature_availability",
            title="AI feature availability",
            status="supported-with-gap" if _any_evidence(ai_evidence) else "blocked",
            category="ai",
            critical=False,
            summary="AI surfaces are governed and disabled/configuration-aware; they must not be marketed as always-on without provider evidence.",
            evidence=ai_evidence,
            gaps=["AI value, repair actions, and signal inbox remain partially implemented and provider-dependent."],
            next_task_refs=["codex/tasks/backlog-152-ai-value-and-operator-signal-workbench.json"],
            metrics={},
        )
    )

    security_evidence = _evidence(
        root,
        [
            EvidenceRule("docs/security_self_assessment.md", "Security self-assessment", ("Automated Validation", "Dependency Audit")),
            EvidenceRule("api/tests/test_input_validation_security.py", "Input validation and tenant/scope tests", ("tenant", "scope")),
        ],
    )
    claims.append(
        _claim(
            claim_id="security_self_test",
            title="Security self-test",
            status="supported-with-gap" if _any_evidence(security_evidence) else "blocked",
            category="security",
            critical=True,
            summary="Local self-security tests exist, with dependency CVE verdict still dependent on audit tooling availability.",
            evidence=security_evidence,
            gaps=["Dependency audit recorded tool_unavailable until pip-audit or safety is provided."],
            next_task_refs=["docs/security_self_assessment.md"],
            metrics={},
        )
    )

    accessibility_evidence = _evidence(
        root,
        [
            EvidenceRule("codex/results/backlog-185-accessibility-keyboard-enterprise-ux-gate-20260502.md", "Accessibility result", ("Keyboard", "reduced-motion")),
            EvidenceRule("docs/accessibility_acceptance.md", "Accessibility acceptance standard"),
            EvidenceRule("ui/tests/test_accessibility_e2e.py", "Accessibility E2E gate", ("focus", "keyboard")),
        ],
    )
    claims.append(
        _claim(
            claim_id="accessibility_keyboard_enterprise_ux",
            title="Accessibility and keyboard enterprise UX",
            status="supported" if _evidence_satisfied(accessibility_evidence) else "supported-with-gap",
            category="ux",
            critical=True,
            summary="A dedicated keyboard/accessibility gate exists for the operator console.",
            evidence=accessibility_evidence,
            gaps=[] if _evidence_satisfied(accessibility_evidence) else ["Accessibility evidence is incomplete."],
            next_task_refs=[] if _evidence_satisfied(accessibility_evidence) else ["codex/tasks/backlog-185-accessibility-keyboard-enterprise-ux-gate.json"],
            metrics={"enterprise_ia_audit": ia_metrics},
        )
    )

    deployment_evidence = _evidence(
        root,
        [
            EvidenceRule("codex/results/backlog-186-enterprise-deployment-hardening-20260503.md", "Deployment hardening result", ("Deployment Hardening", "Remaining Risk")),
            EvidenceRule("docs/host_service_install.md", "Host deployment hardening runbook", ("Production deployment hardening",)),
        ],
    )
    claims.append(
        _claim(
            claim_id="enterprise_deployment_hardening",
            title="Enterprise deployment hardening",
            status="supported-with-gap" if _any_evidence(deployment_evidence) else "blocked",
            category="deployment",
            critical=True,
            summary="Deployment readiness is explicit, but external TLS/proxy/certificate/encryption proof remains operator-managed.",
            evidence=deployment_evidence,
            gaps=["The readiness surface does not install or verify external TLS, proxy, certificate, database, or object-store infrastructure."],
            next_task_refs=["codex/tasks/backlog-186-enterprise-deployment-hardening.json"],
            metrics={},
        )
    )

    backup_evidence = _evidence(
        root,
        [
            EvidenceRule("codex/results/backlog-183-backup-restore-upgrade-rollback-drill-20260502.md", "Backup/restore drill result", ("Artifact hash verified", "Plaintext secrets exposed: false")),
            EvidenceRule("scripts/verify_restore.py", "Restore verification script", ("safe-local",)),
        ],
    )
    claims.append(
        _claim(
            claim_id="backup_restore_upgrade_rollback",
            title="Backup, restore, upgrade, and rollback",
            status="supported-with-gap" if _any_evidence(backup_evidence) else "blocked",
            category="operations",
            critical=True,
            summary="A safe local restore drill exists; production PostgreSQL/secret recovery remains environment-specific.",
            evidence=backup_evidence,
            gaps=["Automated proof is SQLite/local; Compose/PostgreSQL and production secret recovery require operator drills."],
            next_task_refs=["codex/tasks/backlog-183-backup-restore-upgrade-rollback-drill.json"],
            metrics={},
        )
    )

    observability_evidence = _evidence(
        root,
        [
            EvidenceRule("codex/results/backlog-184-observability-support-diagnostics-bundle-20260502.md", "Observability/support diagnostics result", ("Support Diagnostics", "Redaction")),
            EvidenceRule("api/tests/test_diagnostics.py", "Diagnostics API tests", ("support_bundle", "redact")),
        ],
    )
    claims.append(
        _claim(
            claim_id="observability_support_diagnostics",
            title="Observability and support diagnostics",
            status="supported-with-gap" if _any_evidence(observability_evidence) else "blocked",
            category="operations",
            critical=True,
            summary="Diagnostics and redacted support bundles are validated, with live-host availability dependent on deployment refresh.",
            evidence=observability_evidence,
            gaps=["Existing live processes may need restart before new diagnostics routes are visible."],
            next_task_refs=["codex/tasks/backlog-184-observability-support-diagnostics-bundle.json"],
            metrics={},
        )
    )

    identity_evidence = _evidence(
        root,
        [
            EvidenceRule("codex/results/backlog-182-enterprise-identity-session-admin-20260502.md", "Enterprise identity result", ("Enterprise Identity", "Remaining")),
            EvidenceRule("api/tests/test_auth.py", "Auth/identity tests", ("identity", "logout")),
        ],
    )
    claims.append(
        _claim(
            claim_id="enterprise_identity_sessions",
            title="Enterprise identity and sessions",
            status="supported-with-gap" if _any_evidence(identity_evidence) else "blocked",
            category="identity",
            critical=True,
            summary="Identity configuration/status/audit foundations exist, but enforced hosted enterprise SSO remains future work.",
            evidence=identity_evidence,
            gaps=["OIDC/SAML browser enforcement, SCIM, tenant membership, and hosted RBAC remain future work."],
            next_task_refs=["codex/tasks/backlog-182-enterprise-sso-session-identity-administration.json", "codex/tasks/backlog-127-rbac.json"],
            metrics={},
        )
    )

    unsupported_evidence = _evidence(
        root,
        [
            EvidenceRule("DECISIONS.md", "Runtime safety decisions", ("No runtime self-modification", "No uncontrolled plugin installation")),
            EvidenceRule("docs/operator_product_operational_assurance.md", "Unsupported path ledger", ("intentionally-unsupported",)),
        ],
    )
    claims.append(
        _claim(
            claim_id="unsupported_claim_boundary",
            title="Unsupported claim boundary",
            status="unsupported",
            category="truth_boundary",
            critical=True,
            summary="Hosted SaaS completeness, external certification, arbitrary public scanning, runtime self-modification, and uncontrolled plugin installation remain outside the supported claim boundary.",
            evidence=unsupported_evidence,
            gaps=[],
            next_task_refs=[],
            support_boundary="Do not market or imply these capabilities until a future task explicitly implements and validates them.",
            metrics={},
        )
    )

    totals = {status: 0 for status in sorted(SUPPORTED_STATUSES)}
    for claim in claims:
        totals[claim["status"]] += 1
    critical_blocked = [claim for claim in claims if claim["critical"] and claim["status"] == "blocked"]
    critical_gaps = [claim for claim in claims if claim["critical"] and claim["status"] == "supported-with-gap"]
    overall_status = "blocked" if critical_blocked else ("supported-with-gap" if critical_gaps else "supported")
    release_decision = {
        "status": overall_status,
        "can_claim_enterprise_ready": overall_status == "supported",
        "go_no_go": "go" if overall_status == "supported" else "no-go",
        "reason": (
            "Critical release-readiness evidence is missing."
            if critical_blocked
            else "Critical claims still have explicit gaps."
            if critical_gaps
            else "All critical claims have linked evidence and no open gate gaps."
        ),
        "blocked_claim_ids": [claim["id"] for claim in critical_blocked],
        "critical_gap_claim_ids": [claim["id"] for claim in critical_gaps],
    }
    return {
        "kind": "aegispt.enterprise_release_readiness",
        "schema_version": 1,
        "generated_at": _now_iso(),
        "repo_root": str(root),
        "release_decision": release_decision,
        "claim_totals": totals,
        "support_claim_ledger": claims,
        "inputs": {
            "product_acceptance_matrix": "codex/tasks/product_acceptance_matrix.json",
            "target_lab_matrix": "codex/tasks/target_lab_matrix.json",
            "validation_matrix": "codex/results/validation-matrix-latest.json",
            "operator_assurance_matrix": "docs/operator_product_operational_assurance.md",
        },
    }


def render_markdown(report: dict[str, Any]) -> str:
    decision = report["release_decision"]
    lines = [
        "# AegisPT Enterprise Release Readiness",
        "",
        f"- Generated: `{report['generated_at']}`",
        f"- Gate status: `{decision['status']}`",
        f"- Go/no-go: `{decision['go_no_go']}`",
        f"- Enterprise-ready claim allowed: `{str(decision['can_claim_enterprise_ready']).lower()}`",
        f"- Reason: {decision['reason']}",
        "",
        "## Support-Claim Ledger",
        "",
        "| Claim | Status | Critical | Evidence | Gaps / next step |",
        "| --- | --- | --- | --- | --- |",
    ]
    for claim in report["support_claim_ledger"]:
        evidence = "<br>".join(
            f"`{item['path']}`" for item in claim["evidence"] if item.get("exists")
        ) or "Missing"
        gap_text = "; ".join(claim["gaps"]) if claim["gaps"] else "No recorded gap."
        if claim["next_task_refs"]:
            gap_text += "<br>Next: " + ", ".join(f"`{ref}`" for ref in claim["next_task_refs"])
        lines.append(
            "| "
            + " | ".join(
                [
                    claim["title"],
                    f"`{claim['status']}`",
                    str(claim["critical"]).lower(),
                    evidence,
                    gap_text,
                ]
            )
            + " |"
        )
    lines.extend(
        [
            "",
            "## Release Boundary",
            "",
            "This gate is intentionally fail-closed. It aggregates existing repo evidence and does not run live customer targets, change product claims, weaken safety gates, install plugins, or mutate runtime behavior.",
            "",
            "AegisPT must not be called enterprise-ready while any critical claim is `blocked`, and must not overclaim `supported-with-gap` or `unsupported` capabilities.",
            "",
        ]
    )
    return "\n".join(lines)


def write_report(report: dict[str, Any], *, output_json: Path, output_md: Path) -> None:
    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_md.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    output_md.write_text(render_markdown(report), encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build the AegisPT enterprise release-readiness ledger.")
    parser.add_argument(
        "--output-json",
        default=str(REPO_ROOT / "codex" / "results" / "enterprise-release-readiness.json"),
        help="Path for the machine-readable readiness ledger.",
    )
    parser.add_argument(
        "--output-md",
        default=str(REPO_ROOT / "codex" / "results" / "enterprise-release-readiness.md"),
        help="Path for the human-readable readiness report.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    report = build_release_readiness_report()
    write_report(report, output_json=Path(args.output_json), output_md=Path(args.output_md))
    print(
        json.dumps(
            {
                "status": report["release_decision"]["status"],
                "go_no_go": report["release_decision"]["go_no_go"],
                "can_claim_enterprise_ready": report["release_decision"]["can_claim_enterprise_ready"],
                "output_json": str(Path(args.output_json).resolve()),
                "output_md": str(Path(args.output_md).resolve()),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
