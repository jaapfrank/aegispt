from __future__ import annotations

import json
from hashlib import sha256
from typing import Any

from workers.runners.base.contracts import EvidenceArtifact, RunnerExecution

TOOL_NAME = "social-campaign"
SOCIAL_CAMPAIGN_RESULTS_ARTIFACT_NAME = "social-campaign-results.json"
_REDACTED = "[redacted]"
_SECRET_KEY_MARKERS = (
    "password",
    "passwd",
    "secret",
    "token",
    "credential",
    "credentials",
    "submitted_data",
    "submitted_password",
)


def _json_artifact(payload: dict[str, Any]) -> EvidenceArtifact:
    return EvidenceArtifact(
        name=SOCIAL_CAMPAIGN_RESULTS_ARTIFACT_NAME,
        content_type="application/json",
        data=(json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8"),
        kind="runner-results",
    )


def _sha256_text(value: str) -> str:
    return sha256(value.strip().lower().encode("utf-8")).hexdigest()


def _is_secret_key(key: str) -> bool:
    normalized = key.strip().lower()
    return any(marker in normalized for marker in _SECRET_KEY_MARKERS)


def _redact_payload(value: Any) -> Any:
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            normalized_key = str(key)
            if _is_secret_key(normalized_key):
                redacted[normalized_key] = _REDACTED
            elif normalized_key.strip().lower() == "email":
                email = str(item or "").strip().lower()
                domain = email.rsplit("@", 1)[1] if "@" in email else ""
                redacted["email_hash"] = _sha256_text(email) if email else ""
                redacted["email_domain"] = domain
            else:
                redacted[normalized_key] = _redact_payload(item)
        return redacted
    if isinstance(value, list):
        return [_redact_payload(item) for item in value]
    return value


def _event_text(event: Any) -> str:
    if isinstance(event, dict):
        values = [
            event.get("message"),
            event.get("event"),
            event.get("type"),
            event.get("status"),
            event.get("details"),
        ]
        return " ".join(str(value or "") for value in values).lower()
    return str(event or "").lower()


def _campaign_name(campaign: dict[str, Any], fallback: str) -> str:
    return str(campaign.get("name") or campaign.get("campaign_name") or fallback).strip() or fallback


def _result_events(result: dict[str, Any]) -> list[Any]:
    events = result.get("events")
    return events if isinstance(events, list) else []


def _result_email_domain(result: dict[str, Any]) -> str:
    email = str(result.get("email") or result.get("recipient") or "").strip().lower()
    if "@" not in email:
        return ""
    return email.rsplit("@", 1)[1].strip()


def _has_secret_material(value: Any) -> bool:
    if isinstance(value, dict):
        return any(
            _is_secret_key(str(key)) or _has_secret_material(item)
            for key, item in value.items()
        )
    if isinstance(value, list):
        return any(_has_secret_material(item) for item in value)
    return False


def _status_matches(result: dict[str, Any], *needles: str) -> bool:
    status = str(result.get("status") or "").lower()
    event_text = " ".join(_event_text(event) for event in _result_events(result))
    return any(needle in status or needle in event_text for needle in needles)


def _recipient_summary(result: dict[str, Any]) -> dict[str, Any]:
    email = str(result.get("email") or result.get("recipient") or "").strip().lower()
    submitted = _status_matches(result, "submitted", "submitted data")
    clicked = submitted or _status_matches(result, "clicked", "clicked link")
    opened = clicked or _status_matches(result, "opened", "email opened")
    return {
        "recipient_hash": _sha256_text(email) if email else "",
        "recipient_domain": _result_email_domain(result),
        "opened": opened,
        "clicked": clicked,
        "submitted": submitted,
        "reported": _status_matches(result, "reported"),
        "bounced": _status_matches(result, "bounced"),
    }


def _append_finding(
    findings: list[dict[str, Any]],
    *,
    finding_type: str,
    title: str,
    severity: str,
    target: str,
    summary: str,
    evidence: dict[str, Any],
) -> None:
    findings.append(
        {
            "type": finding_type,
            "title": title,
            "severity": severity,
            "target": target,
            "summary": summary,
            "methodology_tags": [
                "social_engineering",
                "phishing_awareness",
                "campaign_review",
            ],
            "ptes_phase": "Reporting",
            "nist_phase": "Reporting",
            "control_family": "identity_management",
            "evidence": evidence,
            "replay_recipe": {
                "tool": TOOL_NAME,
                "mode": "review-only-import",
                "external_send_required": False,
                "operator_approval_required_for_send": True,
            },
        }
    )


def _normalize_campaign_payload(
    campaign_export: dict[str, Any],
    *,
    fallback_target: str,
    approved_recipient_domains: list[str],
) -> dict[str, Any]:
    campaign = campaign_export.get("campaign")
    if not isinstance(campaign, dict):
        campaign = campaign_export
    campaign_name = _campaign_name(campaign, fallback_target)
    results = campaign.get("results")
    if not isinstance(results, list):
        results = campaign_export.get("results")
    if not isinstance(results, list):
        results = []

    recipient_summaries = [
        _recipient_summary(result)
        for result in results
        if isinstance(result, dict)
    ]
    recipient_count = len(recipient_summaries)
    opened_count = sum(1 for item in recipient_summaries if item["opened"])
    clicked_count = sum(1 for item in recipient_summaries if item["clicked"])
    submitted_count = sum(1 for item in recipient_summaries if item["submitted"])
    reported_count = sum(1 for item in recipient_summaries if item["reported"])
    bounced_count = sum(1 for item in recipient_summaries if item["bounced"])
    secret_material_seen = _has_secret_material(campaign_export)
    approved_domains = {
        domain.strip().lower()
        for domain in approved_recipient_domains
        if isinstance(domain, str) and domain.strip()
    }
    observed_domains = {
        item["recipient_domain"]
        for item in recipient_summaries
        if item["recipient_domain"]
    }
    out_of_scope_domains = (
        sorted(observed_domains - approved_domains) if approved_domains else []
    )
    target = campaign_name
    findings: list[dict[str, Any]] = []

    if submitted_count:
        _append_finding(
            findings,
            finding_type="social_campaign_credential_submission_observed",
            title="Credential Submission Observed in Social Engineering Campaign",
            severity="high",
            target=target,
            summary=(
                f"Imported campaign evidence shows {submitted_count} recipient(s) submitted data. "
                "AegisPT redacted submitted values and stores only aggregate evidence."
            ),
            evidence={
                "submitted_count": submitted_count,
                "recipient_count": recipient_count,
                "submitted_values_stored": False,
            },
        )
    if recipient_count and clicked_count / recipient_count >= 0.2:
        _append_finding(
            findings,
            finding_type="social_campaign_high_click_rate",
            title="High Click Rate in Social Engineering Campaign",
            severity="medium",
            target=target,
            summary=(
                f"Imported campaign evidence shows {clicked_count} of {recipient_count} "
                "recipient(s) clicked campaign links."
            ),
            evidence={"clicked_count": clicked_count, "recipient_count": recipient_count},
        )
    if recipient_count and (clicked_count or submitted_count) and reported_count == 0:
        _append_finding(
            findings,
            finding_type="social_campaign_low_reporting_rate",
            title="Low Reporting Rate in Social Engineering Campaign",
            severity="low",
            target=target,
            summary=(
                "Imported campaign evidence includes clicks or submissions but no reported "
                "campaign events."
            ),
            evidence={
                "reported_count": reported_count,
                "clicked_count": clicked_count,
                "submitted_count": submitted_count,
            },
        )
    if out_of_scope_domains:
        _append_finding(
            findings,
            finding_type="social_campaign_out_of_scope_recipients",
            title="Campaign Evidence Contains Out-of-Scope Recipient Domains",
            severity="high",
            target=target,
            summary=(
                "Imported campaign evidence includes recipient domains outside the approved "
                "recipient allowlist."
            ),
            evidence={"out_of_scope_recipient_domains": out_of_scope_domains},
        )

    return {
        "campaign": {
            "name": campaign_name,
            "id_hash": _sha256_text(str(campaign.get("id") or campaign_name)),
            "status": str(campaign.get("status") or campaign_export.get("status") or "imported"),
        },
        "metrics": {
            "recipient_count": recipient_count,
            "opened_count": opened_count,
            "clicked_count": clicked_count,
            "submitted_count": submitted_count,
            "reported_count": reported_count,
            "bounced_count": bounced_count,
            "click_rate": round(clicked_count / recipient_count, 4) if recipient_count else 0.0,
            "submission_rate": round(submitted_count / recipient_count, 4) if recipient_count else 0.0,
            "report_rate": round(reported_count / recipient_count, 4) if recipient_count else 0.0,
        },
        "recipient_summaries": recipient_summaries,
        "observed_recipient_domains": sorted(observed_domains),
        "out_of_scope_recipient_domains": out_of_scope_domains,
        "secret_material_seen_in_import": secret_material_seen,
        "findings": findings,
        "redacted_import": _redact_payload(campaign_export),
    }


def execute_social_campaign_review(
    targets: list[str],
    *,
    campaign_export: dict[str, Any] | None = None,
    approved_recipient_domains: list[str] | None = None,
    launch_requested: bool = False,
    operator_approved: bool = False,
) -> RunnerExecution:
    if launch_requested:
        raise ValueError(
            "social-campaign is review-only in this build lane; runtime campaign dispatch requires "
            "separate operator approval and is not performed by this runner"
        )
    if campaign_export is None:
        raise ValueError("social-campaign requires imported campaign metadata or results")
    if not isinstance(campaign_export, dict):
        raise ValueError("social-campaign campaign_export must be a JSON object")

    normalized_targets = [target.strip() for target in targets if str(target).strip()]
    fallback_target = normalized_targets[0] if normalized_targets else "social-campaign-import"
    normalized = _normalize_campaign_payload(
        campaign_export,
        fallback_target=fallback_target,
        approved_recipient_domains=approved_recipient_domains or [],
    )
    payload = {
        "tool": TOOL_NAME,
        "mode": "review-only-import",
        "targets": normalized_targets,
        "summary": {
            "finding_count": len(normalized["findings"]),
            "recipient_count": normalized["metrics"]["recipient_count"],
            "clicked_count": normalized["metrics"]["clicked_count"],
            "submitted_count": normalized["metrics"]["submitted_count"],
            "reported_count": normalized["metrics"]["reported_count"],
        },
        "campaign": normalized["campaign"],
        "metrics": normalized["metrics"],
        "recipient_summaries": normalized["recipient_summaries"],
        "observed_recipient_domains": normalized["observed_recipient_domains"],
        "out_of_scope_recipient_domains": normalized["out_of_scope_recipient_domains"],
        "findings": normalized["findings"],
        "redacted_import": normalized["redacted_import"],
        "safety": {
            "review_only": True,
            "runtime_campaign_dispatch_performed": False,
            "external_send_performed": False,
            "operator_approved": bool(operator_approved),
            "operator_approval_required_for_send": True,
            "automatic_approval_created": False,
            "credential_values_stored_in_artifacts": False,
            "submitted_secret_values_stored": False,
            "secret_material_seen_in_import": normalized["secret_material_seen_in_import"],
        },
        "provenance": {
            "source": "imported_campaign_export",
            "source_sha256": sha256(
                json.dumps(campaign_export, sort_keys=True, default=str).encode("utf-8")
            ).hexdigest(),
            "runner_digest": "workers.social_campaign.runner:v1",
        },
    }
    artifact = _json_artifact(payload)
    return RunnerExecution(
        tool=TOOL_NAME,
        exit_code=0,
        stdout=(
            "social-campaign review-only import complete: "
            f"{payload['summary']['finding_count']} finding(s)"
        ),
        stderr="",
        metadata={
            "mode": "review-only-import",
            "runtime_campaign_dispatch_performed": False,
            "credential_values_stored_in_artifacts": False,
            "finding_count": payload["summary"]["finding_count"],
        },
        artifacts=[artifact],
        protected_outputs=[],
    )
