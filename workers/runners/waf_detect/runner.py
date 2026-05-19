from __future__ import annotations

import json
import re
from hashlib import sha256
from typing import Any, Callable

import httpx as httpx_client

from api.app.services.runs import web_target_value_is_allowed_with_path
from workers.runners.base.contracts import EvidenceArtifact, RunnerExecution
from workers.runners.httpx.runner import normalize_http_target

TOOL_NAME = "waf-detect"
WAF_DETECT_RESULTS_ARTIFACT_NAME = "waf-detect-results.json"
WAF_SIGNATURES = {
    "Cloudflare": ("cloudflare", "cf-ray", "__cf_bm", "cf-cache-status"),
    "AWS WAF": ("aws waf", "x-amzn-waf", "x-amzn-requestid", "awselb"),
    "Akamai": ("akamai", "ak_bmsc", "akamai bot manager", "akamai ghost"),
    "Imperva": ("imperva", "incapsula", "x-iinfo", "visid_incap"),
    "F5 BIG-IP ASM": ("big-ip", "x-waf-status", "ts01", "f5"),
    "ModSecurity": ("mod_security", "modsecurity", "not acceptable"),
}
BLOCKED_STATUS_CODES = {403, 406, 409, 429, 503}
BLOCK_MARKERS = (
    "access denied",
    "request blocked",
    "blocked by",
    "web application firewall",
    "security policy",
    "not acceptable",
    "bot detection",
)


def _json_artifact(payload: dict[str, Any]) -> EvidenceArtifact:
    return EvidenceArtifact(
        name=WAF_DETECT_RESULTS_ARTIFACT_NAME,
        content_type="application/json",
        data=(json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8"),
        kind="runner-results",
    )


def _response_sample_from_response(
    target: str,
    response: httpx_client.Response,
) -> dict[str, Any]:
    body = response.text or ""
    return {
        "target": target,
        "status_code": response.status_code,
        "headers": {key.lower(): value for key, value in response.headers.items()},
        "body_excerpt": body[:4096],
        "body_sha256": sha256(body.encode("utf-8", errors="replace")).hexdigest(),
    }


def _normalize_response_sample(sample: dict[str, Any], fallback_target: str) -> dict[str, Any]:
    headers = sample.get("headers")
    normalized_headers = {
        str(key).strip().lower(): str(value).strip()
        for key, value in (headers.items() if isinstance(headers, dict) else [])
        if str(key).strip()
    }
    body_excerpt = str(
        sample.get("body_excerpt") or sample.get("body") or sample.get("text") or ""
    )[:4096]
    status_code = sample.get("status_code")
    try:
        normalized_status = int(status_code)
    except (TypeError, ValueError):
        normalized_status = 0
    target = str(sample.get("target") or fallback_target).strip() or fallback_target
    return {
        "target": target,
        "status_code": normalized_status,
        "headers": normalized_headers,
        "body_excerpt": body_excerpt,
        "body_sha256": sha256(body_excerpt.encode("utf-8", errors="replace")).hexdigest(),
    }


def _fingerprint_text(sample: dict[str, Any]) -> str:
    headers = sample.get("headers") if isinstance(sample.get("headers"), dict) else {}
    header_text = " ".join(f"{key}: {value}" for key, value in headers.items())
    return f"{sample.get('status_code')} {header_text} {sample.get('body_excerpt', '')}".lower()


def _detect_vendors(sample: dict[str, Any]) -> list[str]:
    text = _fingerprint_text(sample)
    vendors: list[str] = []
    for vendor, markers in WAF_SIGNATURES.items():
        if any(marker in text for marker in markers):
            vendors.append(vendor)
    return vendors


def _blocked_reason(sample: dict[str, Any]) -> str | None:
    text = _fingerprint_text(sample)
    status = int(sample.get("status_code") or 0)
    if status in BLOCKED_STATUS_CODES and any(marker in text for marker in BLOCK_MARKERS):
        return f"HTTP {status} with WAF/block marker"
    if any(marker in text for marker in ("cf-chl", "captcha", "attention required")):
        return "challenge or bot-detection marker"
    return None


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
                "waf_detection",
                "blocked_request_evidence",
                "defensive_review",
            ],
            "ptes_phase": "Intelligence Gathering",
            "nist_phase": "Discovery",
            "control_family": "configuration",
            "evidence": evidence,
            "replay_recipe": {
                "tool": TOOL_NAME,
                "mode": "defensive-detection",
                "automatic_evasion_enabled": False,
                "operator_approval_required_for_evasion": True,
            },
        }
    )


def _recommendations(vendors: list[str], blocked_targets: list[str]) -> list[dict[str, Any]]:
    recommendations: list[dict[str, Any]] = []
    if vendors:
        recommendations.append(
            {
                "title": "Coordinate active scan intensity with WAF owner",
                "reason": "WAF fingerprints were observed before active validation.",
                "operator_review_only": True,
                "runtime_change": False,
            }
        )
    if blocked_targets:
        recommendations.append(
            {
                "title": "Review blocked-request evidence before changing scan behavior",
                "reason": "At least one approved target returned blocked/challenge evidence.",
                "operator_review_only": True,
                "runtime_change": False,
            }
        )
    recommendations.append(
        {
            "title": "Keep evasion disabled unless explicitly approved in ROE",
            "reason": "Automatic evasion can change assessment risk and must remain an operator decision.",
            "operator_review_only": True,
            "runtime_change": False,
        }
    )
    return recommendations


def _assert_allowed(scope_allowlist: dict[str, Any] | None, target: str) -> None:
    if not web_target_value_is_allowed_with_path(scope_allowlist or {}, target):
        raise ValueError(f"target outside approved WAF detection scope: {target}")


def execute_waf_detection(
    targets: list[str],
    *,
    scope_allowlist: dict[str, Any] | None = None,
    response_samples: list[dict[str, Any]] | None = None,
    auto_evasion_enabled: bool = False,
    timeout_seconds: float = 5.0,
    client_factory: Callable[..., httpx_client.Client] = httpx_client.Client,
) -> RunnerExecution:
    if auto_evasion_enabled:
        raise ValueError("waf-detect never enables automatic evasion; operator review is required")

    normalized_targets = [normalize_http_target(target) for target in targets if str(target).strip()]
    if not normalized_targets and not response_samples:
        raise ValueError("waf-detect requires at least one approved target or imported response sample")
    for target in normalized_targets:
        _assert_allowed(scope_allowlist, target)

    samples: list[dict[str, Any]] = []
    source = "imported_response_samples"
    if response_samples:
        fallback = normalized_targets[0] if normalized_targets else "imported-response-sample"
        samples.extend(
            _normalize_response_sample(sample, fallback)
            for sample in response_samples
            if isinstance(sample, dict)
        )
    else:
        source = "approved_scope_http_probe"
        with client_factory(timeout=timeout_seconds, follow_redirects=False) as client:
            for target in normalized_targets:
                response = client.get(
                    target,
                    headers={"User-Agent": "AegisPT/waf-detect defensive fingerprint"},
                )
                samples.append(_response_sample_from_response(target, response))

    findings: list[dict[str, Any]] = []
    vendor_by_target: dict[str, list[str]] = {}
    blocked_targets: list[str] = []
    for sample in samples:
        target = str(sample.get("target") or "unknown")
        vendors = _detect_vendors(sample)
        blocked = _blocked_reason(sample)
        if vendors:
            vendor_by_target[target] = vendors
            _append_finding(
                findings,
                finding_type="waf_detected",
                title="Web Application Firewall Detected",
                severity="info",
                target=target,
                summary=f"WAF fingerprint evidence indicates {', '.join(vendors)}.",
                evidence={
                    "vendors": vendors,
                    "status_code": sample.get("status_code"),
                    "body_sha256": sample.get("body_sha256"),
                },
            )
        if blocked:
            blocked_targets.append(target)
            _append_finding(
                findings,
                finding_type="waf_blocked_request_evidence",
                title="WAF or Edge Control Blocked Request Evidence",
                severity="low",
                target=target,
                summary=f"Approved WAF detection evidence observed {blocked}.",
                evidence={
                    "blocked_reason": blocked,
                    "status_code": sample.get("status_code"),
                    "body_sha256": sample.get("body_sha256"),
                },
            )

    vendors = sorted({vendor for values in vendor_by_target.values() for vendor in values})
    payload = {
        "tool": TOOL_NAME,
        "mode": "defensive-detection",
        "targets": normalized_targets,
        "source": source,
        "summary": {
            "finding_count": len(findings),
            "sample_count": len(samples),
            "detected_vendor_count": len(vendors),
            "blocked_target_count": len(set(blocked_targets)),
        },
        "detected_vendors": vendors,
        "vendor_by_target": vendor_by_target,
        "blocked_targets": sorted(set(blocked_targets)),
        "samples": [
            {
                "target": sample.get("target"),
                "status_code": sample.get("status_code"),
                "headers_observed": sorted(
                    key
                    for key in (
                        sample.get("headers") if isinstance(sample.get("headers"), dict) else {}
                    ).keys()
                    if re.match(r"^[a-z0-9._-]+$", str(key))
                ),
                "body_sha256": sample.get("body_sha256"),
            }
            for sample in samples
        ],
        "findings": findings,
        "recommendations": _recommendations(vendors, sorted(set(blocked_targets))),
        "safety": {
            "defensive_detection_only": True,
            "automatic_evasion_enabled": False,
            "web_runner_mutation_performed": False,
            "operator_approval_required_for_evasion": True,
            "destructive_payloads_sent": False,
            "credential_materialization_performed": False,
            "scope_expansion_performed": False,
            "automatic_approval_created": False,
        },
        "provenance": {
            "source": source,
            "runner_digest": "workers.waf_detect.runner:v1",
        },
    }
    return RunnerExecution(
        tool=TOOL_NAME,
        exit_code=0,
        stdout=f"waf-detect complete: {len(findings)} finding(s), {len(vendors)} vendor(s)",
        stderr="",
        metadata={
            "mode": "defensive-detection",
            "automatic_evasion_enabled": False,
            "web_runner_mutation_performed": False,
            "finding_count": len(findings),
        },
        artifacts=[_json_artifact(payload)],
        protected_outputs=[],
    )
