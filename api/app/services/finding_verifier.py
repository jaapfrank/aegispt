"""Cross-runner verifier for critical/high findings (Mythos #335).

Before a critical or high finding is trusted, an independent check confirms
the impact claim. The check uses a DIFFERENT code path than the originating
runner (no self-verification) so a runner's own heuristic match cannot
become its own confirmation.

Design:

- :func:`verify_finding` picks a verification strategy based on the
  finding's category/title and runs ONE bounded HTTP request (5s timeout)
  through scope-allowlist enforcement. Returns a :class:`VerifierVerdict`
  describing the outcome.

- :func:`apply_verifier_verdict` persists the outcome:
    * On ``failed``: severity downgraded one notch (critical→high,
      high→medium) and the verdict stored in
      ``FindingAiEnrichment.metadata_json["verifier"]``.
    * On ``confirmed``: severity unchanged; verdict stored alongside.
    * On ``inconclusive`` (network error, no strategy applicable):
      severity unchanged; verdict stored so the operator can see the
      verifier couldn't reach a conclusion (not the same as confirmed).

- :func:`verify_pending_critical_findings` is the convenience entry point
  the picker / loop calls between advances: it queries critical+high
  findings for the run that don't yet have a verifier verdict and runs
  the verifier against each.

Constraints (per backlog-385 must_not_touch):
- No new Finding schema fields. Verdict lives in the existing
  ``FindingAiEnrichment.metadata_json["verifier"]`` sub-dict.
- Verifier MUST use a different code path than the originating runner.
  Implemented via a strategy dispatcher that NEVER imports any runner
  module — it uses raw httpx + scope check directly.
- Bounded: 1 HTTP request, 5s timeout per verification. No loops.
- Verifier only runs on critical and high. Medium/low/info are skipped
  for cost control.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

import httpx as httpx_client
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app.models import EvidenceObservation, Finding, FindingAiEnrichment, Run, Scope
from api.app.services.runs import web_target_value_is_allowed_with_path

logger = logging.getLogger(__name__)

VERIFIER_TIMEOUT_SECONDS = 5.0
VERIFIER_PROVIDER_TAG = "cross-runner-verifier-v1"
VERIFIABLE_SEVERITIES: frozenset[str] = frozenset({"critical", "high"})

# Severity downgrade ladder applied on `failed` verdict.
# Each level drops one notch. Anything not in the ladder keeps its current
# severity (defensive — should never reach the verifier).
_SEVERITY_DOWNGRADE: dict[str, str] = {
    "critical": "high",
    "high": "medium",
}

# Admin-context keywords used by the admin-access verification strategy.
# Intentionally generic (no Gruyere seeds per feedback_no_prescriptive_recipes).
_ADMIN_CONTEXT_KEYWORDS: tuple[str, ...] = (
    "manage this server",
    "administrator panel",
    "admin-only",
    "all users",
    "delete user",
    "manage users",
    "user list",
    "control panel",
)


@dataclass(frozen=True)
class VerifierVerdict:
    """Outcome of a verifier check against a single Finding."""

    verdict: str  # "confirmed" | "failed" | "inconclusive"
    note: str
    original_severity: str
    new_severity: str
    verifier_used: str  # name of the strategy that ran
    checked_url: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_metadata(self) -> dict[str, Any]:
        """Serialize for FindingAiEnrichment.metadata_json['verifier']."""
        return {
            "verdict": self.verdict,
            "note": self.note,
            "original_severity": self.original_severity,
            "new_severity": self.new_severity,
            "verifier_used": self.verifier_used,
            "checked_url": self.checked_url,
            "evidence": dict(self.evidence),
            "timestamp": self.timestamp,
        }


def _make_inconclusive(
    finding: Finding,
    *,
    note: str,
    verifier_used: str = "n/a",
    checked_url: str | None = None,
) -> VerifierVerdict:
    sev = str(finding.severity or "")
    return VerifierVerdict(
        verdict="inconclusive",
        note=note,
        original_severity=sev,
        new_severity=sev,
        verifier_used=verifier_used,
        checked_url=checked_url,
    )


def _scope_for_run(run: Run, *, scope: Scope | None) -> dict[str, Any] | None:
    """Build the scope_allowlist dict shape that
    web_target_value_is_allowed_with_path expects."""
    if scope is not None and getattr(scope, "scope_definition_json", None):
        defn = scope.scope_definition_json
        if isinstance(defn, dict):
            return defn
    if run.engagement is not None:
        engagement_scope = getattr(run.engagement, "scope_definition_json", None)
        if isinstance(engagement_scope, dict):
            return engagement_scope
    return None


def _latest_session_cookie(session: Session, run: Run) -> tuple[str, str] | None:
    """Pull the most recent ``captured_value`` of kind ``cookie`` from the
    evidence graph (#334). Returns (cookie_name, last_4_chars_hint) or
    None. Used by the admin-access verification strategy as a sanity check
    that a session existed at all.

    Note: only the redacted preview is exposed via the graph entity; the
    full cookie value lives in run_credential_vault. The verifier does NOT
    use the full cookie value (no privilege escalation by verifier); it
    uses scope-checked GETs to verify admin keyword presence under whatever
    session the operator's run already established. For unit tests with
    mock httpx this distinction is moot; for live runs the operator-level
    session header injection happens elsewhere.
    """
    stmt = (
        select(EvidenceObservation)
        .where(EvidenceObservation.run_id == run.id)
        .where(EvidenceObservation.entity_type == "captured_value")
        .where(EvidenceObservation.entity_subtype == "cookie")
        .order_by(EvidenceObservation.created_at.desc())
        .limit(1)
    )
    row = session.scalars(stmt).first()
    if row is None:
        return None
    attrs = row.attributes_json if isinstance(row.attributes_json, dict) else {}
    var_name = str((attrs or {}).get("var_name") or "")
    preview = str((attrs or {}).get("redacted_preview") or "")
    return (var_name, preview) if var_name else None


# ---------------------------------------------------------------------------
# Verification strategies
# ---------------------------------------------------------------------------


def _verify_admin_access(
    finding: Finding,
    *,
    http_client: httpx_client.Client,
    scope_allowlist: dict[str, Any] | None,
    timeout: float,
) -> VerifierVerdict:
    """Verifies a 'broken-access-control' / 'admin-compromise' claim.

    Strategy: GET the finding's target URL anonymously (no auth header).
    If the response is 200 AND contains an admin-context keyword, the
    claim is CONFIRMED — the page is admin-equivalent and reachable
    without credentials, which is the impact. If the response is 401/403
    or contains no admin keyword, the claim FAILED — the admin page
    properly blocks anonymous access. Network/scope errors → inconclusive.
    """
    target_url = str(finding.target_id or "").strip()
    sev = str(finding.severity or "")
    if not target_url or not target_url.startswith(("http://", "https://")):
        return _make_inconclusive(
            finding,
            note=f"target_id is not an HTTP URL: {target_url!r}",
            verifier_used="admin_access",
        )
    if scope_allowlist and not web_target_value_is_allowed_with_path(scope_allowlist, target_url):
        return _make_inconclusive(
            finding,
            note="target URL out of scope for verifier",
            verifier_used="admin_access",
            checked_url=target_url,
        )
    try:
        response = http_client.get(target_url, follow_redirects=False, timeout=timeout)
    except httpx_client.HTTPError as exc:
        return _make_inconclusive(
            finding,
            note=f"HTTP error during verification: {type(exc).__name__}: {str(exc)[:120]}",
            verifier_used="admin_access",
            checked_url=target_url,
        )
    status_code = int(response.status_code)
    body_lower = (response.text or "")[:8192].lower()
    has_admin_keyword = any(kw in body_lower for kw in _ADMIN_CONTEXT_KEYWORDS)
    evidence = {
        "status_code": status_code,
        "body_excerpt": (response.text or "")[:300],
        "admin_keyword_present": has_admin_keyword,
    }
    if status_code == 200 and has_admin_keyword:
        return VerifierVerdict(
            verdict="confirmed",
            note="admin-context keyword present in anonymous GET of target",
            original_severity=sev,
            new_severity=sev,
            verifier_used="admin_access",
            checked_url=target_url,
            evidence=evidence,
        )
    return VerifierVerdict(
        verdict="failed",
        note=(
            f"anonymous GET returned status={status_code} "
            f"admin_keyword_present={has_admin_keyword}; "
            "claim of admin compromise not independently confirmed"
        ),
        original_severity=sev,
        new_severity=_SEVERITY_DOWNGRADE.get(sev, sev),
        verifier_used="admin_access",
        checked_url=target_url,
        evidence=evidence,
    )


def _verify_stored_xss(
    finding: Finding,
    *,
    http_client: httpx_client.Client,
    scope_allowlist: dict[str, Any] | None,
    timeout: float,
) -> VerifierVerdict:
    """Verifies a 'Stored XSS Confirmed' claim by re-fetching the render
    endpoint and asserting the payload marker still appears verbatim.

    The marker is recovered from the finding's evidence (replay_recipe_json
    or summary contains it). If the marker is not extractable, the
    verification falls back to inconclusive — there's no independent
    artifact to look for.
    """
    target_url = str(finding.target_id or "").strip()
    sev = str(finding.severity or "")
    if not target_url or not target_url.startswith(("http://", "https://")):
        return _make_inconclusive(
            finding, note=f"target_id is not an HTTP URL: {target_url!r}",
            verifier_used="stored_xss",
        )
    # The exec_plan / stored_xss_probe payloads use a marker like
    # "AEGISXSS_<10 uppercase+digits>"; extract it from the summary if
    # present.
    marker_match = re.search(r"(AEGISXSS_[A-Z0-9]{6,})", str(finding.summary or ""))
    if not marker_match:
        # Fall back: try the replay_recipe_json payload field if available.
        recipe = finding.replay_recipe_json if isinstance(finding.replay_recipe_json, dict) else {}
        for value in recipe.values():
            if isinstance(value, str):
                m = re.search(r"(AEGISXSS_[A-Z0-9]{6,})", value)
                if m:
                    marker_match = m
                    break
    if not marker_match:
        return _make_inconclusive(
            finding,
            note="stored-xss marker not extractable from finding evidence; cannot independently verify",
            verifier_used="stored_xss",
            checked_url=target_url,
        )
    marker = marker_match.group(1)
    if scope_allowlist and not web_target_value_is_allowed_with_path(scope_allowlist, target_url):
        return _make_inconclusive(
            finding, note="target URL out of scope", verifier_used="stored_xss",
            checked_url=target_url,
        )
    try:
        response = http_client.get(target_url, follow_redirects=False, timeout=timeout)
    except httpx_client.HTTPError as exc:
        return _make_inconclusive(
            finding,
            note=f"HTTP error during verification: {type(exc).__name__}: {str(exc)[:120]}",
            verifier_used="stored_xss",
            checked_url=target_url,
        )
    body = (response.text or "")[:32_768]
    marker_present = marker in body
    evidence = {
        "status_code": int(response.status_code),
        "marker_searched": marker,
        "marker_present": marker_present,
    }
    if marker_present:
        return VerifierVerdict(
            verdict="confirmed",
            note=f"stored-xss marker {marker} still reflected on re-fetch",
            original_severity=sev,
            new_severity=sev,
            verifier_used="stored_xss",
            checked_url=target_url,
            evidence=evidence,
        )
    return VerifierVerdict(
        verdict="failed",
        note=f"marker {marker} not found on independent re-fetch; payload may not have persisted",
        original_severity=sev,
        new_severity=_SEVERITY_DOWNGRADE.get(sev, sev),
        verifier_used="stored_xss",
        checked_url=target_url,
        evidence=evidence,
    )


def _verify_info_disclosure(
    finding: Finding,
    *,
    http_client: httpx_client.Client,
    scope_allowlist: dict[str, Any] | None,
    timeout: float,
) -> VerifierVerdict:
    """Verifies an 'info-disclosure' claim by re-fetching the leaky URL
    and asserting the leak pattern still matches."""
    target_url = str(finding.target_id or "").strip()
    sev = str(finding.severity or "")
    if not target_url or not target_url.startswith(("http://", "https://")):
        return _make_inconclusive(
            finding, note=f"target_id is not an HTTP URL: {target_url!r}",
            verifier_used="info_disclosure",
        )
    if scope_allowlist and not web_target_value_is_allowed_with_path(scope_allowlist, target_url):
        return _make_inconclusive(
            finding, note="target URL out of scope",
            verifier_used="info_disclosure",
            checked_url=target_url,
        )
    try:
        response = http_client.get(target_url, follow_redirects=False, timeout=timeout)
    except httpx_client.HTTPError as exc:
        return _make_inconclusive(
            finding,
            note=f"HTTP error during verification: {type(exc).__name__}: {str(exc)[:120]}",
            verifier_used="info_disclosure",
            checked_url=target_url,
        )
    # Re-run a tight subset of the leak-pattern catalogue. Re-using the
    # info_disclosure_probe regex catalogue would be tighter coupling than
    # we want for verifier independence — instead, use a small generic set
    # that proves SOMETHING sensitive is exposed.
    body = (response.text or "")[:32_768]
    body_lower = body.lower()
    indicators = {
        # Handles both `password=secret` and `'password': 'secret'` / `"password": "secret"` patterns.
        "password_keyword": bool(re.search(r"(?i)['\"]?password['\"]?\s*[:=]\s*['\"]?[^\s'\"<>]{3,}", body)),
        "private_key_block": "-----begin" in body_lower and "private key" in body_lower,
        "etc_passwd": bool(re.search(r"^root:[^:]*:[0-9]+:[0-9]+", body, re.MULTILINE)),
        "phpinfo_marker": "<h1>php version" in body_lower,
    }
    leak_seen = any(indicators.values())
    evidence = {
        "status_code": int(response.status_code),
        "indicators": indicators,
        "body_excerpt": body[:300],
    }
    if int(response.status_code) == 200 and leak_seen:
        return VerifierVerdict(
            verdict="confirmed",
            note="leak-pattern indicator(s) present on re-fetch",
            original_severity=sev,
            new_severity=sev,
            verifier_used="info_disclosure",
            checked_url=target_url,
            evidence=evidence,
        )
    return VerifierVerdict(
        verdict="failed",
        note=(
            f"re-fetch returned status={response.status_code} no leak indicators; "
            "original claim not independently confirmed"
        ),
        original_severity=sev,
        new_severity=_SEVERITY_DOWNGRADE.get(sev, sev),
        verifier_used="info_disclosure",
        checked_url=target_url,
        evidence=evidence,
    )


_VerifierFn = Callable[
    [Finding],  # finding
    VerifierVerdict,
]


def _select_strategy(finding: Finding) -> str:
    """Pick a verification strategy name based on the finding's category
    and title keywords. Returns one of:
    'admin_access' | 'stored_xss' | 'info_disclosure' | 'none'.

    The picker is heuristic + emergent (no app-specific seeds). 'none' →
    verifier emits inconclusive (no independent check available)."""
    title_lower = str(finding.title or "").lower()
    methodology = " ".join(str(t).lower() for t in (finding.methodology_tags or []))
    if (
        "mass assignment" in title_lower
        or "privilege" in title_lower
        or "identity forgery" in title_lower
        or "broken-access-control" in methodology
        or "broken_access" in methodology
    ):
        return "admin_access"
    if "stored xss" in title_lower or "stored-xss" in methodology:
        return "stored_xss"
    if (
        "info disclosure" in title_lower
        or "info-disclosure" in methodology
        or "password_leak" in title_lower
        or "leak" in title_lower
    ):
        return "info_disclosure"
    return "none"


def verify_finding(
    finding: Finding,
    run: Run,
    scope: Scope | None,
    *,
    http_client: httpx_client.Client | None = None,
    timeout: float = VERIFIER_TIMEOUT_SECONDS,
    session: Session | None = None,
) -> VerifierVerdict:
    """Verify a critical/high finding via an independent HTTP check.

    Returns a :class:`VerifierVerdict`. For severities below high, returns
    an inconclusive verdict noting that verification was skipped (per
    no_block_low_severity constraint).

    Pass ``http_client`` for tests (httpx.MockTransport). On None, the
    verifier creates a transient client.
    """
    # Deterministic flag-literal proof is self-verifying: the captured flag is
    # grader-matchable and IS the independent confirmation, so it must NOT fall
    # through to the "no strategy -> inconclusive" path (which a re-prober uses
    # for HTTP claims it cannot reproduce — meaningless for a flag we already
    # hold). Same bounded class as the M2-gate DETERMINISTIC_PROOF exemption.
    # Without this, a real solved flag finding shows as inconclusive ->
    # "awaiting verification / blocked" in the run-truth UI.
    from api.app.services.m2_verdict_gate import is_deterministic_flag_proof
    if is_deterministic_flag_proof(finding):
        _sev = str(finding.severity or "")
        return VerifierVerdict(
            verdict="confirmed",
            note="deterministic flag-literal proof (grader-matchable) — verified by the captured flag itself",
            original_severity=_sev,
            new_severity=_sev,
            verifier_used="deterministic_flag_proof",
        )
    sev = str(finding.severity or "").lower()
    if sev not in VERIFIABLE_SEVERITIES:
        return _make_inconclusive(
            finding,
            note=f"severity={sev!r} below threshold (only critical/high are verified)",
            verifier_used="skipped",
        )

    strategy = _select_strategy(finding)
    if strategy == "none":
        # session arg is currently unused for the no-strategy path but is
        # kept on the signature so callers (and tests) can pass it
        # uniformly across strategy selections.
        _ = session
        return _make_inconclusive(
            finding,
            note=f"no verification strategy available for title={finding.title!r}",
            verifier_used="none",
        )

    scope_allowlist = _scope_for_run(run, scope=scope)
    owns_client = False
    client = http_client
    if client is None:
        client = httpx_client.Client(timeout=timeout, follow_redirects=False, verify=True)
        owns_client = True
    try:
        if strategy == "admin_access":
            return _verify_admin_access(
                finding, http_client=client, scope_allowlist=scope_allowlist, timeout=timeout,
            )
        if strategy == "stored_xss":
            return _verify_stored_xss(
                finding, http_client=client, scope_allowlist=scope_allowlist, timeout=timeout,
            )
        if strategy == "info_disclosure":
            return _verify_info_disclosure(
                finding, http_client=client, scope_allowlist=scope_allowlist, timeout=timeout,
            )
        return _make_inconclusive(
            finding, note=f"unknown strategy {strategy!r}", verifier_used=strategy,
        )
    finally:
        if owns_client:
            try:
                client.close()
            except Exception:  # pragma: no cover — defensive
                pass


def apply_verifier_verdict(
    session: Session,
    *,
    finding: Finding,
    verdict: VerifierVerdict,
) -> None:
    """Persist a verifier verdict against a Finding.

    Mechanics:
    - On 'failed': updates ``finding.severity`` to the downgraded value.
    - Always: stores the verdict dict in
      ``finding.ai_enrichment.metadata_json['verifier']``, creating a
      FindingAiEnrichment row if none exists (with provider=
      VERIFIER_PROVIDER_TAG and status='succeeded').

    Idempotent: re-applying the same verdict overwrites the
    ``['verifier']`` sub-dict but does not re-downgrade severity
    (severity is updated only when the verdict says ``failed`` AND the
    current severity matches the verdict's ``original_severity`` — guards
    against double-downgrade if called twice).
    """
    enrichment = finding.ai_enrichment
    if enrichment is None:
        enrichment = FindingAiEnrichment(
            finding_id=finding.id,
            status="succeeded",
            provider=VERIFIER_PROVIDER_TAG,
        )
        session.add(enrichment)
        finding.ai_enrichment = enrichment

    md = dict(enrichment.metadata_json or {})
    md["verifier"] = verdict.to_metadata()
    enrichment.metadata_json = md

    if verdict.verdict == "failed":
        # Only downgrade if the current severity matches what the verdict
        # was computed against (defensive — don't double-downgrade).
        if str(finding.severity or "") == verdict.original_severity:
            finding.severity = verdict.new_severity

    logger.info(
        "finding_verifier: applied verdict=%s for finding=%s severity %s -> %s (strategy=%s)",
        verdict.verdict,
        str(finding.id)[:8],
        verdict.original_severity,
        finding.severity,
        verdict.verifier_used,
    )


def verify_pending_critical_findings(
    session: Session,
    *,
    run: Run,
    scope: Scope | None,
    http_client: httpx_client.Client | None = None,
    limit: int = 10,
) -> list[VerifierVerdict]:
    """Find critical/high findings for ``run`` that don't yet have a
    verifier verdict and verify each. Returns the list of verdicts
    produced.

    Bounded by ``limit`` (default 10) to keep verifier cost per advance
    predictable. Findings already-verified (have
    ``ai_enrichment.metadata_json['verifier']``) are skipped.
    """
    if run is None:
        return []
    verdicts: list[VerifierVerdict] = []
    # Pull candidates: critical + high, scoped to this run.
    stmt = (
        select(Finding)
        .where(Finding.run_id == run.id)
        .where(Finding.severity.in_(list(VERIFIABLE_SEVERITIES)))
        .order_by(Finding.created_at.desc())
        .limit(max(1, limit * 4))  # over-fetch to skip already-verified
    )
    findings = list(session.scalars(stmt))
    for finding in findings:
        existing = finding.ai_enrichment.metadata_json if finding.ai_enrichment else None
        if isinstance(existing, dict) and "verifier" in existing:
            continue
        verdict = verify_finding(
            finding, run, scope,
            http_client=http_client,
            session=session,
        )
        apply_verifier_verdict(session, finding=finding, verdict=verdict)
        verdicts.append(verdict)
        if len(verdicts) >= limit:
            break
    if verdicts:
        session.flush()
    return verdicts


__all__ = [
    "VERIFIABLE_SEVERITIES",
    "VERIFIER_PROVIDER_TAG",
    "VERIFIER_TIMEOUT_SECONDS",
    "VerifierVerdict",
    "apply_verifier_verdict",
    "verify_finding",
    "verify_pending_critical_findings",
]
