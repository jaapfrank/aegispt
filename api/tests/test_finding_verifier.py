"""Tests for finding_verifier service (Mythos #335)."""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from sqlalchemy import select

from api.app.models import (
    Engagement,
    Finding,
    FindingAiEnrichment,
    Run,
    RunProfile,
    Scope,
)
from api.app.services.finding_verifier import (
    VERIFIABLE_SEVERITIES,
    VERIFIER_PROVIDER_TAG,
    VerifierVerdict,
    _select_strategy,
    apply_verifier_verdict,
    verify_finding,
    verify_pending_critical_findings,
)


def _ensure_profiles(client) -> None:
    response = client.get("/api/v1/run-profiles")
    assert response.status_code == 200


def _make_run(session, *, scope_urls: list[str] | None = None) -> tuple[Run, Scope]:
    profile = session.scalar(select(RunProfile).where(RunProfile.name == "autonomous-web"))
    assert profile is not None
    engagement = Engagement(
        name="Verifier Test",
        client="Acme",
        roe_ref="ROE-VERIFY-2026",
        status="active",
    )
    scope = Scope(
        engagement=engagement,
        allowlist_json={"urls": scope_urls or ["http://target.test"]},
        denylist_json={},
    )
    run = Run(
        engagement=engagement,
        profile=profile,
        status="running",
        configuration_json={"targets": {"urls": scope_urls or ["http://target.test"]}},
        requested_by="verifier-test",
        autonomous_mode=True,
        autonomous_intrusive_allowed=False,
    )
    session.add(engagement)
    session.add(run)
    session.flush()
    return run, scope


def _make_finding(
    session,
    run: Run,
    *,
    title: str,
    severity: str,
    target_id: str = "http://target.test/manage",
    summary: str | None = None,
    methodology_tags: list[str] | None = None,
    replay_recipe_json: dict | None = None,
) -> Finding:
    f = Finding(
        run_id=run.id,
        title=title,
        severity=severity,
        target_id=target_id,
        evidence_ref="memory://test",
        finding_origin="standard",
        summary=summary,
        methodology_tags=methodology_tags or [],
        replay_recipe_json=replay_recipe_json,
        status="open",
    )
    session.add(f)
    session.flush()
    return f


def _client_factory(handler):
    def factory(*args, **kwargs):
        kwargs.pop("transport", None)
        return httpx.Client(transport=httpx.MockTransport(handler), *args, **kwargs)

    return factory


# ---------------------------------------------------------------------------
# _select_strategy (pure)
# ---------------------------------------------------------------------------


def test_select_strategy_admin_access_from_title() -> None:
    f = Finding(title="Privilege Escalation via Mass Assignment at Registration", severity="critical",
                target_id="http://x/", evidence_ref="x")
    assert _select_strategy(f) == "admin_access"


def test_select_strategy_admin_access_from_methodology_tag() -> None:
    f = Finding(title="Account Takeover", severity="critical", target_id="http://x/",
                evidence_ref="x", methodology_tags=["broken-access-control", "exec_plan"])
    assert _select_strategy(f) == "admin_access"


def test_select_strategy_identity_forgery() -> None:
    f = Finding(title="Identity Forgery via Pipe-Delimiter Injection in Username",
                severity="critical", target_id="http://x/", evidence_ref="x")
    assert _select_strategy(f) == "admin_access"


def test_select_strategy_stored_xss() -> None:
    f = Finding(title="Stored XSS Confirmed — script_tag via snippet",
                severity="critical", target_id="http://x/", evidence_ref="x")
    assert _select_strategy(f) == "stored_xss"


def test_select_strategy_info_disclosure() -> None:
    f = Finding(title="Info Disclosure — debug-dump — password_leak",
                severity="critical", target_id="http://x/", evidence_ref="x")
    assert _select_strategy(f) == "info_disclosure"


def test_select_strategy_unknown_returns_none() -> None:
    f = Finding(title="Some random finding nobody knows about",
                severity="critical", target_id="http://x/", evidence_ref="x")
    assert _select_strategy(f) == "none"


# ---------------------------------------------------------------------------
# verify_finding — severity gating
# ---------------------------------------------------------------------------


def test_verify_finding_skips_low_severity() -> None:
    f = Finding(title="Stored XSS Confirmed", severity="low",
                target_id="http://target.test/p", evidence_ref="x")
    run = Run(status="running")
    verdict = verify_finding(f, run, scope=None, http_client=None)
    assert verdict.verdict == "inconclusive"
    assert "below threshold" in verdict.note
    assert verdict.verifier_used == "skipped"


def test_verify_finding_skips_medium_severity() -> None:
    f = Finding(title="Stored XSS Confirmed", severity="medium",
                target_id="http://target.test/p", evidence_ref="x")
    run = Run(status="running")
    verdict = verify_finding(f, run, scope=None)
    assert verdict.verdict == "inconclusive"


def test_verifiable_severities_constant_is_critical_and_high() -> None:
    assert VERIFIABLE_SEVERITIES == frozenset({"critical", "high"})


# ---------------------------------------------------------------------------
# admin_access strategy
# ---------------------------------------------------------------------------


def test_verify_admin_access_confirms_when_keyword_present() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        return httpx.Response(200, text="<html>Manage this server: admin panel here</html>")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    try:
        f = Finding(title="Mass Assignment privilege escalation",
                    severity="critical", target_id="http://target.test/manage",
                    evidence_ref="x", methodology_tags=["broken-access-control"])
        run = Run(status="running")
        verdict = verify_finding(f, run, scope=None, http_client=client)
    finally:
        client.close()

    assert verdict.verdict == "confirmed"
    assert verdict.original_severity == "critical"
    assert verdict.new_severity == "critical"
    assert verdict.verifier_used == "admin_access"
    assert verdict.evidence["admin_keyword_present"] is True


def test_verify_admin_access_fails_and_downgrades_when_no_keyword() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html>Login required</html>")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    try:
        f = Finding(title="Mass Assignment privilege escalation",
                    severity="critical", target_id="http://target.test/manage",
                    evidence_ref="x", methodology_tags=["broken-access-control"])
        run = Run(status="running")
        verdict = verify_finding(f, run, scope=None, http_client=client)
    finally:
        client.close()

    assert verdict.verdict == "failed"
    assert verdict.original_severity == "critical"
    assert verdict.new_severity == "high"  # one notch down
    assert verdict.evidence["admin_keyword_present"] is False


def test_verify_admin_access_high_downgrades_to_medium() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, text="forbidden")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    try:
        f = Finding(title="Privilege Escalation", severity="high",
                    target_id="http://target.test/manage", evidence_ref="x",
                    methodology_tags=["broken-access-control"])
        verdict = verify_finding(f, Run(status="running"), scope=None, http_client=client)
    finally:
        client.close()
    assert verdict.verdict == "failed"
    assert verdict.new_severity == "medium"


def test_verify_admin_access_inconclusive_on_network_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("simulated")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    try:
        f = Finding(title="Mass Assignment", severity="critical",
                    target_id="http://target.test/manage", evidence_ref="x",
                    methodology_tags=["broken-access-control"])
        verdict = verify_finding(f, Run(status="running"), scope=None, http_client=client)
    finally:
        client.close()
    assert verdict.verdict == "inconclusive"
    assert verdict.original_severity == verdict.new_severity == "critical"
    assert "ConnectError" in verdict.note


def test_verify_admin_access_inconclusive_on_non_http_target() -> None:
    f = Finding(title="Mass Assignment", severity="critical",
                target_id="not-a-url", evidence_ref="x",
                methodology_tags=["broken-access-control"])
    verdict = verify_finding(f, Run(status="running"), scope=None)
    assert verdict.verdict == "inconclusive"
    assert "not an HTTP URL" in verdict.note


# ---------------------------------------------------------------------------
# stored_xss strategy
# ---------------------------------------------------------------------------


def test_verify_stored_xss_confirms_when_marker_reflected() -> None:
    marker = "AEGISXSS_ABCDEFGHIJ"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=f"<html>...<script>x={marker};</script>...</html>")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    try:
        f = Finding(
            title="Stored XSS Confirmed",
            severity="critical",
            target_id="http://target.test/snippets",
            evidence_ref="x",
            summary=f"payload reflected with marker {marker} on render endpoint",
        )
        verdict = verify_finding(f, Run(status="running"), scope=None, http_client=client)
    finally:
        client.close()
    assert verdict.verdict == "confirmed"
    assert verdict.evidence["marker_present"] is True
    assert verdict.new_severity == "critical"


def test_verify_stored_xss_fails_when_marker_absent() -> None:
    marker = "AEGISXSS_ABCDEFGHIJ"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html>nothing to see here</html>")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    try:
        f = Finding(
            title="Stored XSS Confirmed",
            severity="critical",
            target_id="http://target.test/snippets",
            evidence_ref="x",
            summary=f"payload reflected with marker {marker}",
        )
        verdict = verify_finding(f, Run(status="running"), scope=None, http_client=client)
    finally:
        client.close()
    assert verdict.verdict == "failed"
    assert verdict.new_severity == "high"


def test_verify_stored_xss_inconclusive_when_no_marker_extractable() -> None:
    f = Finding(title="Stored XSS Confirmed",
                severity="critical", target_id="http://target.test/snippets",
                evidence_ref="x", summary="no AEGIS marker here")
    verdict = verify_finding(f, Run(status="running"), scope=None)
    assert verdict.verdict == "inconclusive"
    assert "not extractable" in verdict.note


# ---------------------------------------------------------------------------
# info_disclosure strategy
# ---------------------------------------------------------------------------


def test_verify_info_disclosure_confirms_when_leak_pattern_present() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            text="{'user': 'alice', 'password': 'secret123', 'admin': true}",
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    try:
        f = Finding(title="Info Disclosure — debug-dump — password_leak",
                    severity="critical", target_id="http://target.test/dump",
                    evidence_ref="x")
        verdict = verify_finding(f, Run(status="running"), scope=None, http_client=client)
    finally:
        client.close()
    assert verdict.verdict == "confirmed"
    assert verdict.evidence["indicators"]["password_keyword"] is True


def test_verify_info_disclosure_fails_when_clean_body() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="Hello world")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    try:
        f = Finding(title="Info Disclosure — password_leak", severity="critical",
                    target_id="http://target.test/dump", evidence_ref="x")
        verdict = verify_finding(f, Run(status="running"), scope=None, http_client=client)
    finally:
        client.close()
    assert verdict.verdict == "failed"
    assert verdict.new_severity == "high"


# ---------------------------------------------------------------------------
# Strategy = none → inconclusive
# ---------------------------------------------------------------------------


def test_verify_unknown_finding_kind_inconclusive() -> None:
    f = Finding(title="Generic Mystery Issue", severity="critical",
                target_id="http://target.test/", evidence_ref="x")
    verdict = verify_finding(f, Run(status="running"), scope=None)
    assert verdict.verdict == "inconclusive"
    assert verdict.verifier_used == "none"
    assert verdict.new_severity == verdict.original_severity


# ---------------------------------------------------------------------------
# apply_verifier_verdict — DB integration
# ---------------------------------------------------------------------------


def test_apply_verdict_creates_enrichment_and_stores_verifier(client) -> None:
    _ensure_profiles(client)
    with client.app.state.session_factory() as session:
        run, _scope = _make_run(session)
        f = _make_finding(session, run, title="Stored XSS Confirmed", severity="critical")
        assert f.ai_enrichment is None  # nothing yet

        verdict = VerifierVerdict(
            verdict="confirmed",
            note="test",
            original_severity="critical",
            new_severity="critical",
            verifier_used="stored_xss",
            checked_url="http://target.test/p",
            evidence={"marker_present": True},
        )
        apply_verifier_verdict(session, finding=f, verdict=verdict)
        session.flush()

        assert f.ai_enrichment is not None
        assert f.ai_enrichment.provider == VERIFIER_PROVIDER_TAG
        stored = f.ai_enrichment.metadata_json["verifier"]
        assert stored["verdict"] == "confirmed"
        assert stored["verifier_used"] == "stored_xss"
        assert stored["evidence"]["marker_present"] is True
        # No downgrade on confirmed.
        assert f.severity == "critical"


def test_apply_verdict_downgrades_severity_on_failed(client) -> None:
    _ensure_profiles(client)
    with client.app.state.session_factory() as session:
        run, _scope = _make_run(session)
        f = _make_finding(session, run, title="Privilege Escalation", severity="critical")
        verdict = VerifierVerdict(
            verdict="failed",
            note="no admin keyword",
            original_severity="critical",
            new_severity="high",
            verifier_used="admin_access",
        )
        apply_verifier_verdict(session, finding=f, verdict=verdict)
        session.flush()
        assert f.severity == "high"
        assert f.ai_enrichment.metadata_json["verifier"]["verdict"] == "failed"


def test_apply_verdict_is_idempotent_no_double_downgrade(client) -> None:
    """Re-applying a failed verdict should NOT downgrade twice (high → low)."""
    _ensure_profiles(client)
    with client.app.state.session_factory() as session:
        run, _scope = _make_run(session)
        f = _make_finding(session, run, title="Privilege Escalation", severity="critical")
        verdict = VerifierVerdict(
            verdict="failed",
            note="x",
            original_severity="critical",
            new_severity="high",
            verifier_used="admin_access",
        )
        apply_verifier_verdict(session, finding=f, verdict=verdict)
        # After first apply: severity = high.
        assert f.severity == "high"
        apply_verifier_verdict(session, finding=f, verdict=verdict)
        # Second apply: still high, NOT downgraded again because
        # current severity ('high') no longer matches verdict.original_severity ('critical').
        assert f.severity == "high"


def test_apply_verdict_preserves_other_enrichment_metadata(client) -> None:
    _ensure_profiles(client)
    with client.app.state.session_factory() as session:
        run, _scope = _make_run(session)
        f = _make_finding(session, run, title="Stored XSS Confirmed", severity="critical")
        # Pre-existing enrichment with other metadata.
        existing = FindingAiEnrichment(
            finding_id=f.id,
            status="succeeded",
            provider="prior-enrichment",
            metadata_json={"prior_key": "prior_value"},
        )
        session.add(existing)
        session.flush()
        f.ai_enrichment = existing

        verdict = VerifierVerdict(
            verdict="confirmed",
            note="ok",
            original_severity="critical",
            new_severity="critical",
            verifier_used="stored_xss",
        )
        apply_verifier_verdict(session, finding=f, verdict=verdict)
        session.flush()
        assert f.ai_enrichment.metadata_json["prior_key"] == "prior_value"
        assert f.ai_enrichment.metadata_json["verifier"]["verdict"] == "confirmed"


# ---------------------------------------------------------------------------
# verify_pending_critical_findings — end-to-end DB
# ---------------------------------------------------------------------------


def test_verify_pending_critical_findings_skips_already_verified(client) -> None:
    _ensure_profiles(client)
    with client.app.state.session_factory() as session:
        run, _scope = _make_run(session)
        f1 = _make_finding(session, run, title="Stored XSS Confirmed", severity="critical",
                           summary="marker AEGISXSS_AAAA111111")
        # Pre-mark f1 with a verifier verdict so it should be skipped.
        already = VerifierVerdict(
            verdict="confirmed", note="x", original_severity="critical",
            new_severity="critical", verifier_used="prior",
        )
        apply_verifier_verdict(session, finding=f1, verdict=already)
        session.flush()

        # New unverified critical finding.
        _make_finding(session, run, title="Mass Assignment Privilege Escalation",
                      severity="critical",
                      target_id="http://target.test/manage",
                      methodology_tags=["broken-access-control"])

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text="<html>admin-only panel here</html>")

        client_http = httpx.Client(transport=httpx.MockTransport(handler))
        try:
            verdicts = verify_pending_critical_findings(
                session, run=run, scope=None, http_client=client_http,
            )
        finally:
            client_http.close()
        # Only the unverified one was processed.
        assert len(verdicts) == 1
        assert verdicts[0].verifier_used == "admin_access"
        assert verdicts[0].verdict == "confirmed"


def test_verify_pending_critical_findings_ignores_low_severity(client) -> None:
    _ensure_profiles(client)
    with client.app.state.session_factory() as session:
        run, _scope = _make_run(session)
        _make_finding(session, run, title="Low severity issue", severity="low",
                      target_id="http://target.test/p")
        _make_finding(session, run, title="Info Disclosure password_leak", severity="info",
                      target_id="http://target.test/dump")
        verdicts = verify_pending_critical_findings(session, run=run, scope=None)
        assert verdicts == []


def test_verify_pending_critical_findings_respects_limit(client) -> None:
    """If more than `limit` critical findings exist, only `limit` are
    processed in one call (cost control)."""
    _ensure_profiles(client)
    with client.app.state.session_factory() as session:
        run, _scope = _make_run(session)
        for i in range(5):
            _make_finding(
                session, run,
                title=f"Stored XSS Confirmed #{i}",
                severity="critical",
                target_id=f"http://target.test/p{i}",
                summary=f"marker AEGISXSS_AAA{i}AAAAAA",
            )

        def handler(request: httpx.Request) -> httpx.Response:
            # Body doesn't include the marker; verifier returns failed.
            return httpx.Response(200, text="no marker here")

        client_http = httpx.Client(transport=httpx.MockTransport(handler))
        try:
            verdicts = verify_pending_critical_findings(
                session, run=run, scope=None, http_client=client_http, limit=2,
            )
        finally:
            client_http.close()
        assert len(verdicts) == 2


# ---------------------------------------------------------------------------
# VerifierVerdict.to_metadata
# ---------------------------------------------------------------------------


def test_verdict_to_metadata_round_trip() -> None:
    v = VerifierVerdict(
        verdict="confirmed",
        note="ok",
        original_severity="critical",
        new_severity="critical",
        verifier_used="stored_xss",
        checked_url="http://x/",
        evidence={"a": 1, "b": "two"},
    )
    md = v.to_metadata()
    assert md["verdict"] == "confirmed"
    assert md["evidence"] == {"a": 1, "b": "two"}
    assert md["timestamp"]
    assert "verifier_used" in md


# ---------------------------------------------------------------------------
# #344 — pre-persistence verifier hook in workers/orchestration/findings.py
# ---------------------------------------------------------------------------
#
# #335 wired the verifier as a post-advance hook in assessment_loop.py —
# findings were persisted with original severity, then downgraded on the
# next advance. That left a brief window where consumers saw un-verified
# critical severity. #344 moves the call to pre-persistence inside
# workers/orchestration/findings.store_findings so the severity that lands
# in the DB is already verifier-adjusted. The assessment_loop hook stays
# as a self-no-opping defensive backstop (verify_pending_critical_findings
# already skips findings whose ai_enrichment.metadata_json carries a
# 'verifier' key).


def test_pre_persistence_helper_returns_none_for_low_severity() -> None:
    """Per non_blocking_for_low_severity constraint: medium/low/info skip
    the verifier entirely. No HTTP call, no exception."""
    from workers.orchestration.findings import _verify_pre_persistence

    finding = Finding(
        run_id=None,
        title="Some medium issue",
        severity="medium",
        target_id="http://target.test/",
        finding_origin="standard",
        summary=None,
        methodology_tags=[],
        status="open",
    )
    # run can be anything truthy; we shouldn't reach the verify_finding call.
    assert _verify_pre_persistence(finding=finding, run=object()) is None
    assert finding.severity == "medium"  # severity untouched


def test_pre_persistence_helper_returns_none_when_run_missing() -> None:
    """Defensive: a finding with no associated run can't be verified
    (verifier looks up scope via run.engagement). Returns None gracefully."""
    from workers.orchestration.findings import _verify_pre_persistence

    finding = Finding(
        run_id=None,
        title="Mass assignment to admin",
        severity="critical",
        target_id="http://target.test/manage",
        finding_origin="standard",
        summary=None,
        methodology_tags=[],
        status="open",
    )
    assert _verify_pre_persistence(finding=finding, run=None) is None
    assert finding.severity == "critical"  # untouched


def test_pre_persistence_helper_mutates_severity_on_failed_verdict(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Acceptance: the helper mutates finding.severity IN PLACE when the
    verdict says failed — so when the caller flushes the Finding row, the
    DB sees the downgraded severity from the first INSERT (no second-pass
    update visible to consumers)."""
    from workers.orchestration import findings as findings_mod

    fake_verdict = VerifierVerdict(
        verdict="failed",
        note="admin keyword absent",
        original_severity="critical",
        new_severity="high",
        verifier_used="admin_access",
        checked_url="http://target.test/manage",
        evidence={"status": 200},
    )

    def _fake_verify(*_args, **_kwargs):
        return fake_verdict

    monkeypatch.setattr(
        "api.app.services.finding_verifier.verify_finding", _fake_verify,
    )

    finding = Finding(
        run_id=None,
        title="Mass assignment to admin context",
        severity="critical",
        target_id="http://target.test/manage",
        finding_origin="standard",
        summary=None,
        methodology_tags=[],
        status="open",
    )
    verdict = findings_mod._verify_pre_persistence(finding=finding, run=object())
    assert verdict is fake_verdict
    # The PRIMARY acceptance criterion of #344: severity downgraded before
    # the caller flushes. Consumers reading finding.severity now see "high".
    assert finding.severity == "high"


def test_pre_persistence_helper_does_not_double_downgrade(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If the finding's current severity no longer matches the verdict's
    original_severity (e.g. the caller called the helper twice, or merged
    a higher severity in), the helper does NOT re-mutate severity. Mirrors
    the guard inside apply_verifier_verdict for idempotency."""
    from workers.orchestration import findings as findings_mod

    fake_verdict = VerifierVerdict(
        verdict="failed",
        note="x",
        original_severity="critical",  # verdict was computed against critical
        new_severity="high",
        verifier_used="admin_access",
        checked_url="http://x/",
        evidence={},
    )
    monkeypatch.setattr(
        "api.app.services.finding_verifier.verify_finding",
        lambda *_a, **_k: fake_verdict,
    )

    finding = Finding(
        run_id=None,
        title="Mass assignment",
        severity="high",  # already mid-downgrade — verdict.original_severity != current
        target_id="http://target.test/manage",
        finding_origin="standard",
        summary=None,
        methodology_tags=[],
        status="open",
    )
    findings_mod._verify_pre_persistence(finding=finding, run=object())
    # Helper still returned the verdict but did NOT re-downgrade because
    # current severity (high) ≠ verdict.original_severity (critical).
    assert finding.severity == "high"


def test_pre_persistence_helper_returns_verdict_on_confirmed_no_severity_change(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When the verdict is 'confirmed', severity stays put — only failed
    downgrades. The verdict is still returned so the caller can attach it
    as enrichment metadata."""
    from workers.orchestration import findings as findings_mod

    fake_verdict = VerifierVerdict(
        verdict="confirmed",
        note="admin keyword observed",
        original_severity="critical",
        new_severity="critical",
        verifier_used="admin_access",
        checked_url="http://target.test/manage",
        evidence={"status": 200, "admin_keyword": "manage this server"},
    )
    monkeypatch.setattr(
        "api.app.services.finding_verifier.verify_finding",
        lambda *_a, **_k: fake_verdict,
    )

    finding = Finding(
        run_id=None,
        title="Mass assignment to admin",
        severity="critical",
        target_id="http://target.test/manage",
        finding_origin="standard",
        summary=None,
        methodology_tags=[],
        status="open",
    )
    verdict = findings_mod._verify_pre_persistence(finding=finding, run=object())
    assert verdict is fake_verdict
    assert finding.severity == "critical"


def test_pre_persistence_helper_swallows_verify_exception(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Per graceful_degradation: a verifier exception (network error,
    scope lookup blow-up, etc.) must NOT propagate. Helper returns None
    + logs a warning, and the finding persists with its original severity.
    Acceptance criterion: 'verifier failure does NOT block finding
    persistence.'"""
    from workers.orchestration import findings as findings_mod

    def _boom(*_args, **_kwargs):
        raise RuntimeError("simulated verifier failure")

    monkeypatch.setattr(
        "api.app.services.finding_verifier.verify_finding", _boom,
    )

    finding = Finding(
        run_id=None,
        title="Mass assignment to admin",
        severity="critical",
        target_id="http://target.test/manage",
        finding_origin="standard",
        summary=None,
        methodology_tags=[],
        status="open",
    )
    with caplog.at_level("WARNING"):
        result = findings_mod._verify_pre_persistence(finding=finding, run=object())
    assert result is None
    assert finding.severity == "critical"  # untouched
    assert any("pre-persistence verify failed" in rec.message for rec in caplog.records)


def test_store_findings_source_wires_pre_persistence_helper() -> None:
    """Sentinel: workers/orchestration/findings.store_findings MUST call
    _verify_pre_persistence inside the new-finding branch. If a future
    refactor removes the call, this test fails loudly and the #344
    visibility-window closure regresses.
    """
    import inspect
    from workers.orchestration.findings import store_findings

    src = inspect.getsource(store_findings)
    assert "_verify_pre_persistence(" in src, (
        "store_findings must call _verify_pre_persistence before the Finding "
        "row is flushed — removing this call reopens the #335 un-verified "
        "critical visibility window."
    )
    # The post-flush apply_verifier_verdict step also must remain.
    assert "apply_verifier_verdict(" in src, (
        "store_findings must call apply_verifier_verdict after persistence "
        "to write the verdict into FindingAiEnrichment.metadata_json['verifier']"
    )


def test_assessment_loop_post_advance_hook_stays_as_backstop() -> None:
    """The #335 post-advance hook in assessment_loop.advance_assessment_loop
    is INTENTIONALLY left in place after #344 — it becomes a
    self-no-opping defensive backstop, because
    verify_pending_critical_findings skips findings whose
    ai_enrichment.metadata_json already carries a 'verifier' key. This
    test guards the backstop from being deleted as 'dead code'."""
    import inspect
    from api.app.services.assessment_loop import advance_assessment_loop

    src = inspect.getsource(advance_assessment_loop)
    assert "verify_pending_critical_findings" in src, (
        "advance_assessment_loop must keep the verifier backstop call — "
        "the in-orchestration pre-persistence hook is the primary path, "
        "but this is the defensive net for findings that bypass store_findings."
    )
