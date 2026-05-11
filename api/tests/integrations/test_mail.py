from __future__ import annotations

import socket

import pytest

from api.app.services.mail_triage import build_mail_provider_action_plan, triage_reported_email


def test_reported_eml_parses_and_flags_phishing_without_live_fetch(monkeypatch) -> None:
    def blocked_network(*_args, **_kwargs):  # pragma: no cover - fails only on network regression.
        raise AssertionError("mail triage must not contact external providers or URLs")

    monkeypatch.setattr(socket, "create_connection", blocked_network)
    triage = triage_reported_email(
        eml_content="""From: Microsoft Security <security@micr0soft.example.test>
Reply-To: helpdesk@collector.example.test
To: employee@example.test
Subject: Urgent password verification required
Authentication-Results: example.test; spf=fail smtp.mailfrom=micr0soft.example.test; dmarc=fail
MIME-Version: 1.0
Content-Type: text/html; charset=utf-8

<html><body>
<p>Microsoft sign in required. Verify your account password.</p>
<form action="https://collector.example.test/session" method="post">
<input name="loginfmt"><input type="password" name="passwd">
</form>
<a href="https://login-micr0soft.example.test/security">Review message</a>
</body></html>
"""
    )

    assert triage["decision"] == "malicious"
    assert triage["confidence"] >= 0.75
    assert "https://login-micr0soft.example.test/security" in triage["urls"]
    assert {"mail_auth_failure", "reply_to_mismatch", "urgent_account_lure", "safe_click_block"}.issubset(
        {signal["id"] for signal in triage["signals"]}
    )
    assert triage["evidence_refs"]
    assert triage["boundary"]["external_provider_call_performed"] is False
    assert triage["boundary"]["auto_purge_performed"] is False
    assert triage["boundary"]["live_url_fetch_performed"] is False


def test_microsoft_graph_action_plan_is_review_only_and_mocked() -> None:
    triage = {
        "decision": "malicious",
        "confidence": 0.91,
        "evidence_refs": ["mail-triage:safe_click_block:abc"],
    }

    plan = build_mail_provider_action_plan(
        triage=triage,
        provider="microsoft_graph",
        tenant_opt_in=True,
        message_id="AAMk-example",
    )

    assert plan["mode"] == "review_only"
    assert plan["recommended_action"] == "quarantine"
    assert plan["requires_operator_approval"] is True
    assert plan["external_provider_call_performed"] is False
    assert plan["mailbox_mutation_performed"] is False
    assert plan["auto_purge_performed"] is False
    assert plan["provider_request_preview"]["external_call_performed"] is False
    assert plan["provider_request_preview"]["method"] == "POST"


def test_gmail_action_plan_defaults_to_alert_only() -> None:
    triage = triage_reported_email(
        webhook={
            "subject": "Team lunch notes",
            "sender": "people@example.test",
            "body_text": "No links, just lunch.",
            "urls": [],
        }
    )
    plan = build_mail_provider_action_plan(triage=triage, provider="gmail", message_id="msg-1")

    assert triage["decision"] == "benign"
    assert plan["mode"] == "alert_only"
    assert plan["recommended_action"] == "none"
    assert plan["requires_operator_approval"] is False
    assert plan["provider_request_preview"]["method"] is None
    assert plan["external_provider_call_performed"] is False


def test_unsupported_provider_is_rejected_before_any_action() -> None:
    with pytest.raises(ValueError, match="provider must be"):
        build_mail_provider_action_plan(triage={"decision": "malicious"}, provider="imap")
