from __future__ import annotations

import socket

from api.app.services.safe_click import evaluate_safe_click


def test_safe_click_blocks_obfuscated_microsoft_credential_harvest(client, monkeypatch) -> None:
    def blocked_network(*_args, **_kwargs):  # pragma: no cover - fails only if code regresses into network IO.
        raise AssertionError("safe-click evaluation must not open network connections")

    monkeypatch.setattr(socket, "create_connection", blocked_network)
    response = client.post(
        "/api/v1/safe-click/evaluate",
        headers={"X-Actor": "safe-click-reviewer"},
        json={
            "url": "https://login-micr0soft.example.test/security",
            "html_fixture": """
                <html><head><title>Microsoft account sign in</title></head>
                <body>
                  <form action="https://collector.example.test/session" method="post">
                    <input name="loginfmt" value="">
                    <input type="password" name="passwd">
                    <button>Sign in</button>
                  </form>
                </body></html>
            """,
            "visible_text": "Microsoft sign in Verify your account password",
            "metadata": {"source": "unit-fixture"},
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["decision"] == "block"
    assert payload["confidence"] >= 0.86
    assert payload["evidence_refs"]
    assert {"password_input", "credential_form", "brand_host_mismatch"}.issubset(
        {signal["id"] for signal in payload["signals"]}
    )
    assert payload["boundary"]["live_browsing_performed"] is False
    assert payload["boundary"]["arbitrary_public_url_fetch_performed"] is False
    assert payload["boundary"]["credential_collection_performed"] is False


def test_safe_click_allows_benign_submitted_metadata_without_fetching(client) -> None:
    response = client.post(
        "/api/v1/safe-click/evaluate",
        headers={"X-Actor": "safe-click-reviewer"},
        json={
            "url": "https://intranet.example.test/handbook",
            "page_title": "Engineering handbook",
            "visible_text": "Release calendar and team docs",
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["decision"] == "allow"
    assert payload["normalized_host"] == "intranet.example.test"
    assert payload["signals"][0]["id"] == "no_high_risk_indicators"
    assert payload["boundary"]["runtime_dispatch_performed"] is False


def test_safe_click_service_flags_review_for_suspicious_login_host_without_password() -> None:
    report = evaluate_safe_click(
        {
            "url": "https://secure-office365.example.test/login",
            "visible_text": "Office 365 secure login portal",
        }
    )

    assert report.decision == "review"
    assert report.confidence >= 0.62
    assert "suspicious_login_host" in {signal.id for signal in report.signals}
