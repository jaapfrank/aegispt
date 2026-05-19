from __future__ import annotations

import hashlib
import re
from email import policy
from email.message import EmailMessage, Message
from email.parser import BytesParser
from email.utils import getaddresses
from typing import Any

from api.app.services.safe_click import evaluate_safe_click

URL_PATTERN = re.compile(r"https?://[^\s<>'\"]+", re.IGNORECASE)
RISKY_ATTACHMENT_EXTENSIONS = {".html", ".htm", ".hta", ".iso", ".img", ".js", ".vbs", ".exe", ".scr"}


def triage_reported_email(
    *,
    eml_content: str | bytes | None = None,
    webhook: dict[str, Any] | None = None,
) -> dict[str, Any]:
    message = _parse_eml(eml_content) if eml_content is not None else None
    webhook = webhook if isinstance(webhook, dict) else {}
    headers = _headers_from_message(message) if message is not None else dict(webhook.get("headers") or {})
    subject = _header_value(headers, "subject") or str(webhook.get("subject") or "")
    sender = _header_value(headers, "from") or str(webhook.get("sender") or "")
    reply_to = _header_value(headers, "reply-to") or str(webhook.get("reply_to") or "")
    body_text = _message_text(message) if message is not None else str(webhook.get("body_text") or "")
    html = _message_html(message) if message is not None else str(webhook.get("html") or "")
    urls = sorted(set([*_urls(body_text), *_urls(html), *[str(url) for url in webhook.get("urls") or [] if str(url)]]))
    attachments = _attachments(message) if message is not None else list(webhook.get("attachments") or [])

    signals = _signals(
        headers=headers,
        sender=sender,
        reply_to=reply_to,
        subject=subject,
        body_text=body_text,
        html=html,
        urls=urls,
        attachments=attachments,
    )
    score = min(0.98, sum(float(signal["score"]) for signal in signals))
    decision = "malicious" if score >= 0.75 else ("suspicious" if score >= 0.35 else "benign")
    confidence = max(score, 0.86 if decision == "malicious" else 0.55 if decision == "suspicious" else 0.35)
    evidence_refs = [_evidence_ref(subject=subject, signal_id=str(signal["id"]), index=index) for index, signal in enumerate(signals, start=1)]
    for signal, evidence_ref in zip(signals, evidence_refs, strict=False):
        signal["evidence_ref"] = evidence_ref

    return {
        "schema_version": 1,
        "decision": decision,
        "confidence": round(confidence, 3),
        "subject": subject,
        "sender": sender,
        "reply_to": reply_to or None,
        "urls": urls,
        "attachments": attachments,
        "signals": signals,
        "evidence_refs": evidence_refs,
        "boundary": {
            "alert_only_default": True,
            "external_provider_call_performed": False,
            "mailbox_mutation_performed": False,
            "auto_purge_performed": False,
            "credential_materialization_performed": False,
            "live_url_fetch_performed": False,
        },
    }


def build_mail_provider_action_plan(
    *,
    triage: dict[str, Any],
    provider: str,
    tenant_opt_in: bool = False,
    message_id: str | None = None,
) -> dict[str, Any]:
    normalized_provider = _provider(provider)
    decision = str(triage.get("decision") or "benign")
    should_quarantine = decision in {"malicious", "suspicious"}
    action = "quarantine" if should_quarantine else "none"
    provider_request = _provider_request_preview(
        provider=normalized_provider,
        action=action,
        message_id=message_id,
    )
    return {
        "schema_version": 1,
        "provider": normalized_provider,
        "mode": "review_only" if tenant_opt_in else "alert_only",
        "tenant_opt_in": bool(tenant_opt_in),
        "recommended_action": action,
        "requires_operator_approval": should_quarantine,
        "external_provider_call_performed": False,
        "mailbox_mutation_performed": False,
        "auto_purge_performed": False,
        "credential_materialization_performed": False,
        "provider_request_preview": provider_request,
        "operator_guidance": (
            "Review the mocked provider request and approve through a future governed tenant-level workflow."
            if should_quarantine
            else "No provider action is recommended from the submitted evidence."
        ),
    }


def _parse_eml(eml_content: str | bytes) -> Message:
    raw = eml_content.encode("utf-8") if isinstance(eml_content, str) else bytes(eml_content)
    return BytesParser(policy=policy.default).parsebytes(raw)


def _headers_from_message(message: Message) -> dict[str, str]:
    return {str(key).lower(): str(value) for key, value in message.items()}


def _header_value(headers: dict[str, str], key: str) -> str:
    return str(headers.get(key.lower()) or headers.get(key) or "").strip()


def _message_text(message: Message | None) -> str:
    if message is None:
        return ""
    parts: list[str] = []
    if isinstance(message, EmailMessage):
        for part in message.walk():
            if part.get_content_maintype() == "multipart":
                continue
            if part.get_content_type() == "text/plain":
                try:
                    parts.append(part.get_content())
                except Exception:
                    continue
    return "\n".join(parts)


def _message_html(message: Message | None) -> str:
    if message is None:
        return ""
    parts: list[str] = []
    if isinstance(message, EmailMessage):
        for part in message.walk():
            if part.get_content_type() == "text/html":
                try:
                    parts.append(part.get_content())
                except Exception:
                    continue
    return "\n".join(parts)


def _attachments(message: Message | None) -> list[dict[str, str]]:
    if message is None or not isinstance(message, EmailMessage):
        return []
    attachments: list[dict[str, str]] = []
    for part in message.iter_attachments():
        filename = str(part.get_filename() or "attachment").strip()
        content_type = str(part.get_content_type() or "application/octet-stream")
        attachments.append({"filename": filename, "content_type": content_type})
    return attachments


def _urls(*values: str) -> list[str]:
    urls: list[str] = []
    for value in values:
        urls.extend(match.rstrip(").,;") for match in URL_PATTERN.findall(str(value or "")))
    return urls


def _signals(
    *,
    headers: dict[str, str],
    sender: str,
    reply_to: str,
    subject: str,
    body_text: str,
    html: str,
    urls: list[str],
    attachments: list[dict[str, str]],
) -> list[dict[str, Any]]:
    signals: list[dict[str, Any]] = []
    auth_results = _header_value(headers, "authentication-results").lower()
    if any(marker in auth_results for marker in ("spf=fail", "dkim=fail", "dmarc=fail")):
        signals.append(_signal("mail_auth_failure", "Email authentication failure", "high", 0.34))
    if reply_to and _sender_domain(sender) and _sender_domain(reply_to) and _sender_domain(sender) != _sender_domain(reply_to):
        signals.append(_signal("reply_to_mismatch", "Reply-To domain differs from sender", "medium", 0.2))
    if any(token in subject.lower() for token in ("urgent", "password", "verify", "mfa", "account locked")):
        signals.append(_signal("urgent_account_lure", "Urgent account-security lure", "medium", 0.18))
    for attachment in attachments:
        filename = str(attachment.get("filename") or "").lower()
        if any(filename.endswith(extension) for extension in RISKY_ATTACHMENT_EXTENSIONS):
            signals.append(_signal("risky_attachment", f"Risky attachment: {filename}", "medium", 0.2))
            break
    for url in urls[:10]:
        safe_click = evaluate_safe_click({"url": url, "html_fixture": html, "visible_text": body_text, "page_title": subject})
        if safe_click.decision == "block":
            signals.append(_signal("safe_click_block", f"Safe-click blocked URL host {safe_click.normalized_host}", "high", 0.38))
            break
        if safe_click.decision == "review":
            signals.append(_signal("safe_click_review", f"Safe-click review URL host {safe_click.normalized_host}", "medium", 0.18))
            break
    if not signals:
        signals.append(_signal("no_high_risk_mail_indicators", "No high-risk submitted mail indicators", "info", 0.03))
    return signals


def _signal(signal_id: str, label: str, severity: str, score: float) -> dict[str, Any]:
    return {"id": signal_id, "label": label, "severity": severity, "score": score}


def _sender_domain(value: str) -> str:
    addresses = getaddresses([value])
    if not addresses:
        return ""
    _, address = addresses[0]
    return address.rsplit("@", 1)[-1].lower() if "@" in address else ""


def _provider(provider: str) -> str:
    normalized = str(provider or "").strip().lower().replace("-", "_")
    if normalized in {"o365", "office365", "m365", "microsoft_graph", "graph"}:
        return "microsoft_graph"
    if normalized in {"google", "google_workspace", "gmail"}:
        return "gmail"
    raise ValueError("provider must be microsoft_graph or gmail")


def _provider_request_preview(*, provider: str, action: str, message_id: str | None) -> dict[str, Any]:
    if action == "none":
        return {"method": None, "path": None, "body": None, "external_call_performed": False}
    safe_message_id = str(message_id or "{message-id}").strip() or "{message-id}"
    if provider == "microsoft_graph":
        return {
            "method": "POST",
            "path": f"/security/threatIntelligence/hostedContents/{safe_message_id}/microsoft.graph.security.analyze",
            "body": {"requestedAction": "quarantine", "reviewOnly": True},
            "external_call_performed": False,
        }
    return {
        "method": "POST",
        "path": f"/gmail/v1/users/{{userId}}/messages/{safe_message_id}/modify",
        "body": {"addLabelIds": ["AegisPT-Quarantine-Candidate"], "removeLabelIds": [], "reviewOnly": True},
        "external_call_performed": False,
    }


def _evidence_ref(*, subject: str, signal_id: str, index: int) -> str:
    digest = hashlib.sha256(f"{subject}|{signal_id}|{index}".encode("utf-8")).hexdigest()[:16]
    return f"mail-triage:{signal_id}:{digest}"
