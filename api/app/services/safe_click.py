from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from html import unescape
from typing import Any
from urllib.parse import urlparse

from api.app.schemas.safe_click import SafeClickEvaluationRead, SafeClickSignalRead

OFFICIAL_BRAND_HOST_SUFFIXES = {
    "microsoft": ("microsoft.com", "microsoftonline.com", "office.com", "live.com"),
    "google": ("google.com", "accounts.google.com"),
    "okta": ("okta.com", "okta-emea.com"),
}
BRAND_KEYWORDS = {
    "microsoft": ("microsoft", "office 365", "o365", "outlook", "onedrive", "sharepoint"),
    "google": ("google", "gmail", "workspace"),
    "okta": ("okta",),
}
SUSPICIOUS_HOST_TOKENS = (
    "login-",
    "-login",
    "secure-",
    "verify-",
    "account-",
    "password",
    "microsoft",
    "office365",
    "outlook",
    "micr0soft",
)


@dataclass(frozen=True)
class _Signal:
    id: str
    label: str
    severity: str
    rationale: str

    @property
    def score(self) -> float:
        return {"info": 0.05, "low": 0.15, "medium": 0.28, "high": 0.42}.get(self.severity, 0.0)


def evaluate_safe_click(payload: dict[str, Any]) -> SafeClickEvaluationRead:
    url = str(payload.get("url") or "").strip()
    parsed = urlparse(url if "://" in url else f"https://{url}")
    host = (parsed.hostname or "").strip().lower() or None
    html = str(payload.get("html_fixture") or "")
    title = str(payload.get("page_title") or "")
    visible_text = str(payload.get("visible_text") or "")
    metadata = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
    text = _normalized_text(" ".join([url, title, visible_text, _html_text(html), _metadata_text(metadata)]))

    signals = _collect_signals(url=url, host=host, html=html, text=text)
    score = min(0.98, sum(signal.score for signal in signals))
    has_high = any(signal.severity == "high" for signal in signals)
    has_credential = any(signal.id in {"credential_form", "password_input"} for signal in signals)
    has_brand_mismatch = any(signal.id == "brand_host_mismatch" for signal in signals)
    if has_credential and (has_high or has_brand_mismatch):
        decision = "block"
        confidence = max(score, 0.86)
        guidance = "Block navigation and route the submitted fixture to security review."
    elif score >= 0.45:
        decision = "review"
        confidence = max(score, 0.62)
        guidance = "Hold navigation for operator review before allowing the user to proceed."
    else:
        decision = "allow"
        confidence = max(0.2, min(0.74, 1.0 - score))
        guidance = "Allow navigation based on submitted metadata; no live browsing was performed."

    signal_reads = [
        SafeClickSignalRead(
            id=signal.id,
            label=signal.label,
            severity=signal.severity,  # type: ignore[arg-type]
            evidence_ref=_evidence_ref(url=url, signal_id=signal.id, index=index),
            rationale=signal.rationale,
        )
        for index, signal in enumerate(signals, start=1)
    ]
    return SafeClickEvaluationRead(
        decision=decision,
        confidence=round(float(confidence), 3),
        url=url,
        normalized_host=host,
        signals=signal_reads,
        evidence_refs=[signal.evidence_ref for signal in signal_reads],
        operator_guidance=guidance,
    )


def _collect_signals(*, url: str, host: str | None, html: str, text: str) -> list[_Signal]:
    signals: list[_Signal] = []
    lower_host = host or ""
    if _contains_password_input(html):
        signals.append(
            _Signal(
                id="password_input",
                label="Password input present",
                severity="high",
                rationale="Submitted page fixture contains a password input field.",
            )
        )
    if _contains_login_form(html, text):
        signals.append(
            _Signal(
                id="credential_form",
                label="Credential collection form",
                severity="high",
                rationale="Submitted fixture resembles a username/password sign-in form.",
            )
        )
    brand = _brand_in_text(text)
    if brand and not _host_matches_brand(lower_host, brand):
        signals.append(
            _Signal(
                id="brand_host_mismatch",
                label=f"{brand.title()} brand on unrelated host",
                severity="high",
                rationale="The page references a trusted brand while the URL host is not an official host for that brand.",
            )
        )
    if any(token in lower_host for token in SUSPICIOUS_HOST_TOKENS) and brand and not _host_matches_brand(lower_host, brand):
        signals.append(
            _Signal(
                id="suspicious_login_host",
                label="Suspicious login-themed host",
                severity="medium",
                rationale="The host uses login/security wording combined with brand-like terms.",
            )
        )
    if "xn--" in lower_host or re.search(r"micr[o0]s[o0]ft", lower_host):
        signals.append(
            _Signal(
                id="obfuscated_brand_host",
                label="Obfuscated brand-like host",
                severity="medium",
                rationale="The host contains punycode or look-alike brand text.",
            )
        )
    if _form_action_mismatch(html, host):
        signals.append(
            _Signal(
                id="cross_host_form_action",
                label="Cross-host form submission",
                severity="medium",
                rationale="The submitted login form posts to a different host.",
            )
        )
    if not signals:
        signals.append(
            _Signal(
                id="no_high_risk_indicators",
                label="No high-risk submitted indicators",
                severity="info",
                rationale="Submitted URL and fixture metadata did not contain known credential-harvest indicators.",
            )
        )
    return signals


def _contains_password_input(html: str) -> bool:
    return bool(re.search(r"<input[^>]+type\s*=\s*['\"]?password", html, re.IGNORECASE))


def _contains_login_form(html: str, text: str) -> bool:
    has_form = "<form" in html.lower()
    has_identity_field = bool(re.search(r"name\s*=\s*['\"]?(?:user|username|email|login)", html, re.IGNORECASE))
    has_login_text = any(token in text for token in ("sign in", "log in", "password", "verify your account"))
    return has_form and has_login_text and (has_identity_field or _contains_password_input(html))


def _brand_in_text(text: str) -> str | None:
    for brand, keywords in BRAND_KEYWORDS.items():
        if any(keyword in text for keyword in keywords):
            return brand
    return None


def _host_matches_brand(host: str, brand: str) -> bool:
    suffixes = OFFICIAL_BRAND_HOST_SUFFIXES.get(brand, ())
    return any(host == suffix or host.endswith(f".{suffix}") for suffix in suffixes)


def _form_action_mismatch(html: str, host: str | None) -> bool:
    if not host:
        return False
    for action in re.findall(r"<form[^>]+action\s*=\s*['\"]([^'\"]+)", html, flags=re.IGNORECASE):
        parsed = urlparse(action)
        action_host = (parsed.hostname or "").strip().lower()
        if action_host and action_host != host:
            return True
    return False


def _html_text(html: str) -> str:
    without_tags = re.sub(r"<[^>]+>", " ", html)
    return unescape(without_tags)


def _metadata_text(metadata: dict[str, Any]) -> str:
    pieces: list[str] = []
    for key, value in metadata.items():
        if isinstance(value, (str, int, float, bool)):
            pieces.append(f"{key} {value}")
    return " ".join(pieces)


def _normalized_text(value: str) -> str:
    return re.sub(r"\s+", " ", value.casefold()).strip()


def _evidence_ref(*, url: str, signal_id: str, index: int) -> str:
    digest = hashlib.sha256(f"{url}|{signal_id}|{index}".encode("utf-8")).hexdigest()[:16]
    return f"safe-click:{signal_id}:{digest}"
