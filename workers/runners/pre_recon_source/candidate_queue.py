"""Candidate queue contract for source/runtime proof-loop handoff.

The proof-loop needs structured candidates, not only a markdown source audit.
This module turns pre-recon source facts and optional runtime recon cues into a
stable JSON contract that Claude's runner lane can consume without guessing
field names or candidate states.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

CANDIDATE_QUEUE_ARTIFACT_NAME = "pre-recon-candidate-queue.json"
CANDIDATE_QUEUE_SCHEMA_VERSION = "aegispt.candidate_queue.v1"

ALLOWED_ORIGINS = ("source", "runtime_recon", "source_and_runtime")
ALLOWED_STATES = (
    "untested",
    "tested_no_signal",
    "blocked_needs_auth",
    "blocked_needs_callback",
    "blocked_needs_state",
    "exploited",
    "false_positive",
)
ALLOWED_VULN_CLASSES = (
    "auth_logic_session_forgery",
    "authz_idor",
    "command_or_code_execution",
    "deserialization",
    "file_path_upload",
    "headless_xss",
    "nosql_injection",
    "sql_injection",
    "ssrf_internal",
    "ssti",
    "xss_reflection",
    "xxe",
)
ALLOWED_EVIDENCE_CLASSES = (
    "authenticated_state_change",
    "callback_observed",
    "command_output_or_callback",
    "database_extract",
    "evaluated_template_signal",
    "file_or_internal_resource_read",
    "headless_dialog_observed",
    "internal_service_response",
    "privileged_resource_access",
    "response_body_secret",
    "stored_state_change",
)

_SOURCE_ONLY_TOOL = "code-exec-attack"
_STATEFUL_TOOL = "interactive-exploit"


def _stable_hash(value: Any, length: int = 16) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()[:length]


def _as_list(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [v for v in value if isinstance(v, dict)]
    return []


def _trim(value: Any, limit: int = 240) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    return text[:limit]


def _cue(kind: str, hit: dict[str, Any], *, value_key: str | None = None) -> dict[str, Any]:
    value = hit.get(value_key) if value_key else None
    return {
        "cue_type": kind,
        "file": _trim(hit.get("file")),
        "line": hit.get("line"),
        "kind": _trim(hit.get("kind") or hit.get("sink")),
        "value": _trim(value),
        "snippet": _trim(hit.get("snippet")),
    }


def _route_for_file(routes: list[dict[str, Any]], file_name: str | None) -> dict[str, Any] | None:
    if file_name:
        for route in routes:
            if route.get("file") == file_name:
                return route
    return routes[0] if routes else None


def _first_reflected_param(reflected_inputs: list[dict[str, Any]], file_name: str | None) -> str | None:
    for item in reflected_inputs:
        if not file_name or item.get("file") == file_name:
            return _trim(item.get("param"))
    return None


def _auth_requirement(auth: list[dict[str, Any]], route: dict[str, Any] | None) -> str:
    if not auth:
        return "unknown"
    relevant = auth
    if route and route.get("file"):
        same_file = [a for a in auth if a.get("file") == route.get("file")]
        relevant = same_file or auth
    kinds = {str(a.get("kind") or "").lower() for a in relevant}
    if any("admin" in kind for kind in kinds):
        return "admin_required"
    if any("session" in kind for kind in kinds):
        return "session_required"
    if relevant:
        return "auth_required"
    return "unknown"


def _entry_point(
    route: dict[str, Any] | None,
    *,
    parameter: str | None = None,
    runtime_cue: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if runtime_cue:
        return {
            "method": _trim(runtime_cue.get("method")) or "GET",
            "route": _trim(runtime_cue.get("route") or runtime_cue.get("path")),
            "url": _trim(runtime_cue.get("url")),
            "parameter": _trim(runtime_cue.get("parameter") or runtime_cue.get("param")),
            "source_file": None,
            "source_line": None,
        }
    return {
        "method": _trim(route.get("method") if route else None) or "GET",
        "route": _trim(route.get("path") if route else None),
        "url": None,
        "parameter": parameter,
        "source_file": _trim(route.get("file") if route else None),
        "source_line": route.get("line") if route else None,
    }


def _make_candidate(
    *,
    origin: str,
    vuln_class: str,
    entry_point: dict[str, Any],
    source_cues: list[dict[str, Any]] | None = None,
    runtime_cues: list[dict[str, Any]] | None = None,
    sink: dict[str, Any] | None = None,
    auth_requirement: str = "unknown",
    hypothesis: str,
    rank: int,
    rank_reasons: list[str],
    required_evidence_class: str,
    requires_source_context: bool,
    black_box_compatible: bool,
    compatible_tools: list[str] | None = None,
) -> dict[str, Any]:
    if origin not in ALLOWED_ORIGINS:
        raise ValueError(f"unsupported candidate origin: {origin}")
    if vuln_class not in ALLOWED_VULN_CLASSES:
        raise ValueError(f"unsupported vuln class: {vuln_class}")
    if required_evidence_class not in ALLOWED_EVIDENCE_CLASSES:
        raise ValueError(f"unsupported evidence class: {required_evidence_class}")

    source_cues = source_cues or []
    runtime_cues = runtime_cues or []
    identity = {
        "origin": origin,
        "vuln_class": vuln_class,
        "entry_point": entry_point,
        "sink": sink,
        "source_cues": source_cues[:4],
        "runtime_cues": runtime_cues[:4],
    }
    return {
        "candidate_id": f"cand-{vuln_class}-{_stable_hash(identity)}",
        "schema_version": CANDIDATE_QUEUE_SCHEMA_VERSION,
        "origin": origin,
        "state": "untested",
        "vuln_class": vuln_class,
        "entry_point": entry_point,
        "sink": sink or {},
        "source_cues": source_cues,
        "runtime_cues": runtime_cues,
        "auth_requirement": auth_requirement,
        "hypothesis": hypothesis,
        "rank": max(0, min(100, int(rank))),
        "rank_reasons": rank_reasons,
        "required_evidence_class": required_evidence_class,
        "requires_source_context": requires_source_context,
        "black_box_compatible": black_box_compatible,
        "compatible_tools": compatible_tools or [_STATEFUL_TOOL],
    }


def _sink_class(sink_label: str) -> tuple[str, str, str] | None:
    label = sink_label.lower()
    if label.startswith("ssrf-"):
        return (
            "ssrf_internal",
            "internal_service_response",
            "Server-side fetch sink may reach internal-only services or loopback endpoints.",
        )
    if "render_template_string" in label or "jinja2" in label or "template" in label:
        return (
            "ssti",
            "evaluated_template_signal",
            "Template construction from runtime input may evaluate attacker-controlled expressions.",
        )
    if "raw-sql" in label:
        return (
            "sql_injection",
            "database_extract",
            "Raw SQL construction is near an entry point and should be proven by data extraction.",
        )
    if "xxe" in label or "lxml-xml-parse" in label:
        return (
            "xxe",
            "file_or_internal_resource_read",
            "XML parser configuration indicates external entity or internal resource read risk.",
        )
    if "unserialize" in label or "pickle" in label or "yaml-unsafe" in label:
        return (
            "deserialization",
            "stored_state_change",
            "Unsafe deserialization sink should be proven by bounded state or response evidence.",
        )
    if "include" in label or "upload" in label:
        return (
            "file_path_upload",
            "file_or_internal_resource_read",
            "Dynamic file/path handling should be proven by bounded file or upload evidence.",
        )
    if any(part in label for part in ("eval", "exec", "system", "popen", "function")):
        return (
            "command_or_code_execution",
            "command_output_or_callback",
            "Code or command execution sink should be proven by bounded command output or callback evidence.",
        )
    if "markup" in label or "document-write" in label or "js-" in label:
        return (
            "xss_reflection",
            "response_body_secret",
            "Client-side rendering sink should be proven by reflected execution evidence.",
        )
    return None


def _runtime_vuln_hint(cue: dict[str, Any]) -> tuple[str, str, str]:
    explicit = str(cue.get("vuln_class_hint") or cue.get("vuln_class") or "")
    if explicit in ALLOWED_VULN_CLASSES:
        return explicit, "response_body_secret", "Runtime recon supplied an explicit vuln class hint."

    joined = " ".join(
        str(cue.get(key) or "").lower()
        for key in ("route", "path", "url", "parameter", "param", "cue_type", "label")
    )
    if any(word in joined for word in ("url", "webhook", "callback", "avatar", "fetch")):
        return "ssrf_internal", "internal_service_response", "Runtime recon found a URL-like input or callback surface."
    if any(word in joined for word in ("user", "account", "tenant", "company", "object", "id")):
        return "authz_idor", "privileged_resource_access", "Runtime recon found an object or identity selector."
    if any(word in joined for word in ("upload", "file", "path", "template")):
        return "file_path_upload", "file_or_internal_resource_read", "Runtime recon found a file, path, upload, or template surface."
    if any(word in joined for word in ("search", "query", "filter", "where")):
        return "sql_injection", "database_extract", "Runtime recon found a query/filter input surface."
    return "xss_reflection", "response_body_secret", "Runtime recon found an input reflection candidate."


def build_candidate_queue(
    *,
    source_facts: dict[str, Any] | None = None,
    runtime_recon_cues: list[dict[str, Any]] | None = None,
    producer: str = "pre-recon-source",
) -> dict[str, Any]:
    """Build a deterministic candidate queue from source and runtime cues."""
    source_facts = source_facts or {}
    runtime_recon_cues = runtime_recon_cues or []

    routes = _as_list(source_facts.get("routes"))
    sinks = _as_list(source_facts.get("sinks"))
    auth = _as_list(source_facts.get("auth"))
    creds = _as_list(source_facts.get("creds"))
    listen_ports = _as_list(source_facts.get("listen_ports"))
    gate_tokens = _as_list(source_facts.get("gate_tokens"))
    headless_dialog = _as_list(source_facts.get("headless_dialog"))
    input_filters = _as_list(source_facts.get("input_filters"))
    reflected_inputs = _as_list(source_facts.get("reflected_inputs"))
    internal_gates = _as_list(source_facts.get("internal_gates"))
    internal_endpoints = _as_list(source_facts.get("internal_endpoints"))

    candidates: list[dict[str, Any]] = []
    ssrf_sinks = [s for s in sinks if str(s.get("sink") or "").lower().startswith("ssrf-")]

    if ssrf_sinks and (internal_endpoints or internal_gates):
        for sink in ssrf_sinks[:5]:
            route = _route_for_file(routes, _trim(sink.get("file")))
            cues = [_cue("source_sink", sink, value_key="sink")]
            cues.extend(_cue("internal_endpoint", ep, value_key="route") for ep in internal_endpoints[:5])
            cues.extend(_cue("internal_gate", gate) for gate in internal_gates[:5])
            cues.extend(_cue("listen_port", port, value_key="port") for port in listen_ports[:3])
            candidates.append(_make_candidate(
                origin="source",
                vuln_class="ssrf_internal",
                entry_point=_entry_point(
                    route,
                    parameter=_first_reflected_param(reflected_inputs, _trim(sink.get("file"))),
                ),
                sink={
                    "kind": _trim(sink.get("sink")),
                    "file": _trim(sink.get("file")),
                    "line": sink.get("line"),
                    "severity_hint": _trim(sink.get("severity_hint")),
                },
                source_cues=cues,
                auth_requirement=_auth_requirement(auth, route),
                hypothesis=(
                    "A server-side fetch sink can be driven toward a localhost-gated "
                    "internal endpoint; prove only by observing a real state change or "
                    "internal response, not by reporting the hypothesis."
                ),
                rank=96,
                rank_reasons=[
                    "server-side fetch sink observed",
                    "internal-only gate or endpoint observed",
                    "requires evidence-backed chain, not a single request guess",
                ],
                required_evidence_class="authenticated_state_change",
                requires_source_context=True,
                black_box_compatible=False,
                compatible_tools=[_STATEFUL_TOOL, _SOURCE_ONLY_TOOL],
            ))

    if headless_dialog:
        first_reflection = reflected_inputs[0] if reflected_inputs else {}
        route = _route_for_file(routes, _trim(first_reflection.get("file")))
        candidates.append(_make_candidate(
            origin="source",
            vuln_class="headless_xss",
            entry_point=_entry_point(route, parameter=_trim(first_reflection.get("param"))),
            source_cues=(
                [_cue("headless_dialog", item) for item in headless_dialog[:5]]
                + [_cue("input_filter", item) for item in input_filters[:5]]
                + [_cue("reflected_input", item, value_key="param") for item in reflected_inputs[:5]]
            ),
            auth_requirement=_auth_requirement(auth, route),
            hypothesis=(
                "The target renders user-controlled HTML inside a headless browser; "
                "prove success by observing the dialog callback or in-band success signal."
            ),
            rank=92,
            rank_reasons=[
                "headless browser dialog hook observed",
                "candidate includes reflected input/filter cues when available",
            ],
            required_evidence_class="headless_dialog_observed",
            requires_source_context=True,
            black_box_compatible=False,
            compatible_tools=[_STATEFUL_TOOL, _SOURCE_ONLY_TOOL],
        ))

    for token in gate_tokens:
        if token.get("kind") != "forgeable-session-secret":
            continue
        route = _route_for_file(routes, _trim(token.get("file")))
        candidates.append(_make_candidate(
            origin="source",
            vuln_class="auth_logic_session_forgery",
            entry_point=_entry_point(route),
            source_cues=[_cue("source_gate_token", token, value_key="token")],
            auth_requirement="session_required",
            hypothesis=(
                "A hardcoded signing/session secret can allow a forged privileged "
                "session; prove by accessing a privileged resource or state as that role."
            ),
            rank=88,
            rank_reasons=["forgeable session/JWT secret observed in source"],
            required_evidence_class="privileged_resource_access",
            requires_source_context=True,
            black_box_compatible=False,
            compatible_tools=[_STATEFUL_TOOL, _SOURCE_ONLY_TOOL],
        ))

    for cred in creds:
        if cred.get("kind") not in {"hardcoded-secret", "users-dict-seed", "user/pass-pair"}:
            continue
        route = _route_for_file(routes, _trim(cred.get("file")))
        candidates.append(_make_candidate(
            origin="source",
            vuln_class="auth_logic_session_forgery",
            entry_point=_entry_point(route),
            source_cues=[_cue("source_credential_or_secret", cred, value_key="user_or_role")],
            auth_requirement="auth_required",
            hypothesis=(
                "Source-disclosed credential or signing material may unlock an authenticated "
                "path; prove by an authenticated resource or state transition."
            ),
            rank=74,
            rank_reasons=["source-disclosed credential or secret observed"],
            required_evidence_class="privileged_resource_access",
            requires_source_context=True,
            black_box_compatible=False,
            compatible_tools=[_STATEFUL_TOOL],
        ))

    for sink in sinks:
        label = str(sink.get("sink") or "")
        if label.lower().startswith("ssrf-") and (internal_endpoints or internal_gates):
            continue
        mapped = _sink_class(label)
        if not mapped:
            continue
        vuln_class, evidence_class, hypothesis = mapped
        route = _route_for_file(routes, _trim(sink.get("file")))
        rank = 85 if str(sink.get("severity_hint")) == "critical" else 68
        candidates.append(_make_candidate(
            origin="source",
            vuln_class=vuln_class,
            entry_point=_entry_point(
                route,
                parameter=_first_reflected_param(reflected_inputs, _trim(sink.get("file"))),
            ),
            sink={
                "kind": _trim(sink.get("sink")),
                "file": _trim(sink.get("file")),
                "line": sink.get("line"),
                "severity_hint": _trim(sink.get("severity_hint")),
            },
            source_cues=[_cue("source_sink", sink, value_key="sink")],
            auth_requirement=_auth_requirement(auth, route),
            hypothesis=hypothesis,
            rank=rank,
            rank_reasons=[
                f"{label} sink observed",
                f"severity hint: {sink.get('severity_hint') or 'unknown'}",
            ],
            required_evidence_class=evidence_class,
            requires_source_context=True,
            black_box_compatible=False,
            compatible_tools=[_STATEFUL_TOOL, _SOURCE_ONLY_TOOL],
        ))

    for cue in runtime_recon_cues:
        vuln_class, evidence_class, reason = _runtime_vuln_hint(cue)
        auth_required = bool(cue.get("auth_required") or cue.get("requires_auth"))
        candidates.append(_make_candidate(
            origin="runtime_recon",
            vuln_class=vuln_class,
            entry_point=_entry_point(None, runtime_cue=cue),
            runtime_cues=[{
                "cue_type": _trim(cue.get("cue_type") or cue.get("kind")) or "runtime_surface",
                "route": _trim(cue.get("route") or cue.get("path")),
                "method": _trim(cue.get("method")) or "GET",
                "parameter": _trim(cue.get("parameter") or cue.get("param")),
                "evidence": _trim(cue.get("evidence") or cue.get("snippet")),
            }],
            auth_requirement="auth_required" if auth_required else "unknown",
            hypothesis=(
                "Runtime recon observed an attack surface that should enter the same "
                "proof-loop as source candidates; prove with concrete response/state evidence."
            ),
            rank=int(cue.get("rank") or 62),
            rank_reasons=[reason],
            required_evidence_class=evidence_class,
            requires_source_context=False,
            black_box_compatible=True,
            compatible_tools=[_STATEFUL_TOOL],
        ))

    deduped: dict[str, dict[str, Any]] = {}
    for candidate in candidates:
        deduped[candidate["candidate_id"]] = candidate
    ordered = sorted(deduped.values(), key=lambda item: (-int(item["rank"]), item["candidate_id"]))

    return {
        "schema_version": CANDIDATE_QUEUE_SCHEMA_VERSION,
        "producer": producer,
        "allowed_states": list(ALLOWED_STATES),
        "allowed_vuln_classes": list(ALLOWED_VULN_CLASSES),
        "allowed_evidence_classes": list(ALLOWED_EVIDENCE_CLASSES),
        "candidate_count": len(ordered),
        "candidates": ordered,
    }


def validate_candidate_queue(queue: dict[str, Any]) -> list[str]:
    """Return human-readable schema problems. Empty list means valid."""
    problems: list[str] = []
    if queue.get("schema_version") != CANDIDATE_QUEUE_SCHEMA_VERSION:
        problems.append("invalid schema_version")
    candidates = queue.get("candidates")
    if not isinstance(candidates, list):
        problems.append("candidates must be a list")
        return problems

    seen: set[str] = set()
    for idx, candidate in enumerate(candidates):
        prefix = f"candidate[{idx}]"
        candidate_id = candidate.get("candidate_id")
        if not isinstance(candidate_id, str) or not candidate_id:
            problems.append(f"{prefix}.candidate_id missing")
        elif candidate_id in seen:
            problems.append(f"{prefix}.candidate_id duplicate")
        else:
            seen.add(candidate_id)
        if candidate.get("schema_version") != CANDIDATE_QUEUE_SCHEMA_VERSION:
            problems.append(f"{prefix}.schema_version invalid")
        if candidate.get("origin") not in ALLOWED_ORIGINS:
            problems.append(f"{prefix}.origin invalid")
        if candidate.get("state") not in ALLOWED_STATES:
            problems.append(f"{prefix}.state invalid")
        if candidate.get("vuln_class") not in ALLOWED_VULN_CLASSES:
            problems.append(f"{prefix}.vuln_class invalid")
        if candidate.get("required_evidence_class") not in ALLOWED_EVIDENCE_CLASSES:
            problems.append(f"{prefix}.required_evidence_class invalid")
        if not isinstance(candidate.get("entry_point"), dict):
            problems.append(f"{prefix}.entry_point missing")
        if not isinstance(candidate.get("rank"), int):
            problems.append(f"{prefix}.rank must be int")
        if not isinstance(candidate.get("hypothesis"), str) or not candidate.get("hypothesis"):
            problems.append(f"{prefix}.hypothesis missing")
        if not isinstance(candidate.get("source_cues"), list):
            problems.append(f"{prefix}.source_cues must be list")
        if not isinstance(candidate.get("runtime_cues"), list):
            problems.append(f"{prefix}.runtime_cues must be list")
        if candidate.get("origin") == "runtime_recon" and candidate.get("requires_source_context"):
            problems.append(f"{prefix}.runtime_recon must not require source context")
    if queue.get("candidate_count") != len(candidates):
        problems.append("candidate_count does not match candidates length")
    return problems
