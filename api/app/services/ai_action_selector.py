from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session

from api.app.models import Run, Scope
from api.app.services.assessment_graph import build_assessment_graph, build_assessment_hypotheses
from api.app.services.roe_policy import compile_roe_policy_decision
from api.app.services.runner_contracts import RunnerContractError, runner_contract_for
from api.app.services.runs import target_value_is_allowed
from api.app.services.task_dispatch import supported_execution_tools

SELECTOR_VERSION = "next-best-action-selector-v1"
# Only httpx stays in LOW_IMPACT_AUTO_TOOLS — it is the universal web discovery starter.
# nmap/easm-discover require host_target_present/domain_scope_present signals and must
# not run on URL-only targets; removing them ensures SKIP when those signals are absent.
LOW_IMPACT_AUTO_TOOLS = {"httpx"}
ACTION_PRIORITY = {"RUN": 0, "APPROVAL": 1, "WAIT": 2, "SKIP": 3}
COST_WEIGHT = {"low": 0.05, "medium": 0.1, "high": 0.16}
RISK_WEIGHT = {"passive": 0.0, "active": 0.04, "intrusive": 0.12}


def rank_next_best_actions(
    graph: dict[str, Any],
    *,
    approved_targets: list[dict[str, str]] | None = None,
    tested_action_keys: set[str] | None = None,
    allow_active_without_review: bool = False,
) -> dict[str, Any]:
    nodes = [node for node in _as_list(graph.get("nodes")) if isinstance(node, dict)]
    edges = [edge for edge in _as_list(graph.get("edges")) if isinstance(edge, dict)]
    hypotheses = build_assessment_hypotheses(graph)
    observed = _observed_state(nodes)
    targets = _candidate_targets(nodes, approved_targets or [])
    tested_keys = tested_action_keys or set()
    runner_nodes = [
        node
        for node in nodes
        if node.get("kind") == "runner_metadata"
        and _as_dict(node.get("data")).get("registered") is True
        and str(node.get("source_id") or "") in supported_execution_tools()
    ]

    actions = [
        _rank_runner_action(
            runner_node,
            targets=targets,
            observed=observed,
            hypotheses=_as_list(hypotheses.get("hypotheses")),
            edges=edges,
            tested_action_keys=tested_keys,
            allow_active_without_review=allow_active_without_review,
        )
        for runner_node in runner_nodes
    ]
    actions = [action for action in actions if action is not None]
    actions.sort(
        key=lambda action: (
            -float(action["expected_proof_value"]),
            ACTION_PRIORITY.get(action["decision"], 9),
            -float(action["confidence"]),
            int(action["required_approvals"]),
            action["runner"],
        )
    )
    for index, action in enumerate(actions, start=1):
        action["rank"] = index

    return {
        "selector_version": SELECTOR_VERSION,
        "graph_version": graph.get("graph_version"),
        "run_id": graph.get("run_id"),
        "generated_at": datetime.now(UTC).isoformat(),
        "execution_contract": {
            "analysis_only": True,
            "dispatches_work_directly": False,
            "mutates_approvals": False,
            "mutates_scope": False,
            "runtime_self_modification": False,
            "runner_registry_bypassed": False,
        },
        "observed_prerequisites": sorted(observed["prerequisites"]),
        "actions": actions,
    }


def select_next_best_action_for_run(
    session: Session,
    *,
    run: Run,
    scope: Scope,
    approved_targets: list[dict[str, str]],
    tested_action_keys: set[str],
    allow_active_without_review: bool = False,
    settings: object | None = None,
) -> dict[str, Any]:
    configuration = _as_dict(run.configuration_json)
    loop_config = _as_dict(configuration.get("ai_assessment_loop"))
    if configuration.get("run_mode") != "ai_loop" and loop_config.get("run_mode") != "ai_loop":
        return {
            "selector_version": SELECTOR_VERSION,
            "run_id": str(run.id),
            "enabled": False,
            "reason": "next-best-action selection is gated to run_mode=ai_loop",
            "actions": [],
        }
    session.flush()
    graph = build_assessment_graph(session, run=run)
    allowed_targets = [
        target
        for target in approved_targets
        if _target_allowed(scope, str(target.get("value") or ""))
    ]
    report = {
        **rank_next_best_actions(
            graph,
            approved_targets=allowed_targets,
            tested_action_keys=tested_action_keys,
            allow_active_without_review=allow_active_without_review,
        ),
        "enabled": True,
    }
    report["actions"] = [
        _attach_roe_policy_decision(action, run=run, scope=scope, settings=settings)
        for action in _as_list(report.get("actions"))
        if isinstance(action, dict)
    ]
    return report


def _attach_roe_policy_decision(
    action: dict[str, Any],
    *,
    run: Run,
    scope: Scope,
    settings: object | None,
) -> dict[str, Any]:
    policy_decision = compile_roe_policy_decision(
        run=run,
        scope=scope,
        target=action.get("target"),
        runner=action.get("runner"),
        requested_risk_tier=action.get("risk_tier"),
        settings=settings,
    )
    decision = str(policy_decision.get("decision") or "")
    adjusted = dict(action)
    adjusted["roe_policy_decision"] = policy_decision
    if decision in {"kill_switch_blocked", "wait_for_prerequisite"}:
        adjusted["decision"] = "WAIT"
        adjusted["approval_required"] = False
        adjusted["blocker_reason_ids"] = sorted(
            set(_normalized_strings(action.get("blocker_reason_ids")))
            | set(_normalized_strings(policy_decision.get("blocker_reason_ids")))
        )
        adjusted["blocker_reasons"] = [
            *_normalized_strings(action.get("blocker_reasons")),
            str(policy_decision.get("explanation") or ""),
        ]
    elif decision == "approval_required":
        adjusted["approval_reason_ids"] = sorted(
            set(_normalized_strings(action.get("approval_reason_ids")))
            | set(_normalized_strings(policy_decision.get("approval_reason_ids")))
        )
        if str(action.get("decision") or "") not in {"WAIT", "SKIP"}:
            adjusted["decision"] = "APPROVAL"
            adjusted["approval_required"] = True
    elif decision == "deny":
        adjusted["decision"] = "SKIP"
        adjusted["approval_required"] = False
        adjusted["blocker_reason_ids"] = sorted(
            set(_normalized_strings(action.get("blocker_reason_ids")))
            | set(_normalized_strings(policy_decision.get("blocker_reason_ids")))
        )
        adjusted["blocker_reasons"] = [
            *_normalized_strings(action.get("blocker_reasons")),
            str(policy_decision.get("explanation") or ""),
        ]
    adjusted["provenance"] = {
        **_as_dict(action.get("provenance")),
        "roe_policy_compiler": policy_decision.get("policy_version"),
        "roe_policy_decision": decision,
        "scope_roe_bypassed": False,
        "approval_gates_bypassed": False,
    }
    return adjusted


def _rank_runner_action(
    runner_node: dict[str, Any],
    *,
    targets: list[dict[str, str]],
    observed: dict[str, Any],
    hypotheses: list[Any],
    edges: list[dict[str, Any]],
    tested_action_keys: set[str],
    allow_active_without_review: bool,
) -> dict[str, Any] | None:
    runner = str(runner_node.get("source_id") or "").strip()
    if not runner:
        return None
    data = _as_dict(runner_node.get("data"))
    try:
        runner_contract = runner_contract_for(runner)
    except RunnerContractError as exc:
        return _contract_blocked_action(runner_node, runner=runner, reason=str(exc))
    contract_triggers = _as_dict(runner_contract.get("trigger_signals"))
    data = {
        **data,
        "triggers": _normalized_strings(contract_triggers.get("strong")),
        "weak_triggers": _normalized_strings(contract_triggers.get("weak")),
        "prerequisites": _normalized_strings(runner_contract.get("prerequisites")),
        "blockers": _normalized_strings(runner_contract.get("blockers")),
        "expected_evidence": _normalized_strings(runner_contract.get("expected_evidence")),
        "risk_tier": runner_contract.get("risk_tier"),
        "required_approvals": _as_dict(runner_contract.get("approval")).get("required_approvals"),
        "cost": runner_contract.get("cost"),
        "follow_up_tools": _normalized_strings(runner_contract.get("follow_up_candidates")),
    }
    risk_tier = _selector_tier(runner, data)
    target = _target_for_runner(runner, targets, observed)
    action_key = f"{runner}::{target.get('value')}" if target else ""
    prerequisites = set(_normalized_strings(data.get("prerequisites")))
    missing_prerequisites = sorted(prerequisites - observed["prerequisites"])
    matched_triggers = _matched_triggers(data, observed["signals"])
    source_ids = _source_ids_for_runner(runner_node, hypotheses, edges)
    expected_evidence = _normalized_strings(data.get("expected_evidence"))
    confidence = _selector_confidence(
        hypothesis_confidence=_runner_hypothesis_confidence(runner, hypotheses),
        matched_triggers=matched_triggers,
        missing_prerequisites=missing_prerequisites,
        target_present=target is not None,
    )
    expected_proof_value = _expected_proof_value(
        confidence=confidence,
        expected_evidence=expected_evidence,
        cost=str(data.get("cost") or "medium"),
        risk_tier=risk_tier,
        targeted_evidence=bool(matched_triggers and runner not in LOW_IMPACT_AUTO_TOOLS),
    )
    required_approvals = int(data.get("required_approvals") or 0)
    decision, blocker_reasons = _decision_for_runner(
        runner=runner,
        risk_tier=risk_tier,
        required_approvals=required_approvals,
        confidence=confidence,
        matched_triggers=matched_triggers,
        missing_prerequisites=missing_prerequisites,
        target_present=target is not None,
        already_tested=bool(action_key and action_key in tested_action_keys),
        allow_active_without_review=allow_active_without_review,
    )
    rationale = _action_rationale(
        runner=runner,
        decision=decision,
        matched_triggers=matched_triggers,
        missing_prerequisites=missing_prerequisites,
        blocker_reasons=blocker_reasons,
    )
    return {
        "rank": 0,
        "decision": decision,
        "runner": runner,
        "runner_node_id": runner_node["id"],
        "target": target.get("value") if target else None,
        "target_kind": target.get("kind") if target else None,
        "risk_tier": risk_tier,
        "required_approvals": required_approvals,
        "approval_required": decision == "APPROVAL",
        "confidence": confidence,
        "expected_proof_value": expected_proof_value,
        "cost": data.get("cost"),
        "expected_evidence": expected_evidence,
        "source_ids": source_ids,
        "prerequisite_state": {
            "required": sorted(prerequisites),
            "satisfied": sorted(prerequisites & observed["prerequisites"]),
            "missing": missing_prerequisites,
        },
        "matched_triggers": matched_triggers,
        "blocker_reasons": blocker_reasons,
        "blocker_reason_ids": _blocker_reason_ids(
            decision=decision,
            blocker_reasons=blocker_reasons,
            missing_prerequisites=missing_prerequisites,
        ),
        "approval_reason_ids": (
            _normalized_strings(_as_dict(runner_contract.get("approval")).get("approval_reason_ids"))
            if decision == "APPROVAL"
            else []
        ),
        "runner_contract": {
            "contract_id": runner_contract.get("contract_id"),
            "contract_version": runner_contract.get("contract_version"),
            "validation": runner_contract.get("validation"),
            "blocker_ids": _normalized_strings(runner_contract.get("blockers")),
            "report_mapping": _as_list(runner_contract.get("report_mapping")),
        },
        "rationale": rationale,
        "provenance": {
            "selector_version": SELECTOR_VERSION,
            "runner_metadata_node_id": runner_node["id"],
            "decision_inputs": {
                "matched_trigger_count": len(matched_triggers),
                "missing_prerequisite_count": len(missing_prerequisites),
                "target_present": target is not None,
                "already_tested": bool(action_key and action_key in tested_action_keys),
                "allow_active_without_review": allow_active_without_review,
            },
            "dispatches_work": False,
            "scope_enforced": True,
            "roe_enforced": True,
            "approval_gates_bypassed": False,
            "runtime_self_modification": False,
        },
    }


def _contract_blocked_action(
    runner_node: dict[str, Any],
    *,
    runner: str,
    reason: str,
) -> dict[str, Any]:
    return {
        "rank": 0,
        "decision": "WAIT",
        "runner": runner,
        "runner_node_id": runner_node["id"],
        "target": None,
        "target_kind": None,
        "risk_tier": "unknown",
        "required_approvals": 0,
        "approval_required": False,
        "confidence": 0.0,
        "expected_proof_value": 0.0,
        "cost": None,
        "expected_evidence": [],
        "source_ids": [runner_node["id"]],
        "prerequisite_state": {"required": [], "satisfied": [], "missing": ["valid_runner_contract"]},
        "matched_triggers": [],
        "blocker_reasons": [f"missing runner contract data: {reason}"],
        "blocker_reason_ids": ["missing_runner_contract"],
        "approval_reason_ids": [],
        "runner_contract": {
            "contract_id": None,
            "contract_version": None,
            "validation": {
                "valid": False,
                "missing_fields": ["valid_runner_contract"],
                "invalid_fields": [],
            },
            "blocker_ids": ["missing_runner_contract"],
            "report_mapping": [],
        },
        "rationale": f"{runner} is waiting because required adaptive runner contract data is missing.",
        "provenance": {
            "selector_version": SELECTOR_VERSION,
            "runner_metadata_node_id": runner_node["id"],
            "decision_inputs": {
                "contract_valid": False,
                "allow_active_without_review": False,
            },
            "dispatches_work": False,
            "scope_enforced": True,
            "roe_enforced": True,
            "approval_gates_bypassed": False,
            "runtime_self_modification": False,
        },
    }


def _observed_state(nodes: list[dict[str, Any]]) -> dict[str, Any]:
    text = " ".join(
        f"{node.get('label', '')} {node.get('source_id', '')} {node.get('data', '')}".lower()
        for node in nodes
        if node.get("kind") != "runner_metadata"
    )
    signals = _signals_from_text(text)

    # Extract signals from actual httpx/tool stdout JSON stored in task nodes
    for node in nodes:
        if node.get("kind") not in {"task", "tool_output"}:
            continue
        data = node.get("data") or {}
        if not isinstance(data, dict):
            continue
        stdout = str(data.get("stdout_text") or data.get("stdout") or "").strip()
        if stdout and stdout.startswith("{"):
            signals.update(_signals_from_httpx_json(stdout))

    # Extract signals from confirmed findings — each finding elevates specific next tools
    for node in nodes:
        if node.get("kind") != "finding":
            continue
        data = node.get("data") or {}
        title = str(
            (data.get("title") if isinstance(data, dict) else None)
            or node.get("label")
            or ""
        )
        if title:
            signals.update(_signals_from_finding_title(title))
    prerequisites = set()
    if any(node.get("kind") == "scope" for node in nodes):
        prerequisites.add("approved_scope")
    if any(token in text for token in ("operator_auth_context", "secret_binding", "credential_ref", "session_ref")):
        prerequisites.add("operator_auth_context")
    if any(token in text for token in ("injectable_parameter", "sql_error_pattern", "sql error")):
        prerequisites.add("concrete_parameter_or_error_evidence")
    if "template_safety_review" in text or "template safety review" in text:
        prerequisites.add("template_safety_review")
    return {"text": text, "signals": signals, "prerequisites": prerequisites}


def _candidate_targets(
    nodes: list[dict[str, Any]],
    approved_targets: list[dict[str, str]],
) -> list[dict[str, str]]:
    targets: list[dict[str, str]] = []
    for target in approved_targets:
        value = str(target.get("value") or "").strip()
        kind = str(target.get("kind") or "target").strip() or "target"
        if value:
            targets.append({"kind": kind, "value": value})
    for node in nodes:
        data = _as_dict(node.get("data"))
        for key in ("endpoints_discovered", "target_id", "target", "proposed_target"):
            for value in _as_list(data.get(key)):
                if isinstance(value, dict):
                    value = value.get("value") or value.get("url") or value.get("target")
                target_value = str(value or "").strip()
                if target_value:
                    targets.append(
                        {
                            "kind": "url" if "://" in target_value else "target",
                            "value": target_value,
                        }
                    )
    deduped: dict[str, dict[str, str]] = {}
    for target in targets:
        deduped.setdefault(target["value"], target)
    return list(deduped.values())


def _target_for_runner(
    runner: str,
    targets: list[dict[str, str]],
    observed: dict[str, Any],
) -> dict[str, str] | None:
    if runner == "graphql-probe":
        graphql_targets = [target for target in targets if "graphql" in target["value"].lower()]
        if graphql_targets:
            return graphql_targets[0]
    if runner in {"httpx", "graphql-probe", "sqlmap", "nuclei", "auth-flow", "session-security"}:
        web_targets = [target for target in targets if target["kind"] in {"url", "target"}]
        if web_targets:
            return web_targets[0]
    if targets:
        return targets[0]
    text = str(observed.get("text") or "")
    match = re.search(r"https?://[^\s'\",)}]+", text)
    if match:
        return {"kind": "url", "value": match.group(0)}
    return None


def _signals_from_httpx_json(stdout_text: str) -> set[str]:
    """Extract signals from actual httpx JSON output (links, forms, cookies).

    httpx outputs: {"results": [{"links": [...], "forms": [...], "cookies": [...], ...}]}
    This is more reliable than text-matching because it reads structured data.
    """
    signals: set[str] = set()
    try:
        data = json.loads(stdout_text)
    except (json.JSONDecodeError, ValueError):
        return signals

    results = data.get("results") if isinstance(data, dict) else None
    if not isinstance(results, list):
        return signals

    for result in results:
        if not isinstance(result, dict):
            continue

        # Links discovered — check for login/registration/upload/API paths
        for link in result.get("links") or []:
            lnk = str(link or "").lower()
            if any(kw in lnk for kw in ("/login", "/signin", "/sign-in", "login.gtl")):
                signals.add("login_form_found")
            if any(kw in lnk for kw in ("/newaccount", "/register", "/signup", "/join", "/create")):
                signals.add("registration_form_present")
            if "?" in lnk:
                signals.add("injectable_parameter")
            if any(kw in lnk for kw in ("/upload", "/file", "multipart")):
                signals.add("upload_form_present")
            if any(kw in lnk for kw in ("/api/", "/v1/", "/rest/", ".json")):
                signals.add("api_endpoint_present")
            if any(kw in lnk for kw in ("/graphql", " graphql")):
                signals.update({"graphql_endpoint", "graphql_present", "api_endpoint_present"})

        # Forms — real form elements
        for form in result.get("forms") or []:
            if isinstance(form, dict):
                method = str(form.get("method") or "get").lower()
                if method == "post":
                    signals.add("form_with_post_action")
                action = str(form.get("action") or "").lower()
                if any(kw in action for kw in ("login", "signin", "auth")):
                    signals.add("login_form_found")
                if any(kw in action for kw in ("register", "newaccount", "signup")):
                    signals.add("registration_form_present")
                if any(kw in action for kw in ("upload", "file")):
                    signals.add("upload_form_present")

        # Cookies — session detection
        for cookie in result.get("cookies") or []:
            cookie_name = str(cookie.get("name") or cookie if isinstance(cookie, str) else "").lower()
            if any(kw in cookie_name for kw in ("session", "sid", "jsessionid", "phpsessid", "auth")):
                signals.add("session_cookie_present")
            if any(kw in cookie_name for kw in ("jwt", "token", "bearer")):
                signals.add("jwt_in_response")

        # Content-type / headers
        ct = str(result.get("content_type") or "").lower()
        if "json" in ct or "javascript" in ct:
            signals.add("api_endpoint_present")

        # Status indicates something is there
        if result.get("ok") or result.get("status_code") in (200, 201, 301, 302):
            signals.add("web_target_present")
            signals.add("http_service_present")

    return signals


def _signals_from_finding_title(title: str) -> set[str]:
    """Map a finding title to the signals it implies for the next iteration.

    This is the core of evidence-based chaining: each confirmed finding
    elevates the score of the tools that should investigate it further.
    """
    signals: set[str] = set()
    t = title.lower()

    # XSS family → session exploitation tools score highest
    if any(kw in t for kw in ("xss", "cross-site scripting", "script injection", "html injection")):
        signals.update({"xss_confirmed", "session_cookie_present", "web_target_present"})

    # CSRF → session-security, client-state
    if any(kw in t for kw in ("csrf", "xsrf", "anti-csrf", "forgery")):
        signals.update({"csrf_vulnerable", "session_cookie_present"})

    # Missing security headers → deeper header/CSP analysis
    if any(kw in t for kw in ("csp", "content security policy", "clickjacking", "x-frame",
                               "hsts", "strict-transport", "x-content-type")):
        signals.add("security_header_missing")

    # Cookie issues → session-security, client-state
    if any(kw in t for kw in ("cookie", "session", "samesite", "httponly", "secure flag")):
        signals.update({"session_cookie_present", "cookie_weakness"})

    # Hidden endpoints / admin surfaces
    if any(kw in t for kw in ("hidden endpoint", "admin", "debug", "backup", "/private",
                               "directory listing", "sensitive file")):
        signals.add("hidden_endpoint_found")

    # SQL injection
    if any(kw in t for kw in ("sql injection", "sqli", "sql error", "database error", "syntax error")):
        signals.update({"sql_error_pattern", "injectable_parameter"})

    # Path traversal / file inclusion
    if any(kw in t for kw in ("path traversal", "directory traversal", "file inclusion", "lfi", "rfi")):
        signals.add("path_traversal_confirmed")

    # SSRF
    if any(kw in t for kw in ("ssrf", "server-side request forgery", "internal service")):
        signals.update({"ssrf_confirmed", "web_target_present"})

    # Authentication / privilege
    if any(kw in t for kw in ("auth bypass", "authentication bypass", "privilege escalation",
                               "access control", "idor", "broken access", "unauthorized")):
        signals.update({"xss_confirmed", "session_cookie_present"})  # reuse session chain

    # JWT
    if any(kw in t for kw in ("jwt", "json web token", "bearer", "token forgery")):
        signals.update({"jwt_in_response", "session_cookie_present"})

    # Information disclosure / leaks
    if any(kw in t for kw in ("information disclosure", "suspicious comment", "stack trace",
                               "server version", "sensitive information")):
        signals.add("info_disclosure_found")

    # Cache / redirect
    if any(kw in t for kw in ("cache", "redirect", "open redirect")):
        signals.add("web_target_present")

    return signals


def _signals_from_text(text: str) -> set[str]:
    signals: set[str] = set()
    lower = text.lower()

    # Web target present — any HTTP URL in the graph
    if any(token in text for token in ("http://", "https://", "web_target_present")):
        signals.update({"web_target_present", "http_service_present"})

    # GraphQL
    if any(token in lower for token in ("graphql_endpoint", "graphql_present", "/graphql", " graphql")):
        signals.update({"graphql_endpoint", "graphql_present", "api_endpoint_present"})

    # Login / registration forms — matched from links in httpx output
    if any(token in lower for token in ("/login", "login_form_found", "login form", "/signin", "/sign-in")):
        signals.add("login_form_found")
    if any(token in lower for token in ("/newaccount", "/register", "/signup", "/sign-up", "/create-account")):
        signals.add("registration_form_present")

    # Forms with POST action — matched from httpx forms JSON or content-discovery
    if any(token in lower for token in ("form_with_post_action", '"method": "post"', '"post"', "post action",
                                         '"action":', "upload", "/upload", "file_field")):
        signals.add("form_with_post_action")
    if any(token in lower for token in ("/upload", "file_upload", "upload_url", "file_field", "multipart")):
        signals.add("upload_form_present")

    # XSS confirmed — critical signal for session chaining
    if any(token in lower for token in ("reflected xss", "stored xss", "xss confirmed", "xss via url",
                                         "cross-site scripting", "xss_context_evidence")):
        signals.update({"xss_confirmed", "session_cookie_present", "web_target_present"})

    # URL parameters — injectable candidates
    if any(token in text for token in ("?uid=", "?id=", "?q=", "?search=", "?page=", "?name=",
                                        "injectable_parameter", "snippets.gtl")):
        signals.add("injectable_parameter")
    if "sql_error_pattern" in lower or "sql error" in lower or "syntax error" in lower:
        signals.add("sql_error_pattern")

    # Session / auth signals from httpx cookies or headers
    if any(token in lower for token in ("session_cookie_present", "session cookie", '"session"', '"sid"',
                                         '"jsessionid"', '"phpsessid"', "set-cookie: session",
                                         '"cookies": [{')):
        signals.add("session_cookie_present")
    if any(token in lower for token in ("jwt", "bearer", "authorization:", "access_token", "id_token")):
        signals.add("jwt_in_response")

    # API endpoints from discovered links
    if any(token in lower for token in ("/api/", "/v1/", "/rest/", "/json", ".json", "content-type: application/json",
                                         '"content_type": "application/json"')):
        signals.add("api_endpoint_present")

    # TLS signals — only set when crypto-audit output is present, NOT from target URL alone
    if any(token in lower for token in ("tls_service_present", "certificate_present",
                                         '"cipher_suite"', '"tls_version"', '"certificate":')):
        signals.update({"tls_service_present", "certificate_present"})

    return signals


def _matched_triggers(data: dict[str, Any], signals: set[str]) -> list[str]:
    triggers = set(_normalized_strings(data.get("triggers")))
    weak_triggers = set(_normalized_strings(data.get("weak_triggers")))
    return sorted((triggers | weak_triggers) & signals)


def _source_ids_for_runner(
    runner_node: dict[str, Any],
    hypotheses: list[Any],
    edges: list[dict[str, Any]],
) -> list[str]:
    source_ids = {runner_node["id"]}
    runner = str(runner_node.get("source_id") or "")
    for hypothesis in hypotheses:
        if not isinstance(hypothesis, dict):
            continue
        for candidate in _as_list(hypothesis.get("safe_next_observation_candidates")):
            if isinstance(candidate, dict) and candidate.get("runner") == runner:
                source_ids.update(str(item) for item in _as_list(candidate.get("source_ids")) if str(item))
                source_ids.update(str(item) for item in _as_list(hypothesis.get("source_ids")) if str(item))
    for edge in edges:
        if edge.get("target") == runner_node["id"] or edge.get("source") == runner_node["id"]:
            source_ids.add(str(edge.get("source")))
            source_ids.add(str(edge.get("target")))
    return sorted(source_ids)


def _runner_hypothesis_confidence(runner: str, hypotheses: list[Any]) -> float:
    confidence = 0.0
    for hypothesis in hypotheses:
        if not isinstance(hypothesis, dict):
            continue
        for candidate in _as_list(hypothesis.get("safe_next_observation_candidates")):
            if isinstance(candidate, dict) and candidate.get("runner") == runner:
                try:
                    confidence = max(confidence, float(hypothesis.get("confidence") or 0.0))
                except (TypeError, ValueError):
                    continue
    return confidence


def _selector_confidence(
    *,
    hypothesis_confidence: float,
    matched_triggers: list[str],
    missing_prerequisites: list[str],
    target_present: bool,
) -> float:
    confidence = max(0.18, hypothesis_confidence)
    if matched_triggers:
        confidence = max(confidence, min(0.9, 0.58 + len(matched_triggers) * 0.12))
    if not target_present:
        confidence = min(confidence, 0.25)
    if missing_prerequisites:
        confidence = min(confidence, 0.42)
    return round(confidence, 2)


def _expected_proof_value(
    *,
    confidence: float,
    expected_evidence: list[str],
    cost: str,
    risk_tier: str,
    targeted_evidence: bool,
) -> float:
    value = confidence + min(0.2, len(expected_evidence) * 0.04)
    if targeted_evidence:
        value += 0.1
    value -= COST_WEIGHT.get(str(cost).lower(), COST_WEIGHT["medium"])
    value -= RISK_WEIGHT.get(str(risk_tier).lower(), RISK_WEIGHT["active"])
    return round(max(0.0, min(1.0, value)), 2)


def _decision_for_runner(
    *,
    runner: str,
    risk_tier: str,
    required_approvals: int,
    confidence: float,
    matched_triggers: list[str],
    missing_prerequisites: list[str],
    target_present: bool,
    already_tested: bool,
    allow_active_without_review: bool,
) -> tuple[str, list[str]]:
    blockers: list[str] = []
    if already_tested:
        return "SKIP", ["runner and target already have stored task/proposal evidence"]
    if not target_present:
        return "WAIT", ["no approved target is available for this runner"]
    if missing_prerequisites:
        return "WAIT", [f"missing prerequisite: {item}" for item in missing_prerequisites]
    if not matched_triggers and runner not in LOW_IMPACT_AUTO_TOOLS:
        return "SKIP", ["no matching evidence trigger is present in the graph"]
    # Low-impact auto tools (httpx, nmap, easm-discover) are safe discovery runners
    # that always get RUN regardless of risk_tier label.
    if runner in LOW_IMPACT_AUTO_TOOLS:
        return "RUN", []
    if risk_tier in {"active", "intrusive"} or required_approvals > 0:
        if allow_active_without_review:
            return "RUN", []
        return "APPROVAL", ["active or intrusive runner requires the existing approval flow"]
    if confidence < 0.5:
        return "WAIT", ["confidence is too low for a next action"]
    return "RUN", blockers


def _action_rationale(
    *,
    runner: str,
    decision: str,
    matched_triggers: list[str],
    missing_prerequisites: list[str],
    blocker_reasons: list[str],
) -> str:
    if decision == "WAIT":
        return (
            f"{runner} is waiting because "
            + (", ".join(blocker_reasons) or f"missing prerequisites: {', '.join(missing_prerequisites)}")
        )
    if decision == "SKIP":
        return f"{runner} is skipped because {', '.join(blocker_reasons) or 'no evidence trigger matched'}."
    evidence = ", ".join(matched_triggers) if matched_triggers else "stored approved-scope evidence"
    if decision == "APPROVAL":
        return f"{runner} is the next best observation candidate from {evidence}, pending approval."
    return f"{runner} is the next best low-impact observation candidate from {evidence}."


def _blocker_reason_ids(
    *,
    decision: str,
    blocker_reasons: list[str],
    missing_prerequisites: list[str],
) -> list[str]:
    if decision == "APPROVAL":
        return []
    ids: list[str] = []
    for prerequisite in missing_prerequisites:
        ids.append(f"missing_prerequisite:{prerequisite}")
    for reason in blocker_reasons:
        lowered = reason.lower()
        if "already have stored" in lowered:
            ids.append("already_tested")
        elif "no approved target" in lowered:
            ids.append("no_approved_target")
        elif "no matching evidence trigger" in lowered:
            ids.append("no_matching_trigger")
        elif "confidence is too low" in lowered:
            ids.append("low_confidence")
        elif "missing runner contract data" in lowered:
            ids.append("missing_runner_contract")
    return sorted(set(ids))


def _selector_tier(runner: str, data: dict[str, Any]) -> str:
    risk_tier = str(data.get("risk_tier") or "active").strip().lower()
    required_approvals = int(data.get("required_approvals") or 0)
    if risk_tier == "intrusive" or required_approvals >= 2:
        return "intrusive"
    if required_approvals >= 1:
        return "active"
    if runner in LOW_IMPACT_AUTO_TOOLS:
        return "passive"
    return risk_tier if risk_tier in {"passive", "active"} else "active"


def _target_allowed(scope: Scope, target: str) -> bool:
    if not target:
        return False
    if target_value_is_allowed(scope.denylist_json, target):
        return False
    return target_value_is_allowed(scope.allowlist_json, target)


def _normalized_strings(value: Any) -> list[str]:
    normalized: list[str] = []
    seen: set[str] = set()
    for item in _as_list(value):
        candidate = str(item or "").strip()
        if candidate and candidate not in seen:
            normalized.append(candidate)
            seen.add(candidate)
    return normalized


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, tuple | set):
        return list(value)
    if value is None:
        return []
    return [value]
