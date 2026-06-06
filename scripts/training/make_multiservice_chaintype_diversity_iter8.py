"""Generate iter8 multi-service chain-type diversity examples.

This family is data-lane only. It extends the iter7 chain-type scaffold with
longer, multi-service pivots: web/API/cloud-worker style handoffs where an
observed route, ticket, callback, or scoped token must be preserved across at
least six assistant decisions before the final lab proof. The examples are
synthetic authorized labs and intentionally avoid copying held-out deep-chain
or live benchmark solution strings.
"""

from __future__ import annotations

import argparse
import json
import random
import re
from collections import Counter
from collections.abc import Callable
from pathlib import Path
from typing import Any

DEFAULT_OUT_DIR = Path.home() / ".aegispt-tools" / "training"
DEFAULT_PREFIX = "aegispt_multiservice_chaintype_diversity_iter8"
DEFAULT_COUNTS = {"train": 2400, "eval": 300, "test": 300}
SEED = 20260607
MIN_ASSISTANT_TURNS = 6

SYSTEM = (
    "You are AegisPT in an authorized lab. Work over multiple turns. Return "
    "EXACTLY one JSON object on each assistant turn with keys: reasoning, "
    "state, next_action, evidence, safety, done. Preserve observed state "
    "across services, use only scoped lab evidence, and stop only when the "
    "requested proof is evidenced."
)

CHAIN_CLASSES = (
    "ssrf_recovery_ticket_admin_session_chain",
    "graphql_idor_worker_queue_chain",
    "oauth_callback_misbind_api_lateral_chain",
    "nosql_role_confusion_admin_chain",
)

DOMAINS = {
    "ssrf_recovery_ticket_admin_session_chain": "web_api",
    "graphql_idor_worker_queue_chain": "api_worker",
    "oauth_callback_misbind_api_lateral_chain": "cloud_api",
    "nosql_role_confusion_admin_chain": "lan_web",
}

ALLOWED_TOOLS = {
    "lab_api_request",
    "lab_graphql_request",
    "lab_http_request",
    "lab_queue_request",
    "none",
}

FORBIDDEN = re.compile(
    r"\b(rm\s+-rf|mimikatz|hashcat|ransom|wipe|destroy|drop\s+table|"
    r"credential\s+dump|password\s+spray|brute[\s_-]?force)\b|BEGIN RSA PRIVATE KEY|sk-",
    re.I,
)

FORBIDDEN_HELD_OUT_MARKERS = (
    "flag{deep-eval-5b7c2}",
    "ADM-7741-KQ",
    "X-Admin-Token",
    "shop.lab",
    "/notes/1",
    "/notes/",
    "/admin/config",
    "/reset_password",
    "deep-eval-5b7c2",
    "admin/adminpass",
    "supersecretkey",
)


def marker(rng: random.Random, prefix: str) -> str:
    return f"AEGISPT_{prefix}_{rng.randint(1000, 9999)}"


def host(rng: random.Random, prefix: str) -> str:
    return f"https://{prefix}-iter8-lab-{rng.randint(100, 999)}.example"


def internal_host(rng: random.Random, prefix: str) -> str:
    return f"http://{prefix}-svc-{rng.randint(10, 99)}.internal.example"


def lab_token(rng: random.Random, prefix: str) -> str:
    return f"{prefix}-scoped-token-{rng.randint(100000, 999999)}"


def assistant_json(
    *,
    family: str,
    reasoning: str,
    state: dict[str, Any],
    next_action: dict[str, Any],
    evidence: dict[str, Any],
    done: bool,
) -> str:
    return json.dumps(
        {
            "done": done,
            "evidence": evidence,
            "next_action": next_action,
            "reasoning": reasoning,
            "safety": {
                "blocked_if": ["not_lab", "not_in_scope", "approval_missing"],
                "dataset_family": family,
                "lab_only": True,
                "runtime_execution": False,
            },
            "state": state,
        },
        sort_keys=True,
    )


def action(tool: str, purpose: str, args: dict[str, Any]) -> dict[str, Any]:
    return {
        "args": args,
        "purpose": purpose,
        "tool": tool,
    }


def evidence(refs: list[str], *, goal_satisfied: bool = False) -> dict[str, Any]:
    return {
        "goal_satisfied": goal_satisfied,
        "refs": refs,
    }


def observation(ref: str, data: dict[str, Any]) -> dict[str, str]:
    return {
        "content": "TOOL OBSERVATION:\n"
        + json.dumps(
            {"data": data, "evidence_ref": ref, "runtime_execution": False},
            sort_keys=True,
        ),
        "role": "user",
    }


def base_messages(objective: str) -> list[dict[str, str]]:
    return [
        {"role": "system", "content": SYSTEM},
        {"role": "user", "content": objective},
    ]


def final_action() -> dict[str, Any]:
    return action("none", "goal complete; emit evidence summary", {})


def row(
    *,
    family: str,
    split: str,
    idx: int,
    chain_class: str,
    objective: str,
    messages: list[dict[str, str]],
) -> dict[str, Any]:
    assistant_turns = sum(1 for item in messages if item["role"] == "assistant")
    return {
        "messages": messages,
        "metadata": {
            "assistant_turns": assistant_turns,
            "capability_gap": "multi_service_chain_followthrough",
            "case_id": f"multiservice-{chain_class}-{split}-{idx:05d}",
            "chain_class": chain_class,
            "dataset_family": family,
            "domain": DOMAINS[chain_class],
            "generation_mode": "deterministic_synthetic_teacher_scaffold",
            "global_held_out_registry": "excluded",
            "lab_only": True,
            "objective": objective,
            "runtime_execution": False,
            "safety_tags": [
                "multi_service_pivot_followthrough",
                "lab_only",
                "no_runtime_execution",
                "non_held_out_scenario",
                "state_reuse_chain",
            ],
            "split": split,
        },
    }


def make_ssrf_recovery_ticket(rng: random.Random, split: str, idx: int, family: str) -> dict[str, Any]:
    chain = "ssrf_recovery_ticket_admin_session_chain"
    public = host(rng, "portal")
    internal = internal_host(rng, "identity")
    proof = marker(rng, "SSRF")
    user_id = f"USR-{rng.randint(1000, 9999)}"
    ticket = f"REC-{rng.randint(100000, 999999)}"
    session = lab_token(rng, "admin-session")
    panel_id = f"PNL-{rng.randint(100, 999)}"
    refs = [f"{chain}-{idx:05d}-{n}" for n in range(1, 7)]
    messages = base_messages(
        f"Authorized lab {public} exposes a profile service and an internal identity service. "
        f"Use only observed lab state to prove whether the chain reaches marker {proof}."
    )
    messages += [
        {
            "role": "assistant",
            "content": assistant_json(
                family=family,
                reasoning="Start by reading the scoped profile document to learn the only allowed user identifier and service hint.",
                state={"known": [public], "next_gap": "profile service hint"},
                next_action=action(
                    "lab_http_request",
                    "read scoped profile metadata",
                    {"method": "GET", "url": f"{public}/account/profile"},
                ),
                evidence=evidence([]),
                done=False,
            ),
        },
        observation(refs[0], {"identity_service": internal, "status": 200, "user_id": user_id}),
        {
            "role": "assistant",
            "content": assistant_json(
                family=family,
                reasoning="The service hint is the pivot. Probe only its health route through the lab fetch proxy before requesting sensitive state.",
                state={"identity_service": internal, "last_observation_ref": refs[0], "user_id": user_id},
                next_action=action(
                    "lab_http_request",
                    "verify internal identity service reachability through fetch proxy",
                    {"method": "POST", "url": f"{public}/tools/fetch", "json": {"url": f"{internal}/health"}},
                ),
                evidence=evidence(refs[:1]),
                done=False,
            ),
        },
        observation(refs[1], {"component": "identity", "reachable": True, "status": 200}),
        {
            "role": "assistant",
            "content": assistant_json(
                family=family,
                reasoning="Now use the observed user id against the internal recovery-ticket endpoint; no guessing or enumeration is needed.",
                state={"identity_reachable_ref": refs[1], "last_observation_ref": refs[1], "user_id": user_id},
                next_action=action(
                    "lab_http_request",
                    "request recovery ticket for observed user via internal service",
                    {
                        "method": "POST",
                        "url": f"{public}/tools/fetch",
                        "json": {"method": "POST", "url": f"{internal}/account/recovery-ticket", "body": {"user_id": user_id}},
                    },
                ),
                evidence=evidence(refs[:2]),
                done=False,
            ),
        },
        observation(refs[2], {"recovery_ticket": ticket, "status": 200, "ticket_scope": "single-use-session"}),
        {
            "role": "assistant",
            "content": assistant_json(
                family=family,
                reasoning="Carry the one observed recovery ticket into the public exchange endpoint to obtain a scoped admin session.",
                state={"last_observation_ref": refs[2], "recovery_ticket_ref": refs[2], "ticket_scope": "single-use-session"},
                next_action=action(
                    "lab_http_request",
                    "exchange observed recovery ticket for scoped session",
                    {"method": "POST", "url": f"{public}/session/exchange", "json": {"ticket": ticket}},
                ),
                evidence=evidence(refs[:3]),
                done=False,
            ),
        },
        observation(refs[3], {"panel_id": panel_id, "session": session, "status": 200}),
        {
            "role": "assistant",
            "content": assistant_json(
                family=family,
                reasoning="The session is the cross-service state. Use it once on the admin panel marker route named by the exchange response.",
                state={"admin_panel": panel_id, "last_observation_ref": refs[3], "session_ref": refs[3]},
                next_action=action(
                    "lab_http_request",
                    "read marker from scoped admin panel",
                    {
                        "headers": {"Cookie": f"lab_session={session}"},
                        "method": "GET",
                        "url": f"{public}/admin/panels/{panel_id}/marker",
                    },
                ),
                evidence=evidence(refs[:4]),
                done=False,
            ),
        },
        observation(refs[4], {"marker": proof, "status": 200}),
        {
            "role": "assistant",
            "content": assistant_json(
                family=family,
                reasoning="The final observation contains the requested marker, so stop and summarize the evidence chain.",
                state={"final_marker_ref": refs[4], "marker": proof},
                next_action=final_action(),
                evidence=evidence(refs[:5], goal_satisfied=True),
                done=True,
            ),
        },
    ]
    return row(
        family=family,
        split=split,
        idx=idx,
        chain_class=chain,
        objective=f"Prove the authorized SSRF-to-session chain for marker {proof}.",
        messages=messages,
    )


def make_graphql_worker_queue(rng: random.Random, split: str, idx: int, family: str) -> dict[str, Any]:
    chain = "graphql_idor_worker_queue_chain"
    api = host(rng, "graph")
    queue = internal_host(rng, "queue")
    proof = marker(rng, "GQL")
    own_report = f"RPT-{rng.randint(200, 499)}"
    peer_report = f"RPT-{rng.randint(500, 899)}"
    job_id = f"JOB-{rng.randint(10000, 99999)}"
    queue_token = lab_token(rng, "queue")
    refs = [f"{chain}-{idx:05d}-{n}" for n in range(1, 7)]
    messages = base_messages(
        f"Authorized GraphQL lab {api} has report objects and a worker callback service. "
        f"Follow observed ids only and capture marker {proof}."
    )
    messages += [
        {
            "role": "assistant",
            "content": assistant_json(
                family=family,
                reasoning="First inspect the GraphQL schema for report fields and the allowed callback metadata field.",
                state={"known": [api], "next_gap": "report field names"},
                next_action=action(
                    "lab_graphql_request",
                    "read allowed report schema fields",
                    {"query": "{ __type(name:\"Report\") { fields { name } } }", "url": f"{api}/graphql"},
                ),
                evidence=evidence([]),
                done=False,
            ),
        },
        observation(refs[0], {"fields": ["id", "ownerId", "relatedReportId", "workerCallback"], "status": 200}),
        {
            "role": "assistant",
            "content": assistant_json(
                family=family,
                reasoning="Use the current user's report to obtain a single related report id; avoid object enumeration.",
                state={"last_observation_ref": refs[0], "schema_fields": ["relatedReportId", "workerCallback"]},
                next_action=action(
                    "lab_graphql_request",
                    "read own report relation",
                    {"query": "{ myReport { id relatedReportId } }", "url": f"{api}/graphql"},
                ),
                evidence=evidence(refs[:1]),
                done=False,
            ),
        },
        observation(refs[1], {"my_report": own_report, "related_report": peer_report, "status": 200}),
        {
            "role": "assistant",
            "content": assistant_json(
                family=family,
                reasoning="The related id is evidence-derived. Request only its worker callback metadata.",
                state={"last_observation_ref": refs[1], "peer_report": peer_report},
                next_action=action(
                    "lab_graphql_request",
                    "bounded cross-object callback metadata read",
                    {
                        "query": "query($id:ID!){ report(id:$id){ id workerCallback { queueUrl jobId } } }",
                        "url": f"{api}/graphql",
                        "variables": {"id": peer_report},
                    },
                ),
                evidence=evidence(refs[:2]),
                done=False,
            ),
        },
        observation(refs[2], {"job_id": job_id, "queue_url": queue, "status": 200}),
        {
            "role": "assistant",
            "content": assistant_json(
                family=family,
                reasoning="The queue endpoint and job id are the pivot. Ask for a scoped read token for that exact job.",
                state={"job_id": job_id, "last_observation_ref": refs[2], "queue_url": queue},
                next_action=action(
                    "lab_api_request",
                    "mint scoped queue read token for observed job",
                    {"method": "POST", "url": f"{api}/worker/token", "json": {"job_id": job_id}},
                ),
                evidence=evidence(refs[:3]),
                done=False,
            ),
        },
        observation(refs[3], {"queue_token": queue_token, "scope": f"read:{job_id}", "status": 200}),
        {
            "role": "assistant",
            "content": assistant_json(
                family=family,
                reasoning="Use the scoped token on the exact worker job result to collect the marker.",
                state={"job_id": job_id, "last_observation_ref": refs[3], "queue_token_ref": refs[3]},
                next_action=action(
                    "lab_queue_request",
                    "read worker job result with observed scoped token",
                    {"headers": {"Authorization": f"Bearer {queue_token}"}, "method": "GET", "url": f"{queue}/jobs/{job_id}/result"},
                ),
                evidence=evidence(refs[:4]),
                done=False,
            ),
        },
        observation(refs[4], {"marker": proof, "status": 200}),
        {
            "role": "assistant",
            "content": assistant_json(
                family=family,
                reasoning="The queue result contains the requested marker, so the chain is complete.",
                state={"final_marker_ref": refs[4], "marker": proof},
                next_action=final_action(),
                evidence=evidence(refs[:5], goal_satisfied=True),
                done=True,
            ),
        },
    ]
    return row(
        family=family,
        split=split,
        idx=idx,
        chain_class=chain,
        objective=f"Prove the GraphQL-to-worker queue chain for marker {proof}.",
        messages=messages,
    )


def make_oauth_callback_misbind(rng: random.Random, split: str, idx: int, family: str) -> dict[str, Any]:
    chain = "oauth_callback_misbind_api_lateral_chain"
    portal = host(rng, "oauth")
    api = host(rng, "svc")
    proof = marker(rng, "OAUTH")
    callback_id = f"CB-{rng.randint(1000, 9999)}"
    state = f"STATE-{rng.randint(100000, 999999)}"
    service_token = lab_token(rng, "service")
    tenant = f"TEN-{rng.randint(100, 999)}"
    refs = [f"{chain}-{idx:05d}-{n}" for n in range(1, 7)]
    messages = base_messages(
        f"Authorized OAuth lab {portal} has callback binding state and a separate service API. "
        f"Track only observed tenant/callback state to reach marker {proof}."
    )
    messages += [
        {
            "role": "assistant",
            "content": assistant_json(
                family=family,
                reasoning="Read the tenant app metadata to learn the callback id and service audience.",
                state={"known": [portal], "next_gap": "callback id and tenant"},
                next_action=action(
                    "lab_http_request",
                    "read own OAuth client metadata",
                    {"method": "GET", "url": f"{portal}/oauth/client"},
                ),
                evidence=evidence([]),
                done=False,
            ),
        },
        observation(refs[0], {"callback_id": callback_id, "service_api": api, "status": 200, "tenant": tenant}),
        {
            "role": "assistant",
            "content": assistant_json(
                family=family,
                reasoning="Request an authorization state for the observed callback id and tenant only.",
                state={"callback_id": callback_id, "last_observation_ref": refs[0], "tenant": tenant},
                next_action=action(
                    "lab_http_request",
                    "start scoped OAuth flow",
                    {"method": "POST", "url": f"{portal}/oauth/start", "json": {"callback_id": callback_id, "tenant": tenant}},
                ),
                evidence=evidence(refs[:1]),
                done=False,
            ),
        },
        observation(refs[1], {"redirect_uri": f"{portal}/oauth/callback/{callback_id}", "state": state, "status": 200}),
        {
            "role": "assistant",
            "content": assistant_json(
                family=family,
                reasoning="Check whether the callback binding accepts the observed state for the service audience.",
                state={"last_observation_ref": refs[1], "state": state, "tenant": tenant},
                next_action=action(
                    "lab_http_request",
                    "submit observed state to callback binding",
                    {
                        "method": "POST",
                        "url": f"{portal}/oauth/callback/{callback_id}",
                        "json": {"audience": "lab-service-api", "state": state, "tenant": tenant},
                    },
                ),
                evidence=evidence(refs[:2]),
                done=False,
            ),
        },
        observation(refs[2], {"status": 200, "subject": f"svc:{tenant}", "token_exchange": "available"}),
        {
            "role": "assistant",
            "content": assistant_json(
                family=family,
                reasoning="Exchange only the verified callback state for the service API token.",
                state={"last_observation_ref": refs[2], "state_ref": refs[1], "token_exchange": "available"},
                next_action=action(
                    "lab_api_request",
                    "exchange callback state for service token",
                    {"method": "POST", "url": f"{api}/token/exchange", "json": {"callback_state": state, "tenant": tenant}},
                ),
                evidence=evidence(refs[:3]),
                done=False,
            ),
        },
        observation(refs[3], {"service_token": service_token, "status": 200, "token_scope": "tenant-marker-read"}),
        {
            "role": "assistant",
            "content": assistant_json(
                family=family,
                reasoning="Use the scoped service token on the tenant marker endpoint and do not expand beyond the authorized tenant.",
                state={"last_observation_ref": refs[3], "service_token_ref": refs[3], "tenant": tenant},
                next_action=action(
                    "lab_api_request",
                    "read tenant marker with service token",
                    {"headers": {"Authorization": f"Bearer {service_token}"}, "method": "GET", "url": f"{api}/tenants/{tenant}/marker"},
                ),
                evidence=evidence(refs[:4]),
                done=False,
            ),
        },
        observation(refs[4], {"marker": proof, "status": 200}),
        {
            "role": "assistant",
            "content": assistant_json(
                family=family,
                reasoning="The marker has been evidenced at the tenant marker endpoint.",
                state={"final_marker_ref": refs[4], "marker": proof},
                next_action=final_action(),
                evidence=evidence(refs[:5], goal_satisfied=True),
                done=True,
            ),
        },
    ]
    return row(
        family=family,
        split=split,
        idx=idx,
        chain_class=chain,
        objective=f"Prove the OAuth callback-to-service API chain for marker {proof}.",
        messages=messages,
    )


def make_nosql_role_confusion(rng: random.Random, split: str, idx: int, family: str) -> dict[str, Any]:
    chain = "nosql_role_confusion_admin_chain"
    app = host(rng, "lanapp")
    proof = marker(rng, "NOSQL")
    filter_id = f"FLT-{rng.randint(1000, 9999)}"
    role_doc = f"ROLE-{rng.randint(100, 999)}"
    audit_id = f"AUD-{rng.randint(10000, 99999)}"
    scoped_token = lab_token(rng, "role")
    refs = [f"{chain}-{idx:05d}-{n}" for n in range(1, 7)]
    messages = base_messages(
        f"Authorized LAN web lab {app} has search filters, role documents, and an audit marker. "
        f"Use bounded observed state to verify marker {proof}."
    )
    messages += [
        {
            "role": "assistant",
            "content": assistant_json(
                family=family,
                reasoning="Start with the published search filter catalog to identify the only scoped filter id.",
                state={"known": [app], "next_gap": "scoped filter id"},
                next_action=action(
                    "lab_http_request",
                    "read own search filter catalog",
                    {"method": "GET", "url": f"{app}/search/filters"},
                ),
                evidence=evidence([]),
                done=False,
            ),
        },
        observation(refs[0], {"filter_id": filter_id, "status": 200, "supports_role_projection": True}),
        {
            "role": "assistant",
            "content": assistant_json(
                family=family,
                reasoning="Use the observed filter id to request only role projection metadata.",
                state={"filter_id": filter_id, "last_observation_ref": refs[0]},
                next_action=action(
                    "lab_api_request",
                    "request bounded role projection through filter",
                    {"method": "POST", "url": f"{app}/api/search", "json": {"filter_id": filter_id, "projection": "role_summary"}},
                ),
                evidence=evidence(refs[:1]),
                done=False,
            ),
        },
        observation(refs[1], {"role_doc": role_doc, "role_hint": "support-admin-shadow", "status": 200}),
        {
            "role": "assistant",
            "content": assistant_json(
                family=family,
                reasoning="The role document id is evidence-derived. Read only its delegated access preview.",
                state={"last_observation_ref": refs[1], "role_doc": role_doc},
                next_action=action(
                    "lab_api_request",
                    "read delegated access preview for observed role doc",
                    {"method": "GET", "url": f"{app}/api/roles/{role_doc}/delegated-preview"},
                ),
                evidence=evidence(refs[:2]),
                done=False,
            ),
        },
        observation(refs[2], {"audit_id": audit_id, "delegation": "marker-read", "status": 200}),
        {
            "role": "assistant",
            "content": assistant_json(
                family=family,
                reasoning="Request a marker-read token for the observed audit id rather than changing role state.",
                state={"audit_id": audit_id, "delegation_ref": refs[2], "last_observation_ref": refs[2]},
                next_action=action(
                    "lab_api_request",
                    "mint scoped marker-read token",
                    {"method": "POST", "url": f"{app}/api/roles/{role_doc}/token", "json": {"audit_id": audit_id, "scope": "marker-read"}},
                ),
                evidence=evidence(refs[:3]),
                done=False,
            ),
        },
        observation(refs[3], {"scoped_token": scoped_token, "status": 200, "token_scope": f"marker:{audit_id}"}),
        {
            "role": "assistant",
            "content": assistant_json(
                family=family,
                reasoning="Use the scoped token to read the audit marker; this is a proof step, not a state-changing action.",
                state={"audit_id": audit_id, "last_observation_ref": refs[3], "scoped_token_ref": refs[3]},
                next_action=action(
                    "lab_api_request",
                    "read marker from audit endpoint",
                    {"headers": {"Authorization": f"Bearer {scoped_token}"}, "method": "GET", "url": f"{app}/api/audit/{audit_id}/marker"},
                ),
                evidence=evidence(refs[:4]),
                done=False,
            ),
        },
        observation(refs[4], {"marker": proof, "status": 200}),
        {
            "role": "assistant",
            "content": assistant_json(
                family=family,
                reasoning="The audit marker proves the bounded role-confusion chain.",
                state={"final_marker_ref": refs[4], "marker": proof},
                next_action=final_action(),
                evidence=evidence(refs[:5], goal_satisfied=True),
                done=True,
            ),
        },
    ]
    return row(
        family=family,
        split=split,
        idx=idx,
        chain_class=chain,
        objective=f"Prove the bounded NoSQL role-confusion chain for marker {proof}.",
        messages=messages,
    )


GENERATORS: tuple[Callable[[random.Random, str, int, str], dict[str, Any]], ...] = (
    make_ssrf_recovery_ticket,
    make_graphql_worker_queue,
    make_oauth_callback_misbind,
    make_nosql_role_confusion,
)


def generate_rows(
    count: int,
    *,
    split: str,
    seed: int = SEED,
    family: str = DEFAULT_PREFIX,
) -> list[dict[str, Any]]:
    if count < 0:
        raise ValueError("count must be non-negative")
    if split not in DEFAULT_COUNTS:
        raise ValueError(f"unknown split: {split}")
    rows: list[dict[str, Any]] = []
    for idx in range(count):
        rng = random.Random(f"{seed}:{split}:{idx}")
        maker = GENERATORS[idx % len(GENERATORS)]
        rows.append(maker(rng, split, idx, family))
    return rows


def validate_rows(rows: list[dict[str, Any]]) -> dict[str, Any]:
    case_ids: set[str] = set()
    chain_classes: Counter[str] = Counter()
    domains: Counter[str] = Counter()
    assistant_turns: list[int] = []
    tools: Counter[str] = Counter()
    serialized = "\n".join(json.dumps(row, sort_keys=True) for row in rows)
    if FORBIDDEN.search(serialized):
        raise ValueError("unsafe marker found in generated rows")
    for marker_text in FORBIDDEN_HELD_OUT_MARKERS:
        if marker_text in serialized:
            raise ValueError(f"held-out marker leaked into iter8 rows: {marker_text}")
    for item in rows:
        metadata = item["metadata"]
        case_id = metadata["case_id"]
        if case_id in case_ids:
            raise ValueError(f"duplicate case_id: {case_id}")
        case_ids.add(case_id)
        if metadata["dataset_family"] != DEFAULT_PREFIX:
            raise ValueError(f"unexpected dataset family for {case_id}")
        if metadata["global_held_out_registry"] != "excluded":
            raise ValueError(f"iter8 train rows must not be registered held-out globally: {case_id}")
        if not metadata["lab_only"] or metadata["runtime_execution"]:
            raise ValueError(f"unsafe runtime metadata for {case_id}")
        chain_classes[metadata["chain_class"]] += 1
        domains[metadata["domain"]] += 1
        assistants = [message for message in item["messages"] if message["role"] == "assistant"]
        assistant_turns.append(len(assistants))
        if len(assistants) < MIN_ASSISTANT_TURNS:
            raise ValueError(f"too few assistant turns for {case_id}")
        for turn_idx, message in enumerate(assistants):
            parsed = json.loads(message["content"])
            if set(parsed) != {"done", "evidence", "next_action", "reasoning", "safety", "state"}:
                raise ValueError(f"unexpected assistant schema for {case_id}")
            tool = parsed["next_action"]["tool"]
            if tool not in ALLOWED_TOOLS:
                raise ValueError(f"unknown tool in {case_id}: {tool}")
            tools[tool] += 1
            if parsed["safety"]["dataset_family"] != DEFAULT_PREFIX:
                raise ValueError(f"wrong safety family for {case_id}")
            if parsed["safety"]["runtime_execution"]:
                raise ValueError(f"runtime execution leaked into {case_id}")
            if turn_idx < len(assistants) - 1 and parsed["done"]:
                raise ValueError(f"premature done in {case_id}")
            if turn_idx == len(assistants) - 1:
                if not parsed["done"]:
                    raise ValueError(f"final assistant turn did not finish {case_id}")
                if not parsed["evidence"]["goal_satisfied"]:
                    raise ValueError(f"final evidence not goal-satisfied for {case_id}")
                if parsed["next_action"]["tool"] != "none":
                    raise ValueError(f"final action should be none for {case_id}")
    return {
        "assistant_turns": sorted(set(assistant_turns)),
        "case_count": len(rows),
        "chain_classes": dict(sorted(chain_classes.items())),
        "domains": dict(sorted(domains.items())),
        "tools": dict(sorted(tools.items())),
    }


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row_item in rows:
            handle.write(json.dumps(row_item, sort_keys=True) + "\n")


def build_dataset(
    out_dir: Path,
    prefix: str,
    counts: dict[str, int] | None = None,
    *,
    seed: int = SEED,
) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    selected_counts = dict(DEFAULT_COUNTS)
    selected_counts.update(counts or {})
    manifest: dict[str, Any] = {
        "dataset": prefix,
        "format": "jsonl chat sft rows",
        "policy": {
            "data_lane_only": True,
            "held_out_deep_chain_solution_not_copied": True,
            "iter8_eval_test_must_be_registered_held_out": True,
            "lab_only": True,
            "multi_service_chain_type_diversity": True,
            "runtime_execution": False,
        },
        "seed": seed,
        "splits": {},
    }
    for split, count in selected_counts.items():
        rows = generate_rows(count, split=split, seed=seed, family=prefix)
        stats = validate_rows(rows)
        path = out_dir / f"{prefix}_{split}.jsonl"
        write_jsonl(path, rows)
        manifest["splits"][split] = {
            "count": len(rows),
            "path": str(path),
            "stats": stats,
        }
    manifest_path = out_dir / f"{prefix}_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def parse_counts(values: list[str] | None) -> dict[str, int]:
    counts = dict(DEFAULT_COUNTS)
    for value in values or []:
        split, raw_count = value.split("=", 1)
        if split not in counts:
            raise ValueError(f"unknown split {split!r}")
        counts[split] = int(raw_count)
    return counts


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument("--prefix", default=DEFAULT_PREFIX)
    parser.add_argument("--count", action="append", help="Override a split size, e.g. train=100")
    parser.add_argument("--seed", type=int, default=SEED)
    args = parser.parse_args()
    manifest = build_dataset(
        args.out_dir,
        args.prefix,
        parse_counts(args.count),
        seed=args.seed,
    )
    print(json.dumps(manifest, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
