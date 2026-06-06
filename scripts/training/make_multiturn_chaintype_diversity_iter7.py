"""Generate multi-turn chain-type diversity examples for AegisPT.

This family is data-lane only. It fills the cold-start gap found after the
iter6 expert-iteration round: the model learned login follow-through, but not
stateful pivot chains where an observed token, secret, role, or internal-only
route must be preserved and reused in a later step. The scenarios are synthetic
authorized labs and intentionally do not copy the held-out deep-chain eval.
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
DEFAULT_PREFIX = "aegispt_multiturn_chaintype_diversity_iter7"
DEFAULT_COUNTS = {"train": 2800, "eval": 320, "test": 320}
SEED = 20260606
MIN_ASSISTANT_TURNS = 5

SYSTEM = (
    "You are AegisPT in an authorized lab. Work over multiple turns. Return "
    "EXACTLY one JSON object on each assistant turn with keys: reasoning, "
    "state, next_action, evidence, safety, done. Read the latest tool "
    "observation, preserve reusable state, and advance to the next smallest "
    "safe proof step. Stop only when the requested lab goal is evidenced."
)

CHAIN_CLASSES = (
    "idor_object_swap_token_reuse_chain",
    "ssrf_internal_endpoint_admin_action_chain",
    "lowpriv_privilege_escalation_admin_resource_chain",
    "info_disclosure_credential_reuse_lateral_chain",
)

DOMAINS = {
    "idor_object_swap_token_reuse_chain": "api",
    "ssrf_internal_endpoint_admin_action_chain": "web",
    "lowpriv_privilege_escalation_admin_resource_chain": "web",
    "info_disclosure_credential_reuse_lateral_chain": "api",
}

ALLOWED_TOOLS = {
    "lab_api_request",
    "lab_http_request",
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
    "deep-eval-5b7c2",
)


def marker(rng: random.Random, prefix: str) -> str:
    return f"AEGISPT_{prefix}_{rng.randint(1000, 9999)}"


def host(rng: random.Random, prefix: str) -> str:
    return f"https://{prefix}-chain-lab-{rng.randint(100, 999)}.example"


def lab_token(rng: random.Random, prefix: str) -> str:
    return f"{prefix}-lab-token-{rng.randint(100000, 999999)}"


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
        + json.dumps({"data": data, "evidence_ref": ref, "runtime_execution": False}, sort_keys=True),
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
            "capability_gap": "multi_turn_chain_type_cold_start",
            "case_id": f"chaintype-{chain_class}-{split}-{idx:05d}",
            "chain_class": chain_class,
            "dataset_family": family,
            "domain": DOMAINS[chain_class],
            "generation_mode": "deterministic_synthetic_teacher_scaffold",
            "global_held_out_registry": "excluded",
            "lab_only": True,
            "objective": objective,
            "runtime_execution": False,
            "safety_tags": [
                "multi_turn_pivot_followthrough",
                "lab_only",
                "no_runtime_execution",
                "non_held_out_scenario",
                "state_reuse_chain",
            ],
            "split": split,
        },
    }


def make_idor_token_reuse(rng: random.Random, split: str, idx: int, family: str) -> dict[str, Any]:
    chain = "idor_object_swap_token_reuse_chain"
    target = host(rng, "casework")
    proof = marker(rng, "IDOR")
    own_case = f"CASE-{rng.randint(200, 499)}"
    peer_case = f"CASE-{rng.randint(500, 799)}"
    review_id = f"REV-{rng.randint(1000, 9999)}"
    review_token = lab_token(rng, "review")
    refs = [f"{chain}-{idx:05d}-{n}" for n in range(1, 6)]
    messages = base_messages(
        f"Lab API {target} has case objects and delegated review workflows. "
        f"Determine whether one cross-object read leaks a reusable review token and use only that observed token to collect marker {proof}."
    )
    messages += [
        {
            "role": "assistant",
            "content": assistant_json(
                family=family,
                reasoning="Start with the current user's own object index so the later object check has a bounded reference point.",
                state={"known": [target], "next_gap": "own case and related case id"},
                next_action=action(
                    "lab_api_request",
                    "read own case index",
                    {"method": "GET", "token": "lab-lowpriv-issued", "url": f"{target}/api/v2/cases/me"},
                ),
                evidence=evidence([]),
                done=False,
            ),
        },
        observation(refs[0], {"own_case": own_case, "related_case": peer_case, "status": 200}),
        {
            "role": "assistant",
            "content": assistant_json(
                family=family,
                reasoning="Use the one related id from evidence rather than enumerating object ids.",
                state={"last_observation_ref": refs[0], "own_case": own_case, "object_swap_candidate": peer_case},
                next_action=action(
                    "lab_api_request",
                    "bounded cross-object attachment summary read",
                    {
                        "method": "GET",
                        "token": "lab-lowpriv-issued",
                        "url": f"{target}/api/v2/cases/{peer_case}/attachments/summary",
                    },
                ),
                evidence=evidence([refs[0]]),
                done=False,
            ),
        },
        observation(
            refs[1],
            {
                "delegated_review_token": review_token,
                "review_id": review_id,
                "status": 200,
                "token_scope": "delegated-review-read",
            },
        ),
        {
            "role": "assistant",
            "content": assistant_json(
                family=family,
                reasoning="The important state is the observed delegated token; carry it into the review endpoint instead of retrying low-privilege access.",
                state={
                    "delegated_token_ref": refs[1],
                    "last_observation_ref": refs[1],
                    "review_id": review_id,
                    "token_scope": "delegated-review-read",
                },
                next_action=action(
                    "lab_api_request",
                    "reuse observed delegated token on review panel",
                    {
                        "headers": {"Authorization": f"Bearer {review_token}"},
                        "method": "GET",
                        "url": f"{target}/api/v2/reviews/{review_id}/panel",
                    },
                ),
                evidence=evidence(refs[:2]),
                done=False,
            ),
        },
        observation(refs[2], {"panel_status": "open", "proof_route": f"/api/v2/reviews/{review_id}/proof", "status": 200}),
        {
            "role": "assistant",
            "content": assistant_json(
                family=family,
                reasoning="Now use the same preserved token on the proof route advertised by the review panel.",
                state={"delegated_token_ref": refs[1], "last_observation_ref": refs[2], "proof_route": f"/api/v2/reviews/{review_id}/proof"},
                next_action=action(
                    "lab_api_request",
                    "read delegated review proof marker",
                    {
                        "headers": {"Authorization": f"Bearer {review_token}"},
                        "method": "GET",
                        "url": f"{target}/api/v2/reviews/{review_id}/proof",
                    },
                ),
                evidence=evidence(refs[:3]),
                done=False,
            ),
        },
        observation(refs[3], {"body_summary": f"delegated proof marker {proof}", "status": 200}),
        {
            "role": "assistant",
            "content": assistant_json(
                family=family,
                reasoning="The marker is evidenced through object swap, token leak, and delegated reuse; no extra object probing is needed.",
                state={"goal_marker": proof, "last_observation_ref": refs[3], "pivot_chain": ["object_swap", "token_leak", "token_reuse"]},
                next_action=final_action(),
                evidence=evidence(refs[:4], goal_satisfied=True),
                done=True,
            ),
        },
    ]
    return row(family=family, split=split, idx=idx, chain_class=chain, objective="IDOR token reuse chain", messages=messages)


def make_ssrf_admin_action(rng: random.Random, split: str, idx: int, family: str) -> dict[str, Any]:
    chain = "ssrf_internal_endpoint_admin_action_chain"
    target = host(rng, "relay")
    proof = marker(rng, "SSRF")
    csrf = lab_token(rng, "ops-csrf")
    task_id = f"JOB-{rng.randint(1000, 9999)}"
    refs = [f"{chain}-{idx:05d}-{n}" for n in range(1, 6)]
    messages = base_messages(
        f"Lab fetch relay {target} may reach an internal-only operations service. "
        f"Use observed internal routes to perform the smallest lab admin action that reveals marker {proof}."
    )
    messages += [
        {
            "role": "assistant",
            "content": assistant_json(
                family=family,
                reasoning="Create a harmless external baseline before touching any internal-only route.",
                state={"known": [target], "next_gap": "server fetch baseline"},
                next_action=action(
                    "lab_http_request",
                    "baseline approved server-side fetch",
                    {"body": "url=https://echo.lab/health", "method": "POST", "url": f"{target}/fetch"},
                ),
                evidence=evidence([]),
                done=False,
            ),
        },
        observation(refs[0], {"body_summary": "server fetch ok; internal ops hint /internal/ops/csrf", "status": 200}),
        {
            "role": "assistant",
            "content": assistant_json(
                family=family,
                reasoning="The observation names a remote_addr-gated token route; fetch exactly that internal lab route through the relay.",
                state={"internal_route": "/internal/ops/csrf", "last_observation_ref": refs[0]},
                next_action=action(
                    "lab_http_request",
                    "server-fetch internal ops token",
                    {"body": "url=http://127.0.0.1:9101/internal/ops/csrf", "method": "POST", "url": f"{target}/fetch"},
                ),
                evidence=evidence([refs[0]]),
                done=False,
            ),
        },
        observation(refs[1], {"csrf_token": csrf, "status": 200, "task_id": task_id}),
        {
            "role": "assistant",
            "content": assistant_json(
                family=family,
                reasoning="Carry the internal token forward to the single lab admin action instead of trying unrelated internal paths.",
                state={"csrf_ref": refs[1], "last_observation_ref": refs[1], "task_id": task_id},
                next_action=action(
                    "lab_http_request",
                    "server-fetch internal admin marker action",
                    {
                        "body": f"url=http://127.0.0.1:9101/internal/ops/approve-marker&csrf={csrf}&task={task_id}",
                        "method": "POST",
                        "url": f"{target}/fetch",
                    },
                ),
                evidence=evidence(refs[:2]),
                done=False,
            ),
        },
        observation(refs[2], {"proof_route": f"/internal/ops/proof/{task_id}", "status": 200, "state_change": "lab_marker_approved"}),
        {
            "role": "assistant",
            "content": assistant_json(
                family=family,
                reasoning="The action produced a proof route; fetch that route through the same server-side path for evidence.",
                state={"last_observation_ref": refs[2], "proof_route": f"/internal/ops/proof/{task_id}"},
                next_action=action(
                    "lab_http_request",
                    "server-fetch internal proof marker",
                    {"body": f"url=http://127.0.0.1:9101/internal/ops/proof/{task_id}", "method": "POST", "url": f"{target}/fetch"},
                ),
                evidence=evidence(refs[:3]),
                done=False,
            ),
        },
        observation(refs[3], {"body_summary": f"approved marker {proof}", "status": 200}),
        {
            "role": "assistant",
            "content": assistant_json(
                family=family,
                reasoning="The baseline, token fetch, bounded admin action, and marker proof complete the lab chain.",
                state={"goal_marker": proof, "last_observation_ref": refs[3], "pivot_chain": ["ssrf", "internal_token", "admin_action"]},
                next_action=final_action(),
                evidence=evidence(refs[:4], goal_satisfied=True),
                done=True,
            ),
        },
    ]
    return row(family=family, split=split, idx=idx, chain_class=chain, objective="SSRF internal admin action chain", messages=messages)


def make_lowpriv_escalation(rng: random.Random, split: str, idx: int, family: str) -> dict[str, Any]:
    chain = "lowpriv_privilege_escalation_admin_resource_chain"
    target = host(rng, "tenant")
    proof = marker(rng, "PRIV")
    team_id = f"TEAM-{rng.randint(100, 999)}"
    session = lab_token(rng, "member-session")
    elevated_session = lab_token(rng, "admin-session")
    refs = [f"{chain}-{idx:05d}-{n}" for n in range(1, 6)]
    messages = base_messages(
        f"Lab tenant portal {target} gives an issued low-privilege account. "
        f"Follow observed role-change evidence to reach the admin resource containing marker {proof}."
    )
    messages += [
        {
            "role": "assistant",
            "content": assistant_json(
                family=family,
                reasoning="Open the issued low-privilege session so all later actions are tied to one observed account.",
                state={"known": [target], "next_gap": "low privilege session"},
                next_action=action(
                    "lab_http_request",
                    "login with issued lab member account",
                    {"body": "username=lab-member&password=issued-lab-password", "method": "POST", "url": f"{target}/login"},
                ),
                evidence=evidence([]),
                done=False,
            ),
        },
        observation(refs[0], {"role": "member", "set_cookie": f"session={session}", "status": 302, "team_id": team_id}),
        {
            "role": "assistant",
            "content": assistant_json(
                family=family,
                reasoning="Use the session cookie to inspect only the account's own feature metadata before any role request.",
                state={"last_observation_ref": refs[0], "session_cookie": f"session={session}", "team_id": team_id},
                next_action=action(
                    "lab_http_request",
                    "read role-management affordance",
                    {"headers": {"Cookie": f"session={session}"}, "method": "GET", "url": f"{target}/account/features"},
                ),
                evidence=evidence([refs[0]]),
                done=False,
            ),
        },
        observation(refs[1], {"allowed_form": "/account/role-request", "default_role": "team-maintainer", "status": 200}),
        {
            "role": "assistant",
            "content": assistant_json(
                family=family,
                reasoning="Submit the advertised role request once, preserving the team id from the authenticated context.",
                state={"feature_ref": refs[1], "last_observation_ref": refs[1], "team_id": team_id},
                next_action=action(
                    "lab_http_request",
                    "request lab team-maintainer role",
                    {
                        "body": f"team_id={team_id}&requested_role=team-maintainer",
                        "headers": {"Cookie": f"session={session}"},
                        "method": "POST",
                        "url": f"{target}/account/role-request",
                    },
                ),
                evidence=evidence(refs[:2]),
                done=False,
            ),
        },
        observation(refs[2], {"new_cookie": f"session={elevated_session}", "role": "team-maintainer", "status": 200}),
        {
            "role": "assistant",
            "content": assistant_json(
                family=family,
                reasoning="The role-change result supplied the elevated session; use it on the admin resource advertised for this lab team.",
                state={"elevated_session_ref": refs[2], "last_observation_ref": refs[2], "role": "team-maintainer"},
                next_action=action(
                    "lab_http_request",
                    "read team admin proof resource",
                    {"headers": {"Cookie": f"session={elevated_session}"}, "method": "GET", "url": f"{target}/team/{team_id}/admin/proof"},
                ),
                evidence=evidence(refs[:3]),
                done=False,
            ),
        },
        observation(refs[3], {"body_summary": f"team admin proof marker {proof}", "status": 200}),
        {
            "role": "assistant",
            "content": assistant_json(
                family=family,
                reasoning="Low-privilege login, role-change evidence, elevated session, and admin proof are complete.",
                state={"goal_marker": proof, "last_observation_ref": refs[3], "pivot_chain": ["lowpriv_login", "role_escalation", "admin_resource"]},
                next_action=final_action(),
                evidence=evidence(refs[:4], goal_satisfied=True),
                done=True,
            ),
        },
    ]
    return row(family=family, split=split, idx=idx, chain_class=chain, objective="low-privilege escalation chain", messages=messages)


def make_info_disclosure_lateral(rng: random.Random, split: str, idx: int, family: str) -> dict[str, Any]:
    chain = "info_disclosure_credential_reuse_lateral_chain"
    status_target = host(rng, "status")
    reports_target = host(rng, "reports")
    proof = marker(rng, "INFO")
    service_token = lab_token(rng, "report-reader")
    refs = [f"{chain}-{idx:05d}-{n}" for n in range(1, 6)]
    messages = base_messages(
        f"Lab status service {status_target} may disclose a read-only service token. "
        f"Preserve any observed token and use it only against the linked reports lab to collect marker {proof}."
    )
    messages += [
        {
            "role": "assistant",
            "content": assistant_json(
                family=family,
                reasoning="Start with the public status page to find only advertised diagnostic links.",
                state={"known": [status_target], "next_gap": "diagnostic link"},
                next_action=action("lab_http_request", "read public status page", {"method": "GET", "url": f"{status_target}/status"}),
                evidence=evidence([]),
                done=False,
            ),
        },
        observation(refs[0], {"links": ["/diagnostics/config.json"], "service": "reports", "status": 200}),
        {
            "role": "assistant",
            "content": assistant_json(
                family=family,
                reasoning="The observed diagnostics link is in scope; read it once to check for accidental lab credential disclosure.",
                state={"diagnostic_link": "/diagnostics/config.json", "last_observation_ref": refs[0]},
                next_action=action("lab_http_request", "read lab diagnostic config", {"method": "GET", "url": f"{status_target}/diagnostics/config.json"}),
                evidence=evidence([refs[0]]),
                done=False,
            ),
        },
        observation(
            refs[1],
            {
                "lateral_service": reports_target,
                "read_only_token": service_token,
                "service_account": "report-reader",
                "status": 200,
            },
        ),
        {
            "role": "assistant",
            "content": assistant_json(
                family=family,
                reasoning="Carry the disclosed read-only token to the linked reports service and verify its scope before asking for proof.",
                state={"last_observation_ref": refs[1], "lateral_service": reports_target, "token_ref": refs[1]},
                next_action=action(
                    "lab_api_request",
                    "verify disclosed token scope on linked service",
                    {
                        "headers": {"Authorization": f"Bearer {service_token}"},
                        "method": "GET",
                        "url": f"{reports_target}/api/me",
                    },
                ),
                evidence=evidence(refs[:2]),
                done=False,
            ),
        },
        observation(refs[2], {"account": "report-reader", "allowed": ["reports:read"], "proof_route": "/api/reports/proof", "status": 200}),
        {
            "role": "assistant",
            "content": assistant_json(
                family=family,
                reasoning="The scope permits a read-only proof request, so use the same observed token on that route.",
                state={"last_observation_ref": refs[2], "proof_route": "/api/reports/proof", "token_ref": refs[1]},
                next_action=action(
                    "lab_api_request",
                    "read lateral reports proof marker",
                    {
                        "headers": {"Authorization": f"Bearer {service_token}"},
                        "method": "GET",
                        "url": f"{reports_target}/api/reports/proof",
                    },
                ),
                evidence=evidence(refs[:3]),
                done=False,
            ),
        },
        observation(refs[3], {"body_summary": f"reports proof marker {proof}", "status": 200}),
        {
            "role": "assistant",
            "content": assistant_json(
                family=family,
                reasoning="The disclosure, token preservation, lateral read, and marker evidence complete the lab objective.",
                state={"goal_marker": proof, "last_observation_ref": refs[3], "pivot_chain": ["info_disclosure", "credential_reuse", "lateral_read"]},
                next_action=final_action(),
                evidence=evidence(refs[:4], goal_satisfied=True),
                done=True,
            ),
        },
    ]
    return row(family=family, split=split, idx=idx, chain_class=chain, objective="info-disclosure lateral reuse chain", messages=messages)


TEMPLATES: list[Callable[[random.Random, str, int, str], dict[str, Any]]] = [
    make_idor_token_reuse,
    make_ssrf_admin_action,
    make_lowpriv_escalation,
    make_info_disclosure_lateral,
]


def generate_rows(count: int, *, split: str, seed: int = SEED, family: str = DEFAULT_PREFIX) -> list[dict[str, Any]]:
    rng = random.Random(seed + sum(ord(ch) for ch in split))
    templates = list(TEMPLATES)
    rows: list[dict[str, Any]] = []
    for idx in range(count):
        if idx % len(templates) == 0:
            rng.shuffle(templates)
        rows.append(templates[idx % len(templates)](rng, split, idx, family))
    return rows


def validate_rows(rows: list[dict[str, Any]], *, family: str = DEFAULT_PREFIX) -> dict[str, Any]:
    chain_classes = Counter()
    domains = Counter()
    assistant_turn_counts = Counter()
    for item in rows:
        metadata = item["metadata"]
        chain_class = metadata["chain_class"]
        chain_classes[chain_class] += 1
        domains[metadata["domain"]] += 1
        if metadata["dataset_family"] != family:
            raise ValueError(f"wrong dataset family in {metadata['case_id']}")
        if metadata["runtime_execution"] is not False:
            raise ValueError(f"runtime execution enabled in {metadata['case_id']}")
        if metadata["global_held_out_registry"] != "excluded":
            raise ValueError(f"held-out registry not excluded in {metadata['case_id']}")
        assistant_messages = [message for message in item["messages"] if message["role"] == "assistant"]
        if len(assistant_messages) < MIN_ASSISTANT_TURNS:
            raise ValueError(f"too few assistant turns in {metadata['case_id']}")
        assistant_turn_counts[len(assistant_messages)] += 1
        for turn_idx, message in enumerate(assistant_messages):
            parsed = json.loads(message["content"])
            required = {"done", "evidence", "next_action", "reasoning", "safety", "state"}
            if set(parsed) != required:
                raise ValueError(f"bad assistant schema in {metadata['case_id']}")
            if parsed["safety"].get("runtime_execution") is not False:
                raise ValueError(f"unsafe runtime flag in {metadata['case_id']}")
            if parsed["safety"].get("dataset_family") != family:
                raise ValueError(f"wrong assistant family in {metadata['case_id']}")
            tool = parsed["next_action"].get("tool")
            if tool not in ALLOWED_TOOLS:
                raise ValueError(f"unknown tool {tool!r} in {metadata['case_id']}")
            if "args" not in parsed["next_action"]:
                raise ValueError(f"missing next_action args in {metadata['case_id']}")
            if turn_idx > 0 and "last_observation_ref" not in parsed["state"] and not parsed["done"]:
                raise ValueError(f"missing observation carry-forward in {metadata['case_id']}")
            if turn_idx < len(assistant_messages) - 1 and parsed["done"] is not False:
                raise ValueError(f"premature done in {metadata['case_id']}")
            if turn_idx == len(assistant_messages) - 1:
                if parsed["done"] is not True or parsed["evidence"].get("goal_satisfied") is not True:
                    raise ValueError(f"final turn did not complete goal in {metadata['case_id']}")
        serialized = json.dumps(item, sort_keys=True)
        if FORBIDDEN.search(serialized):
            raise ValueError(f"forbidden content in {metadata['case_id']}")
        for forbidden in FORBIDDEN_HELD_OUT_MARKERS:
            if forbidden in serialized:
                raise ValueError(f"held-out marker {forbidden!r} leaked into {metadata['case_id']}")
    missing = sorted(set(CHAIN_CLASSES) - set(chain_classes))
    if missing:
        raise ValueError(f"missing chain classes: {missing}")
    return {
        "assistant_turns": dict(sorted(assistant_turn_counts.items())),
        "chain_classes": dict(sorted(chain_classes.items())),
        "domains": dict(sorted(domains.items())),
        "row_count": len(rows),
    }


def parse_counts(values: list[str] | None) -> dict[str, int]:
    counts = dict(DEFAULT_COUNTS)
    for value in values or []:
        split, raw_count = value.split("=", 1)
        if split not in counts:
            raise ValueError(f"unknown split {split!r}")
        counts[split] = int(raw_count)
    return counts


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for item in rows:
            handle.write(json.dumps(item, sort_keys=True) + "\n")


def build_dataset(out_dir: Path, prefix: str, counts: dict[str, int], seed: int = SEED) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest: dict[str, Any] = {
        "dataset": prefix,
        "format": "jsonl chat SFT multi-turn chain-type diversity",
        "policy": {
            "chain_type_diversity_for_cold_start": True,
            "data_lane_only": True,
            "held_out_deep_chain_solution_not_copied": True,
            "kept_out_of_global_held_out_registry": True,
            "lab_only": True,
            "not_live_runtime_payloads": True,
            "runtime_execution": False,
            "synthetic_non_held_out_scenarios": True,
            "teacher_demonstration_compatible": True,
            "teaches_pivot_reuse_not_fixed_recipes": True,
            "train_eval_test_separated": True,
        },
        "seed": seed,
        "splits": {},
    }
    for split, count in counts.items():
        rows = generate_rows(count, split=split, seed=seed, family=prefix)
        stats = validate_rows(rows, family=prefix)
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
    manifest = build_dataset(args.out_dir, args.prefix, parse_counts(args.count), seed=args.seed)
    print(json.dumps(manifest["splits"], indent=2, sort_keys=True))
    print(f"manifest: {args.out_dir / (args.prefix + '_manifest.json')}")


if __name__ == "__main__":
    main()
