"""Generate multi-turn agentic follow-through examples for AegisPT.

This family is data-lane only. It teaches the assistant to carry state across
tool observations and keep advancing toward a lab goal, without hard-coding the
held-out deep-chain eval route or binding any runtime targets.
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
DEFAULT_PREFIX = "aegispt_multiturn_agentic_chain_iter6"
DEFAULT_COUNTS = {"train": 3200, "eval": 400, "test": 400}
SEED = 20260605
MIN_ASSISTANT_TURNS = 4

SYSTEM = (
    "You are AegisPT in an authorized lab. Work over multiple turns. Return "
    "EXACTLY one JSON object on each assistant turn with keys: reasoning, "
    "state, next_action, evidence, safety, done. Read the latest tool "
    "observation, preserve useful state, and advance to the next smallest "
    "safe proof step. Stop only when the requested lab goal is evidenced."
)

CHAIN_CLASSES = (
    "web_auth_followthrough",
    "api_object_authorization_chain",
    "ssrf_internal_marker_chain",
    "cloud_iam_simulation_chain",
    "ad_graph_readonly_chain",
    "lan_segmentation_chain",
    "iot_mqtt_topic_chain",
    "kube_rbac_chain",
)

DOMAINS = {
    "web_auth_followthrough": "web",
    "api_object_authorization_chain": "api",
    "ssrf_internal_marker_chain": "web",
    "cloud_iam_simulation_chain": "cloud",
    "ad_graph_readonly_chain": "active_directory",
    "lan_segmentation_chain": "lan",
    "iot_mqtt_topic_chain": "iot",
    "kube_rbac_chain": "cloud",
}

ALLOWED_TOOLS = {
    "cloud_policy_simulator",
    "kube_selfsubject_review",
    "lab_ad_graph_query",
    "lab_api_request",
    "lab_cloud_readonly",
    "lab_http_request",
    "lab_ldap_readonly",
    "lab_mqtt_marker",
    "lab_tcp_marker",
    "none",
}

FORBIDDEN = re.compile(
    r"\b(rm\s+-rf|mimikatz|hashcat|ransom|wipe|destroy|drop\s+table|"
    r"credential\s+dump|password\s+spray|brute[\s_-]?force)\b|BEGIN RSA PRIVATE KEY|sk-",
    re.I,
)


def marker(rng: random.Random, prefix: str = "CHAIN") -> str:
    return f"AEGISPT_{prefix}_{rng.randint(1000, 9999)}"


def host(rng: random.Random, prefix: str) -> str:
    return f"https://{prefix}-lab-{rng.randint(100, 999)}.example"


def lab_ip(rng: random.Random) -> str:
    return f"192.0.2.{rng.randint(10, 240)}"


def assistant_json(
    *,
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
                "dataset_family": DEFAULT_PREFIX,
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


def row(
    *,
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
            "case_id": f"multiturn-{chain_class}-{split}-{idx:05d}",
            "chain_class": chain_class,
            "dataset_family": DEFAULT_PREFIX,
            "domain": DOMAINS[chain_class],
            "lab_only": True,
            "objective": objective,
            "runtime_execution": False,
            "safety_tags": [
                "multi_turn_followthrough",
                "lab_only",
                "no_runtime_execution",
                "no_fixed_deep_chain_recipe",
            ],
            "split": split,
        },
    }


def base_messages(objective: str) -> list[dict[str, str]]:
    return [
        {"role": "system", "content": SYSTEM},
        {"role": "user", "content": objective},
    ]


def final_action() -> dict[str, Any]:
    return action("none", "goal complete; emit evidence summary", {})


def make_web_auth(rng: random.Random, split: str, idx: int) -> dict[str, Any]:
    chain = "web_auth_followthrough"
    target = host(rng, "portal")
    proof = marker(rng, "WEB")
    refs = [f"{chain}-{idx:05d}-{n}" for n in range(1, 5)]
    messages = base_messages(
        f"Lab portal {target} has a low-privilege account and a protected proof page. "
        f"Carry session state forward and collect marker {proof} without guessing credentials."
    )
    messages += [
        {
            "role": "assistant",
            "content": assistant_json(
                reasoning="Start with route discovery so the next step is based on observed links.",
                state={"known": [target], "next_gap": "routes"},
                next_action=action("lab_http_request", "discover login and profile routes", {"method": "GET", "url": target}),
                evidence=evidence([]),
                done=False,
            ),
        },
        observation(refs[0], {"links": ["/login", "/profile", "/proof"], "seeded_user_hint": "lab-reader"}),
        {
            "role": "assistant",
            "content": assistant_json(
                reasoning="The observation names the login route and seeded lab user, so authenticate before reading protected routes.",
                state={"known": ["/login", "/profile", "/proof", "lab-reader"], "last_observation_ref": refs[0]},
                next_action=action(
                    "lab_http_request",
                    "open a lab session with seeded credentials",
                    {"body": "username=lab-reader&password=provided-lab-secret", "method": "POST", "url": f"{target}/login"},
                ),
                evidence=evidence([refs[0]]),
                done=False,
            ),
        },
        observation(refs[1], {"set_cookie": "session=lab-session", "status": 302, "to": "/profile"}),
        {
            "role": "assistant",
            "content": assistant_json(
                reasoning="The session cookie is the state to preserve; use it on the proof page rather than restarting discovery.",
                state={"cookie": "session=lab-session", "last_observation_ref": refs[1], "routes": ["/profile", "/proof"]},
                next_action=action(
                    "lab_http_request",
                    "read protected lab proof with the observed session",
                    {"headers": {"Cookie": "session=lab-session"}, "method": "GET", "url": f"{target}/proof"},
                ),
                evidence=evidence(refs[:2]),
                done=False,
            ),
        },
        observation(refs[2], {"body_summary": f"proof marker {proof}", "status": 200}),
        {
            "role": "assistant",
            "content": assistant_json(
                reasoning="The requested marker was observed; finish with evidence instead of taking extra actions.",
                state={"goal_marker": proof, "last_observation_ref": refs[2]},
                next_action=final_action(),
                evidence=evidence(refs[:3], goal_satisfied=True),
                done=True,
            ),
        },
    ]
    return row(split=split, idx=idx, chain_class=chain, objective="session follow-through", messages=messages)


def make_api_object(rng: random.Random, split: str, idx: int) -> dict[str, Any]:
    chain = "api_object_authorization_chain"
    target = host(rng, "api")
    proof = marker(rng, "API")
    refs = [f"{chain}-{idx:05d}-{n}" for n in range(1, 5)]
    messages = base_messages(
        f"Lab API {target} exposes project objects. Build evidence for an authorization boundary using marker {proof}; "
        "use only the issued lab token and stop after the smallest proof."
    )
    messages += [
        {
            "role": "assistant",
            "content": assistant_json(
                reasoning="First learn the authenticated user's own object and any advertised relation links.",
                state={"known": [target], "next_gap": "own object id"},
                next_action=action("lab_api_request", "read own object index", {"method": "GET", "token": "lab-issued", "url": f"{target}/v1/projects/me"}),
                evidence=evidence([]),
                done=False,
            ),
        },
        observation(refs[0], {"own_project": "P-107", "related": ["P-108"], "status": 200}),
        {
            "role": "assistant",
            "content": assistant_json(
                reasoning="Use the related id from the observation for one bounded comparison, not enumeration.",
                state={"last_observation_ref": refs[0], "own_project": "P-107", "related_candidate": "P-108"},
                next_action=action("lab_api_request", "compare related object authorization", {"method": "GET", "token": "lab-issued", "url": f"{target}/v1/projects/P-108"}),
                evidence=evidence([refs[0]]),
                done=False,
            ),
        },
        observation(refs[1], {"body_summary": f"returned cross-project marker {proof}", "status": 200}),
        {
            "role": "assistant",
            "content": assistant_json(
                reasoning="Confirm the boundary by checking the own object still returns only owned data.",
                state={"cross_object_marker": proof, "last_observation_ref": refs[1]},
                next_action=action("lab_api_request", "read own object as a control", {"method": "GET", "token": "lab-issued", "url": f"{target}/v1/projects/P-107"}),
                evidence=evidence(refs[:2]),
                done=False,
            ),
        },
        observation(refs[2], {"body_summary": "own project returned without cross-project marker", "status": 200}),
        {
            "role": "assistant",
            "content": assistant_json(
                reasoning="The cross-object marker and owned-object control are enough for the lab finding.",
                state={"control_ref": refs[2], "last_observation_ref": refs[2]},
                next_action=final_action(),
                evidence=evidence(refs[:3], goal_satisfied=True),
                done=True,
            ),
        },
    ]
    return row(split=split, idx=idx, chain_class=chain, objective="API authorization follow-through", messages=messages)


def make_ssrf_internal(rng: random.Random, split: str, idx: int) -> dict[str, Any]:
    chain = "ssrf_internal_marker_chain"
    target = host(rng, "fetcher")
    proof = marker(rng, "SSRF")
    refs = [f"{chain}-{idx:05d}-{n}" for n in range(1, 5)]
    messages = base_messages(
        f"Lab fetcher {target} can request approved lab URLs. Discover whether it can reach the internal marker service "
        f"and collect {proof} without touching cloud metadata."
    )
    messages += [
        {
            "role": "assistant",
            "content": assistant_json(
                reasoning="Start with an approved external echo URL so later internal behavior has a baseline.",
                state={"known": [target], "next_gap": "server-fetch baseline"},
                next_action=action("lab_http_request", "baseline server-side fetch", {"method": "POST", "url": f"{target}/fetch", "body": "url=https://echo.lab/ping"}),
                evidence=evidence([]),
                done=False,
            ),
        },
        observation(refs[0], {"body_summary": "server fetched echo.lab and returned route hint /internal/marker", "status": 200}),
        {
            "role": "assistant",
            "content": assistant_json(
                reasoning="The route hint is internal-only; request exactly the lab marker endpoint through the fetcher.",
                state={"internal_hint": "/internal/marker", "last_observation_ref": refs[0]},
                next_action=action(
                    "lab_http_request",
                    "server-fetch internal lab marker",
                    {"body": f"url=http://127.0.0.1:8088/internal/marker?id={proof}", "method": "POST", "url": f"{target}/fetch"},
                ),
                evidence=evidence([refs[0]]),
                done=False,
            ),
        },
        observation(refs[1], {"body_summary": f"internal marker accepted {proof}", "status": 200}),
        {
            "role": "assistant",
            "content": assistant_json(
                reasoning="Add a negative control to show this was server-side internal reachability, not normal client access.",
                state={"last_observation_ref": refs[1], "marker": proof},
                next_action=action("lab_http_request", "direct client control request", {"method": "GET", "url": "http://127.0.0.1:8088/internal/marker"}),
                evidence=evidence(refs[:2]),
                done=False,
            ),
        },
        observation(refs[2], {"body_summary": "client cannot reach internal lab service", "status": 0}),
        {
            "role": "assistant",
            "content": assistant_json(
                reasoning="The baseline, internal marker, and client control prove the chain; stop before extra probing.",
                state={"control_ref": refs[2], "last_observation_ref": refs[2]},
                next_action=final_action(),
                evidence=evidence(refs[:3], goal_satisfied=True),
                done=True,
            ),
        },
    ]
    return row(split=split, idx=idx, chain_class=chain, objective="SSRF internal follow-through", messages=messages)


def make_cloud_iam(rng: random.Random, split: str, idx: int) -> dict[str, Any]:
    chain = "cloud_iam_simulation_chain"
    action_name = rng.choice(["iam:PassRole", "s3:PutBucketPolicy", "ec2:RunInstances"])
    refs = [f"{chain}-{idx:05d}-{n}" for n in range(1, 5)]
    messages = base_messages(
        f"Lab cloud account has one test principal. Use read-only inventory plus policy simulation to determine whether {action_name} is allowed."
    )
    messages += [
        {
            "role": "assistant",
            "content": assistant_json(
                reasoning="Inventory the current lab principal first so the simulation target is explicit.",
                state={"next_gap": "principal arn"},
                next_action=action("lab_cloud_readonly", "read current principal", {"provider": "aws-lab", "query": "current_principal"}),
                evidence=evidence([]),
                done=False,
            ),
        },
        observation(refs[0], {"principal": "arn:aws:iam::111122223333:role/lab-analyst", "status": "ok"}),
        {
            "role": "assistant",
            "content": assistant_json(
                reasoning="Use the observed role in a simulator; do not execute the sensitive action.",
                state={"last_observation_ref": refs[0], "principal": "lab-analyst"},
                next_action=action(
                    "cloud_policy_simulator",
                    "simulate sensitive permission",
                    {"action": action_name, "principal": "arn:aws:iam::111122223333:role/lab-analyst"},
                ),
                evidence=evidence([refs[0]]),
                done=False,
            ),
        },
        observation(refs[1], {"decision": "allowed", "matched_statement": "LabOverbroadPolicy"}),
        {
            "role": "assistant",
            "content": assistant_json(
                reasoning="Collect read-only policy context so the final finding has a remediation anchor.",
                state={"last_observation_ref": refs[1], "simulated_action_allowed": action_name},
                next_action=action("lab_cloud_readonly", "read matching policy summary", {"policy": "LabOverbroadPolicy", "provider": "aws-lab"}),
                evidence=evidence(refs[:2]),
                done=False,
            ),
        },
        observation(refs[2], {"policy_summary": "wildcard resource on lab role", "status": "ok"}),
        {
            "role": "assistant",
            "content": assistant_json(
                reasoning="Read-only inventory plus simulator result satisfy the lab objective.",
                state={"last_observation_ref": refs[2], "policy_summary_ref": refs[2]},
                next_action=final_action(),
                evidence=evidence(refs[:3], goal_satisfied=True),
                done=True,
            ),
        },
    ]
    return row(split=split, idx=idx, chain_class=chain, objective="cloud IAM follow-through", messages=messages)


def make_ad_graph(rng: random.Random, split: str, idx: int) -> dict[str, Any]:
    chain = "ad_graph_readonly_chain"
    refs = [f"{chain}-{idx:05d}-{n}" for n in range(1, 5)]
    group = rng.choice(["Helpdesk Admins", "App Deployers", "Tier-1 Operators"])
    messages = base_messages(
        f"Offline AD lab graph may contain a path from {group} to a privileged group. Confirm with read-only LDAP metadata only."
    )
    messages += [
        {
            "role": "assistant",
            "content": assistant_json(
                reasoning="Use the offline graph first to avoid touching live directory objects.",
                state={"group": group, "next_gap": "graph path"},
                next_action=action("lab_ad_graph_query", "find shortest privileged path", {"from_group": group, "query": "shortest_privileged_path"}),
                evidence=evidence([]),
                done=False,
            ),
        },
        observation(refs[0], {"edge": "GenericAll -> Lab Workstation Admins", "path_length": 2}),
        {
            "role": "assistant",
            "content": assistant_json(
                reasoning="The graph edge needs a read-only directory confirmation before reporting.",
                state={"graph_edge": "GenericAll", "last_observation_ref": refs[0]},
                next_action=action("lab_ldap_readonly", "confirm group ACL metadata", {"attribute": "nTSecurityDescriptor_summary", "group": group}),
                evidence=evidence([refs[0]]),
                done=False,
            ),
        },
        observation(refs[1], {"acl_summary": "GenericAll delegated to lab group", "status": "ok"}),
        {
            "role": "assistant",
            "content": assistant_json(
                reasoning="Add membership context so the evidence explains exposure, not just path shape.",
                state={"acl_ref": refs[1], "last_observation_ref": refs[1]},
                next_action=action("lab_ldap_readonly", "count lab group members", {"attribute": "member_count", "group": group}),
                evidence=evidence(refs[:2]),
                done=False,
            ),
        },
        observation(refs[2], {"member_count": 4, "status": "ok"}),
        {
            "role": "assistant",
            "content": assistant_json(
                reasoning="The path, ACL confirmation, and membership count are sufficient; no credential collection is needed.",
                state={"last_observation_ref": refs[2], "member_count": 4},
                next_action=final_action(),
                evidence=evidence(refs[:3], goal_satisfied=True),
                done=True,
            ),
        },
    ]
    return row(split=split, idx=idx, chain_class=chain, objective="AD graph follow-through", messages=messages)


def make_lan_segmentation(rng: random.Random, split: str, idx: int) -> dict[str, Any]:
    chain = "lan_segmentation_chain"
    target = lab_ip(rng)
    proof = marker(rng, "LAN")
    refs = [f"{chain}-{idx:05d}-{n}" for n in range(1, 5)]
    messages = base_messages(
        f"Lab LAN segment check: determine whether test workstation can reach marker service on {target}. Use bounded TCP marker checks only."
    )
    messages += [
        {
            "role": "assistant",
            "content": assistant_json(
                reasoning="Check the allowed baseline control port first.",
                state={"target": target, "next_gap": "baseline connectivity"},
                next_action=action("lab_tcp_marker", "baseline allowed service check", {"marker": proof, "port": 443, "target": target}),
                evidence=evidence([]),
                done=False,
            ),
        },
        observation(refs[0], {"port": 443, "result": "reachable", "service": "lab-control"}),
        {
            "role": "assistant",
            "content": assistant_json(
                reasoning="Use the same marker against the restricted lab port to test segmentation with one bounded attempt.",
                state={"baseline_ref": refs[0], "last_observation_ref": refs[0], "target": target},
                next_action=action("lab_tcp_marker", "restricted marker service check", {"marker": proof, "port": 8443, "target": target}),
                evidence=evidence([refs[0]]),
                done=False,
            ),
        },
        observation(refs[1], {"marker_echoed": proof, "port": 8443, "result": "reachable"}),
        {
            "role": "assistant",
            "content": assistant_json(
                reasoning="Confirm the route label so the report ties the reachability to a segmentation boundary.",
                state={"last_observation_ref": refs[1], "restricted_reachable": True},
                next_action=action("lab_tcp_marker", "read route label", {"port": 8443, "query": "route_label", "target": target}),
                evidence=evidence(refs[:2]),
                done=False,
            ),
        },
        observation(refs[2], {"route_label": "workstation-to-admin-lab", "result": "ok"}),
        {
            "role": "assistant",
            "content": assistant_json(
                reasoning="The marker proof and route label meet the objective; do not scan additional ports.",
                state={"last_observation_ref": refs[2], "route_label": "workstation-to-admin-lab"},
                next_action=final_action(),
                evidence=evidence(refs[:3], goal_satisfied=True),
                done=True,
            ),
        },
    ]
    return row(split=split, idx=idx, chain_class=chain, objective="LAN segmentation follow-through", messages=messages)


def make_iot_mqtt(rng: random.Random, split: str, idx: int) -> dict[str, Any]:
    chain = "iot_mqtt_topic_chain"
    target = lab_ip(rng)
    proof = marker(rng, "IOT")
    refs = [f"{chain}-{idx:05d}-{n}" for n in range(1, 5)]
    messages = base_messages(
        f"Lab MQTT broker {target} allows a disposable test topic only. Prove topic access with marker {proof}, then clean the retained marker."
    )
    messages += [
        {
            "role": "assistant",
            "content": assistant_json(
                reasoning="Read the approved topic boundary before publishing any marker.",
                state={"broker": target, "next_gap": "approved topic"},
                next_action=action("lab_mqtt_marker", "read allowed topic policy", {"broker": target, "operation": "describe_acl"}),
                evidence=evidence([]),
                done=False,
            ),
        },
        observation(refs[0], {"allowed_topic": "aegispt/test/proof", "retain_allowed": True}),
        {
            "role": "assistant",
            "content": assistant_json(
                reasoning="Publish only to the observed disposable topic with the synthetic marker.",
                state={"allowed_topic": "aegispt/test/proof", "last_observation_ref": refs[0]},
                next_action=action("lab_mqtt_marker", "publish disposable marker", {"broker": target, "marker": proof, "operation": "publish", "topic": "aegispt/test/proof"}),
                evidence=evidence([refs[0]]),
                done=False,
            ),
        },
        observation(refs[1], {"marker_seen": proof, "topic": "aegispt/test/proof"}),
        {
            "role": "assistant",
            "content": assistant_json(
                reasoning="Because retain is allowed, clean the disposable marker before finishing.",
                state={"last_observation_ref": refs[1], "marker": proof},
                next_action=action("lab_mqtt_marker", "clear retained marker", {"broker": target, "operation": "clear_retained", "topic": "aegispt/test/proof"}),
                evidence=evidence(refs[:2]),
                done=False,
            ),
        },
        observation(refs[2], {"cleanup": "retained marker cleared", "topic": "aegispt/test/proof"}),
        {
            "role": "assistant",
            "content": assistant_json(
                reasoning="Marker evidence and cleanup are complete.",
                state={"cleanup_ref": refs[2], "last_observation_ref": refs[2]},
                next_action=final_action(),
                evidence=evidence(refs[:3], goal_satisfied=True),
                done=True,
            ),
        },
    ]
    return row(split=split, idx=idx, chain_class=chain, objective="IoT MQTT follow-through", messages=messages)


def make_kube_rbac(rng: random.Random, split: str, idx: int) -> dict[str, Any]:
    chain = "kube_rbac_chain"
    namespace = rng.choice(["lab-payments", "lab-build", "lab-reports"])
    refs = [f"{chain}-{idx:05d}-{n}" for n in range(1, 5)]
    messages = base_messages(
        f"Lab Kubernetes namespace {namespace}: determine whether the current service account can list pods and read configmaps. "
        "Use SelfSubjectAccessReview and read-only checks only."
    )
    messages += [
        {
            "role": "assistant",
            "content": assistant_json(
                reasoning="Ask Kubernetes what the current service account is allowed to do before making read calls.",
                state={"namespace": namespace, "next_gap": "pod list permission"},
                next_action=action("kube_selfsubject_review", "check pod list permission", {"namespace": namespace, "resource": "pods", "verb": "list"}),
                evidence=evidence([]),
                done=False,
            ),
        },
        observation(refs[0], {"allowed": True, "resource": "pods", "verb": "list"}),
        {
            "role": "assistant",
            "content": assistant_json(
                reasoning="The review allows pod listing, so perform one read-only list to capture scope evidence.",
                state={"last_observation_ref": refs[0], "pods_list_allowed": True},
                next_action=action("lab_cloud_readonly", "list lab pods", {"namespace": namespace, "query": "pods"}),
                evidence=evidence([refs[0]]),
                done=False,
            ),
        },
        observation(refs[1], {"pod_count": 3, "sample": "lab-worker-0"}),
        {
            "role": "assistant",
            "content": assistant_json(
                reasoning="Check configmap permission separately so the final result distinguishes resources.",
                state={"last_observation_ref": refs[1], "pod_count": 3},
                next_action=action("kube_selfsubject_review", "check configmap read permission", {"namespace": namespace, "resource": "configmaps", "verb": "get"}),
                evidence=evidence(refs[:2]),
                done=False,
            ),
        },
        observation(refs[2], {"allowed": False, "resource": "configmaps", "verb": "get"}),
        {
            "role": "assistant",
            "content": assistant_json(
                reasoning="The pod-list proof and configmap denial answer the lab goal without reading sensitive objects.",
                state={"configmaps_get_allowed": False, "last_observation_ref": refs[2]},
                next_action=final_action(),
                evidence=evidence(refs[:3], goal_satisfied=True),
                done=True,
            ),
        },
    ]
    return row(split=split, idx=idx, chain_class=chain, objective="Kubernetes RBAC follow-through", messages=messages)


TEMPLATES: list[Callable[[random.Random, str, int], dict[str, Any]]] = [
    make_web_auth,
    make_api_object,
    make_ssrf_internal,
    make_cloud_iam,
    make_ad_graph,
    make_lan_segmentation,
    make_iot_mqtt,
    make_kube_rbac,
]


def generate_rows(count: int, *, split: str, seed: int = SEED) -> list[dict[str, Any]]:
    rng = random.Random(seed + sum(ord(ch) for ch in split))
    templates = list(TEMPLATES)
    rows: list[dict[str, Any]] = []
    for idx in range(count):
        if idx % len(templates) == 0:
            rng.shuffle(templates)
        rows.append(templates[idx % len(templates)](rng, split, idx))
    return rows


def validate_rows(rows: list[dict[str, Any]]) -> dict[str, Any]:
    chain_classes = Counter()
    domains = Counter()
    assistant_turn_counts = Counter()
    for item in rows:
        metadata = item["metadata"]
        chain_class = metadata["chain_class"]
        chain_classes[chain_class] += 1
        domains[metadata["domain"]] += 1
        if metadata["dataset_family"] != DEFAULT_PREFIX:
            raise ValueError(f"wrong dataset family in {metadata['case_id']}")
        if metadata["runtime_execution"] is not False:
            raise ValueError(f"runtime execution enabled in {metadata['case_id']}")
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
            tool = parsed["next_action"].get("tool")
            if tool not in ALLOWED_TOOLS:
                raise ValueError(f"unknown tool {tool!r} in {metadata['case_id']}")
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
        "format": "jsonl chat SFT multi-turn agentic follow-through",
        "policy": {
            "data_lane_only": True,
            "held_out_deep_chain_solution_not_copied": True,
            "lab_only": True,
            "runtime_execution": False,
            "teaches_followthrough_not_fixed_recipes": True,
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
    manifest = build_dataset(args.out_dir, args.prefix, parse_counts(args.count), seed=args.seed)
    print(json.dumps(manifest["splits"], indent=2, sort_keys=True))
    print(f"manifest: {args.out_dir / (args.prefix + '_manifest.json')}")


if __name__ == "__main__":
    main()
