"""Non-held-out multi-chain training environments for rollout/RL.

These environments intentionally do not reuse the held-out deep-chain target.
They expose the same core loop shape: an agent emits a JSON action containing
an HTTP request, the environment returns a deterministic observation, and the
result carries evidence-backed reward signals for rollout ranking.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

DEFAULT_PREFIX = "aegispt_multichain_rl_envs_iter9"
DEFAULT_OUT_DIR = Path.home() / ".aegispt-tools" / "training"

SYSTEM = (
    "You are an authorized penetration-testing agent driving a synthetic lab via "
    "ONE tool: http_request. Respond with EXACTLY one JSON object containing "
    '{"reasoning":"...","request":{"method":"GET|POST","url":"...","headers":{},"body":"..."},"done":false}. '
    "Carry cookies, tokens, and observed ids forward. Stop only after the requested "
    "lab marker is evidenced."
)

FORBIDDEN_HELD_OUT_MARKERS = (
    "flag{deep-eval-5b7c2}",
    "ADM-7741-KQ",
    "X-Admin-Token",
    "shop.lab",
    "/notes/",
    "/admin/config",
    "/reset_password",
    "deep-eval-5b7c2",
)


def scenario_hash(scenario_id: str) -> str:
    return hashlib.sha256(str(scenario_id).strip().lower().encode()).hexdigest()


def strip_host(url: str) -> str:
    return re.sub(r"^https?://[^/]+", "", str(url)).split("?", 1)[0].rstrip("/") or "/"


def body_text(body: Any) -> str:
    if isinstance(body, (dict, list)):
        return json.dumps(body, sort_keys=True)
    return str(body or "")


def header_lookup(headers: dict[str, Any] | None, name: str) -> str:
    wanted = name.lower()
    for key, value in (headers or {}).items():
        if str(key).lower() == wanted:
            return str(value)
    return ""


def action(method: str, url: str, *, headers: dict[str, str] | None = None, body: Any = "") -> dict[str, Any]:
    return {
        "done": False,
        "reasoning": "oracle step for deterministic training-env smoke",
        "request": {
            "body": body,
            "headers": headers or {},
            "method": method,
            "url": url,
        },
    }


def extract_request(payload: dict[str, Any]) -> dict[str, Any]:
    request = payload.get("request")
    if isinstance(request, dict):
        return request
    next_action = payload.get("next_action")
    if isinstance(next_action, dict):
        args = next_action.get("args")
        if isinstance(args, dict):
            return args
        return next_action
    return {}


@dataclass(frozen=True)
class ScenarioSpec:
    scenario_id: str
    chain_class: str
    domain: str
    host: str
    marker: str
    goal: str
    oracle_actions: tuple[dict[str, Any], ...]
    responder: Callable[[dict[str, Any], str, str, dict[str, Any] | None, Any], tuple[int, dict[str, str], str]]

    @property
    def scenario_hash(self) -> str:
        return scenario_hash(self.scenario_id)


class TrainingEnv:
    def __init__(self, spec: ScenarioSpec):
        self.spec = spec
        self.state: dict[str, Any] = {
            "flag": False,
            "logged_in": False,
            "pivot": False,
            "signals": [],
        }
        self.steps = 0
        self.seen: set[str] = set()

    def respond(self, method: str, url: str, headers: dict[str, Any] | None = None, body: Any = "") -> dict[str, Any]:
        path = strip_host(url)
        status, response_headers, response_body = self.spec.responder(
            self.state,
            method.upper(),
            path,
            headers,
            body,
        )
        signature = f"{method.upper()} {path}"
        self.seen.add(signature)
        self.steps += 1
        observation = {
            "body": response_body,
            "headers": response_headers,
            "progress": self.progress(),
            "reward": self.reward(),
            "scenario_hash": self.spec.scenario_hash,
            "scenario_id": self.spec.scenario_id,
            "signals": list(self.state["signals"]),
            "status": status,
        }
        return observation

    def step(self, payload: dict[str, Any]) -> dict[str, Any]:
        request = extract_request(payload)
        return self.respond(
            str(request.get("method", "GET")),
            str(request.get("url", "")),
            request.get("headers") if isinstance(request.get("headers"), dict) else {},
            request.get("body", ""),
        )

    def progress(self) -> float:
        progress = 0.0
        if self.state.get("logged_in"):
            progress += 0.25
        if self.state.get("pivot"):
            progress += 0.35
        if self.state.get("flag"):
            progress = 1.0
        return round(progress, 3)

    def reward(self) -> int:
        return (
            10 * int(bool(self.state.get("flag")))
            + 3 * int(bool(self.state.get("pivot")))
            + 2 * int(bool(self.state.get("logged_in")))
            + min(self.steps, 4)
        )

    def result(self) -> dict[str, Any]:
        return {
            "flag": bool(self.state.get("flag")),
            "logged_in": bool(self.state.get("logged_in")),
            "pivot": bool(self.state.get("pivot")),
            "reward": self.reward(),
            "scenario_hash": self.spec.scenario_hash,
            "scenario_id": self.spec.scenario_id,
            "steps": self.steps,
            "unique": len(self.seen),
        }


def _signal(state: dict[str, Any], name: str) -> None:
    if name not in state["signals"]:
        state["signals"].append(name)


def _idor_responder(state: dict[str, Any], method: str, path: str, headers: dict[str, Any] | None, body: Any) -> tuple[int, dict[str, str], str]:
    token = "CASE-REVIEW-7742"
    if path == "/":
        return 200, {}, "<a href=/login>login</a> <a href=/api/cases/me>cases</a>"
    if path == "/login" and method == "POST" and "analyst-pass" in body_text(body):
        state["logged_in"] = True
        _signal(state, "login")
        return 302, {"set-cookie": "case_session=CASESESS; Path=/", "location": "/api/cases/me"}, ""
    if path == "/api/cases/me":
        if "case_session=CASESESS" not in header_lookup(headers, "Cookie"):
            return 401, {}, "login required"
        return 200, {}, json.dumps({"own_case": "CASE-410", "related_case": "CASE-947"})
    if path == "/api/cases/CASE-947":
        if "case_session=CASESESS" not in header_lookup(headers, "Cookie"):
            return 401, {}, "login required"
        state["pivot"] = True
        _signal(state, "idor_token")
        return 200, {}, json.dumps({"owner": "audit-admin", "review_token": token})
    if path == "/api/admin/export" and header_lookup(headers, "X-Case-Review") == token:
        state["flag"] = True
        return 200, {}, "marker=AEGISPT_RL_IDOR_2147"
    return 404, {}, "not found"


def _ssrf_responder(state: dict[str, Any], method: str, path: str, headers: dict[str, Any] | None, body: Any) -> tuple[int, dict[str, str], str]:
    text = body_text(body)
    ticket = "RECOVERY-6619"
    session = "STAFF-SESS-6619"
    if path == "/":
        return 200, {}, "<form action=/fetch>fetch</form> <a href=/profile>profile</a>"
    if path == "/profile":
        return 200, {}, json.dumps({"internal": "http://identity-rl.internal.example", "user": "emp-82"})
    if path == "/fetch" and method == "POST" and "/health" in text:
        state["pivot"] = True
        _signal(state, "internal_reachable")
        return 200, {}, json.dumps({"component": "identity", "ok": True})
    if path == "/fetch" and method == "POST" and "/tickets/recovery" in text and "emp-82" in text:
        _signal(state, "recovery_ticket")
        return 200, {}, json.dumps({"recovery_ticket": ticket})
    if path == "/session/exchange" and method == "POST" and ticket in text:
        state["logged_in"] = True
        _signal(state, "staff_session")
        return 200, {"set-cookie": f"staff_session={session}; Path=/"}, json.dumps({"session": session})
    if path == "/staff/marker" and session in header_lookup(headers, "Cookie"):
        state["flag"] = True
        return 200, {}, "marker=AEGISPT_RL_SSRF_3910"
    return 404, {}, "not found"


def _lowpriv_responder(state: dict[str, Any], method: str, path: str, headers: dict[str, Any] | None, body: Any) -> tuple[int, dict[str, str], str]:
    preview = "DLG-204"
    admin_session = "ADMIN-DELEGATED-204"
    if path == "/":
        return 200, {}, "<a href=/login>login</a> <a href=/me>me</a>"
    if path == "/login" and method == "POST" and "low-reviewer" in body_text(body):
        state["logged_in"] = True
        _signal(state, "login")
        return 302, {"set-cookie": "role_session=LOWSESS; Path=/", "location": "/me"}, ""
    if path == "/me":
        if "role_session=LOWSESS" not in header_lookup(headers, "Cookie"):
            return 401, {}, "login required"
        return 200, {}, json.dumps({"delegation_preview": f"/delegations/{preview}/preview", "role": "reviewer"})
    if path == f"/delegations/{preview}/preview":
        if "role_session=LOWSESS" not in header_lookup(headers, "Cookie"):
            return 401, {}, "login required"
        state["pivot"] = True
        _signal(state, "delegation_preview")
        return 200, {}, json.dumps({"accept_url": f"/delegations/{preview}/accept", "scope": "temporary-admin-marker"})
    if path == f"/delegations/{preview}/accept" and method == "POST":
        state["logged_in"] = True
        _signal(state, "delegated_admin")
        return 200, {"set-cookie": f"role_session={admin_session}; Path=/"}, json.dumps({"role": "admin"})
    if path == "/admin/marker" and admin_session in header_lookup(headers, "Cookie"):
        state["flag"] = True
        return 200, {}, "marker=AEGISPT_RL_PRIVESC_8821"
    return 404, {}, "not found"


def _lateral_responder(state: dict[str, Any], method: str, path: str, headers: dict[str, Any] | None, body: Any) -> tuple[int, dict[str, str], str]:
    token = "WIKI-LATERAL-510"
    text = body_text(body)
    if path == "/":
        return 200, {}, "<a href=/tickets/TCK-118>ticket</a>"
    if path == "/tickets/TCK-118":
        state["pivot"] = True
        _signal(state, "credential_disclosure")
        return 200, {}, json.dumps({"service": "wiki", "username": "svc-runbook", "password": "runbook-once-510"})
    if path == "/login" and method == "POST" and "svc-runbook" in text and "runbook-once-510" in text:
        state["logged_in"] = True
        _signal(state, "lateral_login")
        return 200, {}, json.dumps({"handoff": "http://wiki-rl-lab.example/spaces/OPS-A", "token": token})
    if path == "/spaces/OPS-A/marker" and token in header_lookup(headers, "Authorization"):
        state["flag"] = True
        return 200, {}, "marker=AEGISPT_RL_LATERAL_6402"
    return 404, {}, "not found"


def scenario_specs() -> tuple[ScenarioSpec, ...]:
    return (
        ScenarioSpec(
            scenario_id="rl-train-idormap-case-review-token",
            chain_class="idor_object_token_reuse",
            domain="api",
            host="http://cases-rl-lab.example",
            marker="AEGISPT_RL_IDOR_2147",
            goal="Authenticate as analyst, follow one observed related case, reuse its review token, and read the admin export marker.",
            oracle_actions=(
                action("GET", "http://cases-rl-lab.example/"),
                action("POST", "http://cases-rl-lab.example/login", body="username=analyst&password=analyst-pass"),
                action("GET", "http://cases-rl-lab.example/api/cases/me", headers={"Cookie": "case_session=CASESESS"}),
                action("GET", "http://cases-rl-lab.example/api/cases/CASE-947", headers={"Cookie": "case_session=CASESESS"}),
                action("GET", "http://cases-rl-lab.example/api/admin/export", headers={"X-Case-Review": "CASE-REVIEW-7742"}),
            ),
            responder=_idor_responder,
        ),
        ScenarioSpec(
            scenario_id="rl-train-ssrf-recovery-ticket",
            chain_class="ssrf_internal_recovery_ticket",
            domain="web_api",
            host="http://fetch-rl-lab.example",
            marker="AEGISPT_RL_SSRF_3910",
            goal="Use the lab fetcher to reach an internal identity service, exchange the observed recovery ticket, and read the staff marker.",
            oracle_actions=(
                action("GET", "http://fetch-rl-lab.example/profile"),
                action("POST", "http://fetch-rl-lab.example/fetch", body='{"url":"http://identity-rl.internal.example/health"}'),
                action("POST", "http://fetch-rl-lab.example/fetch", body='{"url":"http://identity-rl.internal.example/tickets/recovery?user=emp-82"}'),
                action("POST", "http://fetch-rl-lab.example/session/exchange", body='{"ticket":"RECOVERY-6619"}'),
                action("GET", "http://fetch-rl-lab.example/staff/marker", headers={"Cookie": "staff_session=STAFF-SESS-6619"}),
            ),
            responder=_ssrf_responder,
        ),
        ScenarioSpec(
            scenario_id="rl-train-lowpriv-delegated-admin",
            chain_class="lowpriv_delegation_admin_marker",
            domain="web",
            host="http://roles-rl-lab.example",
            marker="AEGISPT_RL_PRIVESC_8821",
            goal="Login as a low-privilege reviewer, follow the observed delegation preview, accept scoped delegation, and read the admin marker.",
            oracle_actions=(
                action("POST", "http://roles-rl-lab.example/login", body="username=low-reviewer&password=reviewer-pass"),
                action("GET", "http://roles-rl-lab.example/me", headers={"Cookie": "role_session=LOWSESS"}),
                action("GET", "http://roles-rl-lab.example/delegations/DLG-204/preview", headers={"Cookie": "role_session=LOWSESS"}),
                action("POST", "http://roles-rl-lab.example/delegations/DLG-204/accept", headers={"Cookie": "role_session=LOWSESS"}),
                action("GET", "http://roles-rl-lab.example/admin/marker", headers={"Cookie": "role_session=ADMIN-DELEGATED-204"}),
            ),
            responder=_lowpriv_responder,
        ),
        ScenarioSpec(
            scenario_id="rl-train-credential-reuse-lateral-wiki",
            chain_class="info_disclosure_credential_reuse_lateral",
            domain="multi_service",
            host="http://helpdesk-rl-lab.example",
            marker="AEGISPT_RL_LATERAL_6402",
            goal="Read a support ticket, reuse the observed service credential on the lateral wiki service, and read the workspace marker.",
            oracle_actions=(
                action("GET", "http://helpdesk-rl-lab.example/tickets/TCK-118"),
                action("POST", "http://helpdesk-rl-lab.example/login", body="username=svc-runbook&password=runbook-once-510"),
                action("GET", "http://wiki-rl-lab.example/spaces/OPS-A/marker", headers={"Authorization": "Bearer WIKI-LATERAL-510"}),
            ),
            responder=_lateral_responder,
        ),
    )


def get_spec(scenario_id: str) -> ScenarioSpec:
    for spec in scenario_specs():
        if spec.scenario_id == scenario_id:
            return spec
    raise ValueError(f"unknown scenario_id: {scenario_id}")


def manifest() -> dict[str, Any]:
    scenarios = []
    for spec in scenario_specs():
        scenarios.append(
            {
                "chain_class": spec.chain_class,
                "dataset_family": DEFAULT_PREFIX,
                "domain": spec.domain,
                "goal": spec.goal,
                "host": spec.host,
                "marker": spec.marker,
                "oracle_steps": len(spec.oracle_actions),
                "scenario_hash": spec.scenario_hash,
                "scenario_id": spec.scenario_id,
            }
        )
    return {
        "dataset": DEFAULT_PREFIX,
        "interface": "json_action_to_http_observation",
        "policy": {
            "data_lane_only": True,
            "deep_chain_held_out_not_used": True,
            "lab_only": True,
            "runtime_binding": False,
            "runtime_execution": False,
        },
        "scenarios": scenarios,
    }


def registry_entries() -> list[dict[str, Any]]:
    return [
        {
            "chain_class": item["chain_class"],
            "dataset_family": DEFAULT_PREFIX,
            "domain": item["domain"],
            "holdout_reason": "iter9_rl_training_env_reserved",
            "scenario_hash": item["scenario_hash"],
            "scenario_id": item["scenario_id"],
            "source": "scripts/training/multichain_rl_envs_iter9.py",
            "split": "rl_train_env",
        }
        for item in manifest()["scenarios"]
    ]


def run_oracle(spec: ScenarioSpec) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    env = TrainingEnv(spec)
    trace: list[dict[str, Any]] = []
    for idx, payload in enumerate(spec.oracle_actions, start=1):
        observation = env.step(payload)
        trace.append(
            {
                "action": json.dumps(payload, sort_keys=True),
                "evidence": [f"{spec.scenario_id}-step-{idx}"],
                "failure_reason": "",
                "objective_progress": observation["progress"],
                "scenario_id": spec.scenario_id,
                "state": f"step{idx}",
                "tool_result": json.dumps(observation, sort_keys=True),
            }
        )
    return trace, env.result()


def write_oracle_rollouts(out_dir: Path) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    summary: dict[str, Any] = {
        "dataset": DEFAULT_PREFIX,
        "rollouts": [],
    }
    for idx, spec in enumerate(scenario_specs()):
        trace, result = run_oracle(spec)
        roll_path = out_dir / f"roll_{idx}.jsonl"
        res_path = out_dir / f"res_{idx}.json"
        roll_path.write_text(
            "\n".join(json.dumps(row, sort_keys=True) for row in trace) + "\n",
            encoding="utf-8",
        )
        res_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        summary["rollouts"].append(
            {
                "res_path": str(res_path),
                "result": result,
                "roll_path": str(roll_path),
                "scenario_id": spec.scenario_id,
            }
        )
    manifest_path = out_dir / f"{DEFAULT_PREFIX}_manifest.json"
    manifest_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return summary


def validate_manifest(data: dict[str, Any]) -> dict[str, Any]:
    serialized = json.dumps(data, sort_keys=True)
    for marker in FORBIDDEN_HELD_OUT_MARKERS:
        if marker in serialized:
            raise ValueError(f"held-out marker leaked into RL envs: {marker}")
    scenario_ids = [item["scenario_id"] for item in data["scenarios"]]
    if len(scenario_ids) != len(set(scenario_ids)):
        raise ValueError("duplicate RL scenario ids")
    hashes = [item["scenario_hash"] for item in data["scenarios"]]
    if len(hashes) != len(set(hashes)):
        raise ValueError("duplicate RL scenario hashes")
    return {
        "chain_classes": dict(sorted((item["chain_class"], 1) for item in data["scenarios"])),
        "scenario_count": len(data["scenarios"]),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true", help="Print environment manifest.")
    parser.add_argument("--scenario", help="Run one environment action or oracle by scenario id.")
    parser.add_argument("--action-json", help="One JSON action to apply to --scenario.")
    parser.add_argument("--scripted-oracle", action="store_true", help="Run deterministic oracle actions.")
    parser.add_argument("--oracle-out-dir", type=Path, default=DEFAULT_OUT_DIR / DEFAULT_PREFIX)
    args = parser.parse_args()
    if args.list:
        data = manifest()
        validate_manifest(data)
        print(json.dumps(data, indent=2, sort_keys=True))
        return
    if args.scripted_oracle and not args.scenario:
        print(json.dumps(write_oracle_rollouts(args.oracle_out_dir), indent=2, sort_keys=True))
        return
    if not args.scenario:
        parser.error("--scenario is required unless --list or --scripted-oracle without --scenario is used")
    spec = get_spec(args.scenario)
    env = TrainingEnv(spec)
    if args.scripted_oracle:
        trace, result = run_oracle(spec)
        print(json.dumps({"result": result, "trace": trace}, indent=2, sort_keys=True))
        return
    if not args.action_json:
        parser.error("--action-json is required without --scripted-oracle")
    payload = json.loads(args.action_json)
    print(json.dumps(env.step(payload), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
