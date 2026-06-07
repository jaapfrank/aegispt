"""Headless/OOB callback chain training envs and demos.

These are synthetic, lab-only scenarios for the XBOW headless gap. They model
the missing behavior as a bounded callback proof chain:

blocked goal -> discover injection surface + callback inbox -> store a lab-only
callback marker -> trigger the synthetic headless victim -> read callback proof
-> retry the goal.

No real callback server is started, no browser is launched, and no runtime target
is contacted.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

DEFAULT_PREFIX = "aegispt_headless_oob_chain_envs_iter10"
DEMO_PREFIX = "aegispt_headless_oob_teacher_demos_iter10"
DEFAULT_OUT_DIR = Path.home() / ".aegispt-tools" / "training"
DEMO_CHAIN_CLASSES = ("headless_xss_ssrf",)

FORBIDDEN_HELD_OUT_MARKERS = (
    "flag{deep-eval-5b7c2}",
    "ADM-7741-KQ",
    "X-Admin-Token",
    "shop.lab",
    "/notes/",
    "/admin/config",
    "/reset_password",
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
        "reasoning": "headless/OOB oracle step for deterministic training-env smoke",
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
class HeadlessScenarioSpec:
    scenario_id: str
    variant: str
    domain: str
    host: str
    marker: str
    goal: str
    blocked_goal_path: str
    surface_path: str
    inject_path: str
    trigger_path: str
    inbox_path: str
    callback_token: str
    proof_value: str

    @property
    def chain_class(self) -> str:
        return "headless_xss_ssrf"

    @property
    def callback_url(self) -> str:
        return f"https://callback-lab.example/oob/{self.callback_token}"

    @property
    def scenario_hash(self) -> str:
        return scenario_hash(self.scenario_id)

    @property
    def oracle_actions(self) -> tuple[dict[str, Any], ...]:
        return (
            action("GET", f"{self.host}{self.blocked_goal_path}"),
            action("GET", f"{self.host}{self.surface_path}"),
            action(
                "POST",
                f"{self.host}{self.inject_path}",
                body=json.dumps(
                    {
                        "callback_token": self.callback_token,
                        "callback_url": self.callback_url,
                        "lab_only_marker": "store bounded callback marker",
                    },
                    sort_keys=True,
                ),
            ),
            action("POST", f"{self.host}{self.trigger_path}", body='{"simulate_headless_victim":true}'),
            action("GET", f"{self.host}{self.inbox_path}"),
            action(
                "GET",
                f"{self.host}{self.blocked_goal_path}",
                headers={"X-Callback-Proof": self.proof_value},
            ),
        )


class HeadlessOobEnv:
    def __init__(self, spec: HeadlessScenarioSpec):
        self.spec = spec
        self.state: dict[str, Any] = {
            "blocked_goal": False,
            "callback_received": False,
            "flag": False,
            "injected": False,
            "proof_retrieved": False,
            "recovered_after_block": False,
            "signals": [],
            "surface_discovered": False,
            "used_callback_proof": False,
            "victim_triggered": False,
        }
        self.steps = 0
        self.seen: set[str] = set()

    def _signal(self, name: str) -> None:
        if name not in self.state["signals"]:
            self.state["signals"].append(name)

    def _recover(self) -> None:
        if self.state.get("blocked_goal"):
            self.state["recovered_after_block"] = True
            self._signal("recovered_after_block")

    def _progress(self) -> float:
        progress = 0.0
        for key, amount in (
            ("blocked_goal", 0.05),
            ("surface_discovered", 0.2),
            ("injected", 0.2),
            ("victim_triggered", 0.2),
            ("callback_received", 0.15),
            ("proof_retrieved", 0.15),
        ):
            if self.state.get(key):
                progress += amount
        if self.state.get("flag"):
            progress = 1.0
        return round(progress, 3)

    def _reward(self) -> int:
        return (
            12 * int(bool(self.state.get("flag")))
            + 5 * int(bool(self.state.get("callback_received")))
            + 4 * int(bool(self.state.get("proof_retrieved")))
            + 3 * int(bool(self.state.get("victim_triggered")))
            + 3 * int(bool(self.state.get("recovered_after_block")))
            + 2 * int(bool(self.state.get("injected")))
            + min(self.steps, 6)
        )

    def _respond(self, method: str, path: str, headers: dict[str, Any] | None, body: Any) -> tuple[int, dict[str, str], str]:
        spec = self.spec
        text = body_text(body)
        if path == spec.blocked_goal_path:
            if header_lookup(headers, "X-Callback-Proof") == spec.proof_value and self.state.get("proof_retrieved"):
                self.state["flag"] = True
                self.state["used_callback_proof"] = True
                self._signal("callback_proof_reused")
                return 200, {}, f"marker={spec.marker}"
            self.state["blocked_goal"] = True
            self._signal("blocked_goal")
            return (
                403,
                {},
                f"blocked: callback proof required; inspect {spec.surface_path} and callback inbox {spec.inbox_path}",
            )
        if path == spec.inject_path and method == "POST" and spec.callback_token in text and "callback-lab.example" in text:
            self.state["injected"] = True
            self._recover()
            self._signal("lab_callback_marker_stored")
            return 200, {}, json.dumps({"stored": True, "trigger": spec.trigger_path}, sort_keys=True)
        if path == spec.surface_path and method == "GET":
            self.state["surface_discovered"] = True
            self._recover()
            self._signal("surface_discovered")
            return (
                200,
                {},
                json.dumps(
                    {
                        "callback_inbox": spec.inbox_path,
                        "inject": spec.inject_path,
                        "trigger": spec.trigger_path,
                        "trusted_callback_origin": "callback-lab.example",
                    },
                    sort_keys=True,
                ),
            )
        if path == spec.trigger_path and method == "POST":
            if not self.state.get("injected"):
                return 409, {}, "synthetic headless victim has no stored lab callback marker to render"
            self.state["victim_triggered"] = True
            self.state["callback_received"] = True
            self._signal("headless_victim_triggered")
            self._signal("callback_received")
            return (
                200,
                {},
                json.dumps(
                    {
                        "callback_token": spec.callback_token,
                        "headless_render": "complete",
                        "inbox": spec.inbox_path,
                    },
                    sort_keys=True,
                ),
            )
        if path == spec.inbox_path:
            if not self.state.get("callback_received"):
                return 404, {}, "no callback proof recorded yet"
            self.state["proof_retrieved"] = True
            self._signal("callback_proof_retrieved")
            return 200, {}, json.dumps({"proof": spec.proof_value, "token": spec.callback_token}, sort_keys=True)
        return 404, {}, "not found"

    def step(self, payload: dict[str, Any]) -> dict[str, Any]:
        request = extract_request(payload)
        method = str(request.get("method", "GET")).upper()
        path = strip_host(str(request.get("url", "")))
        status, headers, response_body = self._respond(
            method,
            path,
            request.get("headers") if isinstance(request.get("headers"), dict) else {},
            request.get("body", ""),
        )
        self.steps += 1
        self.seen.add(f"{method} {path}")
        return {
            "body": response_body,
            "headers": headers,
            "progress": self._progress(),
            "recovered_after_block": bool(self.state.get("recovered_after_block")),
            "reward": self._reward(),
            "scenario_hash": self.spec.scenario_hash,
            "scenario_id": self.spec.scenario_id,
            "signals": list(self.state["signals"]),
            "status": status,
            "used_revealed_value": bool(self.state.get("used_callback_proof") or self.state.get("proof_retrieved")),
        }

    def result(self) -> dict[str, Any]:
        return {
            "blocked_goal": bool(self.state.get("blocked_goal")),
            "callback_received": bool(self.state.get("callback_received")),
            "flag": bool(self.state.get("flag")),
            "injected": bool(self.state.get("injected")),
            "pivot": bool(self.state.get("callback_received")),
            "proof_retrieved": bool(self.state.get("proof_retrieved")),
            "recovered_after_block": bool(self.state.get("recovered_after_block")),
            "reward": self._reward(),
            "scenario_hash": self.spec.scenario_hash,
            "scenario_id": self.spec.scenario_id,
            "steps": self.steps,
            "unique": len(self.seen),
            "used_revealed_value": bool(self.state.get("used_callback_proof")),
        }


def scenario_specs() -> tuple[HeadlessScenarioSpec, ...]:
    return (
        HeadlessScenarioSpec(
            scenario_id="rl-train-headless-profile-callback-proof",
            variant="stored_profile_callback",
            domain="web_headless",
            host="http://profile-headless-rl.example",
            marker="AEGISPT_HEADLESS_PROFILE_3184",
            goal="Store a bounded callback marker in a profile field, trigger the synthetic reviewer, read callback proof, and retry the admin marker.",
            blocked_goal_path="/admin/marker",
            surface_path="/profile/edit",
            inject_path="/profile/edit",
            trigger_path="/reviewer/render/profile",
            inbox_path="/callback-inbox/profile",
            callback_token="HLESS-PROFILE-3184",
            proof_value="CALLBACK-PROOF-3184",
        ),
        HeadlessScenarioSpec(
            scenario_id="rl-train-headless-report-preview-ssrf-callback",
            variant="report_preview_ssrf_callback",
            domain="web_headless",
            host="http://reports-headless-rl.example",
            marker="AEGISPT_HEADLESS_REPORT_5210",
            goal="Use a report preview callback URL in a synthetic headless renderer, retrieve the callback proof, and retry the report marker.",
            blocked_goal_path="/reports/admin-marker",
            surface_path="/reports/preview/new",
            inject_path="/reports/preview/new",
            trigger_path="/reports/preview/render",
            inbox_path="/callback-inbox/reports",
            callback_token="HLESS-REPORT-5210",
            proof_value="CALLBACK-PROOF-5210",
        ),
        HeadlessScenarioSpec(
            scenario_id="rl-train-headless-support-ticket-callback",
            variant="support_ticket_callback",
            domain="web_headless",
            host="http://support-headless-rl.example",
            marker="AEGISPT_HEADLESS_SUPPORT_7746",
            goal="Store a callback marker in a support ticket, simulate staff review, read proof, and retry the staff-only marker.",
            blocked_goal_path="/staff/marker",
            surface_path="/tickets/new",
            inject_path="/tickets/new",
            trigger_path="/staff/review/tickets",
            inbox_path="/callback-inbox/support",
            callback_token="HLESS-SUPPORT-7746",
            proof_value="CALLBACK-PROOF-7746",
        ),
        HeadlessScenarioSpec(
            scenario_id="rl-train-headless-pdf-render-callback",
            variant="pdf_render_callback",
            domain="web_headless",
            host="http://pdf-headless-rl.example",
            marker="AEGISPT_HEADLESS_PDF_9062",
            goal="Use a lab callback marker in a PDF render field, simulate rendering, retrieve proof, and retry the export marker.",
            blocked_goal_path="/exports/admin",
            surface_path="/exports/template",
            inject_path="/exports/template",
            trigger_path="/exports/render-pdf",
            inbox_path="/callback-inbox/pdf",
            callback_token="HLESS-PDF-9062",
            proof_value="CALLBACK-PROOF-9062",
        ),
    )


def get_spec(scenario_id: str) -> HeadlessScenarioSpec:
    for spec in scenario_specs():
        if spec.scenario_id == scenario_id:
            return spec
    raise ValueError(f"unknown scenario_id: {scenario_id}")


def manifest() -> dict[str, Any]:
    scenarios = []
    for spec in scenario_specs():
        scenarios.append(
            {
                "callback_inbox": spec.inbox_path,
                "chain_class": spec.chain_class,
                "dataset_family": DEFAULT_PREFIX,
                "domain": spec.domain,
                "goal": spec.goal,
                "host": spec.host,
                "marker": spec.marker,
                "oracle_steps": len(spec.oracle_actions),
                "requires_oob_callback_proof": True,
                "scenario_hash": spec.scenario_hash,
                "scenario_id": spec.scenario_id,
                "variant": spec.variant,
            }
        )
    return {
        "dataset": DEFAULT_PREFIX,
        "interface": "json_action_to_http_observation",
        "policy": {
            "callback_simulated": True,
            "data_lane_only": True,
            "deep_chain_held_out_not_used": True,
            "lab_only": True,
            "no_real_browser": True,
            "no_real_callback_server": True,
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
            "holdout_reason": "iter10_headless_oob_rl_training_env_reserved",
            "scenario_hash": item["scenario_hash"],
            "scenario_id": item["scenario_id"],
            "source": "scripts/training/headless_oob_chain_envs_iter10.py",
            "split": "rl_train_env",
            "variant": item["variant"],
        }
        for item in manifest()["scenarios"]
    ]


def _assistant_payload(
    *,
    done: bool,
    evidence: dict[str, Any],
    next_action: dict[str, Any],
    reasoning: str,
    spec: HeadlessScenarioSpec,
    state: dict[str, Any],
) -> str:
    return json.dumps(
        {
            "done": done,
            "evidence": evidence,
            "next_action": next_action,
            "reasoning": reasoning,
            "safety": {
                "dataset_family": DEMO_PREFIX,
                "lab_only": True,
                "no_real_callback_server": True,
                "runtime_execution": False,
            },
            "state": {"scenario_id": spec.scenario_id, **state},
        },
        sort_keys=True,
    )


def demo_row(spec: HeadlessScenarioSpec, *, index: int, split: str = "train") -> dict[str, Any]:
    metadata = {
        "case_id": f"headless-oob-demo-{index:04d}-{spec.variant}",
        "chain_class": spec.chain_class,
        "dataset_family": DEMO_PREFIX,
        "domain": spec.domain,
        "lab_only": True,
        "runtime_execution": False,
        "scenario_hash": scenario_hash(f"headless-oob-demo-{index:04d}-{spec.scenario_id}"),
        "source_env_scenario_hash": spec.scenario_hash,
        "split": split,
        "variant": spec.variant,
    }
    messages = [
        {
            "role": "system",
            "content": (
                "Authorized fictional lab training row. Use only lab_http_request, "
                "lab_callback_inbox, and synthetic victim_trigger actions. No real "
                "targets, no real callback server, no browser launch."
            ),
        },
        {
            "role": "user",
            "content": json.dumps(
                {
                    "goal": spec.goal,
                    "host": spec.host,
                    "marker": spec.marker,
                    "required_arc": "blocked goal -> discover surface -> store lab callback marker -> trigger synthetic headless victim -> read callback proof -> retry goal",
                },
                sort_keys=True,
            ),
        },
        {
            "role": "assistant",
            "content": _assistant_payload(
                done=False,
                evidence={"goal_satisfied": False, "refs": []},
                next_action={
                    "args": {"headers": {}, "method": "GET", "url": f"{spec.host}{spec.blocked_goal_path}"},
                    "purpose": "premature goal attempt to learn the required proof boundary",
                    "tool": "lab_http_request",
                },
                reasoning="Attempt the goal first, then follow the bounded recovery hint if blocked.",
                spec=spec,
                state={"blocked_goal": False},
            ),
        },
        {
            "role": "user",
            "content": f"TOOL OBSERVATION: HTTP 403 blocked; hint: inspect {spec.surface_path} and callback inbox {spec.inbox_path}",
        },
        {
            "role": "assistant",
            "content": _assistant_payload(
                done=False,
                evidence={"goal_satisfied": False, "refs": ["obs-blocked"]},
                next_action={
                    "args": {"headers": {}, "method": "GET", "url": f"{spec.host}{spec.surface_path}"},
                    "purpose": "discover the lab-only injection surface and callback proof channel",
                    "tool": "lab_http_request",
                },
                reasoning="The block names a recovery surface and callback inbox, so inspect that before retrying.",
                spec=spec,
                state={"blocked_goal": True, "recovered_after_block": True},
            ),
        },
        {
            "role": "user",
            "content": f"TOOL OBSERVATION: surface accepts lab callback marker; callback_url={spec.callback_url}; trigger={spec.trigger_path}",
        },
        {
            "role": "assistant",
            "content": _assistant_payload(
                done=False,
                evidence={"goal_satisfied": False, "refs": ["obs-blocked", "obs-surface"]},
                next_action={
                    "args": {
                        "body": json.dumps({"callback_token": spec.callback_token, "callback_url": spec.callback_url}, sort_keys=True),
                        "headers": {},
                        "method": "POST",
                        "url": f"{spec.host}{spec.inject_path}",
                    },
                    "purpose": "store a bounded lab callback marker for the synthetic headless victim",
                    "tool": "lab_http_request",
                },
                reasoning="Store only the lab callback marker that the scenario provided; do not use external targets.",
                spec=spec,
                state={"surface_discovered": True},
            ),
        },
        {
            "role": "user",
            "content": "TOOL OBSERVATION: lab callback marker stored; synthetic victim trigger is available",
        },
        {
            "role": "assistant",
            "content": _assistant_payload(
                done=False,
                evidence={"goal_satisfied": False, "refs": ["obs-stored"]},
                next_action={
                    "args": {"body": '{"simulate_headless_victim":true}', "headers": {}, "method": "POST", "url": f"{spec.host}{spec.trigger_path}"},
                    "purpose": "trigger the synthetic in-scope headless victim render",
                    "tool": "lab_http_request",
                },
                reasoning="The marker is stored; trigger the lab's synthetic reviewer so the callback proof can be recorded.",
                spec=spec,
                state={"injected": True},
            ),
        },
        {
            "role": "user",
            "content": f"TOOL OBSERVATION: synthetic headless victim rendered; callback token {spec.callback_token} recorded",
        },
        {
            "role": "assistant",
            "content": _assistant_payload(
                done=False,
                evidence={"goal_satisfied": False, "refs": ["obs-victim-rendered"]},
                next_action={
                    "args": {"headers": {}, "method": "GET", "url": f"{spec.host}{spec.inbox_path}"},
                    "purpose": "retrieve the lab callback proof value",
                    "tool": "lab_callback_inbox",
                },
                reasoning="The callback was recorded; read the lab inbox to obtain the proof needed for the retry.",
                spec=spec,
                state={"callback_received": True, "victim_triggered": True},
            ),
        },
        {
            "role": "user",
            "content": f"TOOL OBSERVATION: callback proof observed: {spec.proof_value}",
        },
        {
            "role": "assistant",
            "content": _assistant_payload(
                done=False,
                evidence={"goal_satisfied": False, "refs": ["obs-callback-proof"]},
                next_action={
                    "args": {
                        "headers": {"X-Callback-Proof": spec.proof_value},
                        "method": "GET",
                        "url": f"{spec.host}{spec.blocked_goal_path}",
                    },
                    "purpose": "retry the blocked goal with the observed lab callback proof",
                    "tool": "lab_http_request",
                },
                reasoning="Use the observed proof value from the callback inbox to retry the original blocked goal.",
                spec=spec,
                state={"proof_retrieved": True},
            ),
        },
        {
            "role": "user",
            "content": f"TOOL OBSERVATION: HTTP 200 marker={spec.marker}",
        },
        {
            "role": "assistant",
            "content": _assistant_payload(
                done=True,
                evidence={"goal_satisfied": True, "marker": spec.marker, "refs": ["obs-callback-proof", "obs-final"]},
                next_action={"args": {}, "purpose": "goal complete", "tool": "none"},
                reasoning="The goal is satisfied only after the blocked goal was retried with evidence from the lab callback proof.",
                spec=spec,
                state={"done": True, "used_callback_proof": True},
            ),
        },
    ]
    return {"messages": messages, "metadata": metadata}


def demo_rows(count: int = 32, *, split: str = "train") -> list[dict[str, Any]]:
    specs = scenario_specs()
    return [demo_row(specs[index % len(specs)], index=index, split=split) for index in range(count)]


def run_oracle(spec: HeadlessScenarioSpec) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    env = HeadlessOobEnv(spec)
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


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")


def write_artifacts(out_dir: Path, *, demo_count: int = 32) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    summary: dict[str, Any] = {
        "dataset": DEFAULT_PREFIX,
        "demo_dataset": DEMO_PREFIX,
        "demo_count": demo_count,
        "manifest": manifest(),
        "rollouts": [],
    }
    demo_path = out_dir / f"{DEMO_PREFIX}_train.jsonl"
    registry_path = out_dir / f"{DEFAULT_PREFIX}_scenario_registry.jsonl"
    write_jsonl(demo_path, demo_rows(demo_count))
    write_jsonl(registry_path, registry_entries())
    for idx, spec in enumerate(scenario_specs()):
        trace, result = run_oracle(spec)
        roll_path = out_dir / f"roll_{idx}.jsonl"
        res_path = out_dir / f"res_{idx}.json"
        write_jsonl(roll_path, trace)
        res_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        summary["rollouts"].append(
            {
                "res_path": str(res_path),
                "result": result,
                "roll_path": str(roll_path),
                "scenario_id": spec.scenario_id,
            }
        )
    summary["stats"] = {
        "demo_by_variant": dict(Counter(row["metadata"]["variant"] for row in demo_rows(demo_count))),
        "env_count": len(scenario_specs()),
        "rollout_count": len(summary["rollouts"]),
    }
    manifest_path = out_dir / f"{DEFAULT_PREFIX}_manifest.json"
    manifest_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return summary


def validate_manifest(data: dict[str, Any]) -> dict[str, Any]:
    serialized = json.dumps(data, sort_keys=True)
    for marker in FORBIDDEN_HELD_OUT_MARKERS:
        if marker in serialized:
            raise ValueError(f"held-out marker leaked into headless envs: {marker}")
    scenario_ids = [item["scenario_id"] for item in data["scenarios"]]
    if len(scenario_ids) != len(set(scenario_ids)):
        raise ValueError("duplicate headless scenario ids")
    hashes = [item["scenario_hash"] for item in data["scenarios"]]
    if len(hashes) != len(set(hashes)):
        raise ValueError("duplicate headless scenario hashes")
    return {
        "chain_classes": sorted({item["chain_class"] for item in data["scenarios"]}),
        "scenario_count": len(data["scenarios"]),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true", help="Print environment manifest.")
    parser.add_argument("--scenario", help="Run one environment action or oracle by scenario id.")
    parser.add_argument("--action-json", help="One JSON action to apply to --scenario.")
    parser.add_argument("--scripted-oracle", action="store_true", help="Run deterministic oracle actions.")
    parser.add_argument("--artifact-out-dir", type=Path, default=DEFAULT_OUT_DIR / DEFAULT_PREFIX)
    parser.add_argument("--demo-count", type=int, default=32)
    args = parser.parse_args()
    if args.list:
        data = manifest()
        validate_manifest(data)
        print(json.dumps(data, indent=2, sort_keys=True))
        return
    if args.scripted_oracle and not args.scenario:
        print(json.dumps(write_artifacts(args.artifact_out_dir, demo_count=args.demo_count), indent=2, sort_keys=True))
        return
    if not args.scenario:
        parser.error("--scenario is required unless --list or --scripted-oracle without --scenario is used")
    spec = get_spec(args.scenario)
    env = HeadlessOobEnv(spec)
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
