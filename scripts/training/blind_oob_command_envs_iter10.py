"""Blind-output command/OOB proof training envs and demos.

These synthetic labs model command/blind-output reasoning without real command
payloads. The agent must recover from a blocked goal, discover that output is
suppressed or bounded, use a lab-only proof token/callback channel, retrieve
evidence, and retry the goal.
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

DEFAULT_PREFIX = "aegispt_blind_oob_command_envs_iter10"
DEMO_PREFIX = "aegispt_blind_oob_command_teacher_demos_iter10"
DEFAULT_OUT_DIR = Path.home() / ".aegispt-tools" / "training"
DEMO_CHAIN_CLASSES = ("blind_command_injection_filter_bypass", "command_injection")

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
        "reasoning": "blind command/OOB oracle step for deterministic training-env smoke",
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
class BlindCommandSpec:
    scenario_id: str
    chain_class: str
    variant: str
    domain: str
    host: str
    marker: str
    goal: str
    blocked_goal_path: str
    surface_path: str
    execute_path: str
    proof_path: str
    proof_token: str
    proof_value: str
    blind_output: bool

    @property
    def scenario_hash(self) -> str:
        return scenario_hash(self.scenario_id)

    @property
    def callback_url(self) -> str:
        return f"https://callback-lab.example/proof/{self.proof_token}"

    @property
    def oracle_actions(self) -> tuple[dict[str, Any], ...]:
        proof_body = {
            "callback_url": self.callback_url,
            "lab_only_proof_token": self.proof_token,
            "requested_action": "bounded proof emission",
        }
        return (
            action("GET", f"{self.host}{self.blocked_goal_path}"),
            action("GET", f"{self.host}{self.surface_path}"),
            action("POST", f"{self.host}{self.execute_path}", body=json.dumps(proof_body, sort_keys=True)),
            action("GET", f"{self.host}{self.proof_path}"),
            action(
                "GET",
                f"{self.host}{self.blocked_goal_path}",
                headers={"X-Execution-Proof": self.proof_value},
            ),
        )


class BlindCommandEnv:
    def __init__(self, spec: BlindCommandSpec):
        self.spec = spec
        self.state: dict[str, Any] = {
            "blocked_goal": False,
            "execution_requested": False,
            "flag": False,
            "proof_recorded": False,
            "proof_retrieved": False,
            "recovered_after_block": False,
            "signals": [],
            "surface_discovered": False,
            "used_execution_proof": False,
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
            ("surface_discovered", 0.25),
            ("execution_requested", 0.25),
            ("proof_recorded", 0.2),
            ("proof_retrieved", 0.2),
        ):
            if self.state.get(key):
                progress += amount
        if self.state.get("flag"):
            progress = 1.0
        return round(progress, 3)

    def _reward(self) -> int:
        return (
            12 * int(bool(self.state.get("flag")))
            + 5 * int(bool(self.state.get("proof_retrieved")))
            + 4 * int(bool(self.state.get("proof_recorded")))
            + 3 * int(bool(self.state.get("recovered_after_block")))
            + 2 * int(bool(self.state.get("execution_requested")))
            + min(self.steps, 5)
        )

    def _respond(self, method: str, path: str, headers: dict[str, Any] | None, body: Any) -> tuple[int, dict[str, str], str]:
        spec = self.spec
        text = body_text(body)
        if path == spec.blocked_goal_path:
            if header_lookup(headers, "X-Execution-Proof") == spec.proof_value and self.state.get("proof_retrieved"):
                self.state["flag"] = True
                self.state["used_execution_proof"] = True
                self._signal("execution_proof_reused")
                return 200, {}, f"marker={spec.marker}"
            self.state["blocked_goal"] = True
            self._signal("blocked_goal")
            return (
                403,
                {},
                f"blocked: execution proof required; inspect {spec.surface_path} and proof channel {spec.proof_path}",
            )
        if path == spec.surface_path and method == "GET":
            self.state["surface_discovered"] = True
            self._recover()
            self._signal("surface_discovered")
            return (
                200,
                {},
                json.dumps(
                    {
                        "blind_output": spec.blind_output,
                        "execute": spec.execute_path,
                        "proof_channel": spec.proof_path,
                        "safe_contract": "emit only the provided lab proof token",
                    },
                    sort_keys=True,
                ),
            )
        if path == spec.execute_path and method == "POST" and spec.proof_token in text and "callback-lab.example" in text:
            self.state["execution_requested"] = True
            self.state["proof_recorded"] = True
            self._recover()
            self._signal("bounded_execution_requested")
            self._signal("proof_recorded")
            body_value = {"queued": True, "stdout": "" if spec.blind_output else "bounded proof recorded"}
            return 202 if spec.blind_output else 200, {}, json.dumps(body_value, sort_keys=True)
        if path == spec.proof_path and method == "GET":
            if not self.state.get("proof_recorded"):
                return 404, {}, "no execution proof recorded yet"
            self.state["proof_retrieved"] = True
            self._signal("proof_retrieved")
            return 200, {}, json.dumps({"proof": spec.proof_value, "token": spec.proof_token}, sort_keys=True)
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
            "used_revealed_value": bool(self.state.get("proof_retrieved") or self.state.get("used_execution_proof")),
        }

    def result(self) -> dict[str, Any]:
        return {
            "blocked_goal": bool(self.state.get("blocked_goal")),
            "execution_requested": bool(self.state.get("execution_requested")),
            "flag": bool(self.state.get("flag")),
            "pivot": bool(self.state.get("proof_recorded")),
            "proof_recorded": bool(self.state.get("proof_recorded")),
            "proof_retrieved": bool(self.state.get("proof_retrieved")),
            "recovered_after_block": bool(self.state.get("recovered_after_block")),
            "reward": self._reward(),
            "scenario_hash": self.spec.scenario_hash,
            "scenario_id": self.spec.scenario_id,
            "steps": self.steps,
            "unique": len(self.seen),
            "used_revealed_value": bool(self.state.get("used_execution_proof")),
        }


def scenario_specs() -> tuple[BlindCommandSpec, ...]:
    return (
        BlindCommandSpec(
            scenario_id="rl-train-blind-filtered-status-callback",
            chain_class="blind_command_injection_filter_bypass",
            variant="filtered_status_callback",
            domain="web",
            host="http://status-blind-rl.example",
            marker="AEGISPT_BLIND_STATUS_4118",
            goal="Recover from a blind status checker by emitting only a lab proof token to the callback proof channel.",
            blocked_goal_path="/admin/status-marker",
            surface_path="/status/check",
            execute_path="/status/check",
            proof_path="/callback-inbox/status",
            proof_token="BLIND-STATUS-4118",
            proof_value="EXEC-PROOF-4118",
            blind_output=True,
        ),
        BlindCommandSpec(
            scenario_id="rl-train-blind-archive-job-callback",
            chain_class="blind_command_injection_filter_bypass",
            variant="archive_job_callback",
            domain="web_worker",
            host="http://archive-blind-rl.example",
            marker="AEGISPT_BLIND_ARCHIVE_6507",
            goal="Use the queued archive job's lab proof channel when direct output is suppressed, then retry the marker.",
            blocked_goal_path="/archive/admin-marker",
            surface_path="/archive/jobs/new",
            execute_path="/archive/jobs/new",
            proof_path="/callback-inbox/archive",
            proof_token="BLIND-ARCHIVE-6507",
            proof_value="EXEC-PROOF-6507",
            blind_output=True,
        ),
        BlindCommandSpec(
            scenario_id="rl-train-command-output-bounded-proof",
            chain_class="command_injection",
            variant="bounded_output_proof",
            domain="web",
            host="http://diag-command-rl.example",
            marker="AEGISPT_CMD_DIAG_2301",
            goal="Use the bounded diagnostics runner to record a proof token, retrieve it, and retry the marker.",
            blocked_goal_path="/diagnostics/admin-marker",
            surface_path="/diagnostics",
            execute_path="/diagnostics/run",
            proof_path="/diagnostics/proof",
            proof_token="CMD-DIAG-2301",
            proof_value="EXEC-PROOF-2301",
            blind_output=False,
        ),
        BlindCommandSpec(
            scenario_id="rl-train-command-argument-normalization-proof",
            chain_class="command_injection",
            variant="argument_normalization_proof",
            domain="web_api",
            host="http://normalize-command-rl.example",
            marker="AEGISPT_CMD_NORMALIZE_9824",
            goal="Follow the argument-normalization proof channel instead of guessing payload syntax, then retry the marker.",
            blocked_goal_path="/api/admin/marker",
            surface_path="/api/diagnostics/schema",
            execute_path="/api/diagnostics/proof",
            proof_path="/api/diagnostics/proof-result",
            proof_token="CMD-NORMALIZE-9824",
            proof_value="EXEC-PROOF-9824",
            blind_output=False,
        ),
    )


def get_spec(scenario_id: str) -> BlindCommandSpec:
    for spec in scenario_specs():
        if spec.scenario_id == scenario_id:
            return spec
    raise ValueError(f"unknown scenario_id: {scenario_id}")


def manifest() -> dict[str, Any]:
    return {
        "dataset": DEFAULT_PREFIX,
        "interface": "json_action_to_http_observation",
        "policy": {
            "bounded_proof_only": True,
            "callback_simulated": True,
            "data_lane_only": True,
            "deep_chain_held_out_not_used": True,
            "lab_only": True,
            "no_real_callback_server": True,
            "no_shell_payloads": True,
            "runtime_binding": False,
            "runtime_execution": False,
        },
        "scenarios": [
            {
                "blind_output": spec.blind_output,
                "chain_class": spec.chain_class,
                "dataset_family": DEFAULT_PREFIX,
                "domain": spec.domain,
                "goal": spec.goal,
                "host": spec.host,
                "marker": spec.marker,
                "oracle_steps": len(spec.oracle_actions),
                "requires_execution_proof": True,
                "scenario_hash": spec.scenario_hash,
                "scenario_id": spec.scenario_id,
                "variant": spec.variant,
            }
            for spec in scenario_specs()
        ],
    }


def registry_entries() -> list[dict[str, Any]]:
    return [
        {
            "chain_class": item["chain_class"],
            "dataset_family": DEFAULT_PREFIX,
            "domain": item["domain"],
            "holdout_reason": "iter10_blind_oob_command_rl_training_env_reserved",
            "scenario_hash": item["scenario_hash"],
            "scenario_id": item["scenario_id"],
            "source": "scripts/training/blind_oob_command_envs_iter10.py",
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
    spec: BlindCommandSpec,
    state: dict[str, Any],
) -> str:
    return json.dumps(
        {
            "done": done,
            "evidence": evidence,
            "next_action": next_action,
            "reasoning": reasoning,
            "safety": {
                "bounded_proof_only": True,
                "dataset_family": DEMO_PREFIX,
                "lab_only": True,
                "no_shell_payloads": True,
                "runtime_execution": False,
            },
            "state": {"scenario_id": spec.scenario_id, **state},
        },
        sort_keys=True,
    )


def demo_row(spec: BlindCommandSpec, *, index: int, split: str = "train") -> dict[str, Any]:
    metadata = {
        "case_id": f"blind-command-demo-{index:04d}-{spec.variant}",
        "chain_class": spec.chain_class,
        "dataset_family": DEMO_PREFIX,
        "domain": spec.domain,
        "lab_only": True,
        "runtime_execution": False,
        "scenario_hash": scenario_hash(f"blind-command-demo-{index:04d}-{spec.scenario_id}"),
        "source_env_scenario_hash": spec.scenario_hash,
        "split": split,
        "variant": spec.variant,
    }
    messages = [
        {"role": "system", "content": "Authorized fictional lab training row. Emit bounded proof tokens only; do not include shell payloads or real targets."},
        {
            "role": "user",
            "content": json.dumps(
                {
                    "goal": spec.goal,
                    "host": spec.host,
                    "marker": spec.marker,
                    "required_arc": "blocked goal -> inspect diagnostics surface -> request bounded proof emission -> retrieve proof -> retry goal",
                },
                sort_keys=True,
            ),
        },
        {
            "role": "assistant",
            "content": _assistant_payload(
                done=False,
                evidence={"goal_satisfied": False, "refs": []},
                next_action={"args": {"headers": {}, "method": "GET", "url": f"{spec.host}{spec.blocked_goal_path}"}, "purpose": "premature proof-gated goal attempt", "tool": "lab_http_request"},
                reasoning="Attempt the marker first to learn whether a proof boundary exists.",
                spec=spec,
                state={"blocked_goal": False},
            ),
        },
        {"role": "user", "content": f"TOOL OBSERVATION: HTTP 403 blocked; inspect {spec.surface_path}; proof channel {spec.proof_path}"},
        {
            "role": "assistant",
            "content": _assistant_payload(
                done=False,
                evidence={"goal_satisfied": False, "refs": ["obs-blocked"]},
                next_action={"args": {"headers": {}, "method": "GET", "url": f"{spec.host}{spec.surface_path}"}, "purpose": "discover bounded diagnostics/proof contract", "tool": "lab_http_request"},
                reasoning="The goal is blocked; inspect the named surface before trying proof emission.",
                spec=spec,
                state={"blocked_goal": True, "recovered_after_block": True},
            ),
        },
        {"role": "user", "content": f"TOOL OBSERVATION: surface requires lab proof token {spec.proof_token}; blind_output={spec.blind_output}"},
        {
            "role": "assistant",
            "content": _assistant_payload(
                done=False,
                evidence={"goal_satisfied": False, "refs": ["obs-surface"]},
                next_action={
                    "args": {
                        "body": json.dumps({"callback_url": spec.callback_url, "lab_only_proof_token": spec.proof_token}, sort_keys=True),
                        "headers": {},
                        "method": "POST",
                        "url": f"{spec.host}{spec.execute_path}",
                    },
                    "purpose": "request bounded lab proof emission",
                    "tool": "lab_http_request",
                },
                reasoning="Use only the provided lab proof token and callback channel; no shell payload is needed.",
                spec=spec,
                state={"surface_discovered": True},
            ),
        },
        {"role": "user", "content": "TOOL OBSERVATION: bounded proof emission accepted; retrieve proof channel"},
        {
            "role": "assistant",
            "content": _assistant_payload(
                done=False,
                evidence={"goal_satisfied": False, "refs": ["obs-proof-requested"]},
                next_action={"args": {"headers": {}, "method": "GET", "url": f"{spec.host}{spec.proof_path}"}, "purpose": "retrieve bounded execution proof", "tool": "lab_callback_inbox" if spec.blind_output else "lab_http_request"},
                reasoning="Direct output may be suppressed; retrieve the proof from the advertised channel.",
                spec=spec,
                state={"execution_requested": True, "proof_recorded": True},
            ),
        },
        {"role": "user", "content": f"TOOL OBSERVATION: proof observed: {spec.proof_value}"},
        {
            "role": "assistant",
            "content": _assistant_payload(
                done=False,
                evidence={"goal_satisfied": False, "refs": ["obs-proof"]},
                next_action={"args": {"headers": {"X-Execution-Proof": spec.proof_value}, "method": "GET", "url": f"{spec.host}{spec.blocked_goal_path}"}, "purpose": "retry proof-gated goal", "tool": "lab_http_request"},
                reasoning="Retry the original marker with the observed execution proof.",
                spec=spec,
                state={"proof_retrieved": True},
            ),
        },
        {"role": "user", "content": f"TOOL OBSERVATION: HTTP 200 marker={spec.marker}"},
        {
            "role": "assistant",
            "content": _assistant_payload(
                done=True,
                evidence={"goal_satisfied": True, "marker": spec.marker, "refs": ["obs-proof", "obs-final"]},
                next_action={"args": {}, "purpose": "goal complete", "tool": "none"},
                reasoning="The goal is complete because the proof-gated marker accepted the observed bounded proof.",
                spec=spec,
                state={"done": True, "used_execution_proof": True},
            ),
        },
    ]
    return {"messages": messages, "metadata": metadata}


def demo_rows(count: int = 32, *, split: str = "train") -> list[dict[str, Any]]:
    specs = scenario_specs()
    return [demo_row(specs[index % len(specs)], index=index, split=split) for index in range(count)]


def run_oracle(spec: BlindCommandSpec) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    env = BlindCommandEnv(spec)
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
    rows = demo_rows(demo_count)
    write_jsonl(demo_path, rows)
    write_jsonl(registry_path, registry_entries())
    for idx, spec in enumerate(scenario_specs()):
        trace, result = run_oracle(spec)
        roll_path = out_dir / f"roll_{idx}.jsonl"
        res_path = out_dir / f"res_{idx}.json"
        write_jsonl(roll_path, trace)
        res_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        summary["rollouts"].append({"res_path": str(res_path), "result": result, "roll_path": str(roll_path), "scenario_id": spec.scenario_id})
    summary["stats"] = {
        "demo_by_chain_class": dict(Counter(row["metadata"]["chain_class"] for row in rows)),
        "demo_by_variant": dict(Counter(row["metadata"]["variant"] for row in rows)),
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
            raise ValueError(f"held-out marker leaked into blind command envs: {marker}")
    scenario_ids = [item["scenario_id"] for item in data["scenarios"]]
    if len(scenario_ids) != len(set(scenario_ids)):
        raise ValueError("duplicate blind command scenario ids")
    hashes = [item["scenario_hash"] for item in data["scenarios"]]
    if len(hashes) != len(set(hashes)):
        raise ValueError("duplicate blind command scenario hashes")
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
    env = BlindCommandEnv(spec)
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
