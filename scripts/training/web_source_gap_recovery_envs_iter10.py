"""Web source-gap recovery-arc training envs and demos.

These synthetic labs cover the E1 source-proven buckets that still lacked
env/demo coverage after the XBEN source triage:

* sqli_filter_bypass
* file_upload_webroot
* path_traversal_file_read
* static_file_or_server_misconfig

They are deliberately payload-free. The useful behavior is the recovery arc:
blocked goal -> inspect hinted evidence -> reuse a bounded proof token -> retry.
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

DEFAULT_PREFIX = "aegispt_web_source_gap_recovery_envs_iter10"
DEMO_PREFIX = "aegispt_web_source_gap_recovery_teacher_demos_iter10"
DEFAULT_OUT_DIR = Path.home() / ".aegispt-tools" / "training"
DEMO_CHAIN_CLASSES = (
    "file_upload_webroot",
    "path_traversal_file_read",
    "sqli_filter_bypass",
    "static_file_or_server_misconfig",
)

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
        "reasoning": "web source-gap recovery oracle step for deterministic training-env smoke",
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
class WebGapSpec:
    scenario_id: str
    chain_class: str
    variant: str
    host: str
    marker: str
    goal: str
    blocked_goal_path: str
    evidence_path: str
    recovery_path: str
    proof_path: str
    recovery_token: str
    proof_value: str
    recovery_header: str = "X-Recovery-Proof"

    @property
    def scenario_hash(self) -> str:
        return scenario_hash(self.scenario_id)

    @property
    def oracle_actions(self) -> tuple[dict[str, Any], ...]:
        return (
            action("GET", f"{self.host}{self.blocked_goal_path}"),
            action("GET", f"{self.host}{self.evidence_path}"),
            action(
                "POST",
                f"{self.host}{self.recovery_path}",
                body=json.dumps(
                    {
                        "evidence_token": self.recovery_token,
                        "lab_only": True,
                        "requested_decision": "bounded recovery proof",
                    },
                    sort_keys=True,
                ),
            ),
            action(
                "GET",
                f"{self.host}{self.proof_path}",
                headers={self.recovery_header: self.proof_value},
            ),
        )


class WebGapEnv:
    def __init__(self, spec: WebGapSpec):
        self.spec = spec
        self.state: dict[str, Any] = {
            "blocked_goal": False,
            "evidence_collected": False,
            "flag": False,
            "pivot": False,
            "proof_ready": False,
            "recovered_after_block": False,
            "signals": [],
            "used_revealed_value": False,
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
            ("blocked_goal", 0.1),
            ("evidence_collected", 0.25),
            ("pivot", 0.3),
            ("proof_ready", 0.2),
            ("used_revealed_value", 0.1),
        ):
            if self.state.get(key):
                progress += amount
        if self.state.get("flag"):
            progress = 1.0
        return round(progress, 3)

    def _reward(self) -> int:
        return (
            12 * int(bool(self.state.get("flag")))
            + 4 * int(bool(self.state.get("proof_ready")))
            + 3 * int(bool(self.state.get("recovered_after_block")))
            + 3 * int(bool(self.state.get("pivot")))
            + 3 * int(bool(self.state.get("used_revealed_value")))
            + min(self.steps, 4)
        )

    def _respond(
        self,
        method: str,
        path: str,
        headers: dict[str, Any] | None,
        body: Any,
    ) -> tuple[int, dict[str, str], str]:
        spec = self.spec
        if path == spec.proof_path and header_lookup(headers, spec.recovery_header) == spec.proof_value:
            if not self.state.get("proof_ready"):
                return 409, {}, "proof not prepared"
            self.state["flag"] = True
            self.state["used_revealed_value"] = True
            self._signal("proof_reused")
            return 200, {}, f"marker={spec.marker}"
        if path == spec.blocked_goal_path:
            self.state["blocked_goal"] = True
            self._signal("blocked_goal")
            return 403, {}, f"blocked: inspect source-backed evidence at {spec.evidence_path}"
        if path == spec.evidence_path and method == "GET":
            self.state["evidence_collected"] = True
            self._recover()
            self._signal("evidence_collected")
            return (
                200,
                {},
                json.dumps(
                    {
                        "chain_class": spec.chain_class,
                        "recovery_path": spec.recovery_path,
                        "recovery_token": spec.recovery_token,
                        "variant": spec.variant,
                    },
                    sort_keys=True,
                ),
            )
        if path == spec.recovery_path and method == "POST" and spec.recovery_token in body_text(body):
            self.state["pivot"] = True
            self.state["proof_ready"] = True
            self.state["used_revealed_value"] = True
            self._recover()
            self._signal("bounded_recovery_selected")
            return 200, {}, json.dumps({"proof": spec.proof_value, "ready": True}, sort_keys=True)
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
            "used_revealed_value": bool(self.state.get("used_revealed_value")),
        }

    def result(self) -> dict[str, Any]:
        return {
            "blocked_goal": bool(self.state.get("blocked_goal")),
            "evidence_collected": bool(self.state.get("evidence_collected")),
            "flag": bool(self.state.get("flag")),
            "pivot": bool(self.state.get("pivot")),
            "recovered_after_block": bool(self.state.get("recovered_after_block")),
            "reward": self._reward(),
            "scenario_hash": self.spec.scenario_hash,
            "scenario_id": self.spec.scenario_id,
            "steps": self.steps,
            "unique": len(self.seen),
            "used_revealed_value": bool(self.state.get("used_revealed_value")),
        }


def scenario_specs() -> tuple[WebGapSpec, ...]:
    return (
        WebGapSpec(
            scenario_id="rl-train-sqli-filter-bypass-recovery-proof",
            chain_class="sqli_filter_bypass",
            variant="source_filter_recovery",
            host="http://sqli-filter-recovery-rl.example",
            marker="AEGISPT_SQLI_FILTER_RECOVERY_9101",
            goal="Recover from a blocked private-report goal by reading the filter contract and reusing the bounded proof token.",
            blocked_goal_path="/reports/private-marker",
            evidence_path="/search/source-filter-contract",
            recovery_path="/search/bounded-proof",
            proof_path="/reports/private-marker",
            recovery_token="SQLI-FILTER-EVIDENCE-9101",
            proof_value="SQLI-FILTER-PROOF-9101",
        ),
        WebGapSpec(
            scenario_id="rl-train-upload-webroot-metadata-recovery",
            chain_class="file_upload_webroot",
            variant="upload_metadata_recovery",
            host="http://upload-recovery-rl.example",
            marker="AEGISPT_UPLOAD_WEBROOT_9201",
            goal="Recover from a blocked media marker by reading upload metadata policy and reusing the bounded review proof.",
            blocked_goal_path="/media/admin-marker",
            evidence_path="/upload/source-policy",
            recovery_path="/upload/metadata-proof",
            proof_path="/media/admin-marker",
            recovery_token="UPLOAD-METADATA-EVIDENCE-9201",
            proof_value="UPLOAD-METADATA-PROOF-9201",
        ),
        WebGapSpec(
            scenario_id="rl-train-path-traversal-file-read-recovery",
            chain_class="path_traversal_file_read",
            variant="bounded_file_catalog_recovery",
            host="http://file-read-recovery-rl.example",
            marker="AEGISPT_FILE_READ_9301",
            goal="Recover from a blocked private-file marker by reading the bounded file catalog and reusing its proof token.",
            blocked_goal_path="/private/marker",
            evidence_path="/private/source-file-catalog",
            recovery_path="/private/catalog-proof",
            proof_path="/private/marker",
            recovery_token="FILE-CATALOG-EVIDENCE-9301",
            proof_value="FILE-CATALOG-PROOF-9301",
        ),
        WebGapSpec(
            scenario_id="rl-train-nginx-alias-autoindex-recovery",
            chain_class="static_file_or_server_misconfig",
            variant="alias_autoindex_recovery",
            host="http://static-misconfig-recovery-rl.example",
            marker="AEGISPT_STATIC_MISCONFIG_9401",
            goal="Recover from a blocked static marker by reading route/alias evidence and reusing the bounded server-proof value.",
            blocked_goal_path="/admin/static-marker",
            evidence_path="/server/route-alias-evidence",
            recovery_path="/server/alias-proof",
            proof_path="/admin/static-marker",
            recovery_token="ALIAS-EVIDENCE-9401",
            proof_value="ALIAS-PROOF-9401",
        ),
    )


def manifest() -> dict[str, Any]:
    return {
        "dataset": DEFAULT_PREFIX,
        "interface": "json_action_to_http_observation",
        "policy": {
            "data_lane_only": True,
            "deep_chain_held_out_not_used": True,
            "lab_only": True,
            "no_runtime_binding": True,
            "no_runtime_execution": True,
            "payload_free": True,
        },
        "scenarios": [
            {
                "chain_class": spec.chain_class,
                "dataset_family": DEFAULT_PREFIX,
                "goal": spec.goal,
                "host": spec.host,
                "marker": spec.marker,
                "oracle_steps": len(spec.oracle_actions),
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
            "holdout_reason": "iter10_web_source_gap_recovery_rl_training_env_reserved",
            "scenario_hash": item["scenario_hash"],
            "scenario_id": item["scenario_id"],
            "source": "scripts/training/web_source_gap_recovery_envs_iter10.py",
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
    spec: WebGapSpec,
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
                "payload_free": True,
                "runtime_execution": False,
            },
            "state": {"scenario_id": spec.scenario_id, **state},
        },
        sort_keys=True,
    )


def demo_row(spec: WebGapSpec, *, index: int, split: str = "train") -> dict[str, Any]:
    metadata = {
        "case_id": f"web-source-gap-recovery-demo-{index:04d}-{spec.variant}",
        "chain_class": spec.chain_class,
        "dataset_family": DEMO_PREFIX,
        "lab_only": True,
        "runtime_execution": False,
        "scenario_hash": scenario_hash(f"web-source-gap-recovery-demo-{index:04d}-{spec.scenario_id}"),
        "source_env_scenario_hash": spec.scenario_hash,
        "split": split,
        "variant": spec.variant,
    }
    messages = [
        {
            "role": "system",
            "content": "Authorized fictional lab row. Use bounded evidence tokens only; do not include exploit payloads.",
        },
        {
            "role": "user",
            "content": json.dumps(
                {
                    "goal": spec.goal,
                    "host": spec.host,
                    "marker": spec.marker,
                    "required_arc": "blocked goal -> inspect hinted evidence -> recover bounded proof -> retry",
                },
                sort_keys=True,
            ),
        },
        {
            "role": "assistant",
            "content": _assistant_payload(
                done=False,
                evidence={"goal_satisfied": False, "refs": []},
                next_action={"args": {"headers": {}, "method": "GET", "url": f"{spec.host}{spec.blocked_goal_path}"}, "purpose": "premature goal attempt", "tool": "lab_http_request"},
                reasoning="Attempt the goal first to observe the boundary and hint.",
                spec=spec,
                state={"blocked_goal": False},
            ),
        },
        {"role": "user", "content": f"TOOL OBSERVATION: HTTP 403 blocked; inspect {spec.evidence_path}"},
        {
            "role": "assistant",
            "content": _assistant_payload(
                done=False,
                evidence={"goal_satisfied": False, "refs": ["obs-blocked"]},
                next_action={"args": {"headers": {}, "method": "GET", "url": f"{spec.host}{spec.evidence_path}"}, "purpose": "collect source-backed evidence contract", "tool": "lab_http_request"},
                reasoning="Backtrack to the hinted source-backed evidence before selecting a bounded recovery route.",
                spec=spec,
                state={"blocked_goal": True, "recovered_after_block": True},
            ),
        },
        {"role": "user", "content": f"TOOL OBSERVATION: evidence token={spec.recovery_token}"},
        {
            "role": "assistant",
            "content": _assistant_payload(
                done=False,
                evidence={"goal_satisfied": False, "refs": ["obs-evidence"]},
                next_action={
                    "args": {
                        "body": json.dumps({"evidence_token": spec.recovery_token, "lab_only": True}, sort_keys=True),
                        "headers": {},
                        "method": "POST",
                        "url": f"{spec.host}{spec.recovery_path}",
                    },
                    "purpose": "request bounded recovery proof",
                    "tool": "lab_http_request",
                },
                reasoning="Use only the revealed evidence token and ask for the lab's bounded proof value.",
                spec=spec,
                state={"evidence_collected": True},
            ),
        },
        {"role": "user", "content": f"TOOL OBSERVATION: bounded proof ready: {spec.proof_value}"},
        {
            "role": "assistant",
            "content": _assistant_payload(
                done=False,
                evidence={"goal_satisfied": False, "proof": spec.proof_value, "refs": ["obs-proof-ready"]},
                next_action={"args": {"headers": {spec.recovery_header: spec.proof_value}, "method": "GET", "url": f"{spec.host}{spec.proof_path}"}, "purpose": "complete proof-gated goal", "tool": "lab_http_request"},
                reasoning="Retry the blocked goal with the bounded proof recovered from the evidence path.",
                spec=spec,
                state={"pivot": True, "proof_ready": True, "used_revealed_value": True},
            ),
        },
        {"role": "user", "content": f"TOOL OBSERVATION: HTTP 200 marker={spec.marker}"},
        {
            "role": "assistant",
            "content": _assistant_payload(
                done=True,
                evidence={"goal_satisfied": True, "marker": spec.marker, "refs": ["obs-final"]},
                next_action={"args": {}, "purpose": "goal complete", "tool": "none"},
                reasoning="The source-backed recovery arc is complete and evidence-linked.",
                spec=spec,
                state={"done": True},
            ),
        },
    ]
    return {"messages": messages, "metadata": metadata}


def demo_rows(count: int = 32, *, split: str = "train") -> list[dict[str, Any]]:
    specs = scenario_specs()
    return [demo_row(specs[index % len(specs)], index=index, split=split) for index in range(count)]


def run_oracle(spec: WebGapSpec) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    env = WebGapEnv(spec)
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
    rows = demo_rows(demo_count)
    demo_path = out_dir / f"{DEMO_PREFIX}_train.jsonl"
    registry_path = out_dir / f"{DEFAULT_PREFIX}_scenario_registry.jsonl"
    write_jsonl(demo_path, rows)
    write_jsonl(registry_path, registry_entries())
    summary: dict[str, Any] = {
        "dataset": DEFAULT_PREFIX,
        "demo_count": demo_count,
        "demo_dataset": DEMO_PREFIX,
        "manifest": manifest(),
        "rollouts": [],
    }
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
            raise ValueError(f"held-out marker leaked into web source-gap envs: {marker}")
    scenario_ids = [item["scenario_id"] for item in data["scenarios"]]
    if len(scenario_ids) != len(set(scenario_ids)):
        raise ValueError("duplicate web source-gap scenario ids")
    hashes = [item["scenario_hash"] for item in data["scenarios"]]
    if len(hashes) != len(set(hashes)):
        raise ValueError("duplicate web source-gap scenario hashes")
    return {
        "chain_classes": sorted({item["chain_class"] for item in data["scenarios"]}),
        "scenario_count": len(data["scenarios"]),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true", help="Print environment manifest.")
    parser.add_argument("--scripted-oracle", action="store_true", help="Write demos, rollouts, and results.")
    parser.add_argument("--artifact-out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument("--demo-count", type=int, default=32)
    args = parser.parse_args()
    if args.scripted_oracle:
        summary = write_artifacts(args.artifact_out_dir, demo_count=args.demo_count)
        validate_manifest(summary["manifest"])
        print(json.dumps({"demo_count": summary["demo_count"], **summary["stats"]}, indent=2, sort_keys=True))
        return
    data = manifest()
    validate_manifest(data)
    print(json.dumps(data, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
