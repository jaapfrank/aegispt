"""Generate real V4-Pro demonstrated multi-turn chain rows via DeepSeek.

The API key is read at runtime from DEEPSEEK_API_KEY or ~/.aegispt-secrets and
is never printed or written. Generated teacher rows are not trusted directly:
each candidate is passed through ingest_v4pro_demonstrated_chains_iter8.py so
held-out collisions, malformed trajectories, and unsafe/runtime-active rows are
rejected before a train JSONL is emitted.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import re
import sys
import time
import urllib.error
import urllib.request
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.training.ingest_v4pro_demonstrated_chains_iter8 import (
    DEFAULT_TEACHER_MODEL,
    ingest_rows,
    write_jsonl,
)
from scripts.training.jury_factory import scenario_hash
from scripts.training.make_lab_truth_heldout_registry_iter6 import build_registry, load_registry

DEFAULT_OUT_DIR = Path.home() / ".aegispt-tools" / "training" / "v4pro-demonstrated-chains-iter9"
DEFAULT_PREFIX = "aegispt_v4pro_demonstrated_chains_iter9"
DEFAULT_ENDPOINT = "https://api.deepseek.com/v1/chat/completions"
DEFAULT_MODEL = "deepseek-v4-pro"
DEFAULT_MAX_TOKENS = 8192
DEFAULT_TEMPERATURE = 0.7
DEFAULT_SEED = 20260607

HELD_OUT_STRINGS = (
    "flag{deep-eval-5b7c2}",
    "ADM-7741-KQ",
    "X-Admin-Token",
    "shop.lab",
    "/notes/",
    "/admin/config",
    "/reset_password",
)


@dataclass(frozen=True)
class TeacherChainClass:
    chain_class: str
    domain: str
    objective: str


TEACHER_CHAIN_CLASSES = (
    TeacherChainClass(
        "idor_object_swap_token_reuse",
        "api",
        "A case-management API leaks one delegated review token through a cross-object read; reuse only the observed token to read the proof marker.",
    ),
    TeacherChainClass(
        "ssrf_internal_endpoint_recovery",
        "web_api",
        "A public fetch helper can reach one internal identity route; use observed internal metadata and a scoped recovery ticket to read the proof marker.",
    ),
    TeacherChainClass(
        "lowpriv_to_admin_delegation",
        "web",
        "A low-privilege user receives an evidence-derived delegated-admin preview; follow the preview and collect the proof marker without guessing.",
    ),
    TeacherChainClass(
        "info_disclosure_credential_reuse_lateral",
        "multi_service",
        "A support ticket discloses one service credential; reuse it on a separate fictional service to read the proof marker.",
    ),
    TeacherChainClass(
        "xxe_document_parser_pivot",
        "web_api",
        "A fictional XML document parser exposes one bounded parser-context token; recover via hinted parser metadata and use only that lab token to read the proof marker.",
    ),
    TeacherChainClass(
        "ssti_template_context_pivot",
        "web",
        "A fictional template preview reveals one scoped render-context token after a blocked admin preview; reuse only that observed context to read the proof marker.",
    ),
    TeacherChainClass(
        "auth_logic_session_forgery",
        "web_auth",
        "A fictional app leaks a bounded session-claims hint and signing context; recover from a blocked admin marker by creating only the lab-scoped session needed for the proof marker.",
    ),
    TeacherChainClass(
        "nosql_filter_bypass_chain",
        "web_api",
        "A fictional NoSQL-style filter normalization reveals a related object and scoped proof token; recover from the blocked goal by following the hinted object and retrying.",
    ),
)

TEACHER_CHAIN_CLASS_NAMES = tuple(item.chain_class for item in TEACHER_CHAIN_CLASSES)


@dataclass(frozen=True)
class TeacherScenario:
    chain_class: str
    domain: str
    lab_id: str
    host: str
    marker: str
    objective: str

    @property
    def scenario_hash(self) -> str:
        return scenario_hash(self.lab_id)


def read_secret_key(secret_file: Path | None = None) -> str:
    if os.environ.get("DEEPSEEK_API_KEY"):
        return os.environ["DEEPSEEK_API_KEY"].strip()
    secret_file = secret_file or (Path.home() / ".aegispt-secrets")
    if not secret_file.exists():
        return ""
    for line in secret_file.read_text(encoding="utf-8", errors="ignore").splitlines():
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        if value.startswith("export "):
            value = value[len("export ") :].strip()
        if "=" not in value:
            continue
        key, raw = value.split("=", 1)
        if key.strip() != "DEEPSEEK_API_KEY":
            continue
        return raw.strip().strip("\"'")
    return ""


def scenario_plan(count: int, *, seed: int = DEFAULT_SEED) -> list[TeacherScenario]:
    rng = random.Random(seed)
    scenarios: list[TeacherScenario] = []
    for idx in range(count):
        class_spec = TEACHER_CHAIN_CLASSES[idx % len(TEACHER_CHAIN_CLASSES)]
        chain_class = class_spec.chain_class
        domain = class_spec.domain
        objective = class_spec.objective
        suffix = f"{idx:04d}-{rng.randint(1000, 9999)}"
        host = f"https://{chain_class.replace('_', '-')}-{suffix}.fictional-lab.example"
        lab_id = f"v4pro-teacher-{chain_class}-{suffix}"
        marker = f"AEGISPT_V4PRO_{idx:04d}_{rng.randint(100000, 999999)}"
        scenarios.append(
            TeacherScenario(
                chain_class=chain_class,
                domain=domain,
                host=host,
                lab_id=lab_id,
                marker=marker,
                objective=objective,
            )
        )
    return scenarios


def teacher_messages(spec: TeacherScenario) -> list[dict[str, str]]:
    system = (
        "You generate training data for an authorized, fictional AegisPT lab. "
        "Return ONLY one JSON object, with no markdown, no explanations outside JSON. "
        "The JSON object must be {\"messages\":[...],\"metadata\":{...}}. "
        "Every assistant message content must itself be a JSON string with EXACTLY keys "
        "done, evidence, next_action, reasoning, safety, state. Use alternating assistant "
        "actions and user TOOL OBSERVATION messages. The final assistant turn must set "
        "done=true and evidence.goal_satisfied=true. Keep runtime_execution=false and "
        "lab_only=true everywhere. Do not use real public targets, real secrets, malware, "
        "destructive actions, brute force, credential dumping, or any held-out strings. "
        "A valid demonstration must include a blocked-goal recovery arc: attempt the "
        "goal endpoint too early, observe a bounded 403/blocked response with a hint, "
        "backtrack to the hinted intermediate resource, use the revealed token/session/"
        "credential, and retry the goal successfully."
    )
    user = {
        "blocked_goal_recovery_required": {
            "arc": "premature_goal_attempt -> 403_or_blocked_observation -> hinted_resource_exploration -> revealed_value_used -> successful_goal_retry",
            "minimum_blocked_observations": 1,
            "must_use_revealed_value_after_block": True,
        },
        "chain_class": spec.chain_class,
        "domain": spec.domain,
        "forbidden_strings": list(HELD_OUT_STRINGS),
        "host": spec.host,
        "marker": spec.marker,
        "minimum_assistant_turns": 5,
        "objective": spec.objective,
        "required_metadata": {
            "case_id": spec.lab_id,
            "chain_class": spec.chain_class,
            "dataset_family": "external_v4pro_teacher_raw",
            "domain": spec.domain,
            "lab_only": True,
            "runtime_execution": False,
            "scenario_hash": spec.scenario_hash,
            "split": "train",
            "teacher_model": DEFAULT_MODEL,
        },
        "tool_schema": {
            "next_action": {
                "args": {
                    "headers": {},
                    "method": "GET|POST",
                    "url": "fictional lab URL",
                },
                "purpose": "bounded lab proof step",
                "tool": "lab_http_request|lab_api_request|lab_graphql_request|lab_queue_request|none",
            }
        },
    }
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": json.dumps(user, sort_keys=True)},
    ]


def _extract_json_object(text: str) -> dict[str, Any]:
    text = re.sub(r"```(?:json)?|```", "", text).strip()
    found: dict[str, Any] | None = None
    for match in re.finditer(r"\{", text):
        depth = 0
        for pos in range(match.start(), len(text)):
            if text[pos] == "{":
                depth += 1
            elif text[pos] == "}":
                depth -= 1
                if depth == 0:
                    try:
                        candidate = json.loads(text[match.start() : pos + 1])
                    except json.JSONDecodeError:
                        break
                    if isinstance(candidate, dict) and isinstance(candidate.get("messages"), list):
                        found = candidate
                    break
    if found is None:
        raise ValueError("teacher response did not contain a JSON object with messages")
    return found


def call_deepseek(
    *,
    endpoint: str,
    model: str,
    messages: list[dict[str, str]],
    api_key: str,
    max_tokens: int,
    temperature: float,
    timeout: int,
    json_mode: bool = True,
) -> dict[str, Any]:
    payload = {
        "max_tokens": max_tokens,
        "messages": messages,
        "model": model,
        "stream": False,
        "temperature": temperature,
    }
    if json_mode:
        payload["response_format"] = {"type": "json_object"}
    request = urllib.request.Request(
        endpoint,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            data = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")[:400]
        raise RuntimeError(f"DeepSeek request failed: HTTP {exc.code}: {body}") from exc
    message = data["choices"][0]["message"]
    content = str(message.get("content") or message.get("reasoning_content") or "").strip()
    if not content:
        raise RuntimeError("DeepSeek response had no content or reasoning_content")
    return _extract_json_object(content)


def _write_manifest(path: Path, manifest: dict[str, Any]) -> None:
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _has_blocked_goal_recovery_arc(row: dict[str, Any]) -> bool:
    messages = row.get("messages")
    if not isinstance(messages, list):
        return False
    contents = [str(item.get("content", "")) for item in messages if isinstance(item, dict)]
    blocked_index = next(
        (
            idx
            for idx, content in enumerate(contents)
            if any(token in content.lower() for token in ("403", "blocked", "forbidden", "denied"))
        ),
        None,
    )
    if blocked_index is None:
        return False
    later = "\n".join(contents[blocked_index + 1 :]).lower()
    recovered = any(
        token in later
        for token in (
            "callback",
            "credential",
            "delegation",
            "pivot",
            "queue",
            "recovery",
            "session",
            "token",
        )
    )
    successful_retry = any('"done": true' in content.lower() or '"done":true' in content.lower() for content in contents[blocked_index + 1 :])
    return recovered and successful_retry


def _scenario_registry_rows(rows: list[dict[str, Any]], prefix: str) -> list[dict[str, Any]]:
    return [
        {
            "case_id": row["metadata"]["case_id"],
            "dataset_family": prefix,
            "holdout_reason": "teacher_demonstrated_reserved_train",
            "original_case_id": row["metadata"]["original_case_id"],
            "scenario_hash": row["metadata"]["scenario_hash"],
            "scenario_id": row["metadata"]["case_id"],
            "source": "scripts/training/generate_v4pro_demonstrated_chains_iter9.py",
            "split": "train",
            "teacher_model": row["metadata"]["teacher_model"],
        }
        for row in rows
    ]


def _row_chain_class(row: dict[str, Any]) -> str:
    metadata = row.get("metadata")
    if isinstance(metadata, dict):
        value = metadata.get("chain_class")
        if value:
            return str(value)
    return str(row.get("source_chain_class") or "unknown")


def _assistant_turn_count(row: dict[str, Any]) -> int:
    messages = row.get("messages")
    if not isinstance(messages, list):
        return 0
    return sum(
        1
        for item in messages
        if isinstance(item, dict) and str(item.get("role", "")).lower() == "assistant"
    )


def _rejection_reason(row: dict[str, Any]) -> str:
    detail = str(row.get("detail") or "").strip()
    if detail in {"missing_blocked_goal_recovery_arc"}:
        return detail
    return str(row.get("reason") or detail or "unknown")


def _accepted_by_chain_class(rows: list[dict[str, Any]]) -> dict[str, int]:
    counts = Counter(_row_chain_class(row) for row in rows)
    return {name: counts.get(name, 0) for name in TEACHER_CHAIN_CLASS_NAMES}


def _class_quota_satisfied(
    accepted: list[dict[str, Any]],
    *,
    min_per_chain_class: int,
) -> dict[str, bool]:
    counts = _accepted_by_chain_class(accepted)
    if min_per_chain_class <= 0:
        return {name: True for name in TEACHER_CHAIN_CLASS_NAMES}
    return {name: counts.get(name, 0) >= min_per_chain_class for name in TEACHER_CHAIN_CLASS_NAMES}


def _dataset_complete(
    accepted: list[dict[str, Any]],
    *,
    min_per_chain_class: int,
    requested_count: int,
) -> bool:
    if len(accepted) < requested_count:
        return False
    return all(_class_quota_satisfied(accepted, min_per_chain_class=min_per_chain_class).values())


def _flush_outputs(
    *,
    accepted: list[dict[str, Any]],
    attempts: int,
    endpoint: str,
    manifest_path: Path,
    model: str,
    prefix: str,
    raw_path: Path,
    raw_rows: list[dict[str, Any]],
    rejected: list[dict[str, Any]],
    rejected_path: Path,
    min_per_chain_class: int,
    requested_count: int,
    scenario_registry_path: Path,
    stopped_reason: str,
    train_path: Path,
) -> dict[str, Any]:
    accepted = accepted[:requested_count]
    scenario_registry_rows = _scenario_registry_rows(accepted, prefix)
    accepted_by_chain_class = _accepted_by_chain_class(accepted)
    rejected_by_reason = dict(sorted(Counter(_rejection_reason(row) for row in rejected).items()))
    rejected_by_chain_class = dict(sorted(Counter(_row_chain_class(row) for row in rejected).items()))
    assistant_turn_distribution = dict(
        sorted(Counter(str(_assistant_turn_count(row)) for row in accepted).items())
    )
    class_quota_satisfied = _class_quota_satisfied(
        accepted,
        min_per_chain_class=min_per_chain_class,
    )
    quality_report = {
        "accepted_by_chain_class": accepted_by_chain_class,
        "assistant_turn_distribution": assistant_turn_distribution,
        "class_quota_satisfied": class_quota_satisfied,
        "missing_chain_classes": [
            name for name, satisfied in class_quota_satisfied.items() if not satisfied
        ],
        "rejected_by_chain_class": rejected_by_chain_class,
        "rejected_by_reason": rejected_by_reason,
    }
    write_jsonl(raw_path, raw_rows)
    write_jsonl(train_path, accepted)
    write_jsonl(rejected_path, rejected)
    write_jsonl(scenario_registry_path, scenario_registry_rows)
    manifest = {
        "dataset": prefix,
        "endpoint": endpoint,
        "files": {
            "raw_teacher": str(raw_path),
            "rejected": str(rejected_path),
            "scenario_registry": str(scenario_registry_path),
            "train": str(train_path),
        },
        "model": model,
        "policy": {
            "blocked_goal_recovery_required": True,
            "data_lane_only": True,
            "held_out_guard": True,
            "runtime_execution": False,
            "secret_committed": False,
            "train_only": True,
            "v4pro_demonstrated_rows": True,
        },
        "quality_report": quality_report,
        "stats": {
            "accepted_count": len(accepted),
            "accepted_by_chain_class": accepted_by_chain_class,
            "assistant_turn_distribution": assistant_turn_distribution,
            "attempts": attempts,
            "class_quota_satisfied": class_quota_satisfied,
            "min_per_chain_class": min_per_chain_class,
            "rejected_count": len(rejected),
            "rejected_by_reason": rejected_by_reason,
            "requested_count": requested_count,
            "stopped_reason": stopped_reason,
            "target_chain_classes": list(TEACHER_CHAIN_CLASS_NAMES),
        },
    }
    _write_manifest(manifest_path, manifest)
    return manifest


def build_dataset(
    *,
    count: int,
    out_dir: Path = DEFAULT_OUT_DIR,
    prefix: str = DEFAULT_PREFIX,
    endpoint: str = DEFAULT_ENDPOINT,
    model: str = DEFAULT_MODEL,
    max_tokens: int = DEFAULT_MAX_TOKENS,
    temperature: float = DEFAULT_TEMPERATURE,
    timeout: int = 180,
    max_attempts: int | None = None,
    seed: int = DEFAULT_SEED,
    registry_path: Path | None = None,
    secret_file: Path | None = None,
    sleep_seconds: float = 0.0,
    wall_seconds: float | None = None,
    min_per_chain_class: int = 0,
) -> dict[str, Any]:
    api_key = read_secret_key(secret_file)
    if not api_key:
        raise RuntimeError("DEEPSEEK_API_KEY not found in environment or ~/.aegispt-secrets")
    out_dir.mkdir(parents=True, exist_ok=True)
    registry = load_registry(registry_path) if registry_path else build_registry()
    raw_path = out_dir / f"{prefix}_raw_teacher.jsonl"
    train_path = out_dir / f"{prefix}_train.jsonl"
    rejected_path = out_dir / f"{prefix}_rejected.jsonl"
    scenario_registry_path = out_dir / f"{prefix}_scenario_registry.jsonl"
    manifest_path = out_dir / f"{prefix}_manifest.json"

    requested_count = max(count, max(0, min_per_chain_class) * len(TEACHER_CHAIN_CLASSES))
    limit = max_attempts or max(requested_count * 3, requested_count)
    plans = scenario_plan(limit, seed=seed)
    accepted: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    raw_rows: list[dict[str, Any]] = []
    attempts = 0
    start_time = time.monotonic()
    stopped_reason = "completed"
    for spec in plans[:limit]:
        if _dataset_complete(
            accepted,
            min_per_chain_class=min_per_chain_class,
            requested_count=requested_count,
        ):
            break
        attempts += 1
        try:
            candidate = call_deepseek(
                endpoint=endpoint,
                model=model,
                messages=teacher_messages(spec),
                api_key=api_key,
                max_tokens=max_tokens,
                temperature=temperature,
                timeout=timeout,
                json_mode=True,
            )
            metadata = candidate.get("metadata")
            if not isinstance(metadata, dict):
                metadata = {}
            metadata.setdefault("case_id", spec.lab_id)
            metadata.setdefault("chain_class", spec.chain_class)
            metadata.setdefault("dataset_family", "external_v4pro_teacher_raw")
            metadata.setdefault("domain", spec.domain)
            metadata.setdefault("lab_only", True)
            metadata.setdefault("runtime_execution", False)
            metadata.setdefault("scenario_hash", spec.scenario_hash)
            metadata.setdefault("split", "train")
            metadata.setdefault("teacher_model", model)
            candidate["metadata"] = metadata
            raw_rows.append(candidate)
            if not _has_blocked_goal_recovery_arc(candidate):
                raise ValueError("missing_blocked_goal_recovery_arc")
            ingested = ingest_rows(
                [candidate],
                registry=registry,
                prefix=prefix,
                teacher_model=model or DEFAULT_TEACHER_MODEL,
                fail_on_rejected=False,
            )
            if ingested["accepted"]:
                accepted.extend(ingested["accepted"])
            else:
                rejected.extend(
                    {
                        **row,
                        "source_lab_id": spec.lab_id,
                        "source_chain_class": spec.chain_class,
                        "source_domain": spec.domain,
                    }
                    for row in ingested["rejected"]
                )
        except Exception as exc:  # noqa: BLE001
            detail = str(exc)[:240]
            reason = (
                "missing_blocked_goal_recovery_arc"
                if detail == "missing_blocked_goal_recovery_arc"
                else f"teacher_error:{type(exc).__name__}"
            )
            rejected.append(
                {
                    "candidate_ids": [spec.lab_id, spec.scenario_hash],
                    "detail": detail,
                    "index": attempts - 1,
                    "reason": reason,
                    "source_chain_class": spec.chain_class,
                    "source_domain": spec.domain,
                    "source_lab_id": spec.lab_id,
                }
            )
        _flush_outputs(
            accepted=accepted,
            attempts=attempts,
            endpoint=endpoint,
            manifest_path=manifest_path,
            model=model,
            prefix=prefix,
            raw_path=raw_path,
            raw_rows=raw_rows,
            rejected=rejected,
            rejected_path=rejected_path,
            min_per_chain_class=min_per_chain_class,
            requested_count=requested_count,
            scenario_registry_path=scenario_registry_path,
            stopped_reason="running",
            train_path=train_path,
        )
        if sleep_seconds:
            time.sleep(sleep_seconds)
        if (
            wall_seconds is not None
            and time.monotonic() - start_time >= wall_seconds
            and not _dataset_complete(
                accepted,
                min_per_chain_class=min_per_chain_class,
                requested_count=requested_count,
            )
        ):
            stopped_reason = "wall_seconds"
            break

    accepted = accepted[:requested_count]
    if (
        not _dataset_complete(
            accepted,
            min_per_chain_class=min_per_chain_class,
            requested_count=requested_count,
        )
        and stopped_reason == "completed"
    ):
        stopped_reason = "attempt_limit"
    return _flush_outputs(
        accepted=accepted,
        attempts=attempts,
        endpoint=endpoint,
        manifest_path=manifest_path,
        model=model,
        prefix=prefix,
        raw_path=raw_path,
        raw_rows=raw_rows,
        rejected=rejected,
        rejected_path=rejected_path,
        min_per_chain_class=min_per_chain_class,
        requested_count=requested_count,
        scenario_registry_path=scenario_registry_path,
        stopped_reason=stopped_reason,
        train_path=train_path,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--count", type=int, default=20)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument("--prefix", default=DEFAULT_PREFIX)
    parser.add_argument("--endpoint", default=DEFAULT_ENDPOINT)
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--max-tokens", type=int, default=DEFAULT_MAX_TOKENS)
    parser.add_argument("--temperature", type=float, default=DEFAULT_TEMPERATURE)
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument("--max-attempts", type=int)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--registry", type=Path)
    parser.add_argument("--secret-file", type=Path)
    parser.add_argument("--sleep-seconds", type=float, default=0.0)
    parser.add_argument("--wall-seconds", type=float)
    parser.add_argument("--min-per-chain-class", type=int, default=0)
    args = parser.parse_args()
    manifest = build_dataset(
        count=args.count,
        out_dir=args.out_dir,
        prefix=args.prefix,
        endpoint=args.endpoint,
        model=args.model,
        max_tokens=args.max_tokens,
        temperature=args.temperature,
        timeout=args.timeout,
        max_attempts=args.max_attempts,
        seed=args.seed,
        registry_path=args.registry,
        secret_file=args.secret_file,
        sleep_seconds=args.sleep_seconds,
        wall_seconds=args.wall_seconds,
        min_per_chain_class=args.min_per_chain_class,
    )
    print(json.dumps(manifest, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
