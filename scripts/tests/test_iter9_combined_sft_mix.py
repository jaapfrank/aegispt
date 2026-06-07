import gzip
import json

from scripts.training.build_iter9_combined_sft_mix import (
    DEFAULT_PREFIX,
    build_mix,
)


def write_jsonl(path, rows):
    path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )


def read_gzip_jsonl(path):
    with gzip.open(path, "rt", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def sft_row(case_id, family="unit_family", chain_class=None, content="safe row"):
    metadata = {
        "case_id": case_id,
        "dataset_family": family,
        "runtime_execution": False,
        "split": "train",
    }
    if chain_class:
        metadata["chain_class"] = chain_class
    return {
        "messages": [
            {"role": "system", "content": "AegisPT lab mode"},
            {"role": "user", "content": content},
            {"role": "assistant", "content": '{"done": true, "safety": {"runtime_execution": false}}'},
        ],
        "metadata": metadata,
    }


def v4_row(case_id, *, blocked=True):
    observed = "TOOL OBSERVATION: HTTP 403 blocked; hint: visit /case to recover token"
    if not blocked:
        observed = "TOOL OBSERVATION: marker returned directly"
    recovery_state = {"blocked_goal": True} if blocked else {"direct_marker": True}
    final_reasoning = "The revealed token was reused for the retry." if blocked else "The marker was returned directly."
    final_state = {"token_reused": True} if blocked else {"direct_marker": True}
    evidence_refs = ["obs-403"] if blocked else ["obs-start"]
    second_observation = "TOOL OBSERVATION: token=CASE-TOKEN" if blocked else "TOOL OBSERVATION: direct marker already present"
    return {
        "messages": [
            {"role": "system", "content": "synthetic lab"},
            {"role": "user", "content": "recover marker"},
            {
                "role": "assistant",
                "content": json.dumps(
                    {
                        "done": False,
                        "evidence": {"goal_satisfied": False, "refs": []},
                        "next_action": {"args": {"method": "GET", "url": "/admin/marker"}, "tool": "lab_http_request"},
                        "reasoning": "Try the goal first.",
                        "safety": {"lab_only": True, "runtime_execution": False},
                        "state": {},
                    },
                    sort_keys=True,
                ),
            },
            {"role": "user", "content": observed},
            {
                "role": "assistant",
                "content": json.dumps(
                    {
                        "done": False,
                        "evidence": {"goal_satisfied": False, "refs": evidence_refs},
                        "next_action": {"args": {"method": "GET", "url": "/case"}, "tool": "lab_http_request"},
                        "reasoning": "Backtrack to the hinted resource.",
                        "safety": {"lab_only": True, "runtime_execution": False},
                        "state": recovery_state,
                    },
                    sort_keys=True,
                ),
            },
            {"role": "user", "content": second_observation},
            {
                "role": "assistant",
                "content": json.dumps(
                    {
                        "done": True,
                        "evidence": {"goal_satisfied": True, "refs": ["obs-final"]},
                        "next_action": {"args": {}, "tool": "none"},
                        "reasoning": final_reasoning,
                        "safety": {"lab_only": True, "runtime_execution": False},
                        "state": final_state,
                    },
                    sort_keys=True,
                ),
            },
        ],
        "metadata": {
            "case_id": case_id,
            "dataset_family": "aegispt_v4pro_demonstrated_chains_iter9",
            "runtime_execution": False,
            "scenario_hash": f"{case_id}-hash",
            "split": "train",
            "teacher_model": "deepseek-v4-pro",
        },
    }


def test_iter9_combined_mix_uses_curated_iter6_auth_and_recovery_v4(tmp_path):
    curated = tmp_path / "curated.jsonl"
    iter6 = tmp_path / "iter6.jsonl"
    v4 = tmp_path / "v4.jsonl"
    write_jsonl(
        curated,
        [
            sft_row("curated-1", content="curated safe row one"),
            sft_row("curated-2", content="curated safe row two"),
        ],
    )
    write_jsonl(
        iter6,
        [
            sft_row(
                "iter6-auth",
                "aegispt_multiturn_agentic_chain_iter6",
                "web_auth_followthrough",
                "iter6 auth row",
            ),
            sft_row(
                "iter6-other",
                "aegispt_multiturn_agentic_chain_iter6",
                "cloud_iam_simulation_chain",
                "iter6 other row",
            ),
        ],
    )
    write_jsonl(v4, [v4_row("v4-good", blocked=True), v4_row("v4-happy-path", blocked=False)])

    manifest = build_mix(
        curated_path=curated,
        iter6_path=iter6,
        v4pro_paths=[v4],
        held_out_registry_paths=[],
        out_dir=tmp_path,
        prefix=DEFAULT_PREFIX,
        iter6_chain_classes=("web_auth_followthrough",),
    )

    rows = read_gzip_jsonl(tmp_path / f"{DEFAULT_PREFIX}_train.jsonl.gz")
    source_rows = read_gzip_jsonl(tmp_path / f"{DEFAULT_PREFIX}_source_map.jsonl.gz")

    assert manifest["stats"]["per_family"] == {
        "curated_iter5": 2,
        "iter6_auth": 1,
        "v4pro_demonstrated_iter9": 1,
    }
    assert {row["metadata"]["case_id"] for row in rows} == {
        "curated-1",
        "curated-2",
        "iter6-auth",
        "v4-good",
    }
    assert manifest["stats"]["skipped"]["v4pro_guard"]["missing_blocked_goal_recovery_arc"] == 1
    assert len(source_rows) == 4
    assert manifest["policy"]["blocked_goal_recovery_required_for_v4pro"] is True
