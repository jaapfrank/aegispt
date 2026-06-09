import json

from scripts.training.build_free_completion_arc_dataset_iter10 import (
    DEFAULT_DEMO_PATHS,
    DEFAULT_HELDOUT_MANIFEST,
    DEFAULT_ROLLOUT_DIRS,
    augment_row,
    build_dataset,
    row_has_completion_arc,
)


def assistant_payload(*, done=False, goal=False, marker=None, state=None):
    evidence = {"goal_satisfied": goal, "refs": ["obs"]}
    if marker:
        evidence["marker"] = marker
    return {
        "done": done,
        "evidence": evidence,
        "next_action": {"args": {}, "tool": "none" if done else "lab_http_request"},
        "reasoning": "retry with the recovered proof token after the blocked goal",
        "safety": {"lab_only": True, "runtime_execution": False},
        "state": state or {},
    }


def completion_row(*, scenario_hash="train-hash", case_id="case-a"):
    payloads = [
        assistant_payload(state={"started": True}),
        assistant_payload(state={"blocked_goal": True}),
        assistant_payload(state={"recovered_after_block": True}),
        assistant_payload(state={"retrying": True, "reusing": "proof-token"}),
        assistant_payload(done=True, goal=True, marker="proof-marker"),
    ]
    messages = [
        {"role": "system", "content": "fictional authorized lab"},
        {"role": "user", "content": json.dumps({"objective": "recover after blocked goal"})},
    ]
    for index, payload in enumerate(payloads):
        messages.append({"role": "assistant", "content": json.dumps(payload, sort_keys=True)})
        if index < len(payloads) - 1:
            messages.append(
                {
                    "role": "user",
                    "content": "TOOL OBSERVATION: 403 forbidden blocked; proof token available; retry",
                }
            )
    return {
        "messages": messages,
        "metadata": {
            "case_id": case_id,
            "chain_class": "unit_completion_arc",
            "scenario_hash": scenario_hash,
            "source_env_scenario_hash": scenario_hash,
            "source_kind": "unit",
        },
    }


def write_jsonl(path, rows):
    path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )


def write_heldout_manifest(path, scenario_hash="heldout-hash"):
    path.write_text(
        json.dumps(
            {
                "manifest": {
                    "scenarios": [
                        {
                            "chain_class": "heldout",
                            "scenario_hash": scenario_hash,
                            "scenario_id": "heldout-1",
                        }
                    ]
                }
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )


def test_completion_arc_requires_five_turn_final_goal_and_proof():
    row = completion_row()

    assert row_has_completion_arc(row)

    short = completion_row()
    short["messages"] = short["messages"][:-2]
    assert not row_has_completion_arc(short)

    no_goal = completion_row()
    final = json.loads(no_goal["messages"][-1]["content"])
    final["evidence"]["goal_satisfied"] = False
    no_goal["messages"][-1]["content"] = json.dumps(final, sort_keys=True)
    assert not row_has_completion_arc(no_goal)


def test_augment_row_adds_case_anchor_and_preserves_completion_arc():
    row = completion_row(case_id="case-anchor")

    augmented = augment_row(row, variant_name="state_carry", focus="carry state", index=7)

    assert row_has_completion_arc(augmented)
    assert augmented["metadata"]["dataset_family"] == "aegispt_free_completion_arcs_iter10"
    assert augmented["metadata"]["case_id"] == "case-anchor::state_carry"
    assert augmented["metadata"]["source_scenario_hash"] == "train-hash"
    serialized = json.dumps(augmented["messages"], sort_keys=True)
    assert "lab_case_anchor" in serialized
    assert "case-anchor" in serialized


def test_build_dataset_filters_heldout_hash_collisions(tmp_path):
    demo = tmp_path / "demo.jsonl"
    heldout_manifest = tmp_path / "heldout.json"
    write_jsonl(
        demo,
        [
            completion_row(scenario_hash="heldout-hash", case_id="colliding"),
            completion_row(scenario_hash="train-hash", case_id="safe"),
        ],
    )
    write_heldout_manifest(heldout_manifest)

    rows, manifest = build_dataset(
        demo_paths=[demo],
        rollout_dirs=[],
        heldout_manifest=heldout_manifest,
        variants=(("a", "focus a"), ("b", "focus b")),
    )

    assert len(rows) == 2
    assert manifest["leakage_audit"]["heldout_collision_count"] == 1
    assert manifest["leakage_audit"]["skipped"]["heldout_hash_collision"] == 1
    assert {row["metadata"]["case_id"] for row in rows} == {"safe::a", "safe::b"}


def test_default_free_sources_build_training_sized_leakage_free_corpus():
    rows, manifest = build_dataset(
        demo_paths=list(DEFAULT_DEMO_PATHS),
        rollout_dirs=list(DEFAULT_ROLLOUT_DIRS),
        heldout_manifest=DEFAULT_HELDOUT_MANIFEST,
    )

    assert len(rows) >= 500
    assert manifest["stats"]["accepted_count"] == len(rows)
    assert manifest["leakage_audit"]["heldout_collision_count"] == 0
    assert manifest["leakage_audit"]["forbidden_string_hits"] == 0
    assert manifest["stats"]["by_source_kind"]["scripted_teacher_demo"] >= 500
