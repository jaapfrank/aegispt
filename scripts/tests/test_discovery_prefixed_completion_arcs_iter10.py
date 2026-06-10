import json

from scripts.training.build_discovery_prefixed_completion_arcs_iter10 import (
    DEFAULT_HELDOUT_MANIFEST,
    DEFAULT_SOURCE_TRAIN,
    build_dataset,
    goal_phrase_from_path,
    make_discovery_prefixed_row,
    row_has_discovery_prefix,
)
from scripts.training.build_free_completion_arc_dataset_iter10 import row_has_completion_arc


def assistant_payload(index, *, done=False, goal=False, url=None, marker=None, state=None):
    evidence = {"goal_satisfied": goal, "refs": [f"obs-{index}"]}
    if marker:
        evidence["marker"] = marker
    payload = {
        "done": done,
        "evidence": evidence,
        "next_action": {"args": {}, "purpose": "goal complete", "tool": "none"},
        "reasoning": "retry with the recovered proof token after the blocked goal",
        "safety": {"lab_only": True, "runtime_execution": False},
        "state": state or {},
    }
    if url:
        payload["next_action"] = {
            "args": {"headers": {}, "method": "GET", "url": url},
            "purpose": "premature goal attempt to learn the required proof boundary",
            "tool": "lab_http_request",
        }
    return payload


def source_completion_row(*, scenario_hash="train-hash", case_id="case-a"):
    payloads = [
        assistant_payload(0, url="http://unit.example/admin/marker", state={"started": True}),
        assistant_payload(1, url="http://unit.example/hinted-resource", state={"blocked_goal": True}),
        assistant_payload(2, url="http://unit.example/admin/marker", state={"recovered_after_block": True}),
        assistant_payload(3, url="http://unit.example/admin/marker/proof", state={"retrying": True}),
        assistant_payload(4, done=True, goal=True, marker="unit-proof-marker"),
    ]
    observations = [
        "TOOL OBSERVATION: HTTP 403 forbidden blocked; hint: inspect /hinted-resource",
        "TOOL OBSERVATION: recovered proof token available for retry",
        "TOOL OBSERVATION: retry accepted and marker preview available",
        "TOOL OBSERVATION: final proof marker unit-proof-marker",
    ]
    messages = [
        {"role": "system", "content": "fictional authorized lab"},
        {"role": "user", "content": json.dumps({"goal": "recover after blocked goal"})},
    ]
    for index, payload in enumerate(payloads):
        messages.append({"role": "assistant", "content": json.dumps(payload, sort_keys=True)})
        if index < len(observations):
            messages.append({"role": "user", "content": observations[index]})
    return {
        "messages": messages,
        "metadata": {
            "case_id": case_id,
            "chain_class": "unit_discovery_arc",
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


def test_goal_phrase_from_path_keeps_semantics_without_slashes():
    phrase = goal_phrase_from_path("/api/admin/marker", {"chain_class": "auth"})

    assert phrase == "admin marker"
    assert "/" not in phrase


def test_discovery_direct_row_hides_exact_path_until_assistant_action():
    row = source_completion_row()

    prefixed = make_discovery_prefixed_row(
        row,
        variant_name="semantic_direct",
        focus="infer the goal path",
        index=0,
    )

    assert prefixed is not None
    assert row_has_completion_arc(prefixed)
    assert row_has_discovery_prefix(prefixed)
    assert prefixed["metadata"]["dataset_family"] == "aegispt_discovery_prefixed_completion_arcs_iter10"
    assert prefixed["metadata"]["first_goal_path"] == "/admin/marker"
    first_user = next(message for message in prefixed["messages"] if message["role"] == "user")
    assert "/admin/marker" not in first_user["content"]
    first_assistant = json.loads(prefixed["messages"][2]["content"])
    assert first_assistant["state"]["discovery_inferred_goal_path"] is True
    assert first_assistant["next_action"]["args"]["url"].endswith("/admin/marker")


def test_discovery_scout_variant_adds_orientation_probe_before_inference():
    row = source_completion_row()

    prefixed = make_discovery_prefixed_row(
        row,
        variant_name="scout_then_semantic",
        focus="probe then infer",
        index=0,
    )

    assert prefixed is not None
    assert row_has_discovery_prefix(prefixed)
    scout = json.loads(prefixed["messages"][2]["content"])
    inferred = json.loads(prefixed["messages"][4]["content"])
    assert scout["state"]["discovery_probe"] is True
    assert scout["next_action"]["args"]["url"] == "http://unit.example/"
    assert inferred["state"]["discovery_inferred_goal_path"] is True
    assert inferred["next_action"]["args"]["url"].endswith("/admin/marker")


def test_build_dataset_filters_heldout_collisions(tmp_path):
    source = tmp_path / "source.jsonl"
    heldout = tmp_path / "heldout.json"
    write_jsonl(
        source,
        [
            source_completion_row(scenario_hash="heldout-hash", case_id="colliding"),
            source_completion_row(scenario_hash="train-hash", case_id="safe"),
        ],
    )
    write_heldout_manifest(heldout)

    rows, manifest = build_dataset(source_train=source, heldout_manifest=heldout)

    assert len(rows) == 2
    assert manifest["leakage_audit"]["heldout_collision_count"] == 1
    assert manifest["leakage_audit"]["skipped"]["source_heldout_hash_collision"] == 1
    assert {row["metadata"]["source_completion_case_id"] for row in rows} == {"safe"}


def test_default_sources_build_discovery_prefixed_leakage_free_corpus():
    rows, manifest = build_dataset(
        source_train=DEFAULT_SOURCE_TRAIN,
        heldout_manifest=DEFAULT_HELDOUT_MANIFEST,
    )

    assert len(rows) >= 1000
    assert manifest["stats"]["accepted_count"] == len(rows)
    assert manifest["stats"]["by_discovery_variant"] == {
        "scout_then_semantic": 636,
        "semantic_direct": 636,
    }
    assert manifest["leakage_audit"]["heldout_collision_count"] == 0
    assert manifest["leakage_audit"]["forbidden_string_hits"] == 0
