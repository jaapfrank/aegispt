"""Regression suite for the Phase-1 jury system (evidence arbiter + coverage arbiter
+ trace-recorder + factory + held-out guard + pipeline). Pure-logic, no GPU, no
reviewer models -- guards the free training-data slice."""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "training"))

import jury_factory as F  # noqa: E402
import jury_pipeline as P  # noqa: E402
import jury_review as J  # noqa: E402
import trace_record as TR  # noqa: E402


def _step(action, outcome="", safety="ok", prog=0.0):
    return {"state": "s", "action": action, "tool_result": "r", "evidence": [],
            "safety_status": safety, "objective_progress": prog, "failure_reason": "",
            "final_outcome": outcome, "no_finding": {}}


def _rev(verdict, conf=0.8, fws=None, safe=True):
    # a committee member is a CALLABLE trace -> verdict (review_trace calls r(trace))
    def reviewer(_trace):
        return {"verdict": verdict, "confidence": conf, "first_wrong_step": fws, "safety_ok": safe}
    return reviewer


# ---- evidence arbiter ------------------------------------------------------
def test_done_too_early_is_contrastive():
    t = [_step("GET /"), _step("done", outcome="failed")]
    d = J.review_trace(t, [_rev("bad_step", 0.82, 2), _rev("bad_step", 0.7, 2), _rev("good", 0.6)])
    assert d["decision"] == "bad" and d["training"]["training_value"] == "contrastive"
    assert d["jury"]["first_wrong_step"] == 2


def test_solved_evidence_is_boss():
    t = [_step("GET /"), _step("read", outcome="solved")]
    d = J.review_trace(t, [_rev("bad_step", 0.9, 1)])  # a 'bad' reviewer cannot override solved
    assert d["decision"] == "good" and d["by"] == "evidence"
    assert d["training"]["training_value"] == "sft_positive"


def test_no_evidence_split_goes_to_human():
    d = J.review_trace([_step("GET /"), _step("probe")], [_rev("good"), _rev("bad_step", 0.8, 4)])
    assert d["human_review"] is True


def test_unsafe_is_rejected():
    d = J.review_trace([_step("rm -rf", outcome="failed", safety="violation")], [_rev("good")])
    assert d["decision"] == "reject_unsafe" and d["human_review"] is True


# ---- coverage arbiter (no-finding) ----------------------------------------
def _nf(lab, coverage=None, blockers=None, untested=None, restraint=False):
    return [{"state": "s", "action": "report", "tool_result": "r", "evidence": [],
             "safety_status": "ok", "objective_progress": 0, "failure_reason": "",
             "final_outcome": "no_confirmed_finding",
             "no_finding": {"lab_truth": lab, "coverage": coverage or [], "blockers": blockers or [],
                            "untested_boundaries": untested or [], "conscious_restraint": restraint}}]


def test_coverage_labels():
    C = ["routes_seen", "auth_checked", "inputs_tested"]
    cases = {
        "true_negative": (_nf("known_clean", C), "sft_positive", True),
        "missed_finding": (_nf("known_vulnerable", ["x"]), "dpo_negative", True),
        "inconclusive": (_nf("live_no_oracle", ["x"], untested=["admin"]), "do_not_reward", False),
        "blocked": (_nf("live_no_oracle", blockers=["no_creds"]), "exclude", False),
        "correct_restraint": (_nf("live_no_oracle", C, restraint=True), "safety_positive", True),
    }
    for exp_label, (trace, exp_tv, exp_use) in cases.items():
        d = J.review_trace(trace, [])
        assert d["decision"] == exp_label, (exp_label, d["decision"])
        assert d["training"]["training_value"] == exp_tv and d["training"]["use"] == exp_use


def test_hard_rule_live_full_coverage_not_safe():
    d = J.review_trace(_nf("live_no_oracle", ["routes", "auth", "inputs"]), [])
    assert d["decision"] == "inconclusive" and d["training"]["use"] is False


# ---- trace-recorder -> jury ------------------------------------------------
def test_deep_chain_failed_is_missed_finding():
    failed = {"flag": False, "idor": False, "logged_in": False, "steps": 2, "unique": 1}
    d = J.review_trace(TR.from_deep_chain(failed, ["GET /", "done"]), [])
    assert d["decision"] == "missed_finding" and d["training"]["training_value"] == "dpo_negative"


def test_deep_chain_solved_is_sft():
    solved = {"flag": True, "idor": True, "logged_in": True, "steps": 6, "unique": 5}
    d = J.review_trace(TR.from_deep_chain(solved, list("abcdef")), [])
    assert d["decision"] == "good" and d["training"]["training_value"] == "sft_positive"


# ---- factory + held-out guard + pipeline ----------------------------------
def _item(scn, result, sigs, convo):
    trace = TR.from_deep_chain(result, sigs)
    return {"scenario_id": scn, "messages": convo, "trace": trace, "decision": J.review_trace(trace, [])}


def test_factory_pairs_and_guard(tmp_path):
    solved = {"flag": True, "idor": True, "logged_in": True, "steps": 6, "unique": 5}
    failed = {"flag": False, "idor": False, "logged_in": False, "steps": 2, "unique": 1}
    good = [{"role": "user", "content": "g"}, {"role": "assistant", "content": "win"}]
    bad = [{"role": "user", "content": "g"}, {"role": "assistant", "content": "give up"}]
    items = [_item("A", solved, list("abcdef"), good), _item("A", failed, list("xy"), bad),
             _item("HELD", failed, list("xy"), bad)]
    m = F.build_training_sets(items, held_out={F.scenario_hash("HELD")}, out_dir=str(tmp_path))
    assert m["skipped_held_out"] == 1 and m["sft"] == 1 and m["dpo_pairs"] == 1
    assert "HELD" not in (tmp_path / "dpo_pairs.jsonl").read_text()


def test_pipeline_end_to_end(tmp_path):
    tdir = tmp_path / "traces"
    tdir.mkdir()
    odir = tmp_path / "out"
    solved = {"flag": True, "idor": True, "logged_in": True, "steps": 6, "unique": 5}
    failed = {"flag": False, "idor": False, "logged_in": False, "steps": 2, "unique": 1}
    for name, res, sigs in [("shop__win.jsonl", solved, list("abcdef")), ("shop__fail.jsonl", failed, list("xy"))]:
        (tdir / name).write_text("\n".join(json.dumps(s) for s in TR.from_deep_chain(res, sigs)) + "\n")
    m = P.run(str(tdir), held_out_paths=[], out_dir=str(odir))
    assert m["traces_seen"] == 2 and m["sft"] == 1 and m["dpo_pairs"] == 1


def test_pipeline_honors_registry_json_held_out_guard(tmp_path):
    tdir = tmp_path / "traces"
    tdir.mkdir()
    odir = tmp_path / "out"
    held_out_path = tmp_path / "held_out_registry.json"
    held_out_path.write_text(
        json.dumps({"held_out_scenarios": [{"scenario_id": "deep_chain_eval"}]})
        + "\n"
    )
    solved = {"flag": True, "idor": True, "logged_in": True, "steps": 6, "unique": 5}
    failed = {"flag": False, "idor": False, "logged_in": False, "steps": 2, "unique": 1}
    traces = {
        "deep_chain_eval__held.jsonl": TR.from_deep_chain(solved, list("abcdef")),
        "shop__win.jsonl": TR.from_deep_chain(solved, list("abcdef")),
        "shop__fail.jsonl": TR.from_deep_chain(failed, list("xy")),
    }
    for name, trace in traces.items():
        (tdir / name).write_text(
            "\n".join(json.dumps(step) for step in trace) + "\n"
        )

    manifest = P.run(
        str(tdir),
        held_out_paths=[str(held_out_path)],
        out_dir=str(odir),
    )

    assert manifest["traces_seen"] == 3
    assert manifest["held_out_scenarios"] == 1
    assert manifest["skipped_held_out"] == 1
    assert manifest["sft"] == 1
    assert manifest["dpo_pairs"] == 1
    assert "deep_chain_eval" not in (odir / "sft.jsonl").read_text()
    assert "deep_chain_eval" not in (odir / "dpo_pairs.jsonl").read_text()
