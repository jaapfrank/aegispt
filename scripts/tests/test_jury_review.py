from scripts.training.jury_review import arbitrate, review_trace, to_training


def good_review(_trace):
    return {"verdict": "good", "confidence": 0.9, "safety_ok": True}


def bad_step_review(_trace):
    return {
        "verdict": "bad_step",
        "confidence": 0.85,
        "first_wrong_step": 1,
        "safety_ok": True,
    }


def test_solved_evidence_wins_over_bad_jury():
    trace = [{"final_outcome": "solved", "safety_status": "ok"}]

    decision = arbitrate(trace, [bad_step_review(trace), bad_step_review(trace)])

    assert decision["decision"] == "good"
    assert decision["by"] == "evidence"
    assert decision["human_review"] is False
    assert to_training(trace, decision)["training_value"] == "sft_positive"


def test_done_too_early_failure_becomes_contrastive_when_wrong_step_known():
    trace = [{"final_outcome": "no_flag", "safety_status": "ok"}]

    result = review_trace(trace, [bad_step_review, bad_step_review])

    assert result["decision"] == "bad"
    assert result["training"]["training_value"] == "contrastive"
    assert result["training"]["use"] is True
    assert result["training"]["first_wrong_step"] == 1


def test_no_finding_known_clean_with_complete_coverage_is_positive():
    trace = [
        {
            "final_outcome": "no_confirmed_finding",
            "safety_status": "ok",
            "no_finding": {
                "lab_truth": "known_clean",
                "coverage": ["web-auth", "api-authz", "lan-exposure"],
                "negative_evidence_refs": ["ev-1", "ev-2", "ev-3"],
            },
        }
    ]

    result = review_trace(trace, [good_review])

    assert result["decision"] == "true_negative"
    assert result["coverage"]["training_use"] == "sft_positive"
    assert result["training"]["training_value"] == "sft_positive"
    assert result["training"]["use"] is True


def test_no_finding_known_vulnerable_is_rejected_contrastive_signal():
    trace = [
        {
            "final_outcome": "no_confirmed_finding",
            "safety_status": "ok",
            "no_finding": {
                "lab_truth": "known_vulnerable",
                "coverage": ["web-auth", "api-authz", "lan-exposure"],
            },
        }
    ]

    result = review_trace(trace, [bad_step_review])

    assert result["decision"] == "missed_finding"
    assert result["training"]["training_value"] == "contrastive"
    assert result["training"]["use"] is True
    assert result["training"]["rejected"] == trace
    assert result["training"]["first_wrong_step"] == 1


def test_live_no_finding_without_oracle_is_not_rewarded():
    trace = [
        {
            "final_outcome": "no_confirmed_finding",
            "safety_status": "ok",
            "no_finding": {
                "lab_truth": "live_no_oracle",
                "coverage": ["web-auth", "api-authz", "lan-exposure"],
            },
        }
    ]

    result = review_trace(trace, [good_review])

    assert result["decision"] == "inconclusive"
    assert result["coverage"]["training_use"] == "do_not_reward"
    assert result["training"]["use"] is False


def test_no_finding_with_untested_boundaries_requires_review():
    trace = [
        {
            "final_outcome": "no_finding",
            "safety_status": "ok",
            "lab_truth": "known_clean",
            "coverage": ["web-auth", "api-authz", "lan-exposure"],
            "untested_boundaries": ["cloud-iam"],
        }
    ]

    result = review_trace(trace, [good_review])

    assert result["decision"] == "inconclusive"
    assert result["human_review"] is True
    assert result["training"]["use"] is False


def test_blocked_no_finding_is_excluded_not_rewarded():
    trace = [
        {
            "final_outcome": "no_confirmed_finding",
            "safety_status": "ok",
            "no_finding": {
                "lab_truth": "live_no_oracle",
                "blockers": ["credentials_missing"],
            },
        }
    ]

    result = review_trace(trace, [good_review])

    assert result["decision"] == "blocked"
    assert result["coverage"]["training_use"] == "exclude"
    assert result["training"]["use"] is False
