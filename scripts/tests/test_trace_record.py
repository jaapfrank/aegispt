import json
from datetime import UTC, datetime
from types import SimpleNamespace

from scripts.training.jury_review import review_trace
from scripts.training.trace_record import from_runner_tasks, write_trace_jsonl


def ns(**kwargs):
    return SimpleNamespace(**kwargs)


def execution(
    *,
    id="exec-1",
    exit_code=0,
    stdout_text="",
    stderr_text="",
    created_at=None,
    artifacts=None,
):
    return ns(
        id=id,
        exit_code=exit_code,
        stdout_text=stdout_text,
        stderr_text=stderr_text,
        created_at=created_at or datetime(2026, 6, 6, tzinfo=UTC),
        artifacts=artifacts or [],
    )


def task(
    *,
    id="task-1",
    tool="httpx",
    target_id="http://app.test",
    status="completed",
    params_json=None,
    executions=None,
    created_at=None,
):
    return ns(
        id=id,
        tool=tool,
        target_id=target_id,
        status=status,
        params_json=params_json or {},
        executions=executions or [],
        created_at=created_at or datetime(2026, 6, 6, tzinfo=UTC),
    )


def test_runner_tasks_with_persisted_finding_export_objective_met_trace(tmp_path):
    artifact = ns(uri="artifact://runner/results", sha256="abc123", kind="json")
    trace = from_runner_tasks(
        [
            task(
                id="task-a",
                tool="interactive-exploit",
                params_json={"mode": "safe"},
                executions=[
                    execution(
                        id="exec-a",
                        stdout_text="captured proof",
                        artifacts=[artifact],
                    )
                ],
            )
        ],
        run=ns(id="run-1", status="completed"),
        findings=[ns(id="finding-1")],
    )

    assert len(trace) == 1
    assert trace[-1]["final_outcome"] == "objective_met"
    assert "interactive-exploit" in trace[0]["action"]
    assert "artifact://runner/results" in trace[0]["evidence"]

    out = tmp_path / "run_trace.jsonl"
    write_trace_jsonl(trace, out)
    rows = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
    assert rows == trace


def test_live_runner_no_finding_without_oracle_is_not_rewarded():
    trace = from_runner_tasks(
        [
            task(
                tool="headers-security",
                executions=[execution(id="exec-a", stdout_text='{"findings": []}')],
            ),
            task(
                id="task-b",
                tool="smart-web-probe",
                executions=[execution(id="exec-b", stdout_text='{"status": "ok"}')],
            ),
        ],
        run=ns(id="run-live", status="completed"),
        findings=[],
    )

    result = review_trace(trace, [])

    assert trace[-1]["final_outcome"] == "no_confirmed_finding"
    assert trace[-1]["no_finding"]["lab_truth"] == "live_no_oracle"
    assert trace[-1]["no_finding"]["coverage"] == ["tool:headers-security", "tool:smart-web-probe"]
    assert result["decision"] == "inconclusive"
    assert result["training"]["use"] is False
    assert result["training"]["training_value"] == "do_not_reward"


def test_known_vulnerable_runner_no_finding_becomes_dpo_negative():
    trace = from_runner_tasks(
        [
            task(
                tool="interactive-exploit",
                executions=[execution(stdout_text="attempted chain, no flag")],
            )
        ],
        run=ns(id="run-lab", status="completed"),
        findings=[],
        lab_truth="known_vulnerable",
    )

    result = review_trace(trace, [])

    assert trace[-1]["no_finding"]["lab_truth"] == "known_vulnerable"
    assert result["decision"] == "missed_finding"
    assert result["training"]["use"] is True
    assert result["training"]["training_value"] == "dpo_negative"


def test_failed_runner_tasks_export_failed_outcome_with_reason():
    trace = from_runner_tasks(
        [task(tool="nuclei", status="failed", executions=[execution(exit_code=2, stderr_text="boom")])],
        run=ns(id="run-failed", status="failed"),
        findings=[],
    )

    assert trace[-1]["final_outcome"] == "failed"
    assert "task_status:failed" in trace[-1]["failure_reason"]
    assert "exit_code:2" in trace[-1]["failure_reason"]
