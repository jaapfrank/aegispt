"""Trace recorder — Phase 1 of the jury direction (no reviewer models, no GPU).

Turns an agent run into the frozen run_trace.jsonl that jury_review.py consumes, so
the evidence + coverage arbiter can mint training data from the trajectories we
ALREADY generate. Standalone on purpose: it does NOT modify deep_chain_eval (which
the live gate is using); the runner/deep-chain just CALL this.

Key correctness point baked in: the deep-chain (and any CTF/lab with a known flag)
is `lab_truth=known_vulnerable`, so a no-flag run is a MISSED finding (gold for
dpo_negative), never a true negative. See [[ai-trains-ai-jury-direction]].
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any
from uuid import UUID


class TraceRecorder:
    """Append one frozen-schema step per agent turn, then finalize with the outcome."""

    def __init__(self) -> None:
        self.steps: list[dict] = []

    def step(self, *, state: str = "", action: str = "", tool_result: str = "",
             evidence=None, safety_status: str = "ok",
             objective_progress: float = 0.0, failure_reason: str = "") -> "TraceRecorder":
        self.steps.append({
            "state": state, "action": action, "tool_result": tool_result,
            "evidence": list(evidence or []), "safety_status": safety_status,
            "objective_progress": objective_progress, "failure_reason": failure_reason,
            "final_outcome": "", "no_finding": {},
        })
        return self

    def finalize(self, outcome: str, *, no_finding: dict | None = None) -> list[dict]:
        if self.steps:
            self.steps[-1]["final_outcome"] = outcome
            if no_finding:
                self.steps[-1]["no_finding"] = no_finding
        return self.steps

    def write(self, path: str) -> list[dict]:
        Path(path).write_text("\n".join(json.dumps(s) for s in self.steps) + "\n", encoding="utf-8")
        return self.steps


def from_deep_chain(result: dict, step_sigs: list[str], *,
                    lab_truth: str = "known_vulnerable") -> list[dict]:
    """Build a trace from a deep_chain run: its {flag,steps,idor,logged_in,unique}
    result + the per-step action signatures. Because the lab HAS a flag, a no-flag
    run is a missed_finding, never a true negative."""
    rec = TraceRecorder()
    n = max(len(step_sigs), 1)
    for i, sig in enumerate(step_sigs):
        rec.step(state=f"step{i + 1}", action=sig, tool_result="observed",
                 evidence=[f"deep_chain-step-{i + 1}"],
                 objective_progress=round((i + 1) / n, 3))
    if result.get("flag"):
        return rec.finalize("solved")
    coverage = [f"routes_seen:{result.get('unique', 0)}"]
    if result.get("logged_in"):
        coverage.append("auth_checked")
    if result.get("idor"):
        coverage.append("idor_probed")
    untested = [] if result.get("idor") else ["admin/token path not reached"]
    return rec.finalize("no_confirmed_finding", no_finding={
        "lab_truth": lab_truth, "coverage": coverage, "blockers": [],
        "untested_boundaries": untested, "conscious_restraint": False,
    })


def _safe_dict(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


def _obj_id(value: Any) -> str:
    raw = getattr(value, "id", "")
    return str(raw or "")


def _sort_key(value: Any) -> tuple[str, str]:
    created = getattr(value, "created_at", None)
    return (str(created or ""), _obj_id(value))


def _latest_execution(task: Any) -> Any | None:
    executions = list(getattr(task, "executions", None) or [])
    if not executions:
        return None
    return sorted(executions, key=_sort_key)[-1]


def _tail(value: Any, *, limit: int = 1200) -> str:
    text = str(value or "")
    if len(text) <= limit:
        return text
    return text[-limit:]


def _artifact_refs(execution: Any) -> list[str]:
    refs: list[str] = []
    for artifact in list(getattr(execution, "artifacts", None) or []):
        uri = str(getattr(artifact, "uri", "") or "").strip()
        sha = str(getattr(artifact, "sha256", "") or "").strip()
        kind = str(getattr(artifact, "kind", "") or "artifact").strip()
        if uri:
            refs.append(uri)
        elif sha:
            refs.append(f"artifact:{kind}:{sha}")
    return refs


def _task_action(task: Any) -> str:
    tool = str(getattr(task, "tool", "") or "unknown-tool")
    target = str(getattr(task, "target_id", "") or "").strip()
    params = _safe_dict(getattr(task, "params_json", None))
    params_preview = json.dumps(params, sort_keys=True, separators=(",", ":")) if params else "{}"
    return f"{tool} {target} params={params_preview}"


def _execution_result(task: Any, execution: Any | None) -> str:
    if execution is None:
        return "no stored tool execution"
    payload = {
        "exit_code": getattr(execution, "exit_code", None),
        "status": getattr(task, "status", ""),
        "stderr_tail": _tail(getattr(execution, "stderr_text", "")),
        "stdout_tail": _tail(getattr(execution, "stdout_text", "")),
        "artifact_count": len(list(getattr(execution, "artifacts", None) or [])),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _evidence_refs(run_id: str, task: Any, execution: Any | None) -> list[str]:
    refs: list[str] = []
    task_id = _obj_id(task)
    if execution is None:
        return refs
    execution_id = _obj_id(execution)
    if getattr(execution, "stdout_text", None):
        refs.append(f"inline://runs/{run_id}/tasks/{task_id}/executions/{execution_id}/stdout.txt")
    if getattr(execution, "stderr_text", None):
        refs.append(f"inline://runs/{run_id}/tasks/{task_id}/executions/{execution_id}/stderr.txt")
    refs.extend(_artifact_refs(execution))
    return refs


def _failure_reason(task: Any, execution: Any | None) -> str:
    status = str(getattr(task, "status", "") or "").lower()
    reasons: list[str] = []
    if status in {"failed", "cancelled", "skipped", "blocked"}:
        reasons.append(f"task_status:{status}")
    if execution is None:
        reasons.append("no_tool_execution")
    elif int(getattr(execution, "exit_code", 0) or 0) != 0:
        reasons.append(f"exit_code:{getattr(execution, 'exit_code', None)}")
    return ";".join(reasons)


def _classify_runner_outcome(
    *,
    run: Any | None,
    findings: list[Any],
    final_outcome: str | None,
) -> str:
    if final_outcome:
        return final_outcome
    if findings:
        return "objective_met"
    run_status = str(getattr(run, "status", "") or "").lower()
    if run_status in {"failed", "error"}:
        return "failed"
    if run_status in {"cancelled", "aborted"}:
        return "aborted"
    if run_status in {"completed", "completed_with_errors", "stopped"}:
        return "no_confirmed_finding"
    return ""


def from_runner_tasks(
    tasks: list[Any],
    *,
    run: Any | None = None,
    findings: list[Any] | None = None,
    final_outcome: str | None = None,
    lab_truth: str = "live_no_oracle",
) -> list[dict]:
    """Build a jury trace from stored AegisPT Task/ToolExecution records.

    This is the runner-side counterpart to from_deep_chain(): it reads persisted
    task/execution objects and emits the same frozen trace schema without changing
    runner dispatch, task status, findings, or live runtime behavior.
    """
    ordered_tasks = sorted(list(tasks or []), key=_sort_key)
    finding_rows = list(findings or [])
    run_id = _obj_id(run) or "unknown-run"
    rec = TraceRecorder()
    n = max(len(ordered_tasks), 1)
    all_evidence: list[str] = []
    coverage: list[str] = []
    blockers: list[str] = []
    untested: list[str] = []

    for index, task in enumerate(ordered_tasks):
        execution = _latest_execution(task)
        evidence = _evidence_refs(run_id, task, execution)
        all_evidence.extend(evidence)
        tool = str(getattr(task, "tool", "") or "unknown-tool")
        status = str(getattr(task, "status", "") or "").lower()
        if execution is not None and status in {"completed", "completed_with_errors"}:
            coverage.append(f"tool:{tool}")
        if status in {"failed", "cancelled", "blocked"}:
            blockers.append(f"{tool}:{status}")
        if execution is None or status in {"queued", "running", "skipped"}:
            untested.append(f"{tool}:{status or 'no_status'}")
        rec.step(
            state=json.dumps(
                {
                    "task_id": _obj_id(task),
                    "task_status": getattr(task, "status", ""),
                    "tool": tool,
                    "target_id": getattr(task, "target_id", ""),
                },
                sort_keys=True,
                separators=(",", ":"),
            ),
            action=_task_action(task),
            tool_result=_execution_result(task, execution),
            evidence=evidence,
            objective_progress=round((index + 1) / n, 3),
            failure_reason=_failure_reason(task, execution),
        )

    if not rec.steps:
        rec.step(
            state="no stored tasks",
            action="none",
            tool_result="no stored runner tasks for run",
            evidence=[],
            objective_progress=0.0,
            failure_reason="no_tasks",
        )
        untested.append("run:no_tasks")

    outcome = _classify_runner_outcome(run=run, findings=finding_rows, final_outcome=final_outcome)
    if outcome in {"no_confirmed_finding", "no_finding"}:
        no_finding = {
            "lab_truth": lab_truth,
            "coverage": sorted(set(coverage)),
            "negative_evidence_refs": sorted(set(all_evidence)),
            "blockers": sorted(set(blockers)),
            "untested_boundaries": sorted(set(untested)),
            "conscious_restraint": False,
        }
        return rec.finalize("no_confirmed_finding", no_finding=no_finding)
    return rec.finalize(outcome)


def write_trace_jsonl(trace: list[dict], path: str | Path) -> list[dict]:
    Path(path).write_text(
        "\n".join(json.dumps(step, sort_keys=True) for step in trace) + "\n",
        encoding="utf-8",
    )
    return trace


def _load_run_trace_from_db(run_id: str, *, lab_truth: str, final_outcome: str | None) -> list[dict]:
    from sqlalchemy import select
    from sqlalchemy.orm import selectinload, sessionmaker

    from api.app.config import get_settings
    from api.app.db import build_engine
    from api.app.models import Finding, Run, Task, ToolExecution

    settings = get_settings()
    engine = build_engine(settings.database_url, db_key=settings.aegispt_db_key)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
    with SessionLocal() as session:
        run = session.scalar(select(Run).where(Run.id == UUID(run_id)))
        if run is None:
            raise SystemExit(f"run not found: {run_id}")
        tasks = session.scalars(
            select(Task)
            .options(selectinload(Task.executions).selectinload(ToolExecution.artifacts))
            .where(Task.run_id == run.id)
        ).all()
        findings = session.scalars(select(Finding).where(Finding.run_id == run.id)).all()
        return from_runner_tasks(
            list(tasks),
            run=run,
            findings=list(findings),
            final_outcome=final_outcome,
            lab_truth=lab_truth,
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="Export stored AegisPT runner tasks as jury run_trace.jsonl")
    parser.add_argument("--run-id", required=True, help="Stored AegisPT run UUID to export")
    parser.add_argument("--out", required=True, help="Output run_trace.jsonl path")
    parser.add_argument(
        "--lab-truth",
        default="live_no_oracle",
        choices=["live_no_oracle", "known_clean", "known_vulnerable"],
        help="Oracle label for no-finding traces. Live runs should keep the default.",
    )
    parser.add_argument(
        "--final-outcome",
        default=None,
        help="Optional explicit final_outcome override for the final trace step.",
    )
    args = parser.parse_args()

    trace = _load_run_trace_from_db(
        args.run_id,
        lab_truth=args.lab_truth,
        final_outcome=args.final_outcome,
    )
    write_trace_jsonl(trace, args.out)
    print(json.dumps({"path": args.out, "steps": len(trace), "final_outcome": trace[-1].get("final_outcome")}))


if __name__ == "__main__":
    main()
