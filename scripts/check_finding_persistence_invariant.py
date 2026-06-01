"""Canonical-solve persistence invariant (Track B canary).

A solve counts canonically ONLY when all four hold:
  1) grader-verified  (a captured flag literal — verified externally by the lab
     grader / run_lab_suite; here we use the captured flag in the runner output
     as the in-DB proxy, since the grader matches that exact literal)
  2) persisted as a finding
  3) transcript present  (the finding's evidence_ref points to a stored artifact)
  4) scope provenance present  (the finding has a target_id)

This canary asserts, for a run: every flag the interactive-exploit runner
captured (tool_executions.stdout_text captured_flags) is matched by a persisted
Finding that has evidence_ref AND target_id. A violation = a "solve seen but not
in findings" case — the exact regression the M2-gate deterministic-proof
exemption fixes. Exit code 1 on any violation so it can gate CI / a validation run.

Usage:
    python scripts/check_finding_persistence_invariant.py [RUN_ID]
    (no arg = most recent run)
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from sqlalchemy import text  # noqa: E402

from api.app.config import get_settings  # noqa: E402
from api.app.db import build_engine  # noqa: E402

_FLAG_RE = re.compile(r"(?:aegispt|flag|FLAG)\{[^}]{1,200}\}|xbow-[0-9a-fA-F]{6,}")


def _flags_from(text_blob: str) -> set[str]:
    return set(_FLAG_RE.findall(text_blob or ""))


def check_run(run_id: str | None) -> int:
    settings = get_settings()
    engine = build_engine(settings.database_url, db_key=settings.aegispt_db_key)
    with engine.connect() as conn:
        if not run_id:
            row = conn.execute(text("SELECT id FROM runs ORDER BY created_at DESC LIMIT 1")).first()
            if not row:
                print("no runs found")
                return 1
            run_id = str(row[0])
        # captured flags from interactive-exploit executions
        execs = conn.execute(text(
            "SELECT te.stdout_text FROM tool_executions te "
            "JOIN tasks t ON t.id = te.task_id "
            "WHERE t.run_id = :rid AND t.tool = 'interactive-exploit'"
        ), {"rid": run_id}).all()
        captured: set[str] = set()
        for (stdout_text,) in execs:
            try:
                summ = json.loads(stdout_text) if stdout_text else {}
                for f in (summ.get("captured_flags") or []):
                    captured.add(str(f))
            except (ValueError, TypeError):
                captured |= _flags_from(stdout_text or "")
        # persisted findings (flag literal in title) + provenance fields
        findings = conn.execute(text(
            "SELECT title, evidence_ref, target_id FROM findings WHERE run_id = :rid"
        ), {"rid": run_id}).all()
        persisted: dict[str, tuple[bool, bool]] = {}
        for title, evidence_ref, target_id in findings:
            for flag in _flags_from(title or ""):
                persisted[flag] = (bool((evidence_ref or "").strip()),
                                   bool((target_id or "").strip()))

    violations: list[str] = []
    for flag in sorted(captured):
        if flag not in persisted:
            violations.append(f"NOT PERSISTED: {flag}")
            continue
        has_transcript, has_scope = persisted[flag]
        if not has_transcript:
            violations.append(f"NO TRANSCRIPT (evidence_ref): {flag}")
        if not has_scope:
            violations.append(f"NO SCOPE PROVENANCE (target_id): {flag}")

    print(f"run={run_id}")
    print(f"captured flags (grader-matchable): {len(captured)}")
    print(f"persisted as findings: {len([f for f in captured if f in persisted])}")
    pct = (100.0 * len([f for f in captured if f in persisted]) / len(captured)) if captured else 100.0
    print(f"findings-persistence: {pct:.1f}%")
    if violations:
        print(f"\n[FAIL] {len(violations)} canonical-solve invariant violation(s):")
        for v in violations:
            print(f"  - {v}")
        return 1
    print("\n[PASS] every captured flag persisted as a finding with transcript + scope provenance.")
    return 0


if __name__ == "__main__":
    raise SystemExit(check_run(sys.argv[1] if len(sys.argv) > 1 else None))
