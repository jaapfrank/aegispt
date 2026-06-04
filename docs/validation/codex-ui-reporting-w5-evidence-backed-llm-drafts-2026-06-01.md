# Codex UI/Reporting W5 Validation - Evidence-Backed LLM Report Drafts

Date: 2026-06-01

## Scope

W5 hardens AI-assisted report drafting so an LLM can only phrase structured
facts already present in the report payload. It does not create canonical
findings, alter exported report facts, or rewrite raw proof/evidence exports.

Touched files:

- `api/app/services/reports.py`
- `api/app/schemas/report_center.py`
- `api/tests/test_reports.py`

## Payload Contract Snapshot

Representative draft payload shape now exposed on `RunReportDraftRead`:

```json
{
  "draft_contract": {
    "facts_source": "structured_payload_only",
    "review_only": true,
    "canonical_report_unchanged": true,
    "allowed_input_facts": [
      "tested_scope",
      "supported_findings",
      "source_evidence_refs",
      "not_tested",
      "not_verified",
      "methodology"
    ],
    "raw_proof_export_non_llm": true
  },
  "variant_contract": {
    "audience": "technical",
    "template": "technical_evidence_narrative",
    "llm_allowed": true
  },
  "tested_scope": {
    "tested_targets": ["https://app.example.test/admin"],
    "completed_task_count": 1
  },
  "supported_findings": [
    {
      "title": "Admin panel exposed",
      "severity": "high",
      "target_id": "https://app.example.test/admin",
      "evidence_ref": "artifact://zap/admin-panel",
      "validation_status": "validated"
    }
  ],
  "not_tested": [
    {
      "type": "authorized_target_without_completed_task",
      "claim_rule": "May be described as authorized scope, not as tested coverage."
    }
  ],
  "not_verified": [
    {
      "title": "Unsupported admin takeover claim",
      "reason": "missing_evidence_ref",
      "claim_rule": "Keep as a review caveat. Do not present this item as a supported report finding."
    }
  ]
}
```

The ChatGPT OAuth request now sends this structured payload directly. It no
longer sends raw top-level `findings` or `tasks` arrays to the LLM. The
instructions explicitly forbid turning `not_tested` or `not_verified` items into
positive report claims.

## Behavior Proved

- Deterministic and ChatGPT OAuth draft paths expose the same review-only
  contract fields.
- Unsupported findings without an evidence reference are excluded from
  `supported_findings` and placed under `not_verified`.
- Draft markdown does not include the unsupported finding title as a positive
  report claim.
- Management and technical variants carry different template/audience
  constraints.
- The `evidence` variant returns `not_applicable` for AI drafting because proof
  exports remain deterministic and non-LLM.
- Canonical report export bytes before and after drafting remain unchanged in
  the draft test.
- Existing full report export coverage still passes after making its active ZAP
  fixture explicitly authorized for the active dispatch it expects.

## Validation Commands

```bash
python3 -m compileall -q api/app/services/reports.py api/app/schemas/report_center.py api/tests/test_reports.py
. .venv/bin/activate && ruff check api/app/services/reports.py api/app/schemas/report_center.py api/tests/test_reports.py
. .venv/bin/activate && python -m pytest api/tests/test_reports.py -k "ai_report_draft"
. .venv/bin/activate && python -m pytest api/tests/test_reports.py
```

Results:

- compileall: passed
- ruff touched backend/report test files: passed
- focused AI draft tests: `5 passed, 17 deselected`
- full report tests: `22 passed`

## Repo Hygiene Notes

- Full report tests generated temporary Codex task JSON files under
  `codex/tasks/`; both generated files were removed because they were test
  byproducts, not queue-backed task packages.
- The W5 patch did not require edits to `NEXT_TASK.md`, `TASK_QUEUE.md`,
  score-lane runtime files, solver/scoring files, or active benchmark
  validation artifacts. A concurrent score-lane `NEXT_TASK.md` working-tree
  diff was present after validation and is not part of this W5 change set.
