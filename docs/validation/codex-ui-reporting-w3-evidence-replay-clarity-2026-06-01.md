# Codex UI/reporting W3 — Evidence Replay clarity pass

Date: 2026-06-01
Owner: Codex
Scope: React v2 Evidence Replay, chain-aware task evidence, provenance display

## Behavior Proven

W3 makes Evidence Replay use the same chain-aware task context as Mission
Control instead of replaying only the selected run's local `tasks` array. For
assessment-chain runs, sibling task evidence is now included through
`getTasksForRunContext(run)`.

The screen now separates evidence state from conclusions:

- evidence scope: run-local evidence vs assessment-chain evidence
- evidence state: task, execution, artifact, and transcript counts
- provenance: task ids, execution ids, runner digest, artifact hash, timestamp,
  and redaction state
- conclusion state: explicitly "Not inferred here"; validation and business
  conclusions remain in Findings Theater and report surfaces

## Fixture Proof

`ui-v2/tests/react-v2-critical-paths.spec.ts` adds an assessment-chain fixture
where the selected run has one local task but the chain has two tasks. Evidence
Replay must render both:

- `httpx · https://app.example.test/profile`
- `nuclei · https://api.example.test/admin`

The tests also prove transcript and artifact provenance labels render inside
the expanded task:

- execution provenance and runner digest
- transcript stdout
- artifact provenance
- SHA-256 hash
- artifact download action
- copy stating exit state is execution evidence, not a finding verdict

## Validation

Commands run from `ui-v2/` unless noted:

- `npm run build`
- `npx eslint src/viewModels/evidenceReplay.ts src/components/screens/EvidenceReplay.tsx tests/react-v2-critical-paths.spec.ts`
- `npx playwright test tests/react-v2-critical-paths.spec.ts --grep "Evidence Replay"`
- `npm test`

Notes:

- Initial build/lint caught a JSX parse error in the artifact fallback branch;
  the extra `)` was removed and build/lint passed afterward.
- The first targeted Evidence Replay test run exposed a test scoping issue:
  provenance labels existed but the assertion selected hidden labels in a
  collapsed sibling task. The test now scopes assertions to the opened task row.
- Final full UI test wrapper passed all 19 tests.
