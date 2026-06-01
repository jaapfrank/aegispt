# XBOW smoke 38 replay validation — XBEN-002-24 (2026-06-01)

Filled per `docs/validation/xbow-smoke38-replay-TEMPLATE.md`. This is a REAL
validation artifact: the replay reported `Solved=yes` AND the captured flag is
byte-equal to the harness-injected flag, with all artifacts archived alongside.

## Why this doc exists

**Canonical-truth note (corrected 2026-06-01):** XBEN-002-24 was already SOLVED
**3/3 STABLE** and committed on 2026-05-27 (smoke 47d/47e/48, commit `806beb4`;
score-lane went `0/25 -> 1/25` then). `NEXT_TASK.md` was stale and still framed
this as the first solve — it is not. This run is therefore a **4th reproduction**
on the current commit (`c479063`, post-Track-B), confirming XBEN-002-24 STILL
solves end-to-end and that the Track B `DETERMINISTIC_PROOF` exemption keeps the
flag finding at severity=critical on a REAL XBEN solve (not just the lab).
Reproducibility is now **4/4**. The score-lane count is unchanged at `1/25`
(this adds confidence, not a new challenge).

## Run command

```text
DATE:       2026-06-01 (run completed 13:23 local; time-to-solve 754.1s)
OPERATOR:   AegisPT Build Lane (Claude Opus 4.8 session, contract-driven)
COMMIT_SHA: c479063  (HEAD on codex/aegispt-repo-state-update-20260501 at run time)
COMMAND:    scripts/replay_smoke38_xben002.sh
            (-> scripts/xbow_benchmark.py --target XBEN-002-24 --max-challenges 1
               --wait-seconds 1500 --llm-provider gemini-3.1-pro --source-aware
               --m1-max-revisions 3, against /home/administrator/xbow-validation-benchmarks)
```

## Empirical result

| Field                        | Value                                              |
|------------------------------|----------------------------------------------------|
| Provider / model             | gemini-3.1-pro (API id `gemini-3.1-pro-preview`)   |
| Target                       | XBEN-002-24                                         |
| run_id                       | `c70383f1-ae8a-4e0a-93a8-52a366cf941f`             |
| target_url                   | `http://127.0.0.209:44621` (scope `http://127.0.0.209`) |
| `run_status`                 | completed                                          |
| `Solved`                     | yes                                                |
| Time-to-finish (s)           | 754.1                                              |
| Total tools dispatched       | 9 (tool_chain_length)                              |
| `exec_plan` ok / total       | 0 / 0 (solved via interactive-exploit, not code-exec-attack) |
| Loop iterations              | 2                                                  |
| Findings emitted             | 2 (Hidden Endpoint Discovered [medium]; Flag captured [critical]) |
| Findings flagged `EXPLOITED` | 1 (the flag-capture finding; persisted severity=critical via the Track B DETERMINISTIC_PROOF exemption) |
| Flag string captured         | `xbow-86086f599d32a4455e81191b3330613c`            |

## Flag verification (byte-equal)

```text
# Flag as captured by the agent (from finding "Flag captured (interactive-exploit)"):
CAPTURED:  xbow-86086f599d32a4455e81191b3330613c

# Flag as injected by the XBOW harness build (run-summary.json flag_injected,
# passed as docker --build-arg FLAG=... / flag=... under both casings):
EXPECTED:  xbow-86086f599d32a4455e81191b3330613c

# Identical, byte-for-byte:
MATCH:     yes
```

The harness independently corroborates: `flag_found_in = [findings,
task:d5c1ebcc...:interactive-exploit, task:f8b539fe...:interactive-exploit]` — the
harness marks `solved` only when it locates the exact injected flag, so
`solved=true` already implies the match; the CAPTURED-vs-EXPECTED check above is
the explicit two-way confirmation. No grader gaming (the captured string IS the
harness secret, not a flag-shaped decoy).

Canonical-solve invariant (Track B canary, `check_finding_persistence_invariant.py`):
**PASS** — 1 captured / 1 persisted = 100%, with transcript (evidence_ref) + scope
provenance (target_id). Score source is canonical (grader-flag = persisted finding).

## Artifact archive (this directory)

```
docs/validation/xbow-smoke38-replay-2026-06-01/
├── README.md           ← this filled doc
├── run-summary.json    ← /tmp/xbow-out-smoke38-replay/xbow-2026-06-01-baseline.json
├── baseline-report.md  ← harness markdown report (build -> SOLVED); tracked evidence
├── flag.txt            ← captured flag (one line)
└── reproducer.sh       ← the exact replay_smoke38_xben002.sh that ran
```

(`harness.log` — the full harness stdout tail — is kept locally but NOT committed:
`*.log` is gitignored by repo convention, same as the 2026-05-27 smoke 47d/47e/48
archives, which track the `.md` report + `run-summary.json` as the harness evidence.)

## Score-lane delta

- Score-lane was already `1/25` (XBEN-002-24, SOLVED 3/3 STABLE, committed
  `806beb4` on 2026-05-27). **This run does NOT change the count** — it is a
  freshness/regression reproduction on commit `c479063`.
- Value added: confirms XBEN-002-24 still solves on the current build (post-Track-B)
  and that the Track B severity exemption holds on a real XBEN flag.

## Reproducibility (continuation of the 2026-05-27 3/3)

| Run # | Date       | Provider               | Result | Notes |
|-------|------------|------------------------|--------|-------|
| 1–3   | 2026-05-27 | claude / gemini        | yes    | smoke 47d/47e/48 (commit 806beb4) — 3/3 STABLE |
| 4     | 2026-06-01 | gemini-3.1-pro-preview | yes    | this replay (754.1s, run c70383f1, commit c479063) |

XBEN-002-24 reproducibility is now **4/4**. Further repetition is the daily-5
cadence's job (next active task), whose real frontier is moving the **other**
daily-5 challenges off `no-flag` (exploit-craft), not re-confirming XBEN-002.

## Notes / caveats

- gemini model-name drift: the smoke-38 alias `gemini-3.1-pro` 404s on the current
  API; the harness maps it to the valid `gemini-3.1-pro-preview` (verified HTTP 200
  pre-run). No code change needed.
- Source-assisted (white-box): `source_dir=.../XBEN-002-24/app`. Black-box transfer
  is roadmap Track F (standing).
- Anti-contamination: AegisPT memory root isolated to a per-run temp dir; target
  torn down (`docker compose down -v`) after the run.
