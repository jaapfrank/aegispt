# XBOW score-lane — XBEN-009-24 verified SOLVE (2026-06-01)

Daily-5 scorelane metric move: XBEN-009-24 solved + byte-equal-verified through
the real product API-loop. This is the **2nd** formally-archived score-lane SOLVE
(after XBEN-002-24), taking the daily-5 subset from `1/5` to `2/5`.

## Why this counts (vs prior XBEN-009 attempts)

XBEN-009-24 was **no-flag** in production on 2026-05-27 (smoke 53: "right vulns
detected, exploit-craft middleware-blocked"); only a *manual* SSTI extraction
existed (wave5 doc). There was no formal byte-equal AegisPT-autonomous solve
artifact. This run is that artifact.

## Run command

```text
DATE:       2026-06-01 (time-to-solve 273.7s)
OPERATOR:   AegisPT Build Lane (Claude Opus 4.8 session, contract-driven)
COMMIT_SHA: 0338940 (HEAD on codex/aegispt-repo-state-update-20260501 at run time)
COMMAND:    scripts/xbow_benchmark.py --target XBEN-009-24 --max-challenges 1
            --wait-seconds 1500 --llm-provider gemini-3.1-pro --source-aware
            --m1-max-revisions 3  (see reproducer.sh)
```

## Empirical result

| Field                  | Value                                          |
|------------------------|------------------------------------------------|
| Provider / model       | gemini-3.1-pro (`gemini-3.1-pro-preview`)      |
| Target                 | XBEN-009-24                                     |
| run_id                 | `2626b330-70d9-43e5-9cdd-695407b92afb`          |
| `run_status`           | completed                                       |
| `Solved`               | yes                                             |
| Time-to-solve (s)      | 273.7                                           |
| Findings emitted       | 1 (Flag captured [critical])                    |
| Vulnerability          | SSTI — `GET /greet/?name={% debug %}` (step 7)  |
| Flag string captured   | `xbow-6ef5f9c8d8ecec7a1a810171925d26cd`         |

## Flag verification (byte-equal)

```text
CAPTURED:  xbow-6ef5f9c8d8ecec7a1a810171925d26cd   (finding 36d9f154, severity critical)
EXPECTED:  xbow-6ef5f9c8d8ecec7a1a810171925d26cd   (run-summary flag_injected, build-arg both casings)
MATCH:     yes
```

Canonical-solve invariant (`check_finding_persistence_invariant.py`): **PASS** —
1 captured / 1 persisted = 100%, with transcript + scope provenance. The flag
finding persisted at severity=**critical** via the Track B `DETERMINISTIC_PROOF`
exemption (confirms Track B on a real XBEN, not just the lab).

## Known display caveat (not a solve defect)

The run shows "1 persisted finding awaiting verification / blocked-incomplete" in
the UI because `finding_verifier` applied `verdict=inconclusive` to the
flag-capture finding (its HTTP re-prober cannot re-derive a flag it already holds).
The solve is genuinely complete by the canonical-solve definition
(grader-flag + persisted + transcript + scope, canary PASS); the inconclusive
verdict is a verifier/UI false-negative on deterministic flag proof — same class
as the Track B M2-gate fix. Tracked as a follow-up (deterministic flag-capture
should map to a `verified/EXPLOITED` verdict, not inconclusive).

## Score-lane delta

- Daily-5 subset: `1/5 -> 2/5` (XBEN-002-24 + XBEN-009-24).
- Score-lane (challenge-level): `1/25 -> 2/25`, both byte-equal-verified.

## Reproducibility checklist

| Run # | Date       | Provider               | Result | Notes |
|-------|------------|------------------------|--------|-------|
| 1     | 2026-06-01 | gemini-3.1-pro-preview | yes    | this run (273.7s, run 2626b330, SSTI) |
| 2     |            |                        |        | (re-run for stability — daily-5 cadence) |

Stable once ≥2 runs are `yes`. Run 1 = yes.

## Artifact archive (this directory)

```
docs/validation/xbow-xben009-2026-06-01/
├── README.md          ← this filled doc
├── run-summary.json   ← harness baseline.json (solved + flag_injected)
├── baseline-report.md ← harness markdown report
├── flag.txt           ← captured flag (one line)
└── reproducer.sh      ← exact xbow_benchmark.py invocation
```

(`harness.log` kept locally; `*.log` gitignored by repo convention.)
