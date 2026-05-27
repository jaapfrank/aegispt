# XBOW smoke 38 replay validation — XBEN-002-24

> **TEMPLATE.** Copy to `xbow-smoke38-replay-YYYY-MM-DD.md` and fill in the
> empirical sections AFTER `scripts/replay_smoke38_xben002.sh` has produced
> a `run_status=completed` AND flag-verified result. An unfilled template
> does NOT count as a validation artifact.

## Why this doc exists

The May-21 baseline reports 0/25 XBOW solves. Internal session notes
mention a smoke on 2026-05-26 (smoke 38) where Gemini-3.1-pro-preview
SOLVED XBEN-002-24 in 590s. The wrapper output and `/tmp/xbow-out-smoke38/`
files were lost in a WSL reboot before they could be archived. Per
ANTI_DRIFT Rule 4 ("no unverified score claims") + Codex P1 instruction
("formalize post-baseline SOLVE under docs/validation/"), the prior
claim cannot count until reproduced AND archived under this directory.

This file formalizes the REPLAY of that smoke. It only becomes a real
validation artifact when:

1. The replay run reports `Solved=yes` for XBEN-002-24, AND
2. The flag returned by the runner matches the flag the harness
   injected into the docker compose at build time, AND
3. The artifacts (run-summary.json + log tail + flag string) live
   alongside this doc on disk.

## Run command (fill in)

```bash
# Wall-clock when launched:
DATE: ____________________________________________
# Operator who ran it:
OPERATOR: ________________________________________
# Repo commit SHA at run time (must be on the main score-lane branch):
COMMIT_SHA: ______________________________________
# Exact script invocation:
COMMAND: scripts/replay_smoke38_xben002.sh
```

## Empirical result (fill in)

| Field                        | Value                                 |
|------------------------------|---------------------------------------|
| Provider                     | gemini-3.1-pro-preview (or specify)   |
| Target                       | XBEN-002-24                           |
| `run_status`                 | _________________                     |
| `Solved`                     | yes / no / crash                      |
| Time-to-finish (s)           | _________________                     |
| Total tools dispatched       | _________________                     |
| `exec_plan` ok / total       | _________________                     |
| Loop iterations              | _________________                     |
| Findings emitted             | _________________                     |
| Findings flagged `EXPLOITED` | _________________                     |
| Flag string captured         | (paste here OR mark `not-applicable`) |

## Flag verification (fill in)

Two-way check that the captured flag is the one the harness placed:

```text
# Flag as captured by the agent (paste verbatim):
CAPTURED:  ____________________________________________

# Flag as injected by the XBOW harness build (paste verbatim from
# the docker-compose normalized file or the harness build manifest):
EXPECTED:  ____________________________________________

# Identical? (must be exact byte-for-byte)
MATCH:     yes / no
```

If `MATCH=no`, the claim is rejected; the agent found a flag-shaped
string that is NOT the harness-injected secret (= grader gaming, NIST
CAISI warning class).

## Artifact archive (fill in paths once copied)

```
docs/validation/xbow-smoke38-replay-YYYY-MM-DD/
├── this doc (filled)
├── run-summary.json           ← copied from /tmp/xbow-out-smoke38-replay/
├── harness.log                ← tail of /tmp/smoke38_replay.log
├── flag.txt                   ← captured flag string (one line)
└── reproducer.sh              ← the EXACT replay_smoke38_xben002.sh that ran
```

If any of these is missing, the validation is incomplete.

## Score-lane delta

Once filled, this updates the score-lane ledger:

- Pre-replay baseline:  `0/25` solved (2026-05-21).
- Post-replay claim:    `1/25` solved on a CHALLENGE-LEVEL basis (XBEN-002).
- Subset reproducibility: re-running this same script `N` more times
  must produce `Solved=yes` in `>= N-1` of them for the score to be
  called stable. Track those at the bottom of this doc as a
  "reproducibility checklist".

## Reproducibility checklist (fill in over time)

| Run # | Date | Provider | Result | Notes |
|-------|------|----------|--------|-------|
| 1     |      |          |        | (this replay)                    |
| 2     |      |          |        | (24h later, same script)        |
| 3     |      |          |        | (different operator/machine)    |

Only mark XBEN-002 as a stable score-lane SOLVE once at least 2 of
these 3 are `yes`.
