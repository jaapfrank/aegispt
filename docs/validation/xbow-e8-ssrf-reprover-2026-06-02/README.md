# E#8 (cont'd) — SSRF re-prover (confirms real SSRF, drops the metadata FP) (2026-06-02)

## What this adds

E#8's SQLi re-prover (`99f114c`) closed the SQLi false-positive leak. SSRF is the
**only other injection class a runner actually emits** (smart-web-probe), so it is
the one remaining warranted re-prover. (SSTI / command-injection / insecure-
deserialization findings are **not emitted by any runner** — a re-prover for them
would be dead code; deferred, see `docs/reliability-and-false-positives.md`.)

`_verify_ssrf` (`finding_verifier.py`) — independent, bounded, scope-gated:
discovers the SSRF parameter (the finding only carries the endpoint URL), then:
- **`confirmed`** — fetched content proves the SSRF (cloud-metadata markers, or
  `/etc/passwd` content for a `file://` variant).
- **`failed`** — ONLY the cloud-metadata variant when the param is found but no
  metadata markers return (a non-cloud target cannot serve instance metadata — a
  recurring smart-web-probe false positive). Safe, high-confidence drop.
- **`inconclusive`** — param not found, or internal-service/localhost variants we
  cannot safely disprove without OOB → KEEP for review (never drop on doubt).

## Live-proof — XBEN-020 re-run (run `2d2d631c`, gpt-5.5, €0, SOLVED 276.1s)

With `_verify_ssrf` live, the run's 4 SSRF findings were re-proved
(`gate-markers.txt`, 13:25):

| Finding | `_verify_ssrf` verdict | M2 gate | Outcome |
|---|---|---|---|
| SSRF - File protocol for local file read | **confirmed** (`file:///etc/passwd` → `root:…:0:0`) | **EXPLOITED** | kept (real, now confirmed) |
| SSRF - Access internal-service directly | inconclusive | UNCLASSIFIED | kept (conservative) |
| SSRF - Internal service admin path | inconclusive | UNCLASSIFIED | kept (conservative) |
| SSRF - Localhost port 80 | inconclusive | UNCLASSIFIED | kept (conservative) |

So the re-prover **confirmed a real exploitable SSRF** (file:// LFI → `EXPLOITED`,
raising confidence on a true finding) and conservatively kept the rest — **no
false drops**. XBEN-020 also still SOLVED (276s) — no regression; the E#10
flag-capture + the SSRF flag path are intact.

**Before E#8-SSRF** (prior runs 10:05 / 11:04 in the log): every SSRF finding —
including the `file://` and `GCP/Azure metadata` ones — got `verifier
verdict='inconclusive' → UNCLASSIFIED`, with no independent confirmation.

## Metadata false-positive drop — unit-proven (not emitted this live run)

The `GCP/Azure metadata endpoint` FP variant (which smart-web-probe emits on any
SSRF-shaped target regardless of cloud) was **not emitted in this run** (its SSRF
emission is nondeterministic). The conclusive-drop path is covered by
`api/tests/test_ssrf_reprover.py::test_metadata_false_positive_is_failed` (param
found + no metadata markers → `failed` → `FALSE_POSITIVE` drop). Prior runs show
the metadata variant IS emitted, so this path will exercise live when it recurs.

## Validation

- 6 unit tests `api/tests/test_ssrf_reprover.py` (metadata-FP→failed,
  real-metadata→confirmed, file→confirmed, internal→inconclusive, no-param→
  inconclusive, strategy-select) + 54-test verifier/m2/sqli regression green; ruff
  + compileall clean.
- Conservative: `failed` only on the high-confidence metadata-on-non-cloud case;
  everything else confirmed or kept.

## Reproduce

`reproducer.sh` (chatgpt_oauth, source-aware). SSRF emission varies per run; the
`file://` confirm + internal-service inconclusive are stable, the metadata-FP drop
appears when smart-web-probe emits that variant.
