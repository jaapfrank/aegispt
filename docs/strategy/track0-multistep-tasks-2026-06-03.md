# Track 0 — recon→action loop closure (multi-step). Tasks. 2026-06-03

Operator diagnosis (Gruyere run `15357dd6`): the system finds things, records them as
"proof", and stops — it does NOT create cause→follow-up. Found 20 endpoints incl `/admin`,
`/upload.gtl`, the stored-XSS→cookie-theft admin-takeover chain — but all 29 findings
`unvalidated`, no admin access, discovered endpoints never attacked. Multi-step is the gap.

Goal: a finding/discovery TRIGGERS targeted follow-up that is pursued to `EXPLOITED`
(impact), and the loop does not terminate while untested surface / open hypotheses remain.

## REFINED SCOPE (2026-06-03, after reading the loop)

The picture is more advanced than the initial diagnosis — and the gap is precise:
- **Hypothesis QUEUE + depth-first pursue: ALREADY BUILT** (`assessment_loop.py:3310-3351`
  "Refinement #1": cache queue in run.configuration_json; `has_open_work()` → `pick_next_open()`
  pursues open hypotheses BEFORE re-fanning-out). So T0.2's "(a)" exists.
- **Endpoints → specialists: DONE** (`cd1ac81`, T0.1) — the specialists now SEE the discovered
  endpoints, so they generate endpoint-TARGETED hypotheses that the existing queue pursues.
  This was the real gap that fed the queue.
- **EXPLOITED-verification ("(c)"): UNBUILT — the precise remaining gap.** `success_condition`
  appears ONLY in the docstring (2879); it is passed to the exploit task but NEVER consumed
  post-task, and nowhere is `validation_status` set to confirmed/exploited from it. So every
  finding stays `unvalidated` and the agent stops at "detected" (Gruyere: 29× unvalidated).

So the high-leverage remaining work is T0.2-(c) + T0.3, NOT a new queue system.

## Tasks (ROI-ordered, each independently verifiable)

### T0.1 — Continuous discovery→hypothesis feedback  [START HERE]
Newly discovered endpoints/params/forms/files (at ANY iteration, not just initial recon)
become follow-up hypotheses in the picker queue. Today the specialists/hypotheses are built
mostly up-front; later discoveries don't re-trigger them.
- Files: `api/app/services/assessment_loop.py` (picker state + hypothesis queue ~L2865),
  `picker_specialists/*`.
- Acceptance: a unit test — given a run whose findings include "Hidden Endpoint Discovered:
  /admin", the picker state/queue contains a pending hypothesis/target for `/admin`.

### T0.2 — Depth-first pursue-to-EXPLOITED
The picker chases the top hypothesis to `EXPLOITED` or refuted before breadth-scanning the
tool menu. A lead is "done" only at impact or exclusion.
- Acceptance: on a target with a clear lead, the loop spends consecutive iterations on that
  lead (not one tool then move on); measured by task sequence in a run.

### T0.3 — Don't-terminate-while-leads-remain
The loop's stop condition must not fire while there is untested discovered surface or an open
(non-refuted, non-exploited) hypothesis.
- Acceptance: a run with discovered-but-untested endpoints does not reach a terminal stop_reason.

### T0.4 — Per-endpoint probe matrix
Each discovered endpoint gets a structured probe: access-control (`/admin`), unrestricted
upload→RCE (`/upload.gtl`), injection, IDOR, path-traversal/files-behind-it, open-redirect.
- Acceptance: re-run Gruyere → evidence `/admin` + `/upload.gtl` were actively tested.

## Overall acceptance (the operator's bar)
Re-run Gruyere → `/admin` and `/upload.gtl` actively tested + ≥1 `validation_status=exploited`
(real admin session / account-takeover), not 29× `unvalidated`.

## Discipline
- Proven increments only (ANTI_DRIFT R3): each task lands with a test or a live before/after.
- Live runs SOLO (never parallel). Local test targets on dedicated 127.0.0.X.
