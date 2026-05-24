# XBEN miss triage method

Standard process for diagnosing why AegisPT failed to solve a specific XBEN challenge. Output is a written diagnosis with a classification + a concrete proposal for the change that would (probably) unblock it. Designed to convert a single miss into a generic capability or a backlog item, not a one-off fix.

## When to use

After any XBOW smoke that reports a `no-flag` outcome on a challenge that ran end-to-end (not a `CRASH`). Skip on infra crashes — those go through the harness reliability bucket (M8), not this method.

## Step 1 — Pull the artifacts

For run `<run_id>`:

```sql
-- All tasks for the run
SELECT substr(id::text,1,8), tool, status, created_at
FROM tasks WHERE run_id = '<run_id>'
ORDER BY created_at;

-- All findings for the run
SELECT severity, title, substr(summary,1,200), target_id
FROM findings WHERE run_id = '<run_id>'
ORDER BY created_at;

-- Picker decisions (action_type + reasoning) from episodic memory
SELECT action_type, action_context_json->>'reasoning' AS reasoning, action_context_json->>'tool' AS tool, action_context_json->>'target' AS target, created_at
FROM agent_episodic_memory WHERE run_id = '<run_id>'
ORDER BY created_at;

-- All tool_executions stdout (truncated)
SELECT t.tool, substr(te.stdout_text, 1, 500) AS stdout_excerpt, te.exit_code
FROM tool_executions te
JOIN tasks t ON t.id = te.task_id
WHERE t.run_id = '<run_id>'
ORDER BY te.created_at;
```

Then read the challenge source: `/home/administrator/xbow-validation-benchmarks/benchmarks/<XBEN-NNN-YY>/{app,src,code}/`. Identify the **win condition** in the source — where in the code does the flag get returned.

## Step 2 — Classify the miss

Pick the dominant reason from this list. If two apply, pick the upstream one (the one that, if fixed, makes the others go away).

| code | reason | example |
|---|---|---|
| `no_endpoint_discovery` | recon did not surface the endpoint that holds the win-condition path | XBEN-010 `/post?msg=...` was never observed by content-discovery |
| `no_auth` | endpoint discovered but reachable only with credentials that AI didn't obtain or use | XBEN-NNN requires login, AI never POST'd to `/login` |
| `bad_plan` | exec_plan was correct shape but wrong target/payload class for the vuln | AI tries reflected XSS on a stored-XSS challenge |
| `timeout` | the right action started but exceeded its budget | CEA hit `--script-timeout-seconds` ceiling before reaching the sink |
| `hallucinated_path` | AI invented an endpoint that doesn't exist | exec_plan against `/admin/dump` when source has no such route |
| `missing_source` | source-aware mode skipped (wrong directory name, no source mounted) | XBEN-NNN had `src/` not `app/` and pre-recon-cpg never ran |
| `missing_tool` | the vuln class requires a runner we do not have | XBEN-010 phantomjs XSS needs a headless-browser XSS callback runner |
| `missing_payload_class` | the runner exists but the AI's exec_plan didn't include the payload class that works | SSTI challenge, CEA tried generic XSS payloads instead of `{{config}}` |
| `verifier_dropped` | finding emitted but M2 verdict gate classified it as FALSE_POSITIVE | rare; gate must show this in PROOF_EXEC_M2_VERDICT_GATE log |
| `early_stop_wrong` | system halted before the win condition was reachable | should not happen post-2026-05-24 (early-stop only fires on flag literal) |

## Step 3 — Decide the change

| if classified as | propose |
|---|---|
| `no_endpoint_discovery` | (a) new wordlist entry for content-discovery, OR (b) extend pre-recon-cpg ROUTES extractor to find this route shape |
| `no_auth` | check auth-discoverer config; widen credential probe; verify auth-flow runner ran |
| `bad_plan` | add the missing payload class to script_critic's revision prompt; if class is reusable, propose an H3 SkillLibrary entry |
| `timeout` | bump runner timeout if the class needs it; tighten the script focus prompt to skip pre-amble |
| `hallucinated_path` | add HARD RULE in picker prompt: "endpoints only from CPG ROUTES / pre-recon-source / recon deliverable" |
| `missing_source` | extend `_run_one_challenge` source-dir resolution (we already cover app/src/code/Dockerfile-bearing — add more if discovered) |
| `missing_tool` | open a backlog task for the new runner; in the meantime, file under "vuln-class capability gap" |
| `missing_payload_class` | extend the specialist's hypothesis schema for that vuln class to include the missing payload variants |
| `verifier_dropped` | inspect the verifier's decision; if too strict, tune the verdict-gate rule |
| `early_stop_wrong` | should not happen — if it does, file a P0 bug |

## Step 4 — Write the diagnosis

One markdown file per miss, in `docs/triage/<date>-<XBEN-id>-<run-prefix>.md`:

```markdown
# Triage: XBEN-NNN-YY (run <prefix>)

- Date: YYYY-MM-DD
- Smoke: <smoke-id>
- Outcome: no-flag (<seconds>s, <N> findings, <N> tools, <iters> iters)

## Win condition (from source)
<file:line> — <one-line description of the code path that returns the flag>

## What the AI did
<3-5 line summary of the tool chain and where it stopped>

## Classification
<code> — <one-line justification>

## Proposed change
<concrete change, with file/line if applicable>

## Backlog item proposal
<title for the queue item, or "no new queue item needed if X is patched">
```

## Step 5 — Apply: XBEN-010 example

The first application of this method. Captured separately as `docs/triage/2026-05-24-XBEN-010-pending.md` once we have a fresh smoke run-id to triage against (smoke 24's XBEN-010 run-id is gone after the cleanup truncate; need to re-run a single-XBEN-010 smoke to get fresh artifacts).
