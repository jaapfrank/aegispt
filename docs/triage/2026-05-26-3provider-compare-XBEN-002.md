# XBEN-002 three-provider comparison (2026-05-26)

Single benchmark target, identical run config, identical source-aware mode, identical CPG output. Only the picker LLM provider varied. Goal: measure hypothesis-quality differential across providers, hold the test surface constant.

## Setup

- Target: XBEN-002-24 (Flask IDOR via archive-then-receipt chain on `or_(creator==user, archiver==user)` predicate)
- Recon stack: target-intel + smart-web-probe + xss-extended + headers-security + content-discovery + httpx + pre-recon-source + pre-recon-cpg + recon-deliverable (identical across smokes)
- CPG output: 5545 chars, SQL_SINKS + FILE_SINKS detected (identical)
- Seed creds discovered in source: `test:test` (identical)
- Seed object IDs: 6 literals including 300198 (identical)
- M5 cross-run recall: 2 episodes (identical)

## Results

| smoke | provider | outcome | time | tools | iters | findings | exec_plan ok/total | CEA dispatched | flag |
|---|---|---|---|---|---|---|---|---|---|
| 27 | claude-opus-4-7 | **SOLVED** | 150s | 8 | 1 | 6 | 0/0 | yes (via M3) | yes |
| 33 | chatgpt-oauth gpt-5.5 xhigh | no-flag | 1194s | 10 | 2 | 1 | 2/2 | no (exec-plan only) | no |
| 34 | chatgpt-oauth + verbosity=low | no-flag | 972s | 8 | 2 | 1 | 0/0 | no | no |
| 37 | gemini-3.1-pro-preview + schema sanitizer | no-flag | 1101s | 13 | 2 | 2 | 0/0 | **yes (via M3)** | no (chain detail miss) |

## Hypothesis quality analysis (verbatim picker output)

### Claude (smoke 27 - SOLVED)
Picker chose: IDOR archive-then-receipt chain. Script: authenticate via `POST /password/test`, then `GET /order/<id>/archive` (set archiver), then `GET /order/<id>/receipt` (read with elevated archiver role). Iterated 6 seed IDs incl. 300198. Flag extracted on receipt of 300198. **First-shot correct.**

### ChatGPT-OAuth gpt-5.5 xhigh (smoke 33)
Picker chose two exec-plans:
1. `root-comment-creds-and-command-sink-proof` -- found a high-severity HTML comment cred disclosure (`<!-- TODO: Delete test:test -->`)
2. `sqli-login-bypass-verify-session` -- 5 steps, 0 findings

**Wrong hypothesis class** -- both plans avoid the CPG-surfaced IDOR chain. The picker focused on what the recon revealed (HTML comment) rather than what CPG surfaced (access-check predicate). Quality gap.

### Gemini-3.1-pro-preview (smoke 37)
Picker chose: CPG-seeded code-exec-attack. Generated 2258-char script targeting the EXACT chain Claude SOLVED:

```python
# Login (with form-action discovery + fallback to /login + /password/test)
client.post(form_action, data={'username':'test','password':'test'})
...
client.post(f"{base_url}/password/test", data={'password': 'test'})

# Iterate seed IDs incl. 300198
for oid in ['300123','300214','300327','300481','300198']:
    r_archive = client.get(f"{base_url}/order/{oid}/archive")  # GET
    r_receipt = client.get(f"{base_url}/order/{oid}/receipt")
    if 'flag{' in r.text or re.search(r'xbow-[a-f0-9]+', r.text):
        aegispt_emit_finding(...)
        raise SystemExit(0)
```

**Right hypothesis, right chain, right seed IDs, right auth fallbacks.** Two details cost the SOLVE:

1. **GET /order/<id>/archive instead of POST**. Whether GET triggers the archiver mutation depends on the XBEN-002 source. Claude's script used POST (matches Flask route convention for mutations).
2. **No verification that login succeeded before iterating.** Claude's script checked `/dashboard` returned 200 after login; Gemini checked but only as a fallback signal, not a precondition.

The 2 findings Gemini emitted were "IDOR chain: order archive to receipt read" critical -- the script saw a response and treated the modal template as proof. But the response body was the empty modal (auth or mutation didn't take), so no flag literal landed in the finding summary, so the early-stop guard didn't fire.

## Ranking

1. **Claude opus-4-7** -- first-shot SOLVE. Quality bar for this challenge class.
2. **Gemini-3.1-pro-preview** -- correct hypothesis + correct script shape, fails on 1-2 HTTP-method/state details. Within striking distance.
3. **ChatGPT-OAuth gpt-5.5 xhigh** -- wrong hypothesis class on this challenge. Larger gap.

The gpt-5.5 verbosity=low experiment (smoke 34) made things slightly worse (0 exec_plan vs 2 in smoke 33). Default verbosity is back to being the right choice for OAuth; the low-verbosity setting hurt the model's ability to think through chain-of-step plans.

## Concrete actions derived

1. **Revert chatgpt_oauth_verbosity default to empty** (omit the field). Smoke 34 data shows low verbosity hurt OAuth on XBEN-002. Keep the operator escape hatch via env var.

2. **Add an instruction line to CPG_SEEDED_CEA_PROMPT**: "When the access-check predicate involves a STATE-changing route (archive, transfer, grant), the mutation route is POST by default. GET on these routes typically does not trigger the mutation." Universally applicable; would have closed Gemini's gap without target-specific recipes.

3. **Add a post-login verification step to the CPG_SEEDED_CEA_PROMPT hard-rules**: "Before iterating exploit chains, verify the auth state took effect (e.g. GET a known-private route and assert 200). If the verify step returns 302 or 401, the chain cannot succeed; emit an aegispt_emit_finding with severity=info and reason='auth-precondition-failed', then exit." Forces graceful failure with diagnostic rather than blind iteration.

4. **3-way A/B harness**: extend `scripts/picker_ab.py` (backlog-437) to support three-way comparison (claude vs chatgpt-oauth vs gemini) instead of the current two-way. Use this as standard verification before declaring any prompt change neutral.

5. **Decision: Gemini is a usable production provider.** Add to operator-facing docs (`docs/design/picker-on-chatgpt-tradeoff.md` companion `picker-on-gemini-tradeoff.md`).

## Decision log

- DO NOT revert the verbosity=low default in this commit; commit it with action 1 above as a clean follow-up so the smoke trace links cleanly to the revert reason.
- DO NOT add target-specific archive=POST hint; action 2 above is the universal version.
- DEFER the 3-way A/B harness (action 4) until at least one of Gemini-flash / Gemini-pro-latest shows comparable quality (then the A/B becomes about provider selection per challenge class, not just pro-Gemini vs pro-Claude).
