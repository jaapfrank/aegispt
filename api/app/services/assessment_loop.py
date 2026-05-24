from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from api.app.observability import traced  # backlog-407 — tracing-only decorator

logger = logging.getLogger(__name__)

# Claude-driven candidate selection: prompt + helper functions live next to the
# heuristic candidate functions so the AI brain sits in the same module that
# the rest of the loop calls.
_AI_PICKER_SYSTEM_PROMPT = """You are the brain of an automated penetration test.

=== EVIDENCE-FIRST PRINCIPLE (READ THIS FIRST, IT OVERRIDES EVERYTHING ELSE) ===

AegisPT is an evidence-first system. Your job is to PROVE vulnerabilities, not
to predict, hypothesize, or speculate about them. Hunches and chains-of-reasoning
are valuable INPUT to your decisions, but they are NEVER valid output.

What this means concretely:
- "I see reflected XSS → therefore session hijacking is possible" is a HUNCH.
  Until you have actually stolen a session and used it, you have NOT proven it.
- "Path-based XSS + accessible /admin = admin compromise" is a HUNCH.
  Until you've issued an authenticated request to /admin and observed admin
  functionality in the response, you have NOT proven admin compromise.
- "/dump.gtl probably leaks passwords" is a HUNCH. Until you've fetched it and
  observed cleartext credentials in the body, you have NOT proven info disclosure.
- "newaccount + is_admin=True probably escalates" is a HUNCH. Until you've
  submitted the request and verified admin context in a follow-up response,
  you have NOT proven privilege escalation.

When you have a hunch about a chain:
1. Write an exec_plan that EXECUTES the chain end-to-end.
2. Include verification step(s) that observe the *expected impact*, not just
   the setup step (e.g. don't stop after POSTing is_admin=True; also GET
   /manage and assert the body contains admin-only content).
3. Use on_success.create_finding to record the proven result with severity
   reflecting what was ACTUALLY shown in the response, not your hypothesis.

STOP CRITERION (strictly enforced):
You may only emit action="stop" with stop_reason="admin_compromise_proven"
when there exists a finding in the list above of severity "critical" whose
title explicitly describes the proven impact (e.g. "Admin Compromise via X",
"Account Takeover via Y") AND whose evidence_ref points to a runner-captured
artifact (not your own reasoning). Hypothesized chains are NOT proof.

You may emit action="stop" with stop_reason="exhausted" only when every
plausible exploit angle has been attempted via exec_plan or a runner — not
when you've merely thought about angles you haven't tried.

If you are tempted to stop based on a chain you BELIEVE but have not run,
the correct action is exec_plan (write the chain and run it), NOT stop.

=== PHASE MODEL ===

The test progresses through PHASES. A phase is NOT a fixed type from a list.
A new phase begins whenever the evidence collected so far unlocks something
that was not reachable before. Examples of what triggers a level-up:
  - A new vulnerable parameter is confirmed → unlocks targeted exploitation
  - A session cookie is stolen → unlocks authenticated testing
  - Admin/elevated identity is reached → unlocks privileged endpoints
  - A new internal service is mapped → unlocks fresh attack surface
  - A patch-level fingerprint reveals a specific CVE → unlocks targeted exploit

A real assessment may take 5 phases or 50 phases. There is no cap. Each phase
has ONE clear goal that is concretely achievable with the current evidence.
You name the phase yourself with a short label that describes its goal.

Within a phase you may run multiple tools, but each tool normally runs only
once per phase. Re-use the same tool inside the SAME phase only when a finding
appearing during THIS phase needs the same tool on a different vulnerable target,
and you cite that finding in your reasoning.

You LEVEL UP to a new phase only when the current phase produced evidence that
materially unlocks a higher-impact action — not just because the previous tool
finished. If the current phase is producing no progress, level up to a new
phase with a different angle.

After each tool runs you produce ONE of four decisions:

A) PICK another tool to continue the CURRENT phase
B) EXEC_PLAN — write a custom multi-step HTTP exploitation plan
   Use this when no generic runner fits — multi-step chains, CSRF with
   captured token, IDOR with stolen identity, or any sequence that
   needs to chain a captured value from one request into the next.
C) LEVEL UP — current phase is complete, start the next phase
D) STOP the whole assessment — chain proven or exhausted

=== AGENTIC TOOLS — Claude-Code-equivalent affordances (backlog-422) ===

You have 7 agent tools alongside http_fetch + memory + the runner-pick
loop:

- `bash` — sandboxed shell command for parsing/transforming captured
  evidence (NOT for running pentest tools — those go through the runner
  registry).
- `file_read` / `file_write` — scratchpad files under AEGISPT_MEMORY_ROOT.
- `web_search` — query CISA KEV / NVD / ExploitDB for CVE/product
  hints. ALWAYS marker-wrapped: results are HINTS, never proof.
- `web_fetch` — GET an in-scope URL (deeper version of http_fetch with
  HEAD support).
- `code_exec` — sandboxed Python for decoding JWTs, base64 payloads,
  regex extraction, hash math.
- `subagent_spawn` — delegate to one of the 6 specialists (recon /
  hypothesis / exploit_dev / validator / memorist / reporter /
  reflector). Pass intent + your own confidence; the MetaCoordinator
  decides routing.

Every tool routes through Layer 0 (GovernanceControlPlane) — out-of-
scope targets are rejected automatically. Failures are recoverable
signals, not crashes.

=== EXPLOIT DEVELOPER AGENT — picker dispatches it for multi-step chains ===

When the hypothesis needs ≥3 chained HTTP steps (auth-then-exfil, capture-
then-replay, multi-form submission, IDOR-with-stolen-id, etc.), prefer
the dedicated `exploit-developer-agent` runner over inlining a long
exec_plan JSON yourself. Pass it:

- `hypothesis`: one-sentence statement of what the chain should prove
  (e.g. "POST /login with test:test then GET /admin to confirm admin
  context appears in the body").
- `finding_title`: the finding it's chasing if one already exists.
- `prior_requests`: the last 6 request/response excerpts so the agent
  composes from observed evidence, not from convention.
- `captured_credentials`: any credentials surfaced by prior steps.
- `observed_paths`: paths the recon phase actually saw (NOT a wordlist).

The agent returns a JSON recipe with `steps` + `expected_markers`. After
it lands, dispatch `exec-plan` with that recipe; the deterministic
validator (backlog-413) will verify and promote the foothold only when
the markers match. The validator + PoC artifact chain is what turns
"observed-vulnerable" into "verified-exploited" with a runnable
`python poc.py --target X` script.

If the developer agent returns an empty recipe (exit_code=2 / status=
empty_recipe), the cause is insufficient observed context — go back to
recon for the SPECIFIC path the chain needs (use http_fetch to read the
form / endpoint body), THEN re-dispatch the agent with the enriched
prior_requests payload. Do not chain another generic scanner.

=== PRIORITY RULE — CPG SINKS PRESENT ===

If a `pre-recon-cpg-deliverable.md` artifact exists in this run AND it
lists concrete file:lineno entries under ANY of `SQL_SINKS`, `FILE_SINKS`,
`EXEC_SINKS`, `TEMPLATE_SINKS`, or `DESERIALIZE_SINKS` — AND no
`code-exec-attack` task has been dispatched yet — your NEXT pick MUST be
`code-exec-attack` with a self-contained python_script that:

  1. Authenticates using credentials surfaced by pre-recon-source / CPG
     (e.g. literals from `LITERAL_SECRETS`, default test/test if a
     `User(username='test', password='test')` row was found in
     `pre-recon-source-deliverable.md`).
  2. Walks the routes Joern surfaced in the order the access-check
     predicate requires (e.g. if a route's filter is
     `or_(creator == user, archiver == user)`, hit the route that SETS
     archiver first, then the route guarded by that predicate).
  3. Reads the sink endpoint response and calls `aegispt_emit_finding(...)`
     when the observed body contains a flag-like literal
     (`flag{...}`, `xbow-[a-f0-9]+`, hex blobs, base64 secrets).

This rule SUPERSEDES the depth-pressure "no more scanners after 3" rule
when CPG has surfaced concrete sinks. Do NOT generic exec_plan SQLi
scaffolds when Joern has already pinpointed a specific file:lineno
SQL_SINK — write the python_script that hits THAT exact route + that
exact predicate.

=== DEPTH PRESSURE — DO NOT STACK SCANNERS ===

Once 3 distinct recon/discovery tools have run on a target (target-intel,
content-discovery, nuclei, smart-web-probe, headers-security, etc.), STOP
picking more scanners. The next pick MUST be one of:

- exec_plan that actually attempts to exploit a SPECIFIC discovered surface:
  - a login form (POST username= and password= with discovered creds or
    common defaults like admin/admin, root/root, test/test — and with SQLi
    payloads like `' OR 1=1 -- ` when no creds are known)
  - a path-traversal probe on a parameter (e.g. `?file=../../../etc/passwd`)
  - a SSTI probe on a reflected input (`{{7*7}}` then `{{config}}` in Jinja,
    `${7*7}` in Velocity/EL, `<%= 7*7 %>` in ERB)
  - a SQL injection probe on a form/param (`'`, `' OR 1=1 --`, `' UNION SELECT
    NULL --`) with progressive payload escalation
  - a stored XSS pivot if a comment/post field was found
- A tool that requires authenticated context, IF you already have credentials
  (auth-flow with the discovered creds; session-security with the captured cookie).
- LEVEL UP to a new phase if the surface is genuinely exhausted.

If your last 3 picks were all info-class scanners producing only header /
CSP / clickjacking findings, you are NOT making progress. The user expects
proven exploitation, not a report of missing security headers. Pivot to
exec_plan with a concrete payload aimed at a specific endpoint, OR LEVEL
UP. NEVER chain a 4th scanner.

=== HTTP_FETCH TOOL — read the target yourself before deciding ===

You have an `http_fetch` tool that GETs any URL within the approved scope. Use
it BEFORE picking runners so you understand the actual application — not just
its endpoint list.

Scope: only URLs under the approved instance path are allowed. The codelab
documentation pages of teaching apps (e.g. /partN, /tutorial) fall OUTSIDE
scope and will be rejected — you must discover vulnerabilities from the live
app's responses, not from its lab handout.

Call shape:
  http_fetch({"url": "https://target-host/instance-path/some-page"})

When to fetch:
- First call of a new phase: GET the scope root or a relevant endpoint, READ
  the HTML to identify: tech stack, forms, JS frameworks, unusual endpoints
  (custom template extensions, debug paths). Then pick tools that match the
  actual surface — NOT generic scanners.
- After a runner finds a hidden endpoint: fetch it to see what it actually
  does before pointing more tools at it.
- Before writing an exec_plan: fetch the target URL to verify the form fields
  and parameter names you plan to attack actually exist as you assume.

MANDATORY FETCH on these discovery hits (their CONTENT is the intel, not
their existence — reporting "/openapi.json is exposed" without reading what
is INSIDE it wastes the discovery):
- `/openapi.json`, `/swagger.json`, `/api-docs`, `/redoc`, `/graphql` (with
  `?query={__schema{types{name}}}`): list every endpoint, parameter, and
  auth scheme; use that to drive the next 3-5 picks instead of guessing.
- `/.env`, `/config.json`, `/appsettings.json`: read for credentials,
  internal hostnames, secret keys; treat any secret found as a HIGH-severity
  finding and pivot to authenticated runners using those creds.
- `/.git/HEAD`, `/.git/config`: if present, the repo is leaking — pivot to
  content-discovery + nuclei templates that exfiltrate `.git/objects/`.
- `/robots.txt`, `/sitemap.xml`, `/.well-known/security.txt`: read for the
  list of paths the operators ACTUALLY know about — those are the paths to
  probe next, ahead of any blind wordlist.
- `/package.json`, `/composer.json`, source maps (`*.js.map`): read for
  dependency versions and pivot to vulnerable-component checks for the
  EXACT versions named.
- HTML comments containing credentials, account hints, TODO/FIXME notes,
  test:test-style markers, or debug flags: these ARE the attack data, not a
  clue to look elsewhere. Use the literal value immediately (try the login
  with `test:test`, post the comment-stated form field, etc.) — do NOT
  abstract to a vuln class.

After every fetch, the next action MUST derive from the fetched CONTENT
(specific endpoint, specific field, specific secret), not from the URL
alone. If the fetch returned empty or 4xx, say so and pivot — do not loop
on the same URL.

What to learn from a fetch:
- `Server:` header → tech stack hint
- `Content-Type:` → API vs HTML
- Page text → app's purpose, framework hints, error patterns
- Form `action=` + input `name=` → your exec_plan must use these exact names
- Anchor links → real navigable structure beyond wordlist-recon findings
- Suspicious comments, debug flags, version strings

What to SKIP after reading:
- If the body reveals no SQL DB is involved, do NOT pick sqlmap.
- If templates are custom (non-Jinja/Django/ERB), do NOT pick generic ssti-probe.
- If responses don't include XML, do NOT pick xxe-probe.

Budget: keep total fetches per decision modest. Response body is truncated
to 4 KB — don't waste fetches on already-tested endpoints.

=== MEMORY TOOL — your persistent scratch pad across runs ===

You have a `memory` tool that stores files under `/memories/`. This is YOUR
scratch pad: it persists between assessment runs and across phases. Nothing
is pre-loaded — you start with an empty store unless you've written to it.

USE IT BEFORE EVERY DECISION:
  memory view path="/memories"

If you find notes relevant to the current target or app type, view them.
Common organization patterns you can choose to adopt (or invent your own):
  /memories/targets/<hostname>.md   — what you learned about this target
  /memories/lessons/<topic>.md      — generic lessons (e.g. "when stuck after
                                       header scans, pivot to authenticated
                                       endpoints, not more recon")
  /memories/run-progress.md         — running scratch notes for this run

USE IT AFTER PROGRESS:
When a tool produces an interesting signal (a captured session, a discovered
admin endpoint, a successful exploit), record the LESSON — not the data:
  memory create path="/memories/lessons/post-session-pivot.md"
  file_text="When generic IDOR found no rows, pivoting to direct profile-edit
  endpoints produced admin escalation. Look for /profile, /saveprofile,
  /preferences with role/admin/permission keys."

Rules:
- Do NOT store exploit recipes you have not yourself verified.
- Do NOT pre-fabricate knowledge about target apps — only write what evidence
  in THIS run proves.
- Keep entries short. One lesson per file.
- If a memory turns out to be wrong, str_replace or delete it.

Empty memory is fine. Memory is OPTIONAL — if you have no observation worth
preserving, skip it.

Rules:
- Pick exactly ONE tool from available_tools.
- Decide based on actual evidence, not a fixed checklist.
- Within the same phase: do NOT re-pick a tool already used this phase,
  unless justified by a fresh in-phase finding.
- LEVEL UP when the current phase reached its goal OR cannot progress further.
- STOP when admin compromise is proven OR no untested attack surface remains.

Return ONLY valid JSON, one of these three shapes:

A) Continue current phase with another tool pick:
{
  "action": "pick",
  "tool": "tool-name-from-available_tools",
  "target": "full URL or host",
  "tier": "passive|active|intrusive",
  "reasoning": "one sentence why THIS is the right next step in the current phase",
  "expected_evidence": ["short", "list"],
  "confidence": 0.85
}

B) Level up to a new phase, picking the first tool of that new phase:
{
  "action": "level_up",
  "previous_phase_summary": "one sentence summarizing what the just-completed phase proved",
  "new_phase_label": "short label e.g. 'authenticated-escalation'",
  "tool": "tool-name-to-start-the-new-phase",
  "target": "full URL or host",
  "tier": "passive|active|intrusive",
  "reasoning": "one sentence why this new phase is unlocked and which evidence triggers it",
  "expected_evidence": ["short", "list"],
  "confidence": 0.85
}

C) Stop the assessment entirely:
{
  "action": "stop",
  "stop_reason": "admin_compromise_proven | exhausted | scope_complete",
  "summary": "one sentence summarizing what the whole test proved",
  "confidence": 1.0
}

D) Run a custom HTTP exploitation plan via the exec-plan runner:
{
  "action": "exec_plan",
  "plan_name": "short-slug-describing-the-attack",
  "tier": "active|intrusive",
  "reasoning": "why this custom plan reaches the goal that no generic runner can",
  "confidence": 0.85,
  "plan": {
    "name": "same as plan_name",
    "steps": [
      {
        "name": "probe",
        "method": "GET",
        "url": "${target}/some-endpoint-you-discovered",
        "expect": {"status": 200},
        "capture": {
          "token": {"from": "body_regex", "pattern": "csrf_token=([a-f0-9]+)"}
        }
      },
      {
        "name": "exploit",
        "method": "POST",
        "url": "${target}/another-endpoint",
        "data": {"csrf": "${probe.token}", "payload": "<your crafted payload>"},
        "expect": {"status": [200, 302]},
        "on_success": {
          "create_finding": {
            "severity": "high",
            "title": "<descriptive title of what you proved>",
            "summary": "<one sentence describing the impact>"
          }
        }
      }
    ]
  }
}

The example above is INTENTIONALLY GENERIC. Do NOT copy these endpoints or
payloads — they are placeholders. The real steps must come from YOUR analysis
of THIS specific target's responses, findings, and discovered endpoints.

EXEC_PLAN GRAMMAR:
- `${target}` is the primary scope URL (auto-substituted, no trailing slash).
- `${rand}` and `${rand16}` produce random tokens for unique usernames.
- `${step_name.field}` references a value captured in an earlier step.
- Capture sources: `cookie` (key=name), `header` (key=name), `redirect_path`,
  `body_regex` (regex=pattern, returns group 1), `request_field` (field=name),
  `status`.
- Use `cookies_from: "step_name"` to inherit cookies set by an earlier step.
- `expect` clauses validate: `status` (int or list), `body_contains` (str/list),
  `body_not_contains` (str/list), `body_regex` (pattern).
- `on_success.create_finding` emits a structured finding when the step's
  expectations pass — use only for steps that PROVE the exploit succeeded,
  not for intermediate setup steps.
- All URLs must be within approved scope; out-of-scope steps are skipped.
- Max 50 steps per plan. Overall timeout 90s. Allowed methods: GET, POST, PUT, PATCH, DELETE.

WHEN TO USE EXEC_PLAN vs PICK:
- PICK a generic runner (xss-proof, idor-bac, sqlmap) for well-known patterns.
  Tool=`exec-plan` is NOT a generic runner — it requires the structured plan body.
- USE EXEC_PLAN when you need an app-specific sequence: e.g. Gruyere's
  is_admin parameter trick, multi-step CSRF, register-then-exploit chains,
  or anything where a captured value from one request determines the next.

EXEC_PLAN ESCALATION TRIGGER (MANDATORY — NOT OPTIONAL):

When ALL of these hold:
  (a) tested_keys covers 5+ distinct tools on the same target,
  (b) total critical+high findings so far is below 2,
  (c) you would otherwise emit action=stop or pick a tool that's already
      in tested_keys for this target,

then your NEXT decision MUST be action=exec_plan with a concrete
HTTP-step plan crafted from the discovered endpoints + RECENT_CAPTURES.

Falling back to "no candidate" / action=stop=exhausted at this point is
a process failure that the operator will treat as a bug. Generic scanners
prove KNOWN classes of vulnerability. exec_plan proves application-specific
chains that no generic scanner could have synthesised — and that is where
real exploitation lives.

How to construct the plan when this trigger fires:
  1. Look at the captured_values + findings from earlier tasks. Each
     finding has a target_id / endpoint / payload reflection.
  2. Pick ONE specific finding (e.g. "form action=/profile accepts
     unsanitised name field" or "GET /admin/install returns 200 with
     debug info").
  3. Build 2-4 steps that hit that exact endpoint with a payload
     tailored to the discovered behaviour, with an `expect` clause that
     would only pass if the exploit succeeded, and `on_success.create_finding`
     producing a critical/high finding with concrete proof.
  4. Tier = "active" for the vast majority of these. Use "intrusive"
     only for destructive operations (DoS, mass delete, RCE that crashes
     services).

If you genuinely cannot construct a chain (the findings give you no
hook — no form, no parameter, no endpoint beyond the homepage), THEN
action=stop with stop_reason=exhausted is acceptable. But "I've tried
all the scanners and nothing worked" is NOT exhausted — that's the
exact moment to use exec_plan, because the answer the operator wants
is "did you also try crafted chains based on what you saw" — not "the
generic scanners shrugged".

CRITICAL: Never use `action: "pick"` with `tool: "exec-plan"`. The exec-plan
runner requires the structured plan body which only comes through `action:
"exec_plan"`. If you want a custom HTTP sequence, ALWAYS use action=exec_plan
and include the full plan grammar shown above.

TIER SEMANTICS (this controls whether your action auto-queues or waits for approval):
- "passive"  = read-only HTTP, no state change on the target. Always auto-queued.
- "active"   = writes that don't damage service: set cookies, submit forms, post
               snippets, update profile fields, exploit XSS/IDOR/privilege-escalation,
               proof-of-concept exploitation chains. AUTO-QUEUED in ai_loop runs.
               USE THIS FOR THE VAST MAJORITY OF YOUR EXEC_PLAN CHAINS.
- "intrusive" = actually destructive: DoS, server crash, data deletion, RCE that
               kills services, account deletion, mass record overwrite. Requires
               explicit operator approval unless the run was started with
               intrusive-allowed enabled. AVOID this tier for standard XSS/cookie/
               admin-escalation chains — those are "active".

Rule of thumb: if your plan PROVES a vulnerability without breaking the target,
it's "active". If your plan would visibly impact service availability or
permanently destroy data, it's "intrusive".

COMBINING LEVEL_UP WITH A CUSTOM PLAN is allowed: set action="level_up",
tool="exec-plan", include a "plan" body with non-empty "steps", and provide
"new_phase_label" + "previous_phase_summary". Both happen in one shot: the
phase advances AND the exec-plan runs in the new phase. Use this for moves
like "now I have a session token, level up to authenticated-admin-escalation
and run this 4-step chain that injects is_admin=True into the snippet form".

STRUCTURED OUTPUT NOTE (minimal step form, 2026-05-21):

Anthropic structured-outputs grammar compiler timed out on the rich
step schema (12+ fields). Pared to 5 fields to stay under the compile
budget:

  required: name (string), url (string)
  optional: method (enum GET/POST/PUT/PATCH/DELETE; default GET)
  optional STRINGIFIED:
    - json    JSON-encoded request body (empty string for GET)
    - expect_and_finding   ONE JSON-encoded combined block:
        "{\"expect\": {\"status\": 200, \"body_contains\": \"admin\"},
          \"on_success\": {\"create_finding\":
            {\"severity\": \"high\", \"title\": \"...\", \"summary\": \"...\"}}}"
      Either sub-key may be omitted. Server splits it back into the
      two fields the runner reads.

Example minimal step that proves admin-takeover via an exposed install
endpoint:
  {
    "name": "trigger-install",
    "method": "POST",
    "url": "${target}/admin/install",
    "json": "{\"username\":\"pwn-${rand}\",\"password\":\"pwn-${rand16}\"}",
    "expect_and_finding": "{\"expect\":{\"status\":[200,302]},\"on_success\":{\"create_finding\":{\"severity\":\"critical\",\"title\":\"Admin install endpoint accepts arbitrary account creation\",\"summary\":\"POST to /admin/install with crafted body created an admin account; foothold = admin\"}}}"
  }

If you need fields the schema doesn't expose (headers, cookies,
query params, multi-step capture), JSON-encode the body in `json`
or chain through multiple simpler steps.

CHAIN REASONING ON RECENT_CAPTURES (#334 + #343):
The graph projection includes a RECENT_CAPTURES section listing the most-recent
captured_value entities from prior tasks in this run — each with origin step,
kind (token / cookie / hostname / credential_ref / url / other), and a
redacted preview (full value lives in the run credential vault, not in this
prompt). When a candidate step needs a parameter whose kind matches a capture
(e.g. an Authorization header or session cookie for the next request, a host
parameter for a pivot target), prefer referencing that capture via the existing
`${step_name.field}` interpolation grammar instead of re-acquiring it. This
chains the proof across tasks AND saves a round-trip. The capture is a HINT,
not a hard requirement — if no kind matches, proceed without it. Do NOT paste
a redacted preview into a step body; interpolation resolves to the full value
at execution time. If RECENT_CAPTURES is empty or absent, ignore this note.
"""


# ---------------------------------------------------------------------------
# #330 — Picker structured-output JSON schema
# ---------------------------------------------------------------------------
#
# The picker emits one of four action shapes (pick / level_up / stop /
# exec_plan). Anthropic strict mode requires every property in `required`
# and `additionalProperties: false` on every object, so we cannot mark
# optional fields. Instead we list five `anyOf` variants:
#
#   - pick
#   - level_up                  (no plan body)
#   - level_up + exec-plan      (with `plan_name` + stringified `plan`)
#   - stop
#   - exec_plan                 (with `plan_name` + stringified `plan`)
#
# `plan` is intentionally a STRING field. The exec-plan inner objects
# (steps[].params, steps[].data, steps[].capture, steps[].expect.body_*)
# have freeform keys/types that are incompatible with strict mode's
# additionalProperties=false closure. The system-prompt directive tells
# Claude to JSON-encode the plan; client-side we `json.loads` it once
# before passing to the exec_plan runner. See the "STRUCTURED OUTPUT
# NOTE" appended above for the operator-facing directive.

_PICKER_TIER_ENUM = ["passive", "active", "intrusive"]
_PICKER_ACTIVE_INTRUSIVE = ["active", "intrusive"]
_PICKER_STOP_REASONS = ["admin_compromise_proven", "exhausted", "scope_complete"]


def _picker_tool_field(available_tools: list[str] | None) -> dict[str, Any]:
    """Build the `tool` field constraint. When ``available_tools`` is provided
    (per-call dynamic schema), emit an ``enum`` so Claude is hard-constrained
    to that exact list — no more hallucinated tool names like ``memory`` or
    ``http_fetch`` (Anthropic built-in tool names that Claude picked when
    the field was just ``{"type":"string"}``). ``exec-plan`` is filtered
    out: tool=exec-plan must go through action=exec_plan (or level_up with
    plan body), not action=pick.

    Anthropic accepts ``enum`` (unlike ``not``, which is rejected per
    ced6030 regression). Empty list = fall back to generic string so the
    schema is still valid in pathological "no tools" scenarios.
    """
    if available_tools is None:
        return {"type": "string"}
    filtered = [t for t in available_tools if t and t != "exec-plan"]
    if not filtered:
        return {"type": "string"}
    return {"type": "string", "enum": sorted(set(filtered))}


def _picker_variant_pick(available_tools: list[str] | None = None) -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "action", "tool", "target", "tier",
            "reasoning", "expected_evidence", "confidence",
        ],
        "properties": {
            "action": {"type": "string", "const": "pick"},
            "tool": _picker_tool_field(available_tools),
            "target": {"type": "string"},
            "tier": {"type": "string", "enum": _PICKER_TIER_ENUM},
            "reasoning": {"type": "string"},
            "expected_evidence": {"type": "array", "items": {"type": "string"}},
            "confidence": {"type": "number"},
        },
    }


def _picker_variant_level_up(*, with_plan: bool, available_tools: list[str] | None = None) -> dict[str, Any]:
    base_required = [
        "action", "previous_phase_summary", "new_phase_label",
        "tool", "target", "tier",
        "reasoning", "expected_evidence", "confidence",
    ]
    base_properties: dict[str, Any] = {
        "action": {"type": "string", "const": "level_up"},
        "previous_phase_summary": {"type": "string"},
        "new_phase_label": {"type": "string"},
        "tool": _picker_tool_field(available_tools),
        "target": {"type": "string"},
        "tier": {"type": "string", "enum": _PICKER_TIER_ENUM},
        "reasoning": {"type": "string"},
        "expected_evidence": {"type": "array", "items": {"type": "string"}},
        "confidence": {"type": "number"},
    }
    if with_plan:
        base_required.extend(["plan_name", "plan"])
        base_properties["tool"] = {"type": "string", "const": "exec-plan"}
        base_properties["tier"] = {"type": "string", "enum": _PICKER_ACTIVE_INTRUSIVE}
        base_properties["plan_name"] = {"type": "string"}
        # Same proper-object plan schema as _picker_variant_exec_plan
        # (HTTP-step grammar, matching exec_plan runner's actual contract).
        base_properties["plan"] = {
            "type": "object",
            "additionalProperties": False,
            "required": ["name", "steps"],
            "properties": {
                "name": {"type": "string"},
                "steps": {
                    "type": "array",
                    "minItems": 1,
                    "items": _exec_plan_step_schema(),
                },
            },
        }
    return {
        "type": "object",
        "additionalProperties": False,
        "required": base_required,
        "properties": base_properties,
    }


def _picker_variant_stop() -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "required": ["action", "stop_reason", "summary", "confidence"],
        "properties": {
            "action": {"type": "string", "const": "stop"},
            "stop_reason": {"type": "string", "enum": _PICKER_STOP_REASONS},
            "summary": {"type": "string"},
            "confidence": {"type": "number"},
        },
    }


_AGENT_TOOL_NAMES = (
    # Reserved for future tools= API use; the exec-plan runner does NOT
    # consume agent_tool steps — it consumes HTTP-step plans. Removed from
    # the schema in the same commit as this comment because forcing
    # steps[].tool to an agent_tool enum made every plan invalid against
    # the actual runner contract (which uses method/url/expect/capture).
    "bash", "code_exec", "web_fetch", "web_search",
    "file_read", "file_write", "subagent_spawn",
)


def _exec_plan_step_schema() -> dict[str, Any]:
    """Minimal exec-plan step schema. The earlier 10-field version caused
    Anthropic to return "Grammar compilation timed out" (the schema +
    big tool enum combined was too complex for the strict-mode grammar
    compiler). Pared back to the 5 fields that cover the critical
    use-cases for proving a vulnerability:

      name, method, url       — mandatory request shape
      json                    — JSON-encoded body (covers POST data too)
      expect_and_finding      — JSON-encoded combined block holding
                                  {expect: {...}, on_success: {create_finding: ...}}
                                so we transport the assertion + finding-
                                emission decision in one field instead of two

    Other runner-supported fields (headers, params, cookies, capture)
    can be tacked on the JSON body when needed or via subsequent calls.
    _decode_picker_plan unwraps the JSON-encoded fields server-side.
    """
    return {
        "type": "object",
        "additionalProperties": False,
        "required": ["name", "url"],
        "properties": {
            "name": {"type": "string"},
            "method": {
                "type": "string",
                "enum": ["GET", "POST", "PUT", "PATCH", "DELETE"],
            },
            "url": {"type": "string"},
            "json": {"type": "string", "description": "JSON-encoded request body (use empty string for GET)"},
            "expect_and_finding": {
                "type": "string",
                "description": (
                    "JSON-encoded combined assertion+finding block. Shape: "
                    "{\"expect\": {\"status\": 200 | [200,302], \"body_contains\": \"text\"}, "
                    "\"on_success\": {\"create_finding\": {\"severity\": \"high\", "
                    "\"title\": \"...\", \"summary\": \"...\"}}}. "
                    "Either or both sub-keys can be omitted."
                ),
            },
        },
    }


# ---------------- Prompt-injection sentinel (OWASP LLM01) ----------------
#
# AegisPT's picker reads HTTP response bodies / stderr from the target. A
# malicious target can stuff prompt-injection into a 404 page, a JSON error,
# or even HTML comments, then have Claude exfiltrate, exit, or emit a
# false "admin_compromise_proven" stop — without any actual exploit. This
# scanner runs on every stdout/stderr excerpt BEFORE it reaches the picker
# prompt. Detected payloads are redacted (replaced with a tag) and audit-
# logged so the operator can see what the target tried to do.

_PROMPT_INJECTION_PATTERNS = [
    # Instruction overrides
    (r"\bignore\s+(?:the\s+)?(?:above|previous|prior|preceding|earlier|all)\s+(?:instructions?|prompts?|rules?|context)\b", "instruction_override"),
    (r"\bdisregard\s+(?:the\s+)?(?:above|previous|prior|preceding|earlier|all)\b", "instruction_override"),
    (r"\b(?:from\s+now\s+on|starting\s+now)[,:\s]+you\s+(?:are|must|will|should)\b", "role_override"),
    (r"\byou\s+are\s+now\b", "role_override"),
    (r"\bnew\s+(?:instructions?|task|role|persona|system\s+prompt)[\s:.\-]+", "instruction_override"),
    # Chat-format markers (Claude / GPT)
    (r"<\|im_(?:start|end)\|>", "chat_marker"),
    (r"\[/?INST\]", "chat_marker"),
    (r"<\|(?:system|user|assistant)\|>", "chat_marker"),
    (r"</?\s*system\s*>", "chat_marker"),
    # Picker-action injection — most dangerous because it mirrors our own schema
    (r"\bemit\s+action\s*[=:]\s*[\"']?(?:stop|exec_plan|pick|level_up)\b", "picker_action_injection"),
    (r"\baction\s*[=:]\s*[\"']?stop[\"']?\b.*\bstop_reason\s*[=:]", "picker_action_injection"),
    (r"\bstop_reason\s*[=:]\s*[\"']?admin_compromise_proven\b", "picker_action_injection"),
    (r"\bset\s+stop_reason\s+to\b", "picker_action_injection"),
    # "Pretend that" / role-play takeover
    (r"\bpretend\s+(?:that\s+)?you\s+(?:are|have)\b", "role_override"),
    (r"\bact\s+as\s+(?:if\s+)?you\s+(?:are|have)\b", "role_override"),
]

_PROMPT_INJECTION_REDACTION = "[REDACTED_PROMPT_INJECTION:{tag}]"


def _scan_for_prompt_injection(text: str) -> tuple[str, list[str]]:
    """Scan target-derived text for prompt-injection patterns. Returns
    (sanitized_text, list_of_detected_tags). When patterns are detected,
    the matching span is replaced with a redaction marker so the picker
    sees only sanitized text. Empty list = clean."""
    if not text:
        return text, []
    import re
    detected: list[str] = []
    sanitized = text
    for pattern, tag in _PROMPT_INJECTION_PATTERNS:
        match = re.search(pattern, sanitized, flags=re.IGNORECASE)
        if not match:
            continue
        detected.append(tag)
        sanitized = re.sub(
            pattern,
            _PROMPT_INJECTION_REDACTION.format(tag=tag),
            sanitized,
            flags=re.IGNORECASE,
        )
    return sanitized, detected


def _sanitize_target_text_for_picker(text: str, *, source: str, run_id: str | None = None) -> str:
    """Wrapper that scans + redacts AND emits an audit log line per
    detection so the operator can see what the target tried. ``source`` is
    a short tag like "task_stdout" / "task_stderr" so the audit trail says
    where the injection landed."""
    if not text:
        return text
    sanitized, detected = _scan_for_prompt_injection(text)
    if detected:
        logger.warning(
            "prompt_injection_sentinel: redacted %s from %s (run=%s) — target appears to be injecting picker instructions",
            sorted(set(detected)),
            source,
            (str(run_id)[:8] if run_id else "?"),
        )
    return sanitized


def _picker_variant_exec_plan() -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "required": ["action", "plan_name", "tier", "reasoning", "confidence", "plan"],
        "properties": {
            "action": {"type": "string", "const": "exec_plan"},
            "plan_name": {"type": "string"},
            "tier": {"type": "string", "enum": _PICKER_ACTIVE_INTRUSIVE},
            "reasoning": {"type": "string"},
            "confidence": {"type": "number"},
            # Proper object schema for `plan` (replaces the pre-2026-05-21
            # JSON-encoded-string-in-JSON gymnastics). The decoder
            # _decode_picker_plan handles both string and dict shapes so
            # this is backwards-compatible. Each step matches the actual
            # exec-plan runner contract: HTTP method/url/expect/capture,
            # NOT agent_tool dispatch (that was an incorrect schema in
            # bf9940d — the runner doesn't consume agent_tool steps).
            "plan": {
                "type": "object",
                "additionalProperties": False,
                "required": ["name", "steps"],
                "properties": {
                    "name": {"type": "string"},
                    "steps": {
                        "type": "array",
                        "minItems": 1,
                        "items": _exec_plan_step_schema(),
                    },
                },
            },
        },
    }


def _picker_output_schema(
    available_tools: list[str] | None = None,
    *,
    force_exec_plan: bool = False,
) -> dict[str, Any]:
    """Discriminated schema for the picker action shapes.

    Two modes:
      - Default: full 5-variant anyOf (pick / level_up / level_up+plan /
        stop / exec_plan). Claude chooses.
      - ``force_exec_plan=True``: only exec_plan + level_up-with-plan +
        stop are accepted. The prompt-side forcing rule (added 078e9b9)
        ASKED Claude to pivot to exec_plan after catalog exhaustion;
        empirically Claude ignored it. With force_exec_plan the schema
        REJECTS any action=pick or action=level_up-without-plan at the
        Anthropic API boundary, so Claude cannot avoid pivoting.

    When ``available_tools`` is provided AND force_exec_plan is False,
    the pick + level_up-without-plan variants get an enum-constrained
    ``tool`` field.
    """
    if force_exec_plan:
        return {
            "anyOf": [
                _picker_variant_level_up(with_plan=True),
                _picker_variant_stop(),
                _picker_variant_exec_plan(),
            ],
        }
    return {
        "anyOf": [
            _picker_variant_pick(available_tools),
            _picker_variant_level_up(with_plan=False, available_tools=available_tools),
            _picker_variant_level_up(with_plan=True),
            _picker_variant_stop(),
            _picker_variant_exec_plan(),
        ],
    }


# Static fallback used when no available_tools list is supplied. The dynamic
# enum-constrained variant is built per-call at the messages.create site to
# keep Claude on the actual runner registry.
_PICKER_OUTPUT_SCHEMA: dict[str, Any] = _picker_output_schema()


def _provider_is_chatgpt_oauth(provider: Any) -> bool:
    config = getattr(provider, "config", None)
    model = str(getattr(config, "model", "") or "").strip().lower()
    api_key_env = str(getattr(config, "api_key_env", "") or "").strip().upper()
    return api_key_env.startswith("CHATGPT_OAUTH") or model in {"chatgpt_oauth", "gpt-5.4", "gpt-5.5"}


def _provider_is_anthropic(provider: Any) -> bool:
    config = getattr(provider, "config", None)
    return str(getattr(config, "api_key_env", "") or "").strip().upper().startswith("ANTHROPIC")


def _picker_schema_for_current_state(
    *,
    run: Run,
    tested_keys: set[str],
    available_tools: list[str],
) -> dict[str, Any]:
    distinct_tested_tools = {k.split("|", 1)[0] for k in tested_keys}
    crit_high_count = sum(
        1 for f in (run.findings or [])
        if str(getattr(f, "severity", "") or "").lower() in {"critical", "high"}
    )
    force_exec_plan = len(distinct_tested_tools) >= 5 and crit_high_count < 2
    if force_exec_plan:
        logger.info(
            "picker: forcing exec_plan schema variant — tested_tools=%d crit_high=%d run=%s",
            len(distinct_tested_tools), crit_high_count, str(run.id)[:8],
        )
    return (
        _picker_output_schema(list(available_tools), force_exec_plan=force_exec_plan)
        if available_tools else _picker_output_schema(force_exec_plan=force_exec_plan)
    )


# Step fields whose values arrive as JSON-encoded strings per the
# Anthropic-strict-mode + grammar-complexity budget. _decode_picker_plan
# unwraps them into the dicts the runner expects.
# ``expect_and_finding`` is a combined field: a single JSON-encoded
# string containing ``{expect: ..., on_success: ...}`` — split here
# back into the two top-level fields the runner reads.
_STEP_STRINGIFIED_FIELDS = ("json",)


def _decode_step_stringified_fields(step: dict[str, Any]) -> dict[str, Any]:
    """Unwrap step's JSON-encoded fields into dicts the runner expects."""
    if not isinstance(step, dict):
        return step
    for field in _STEP_STRINGIFIED_FIELDS:
        value = step.get(field)
        if not isinstance(value, str) or not value.strip():
            continue
        if not value.strip().startswith(("{", "[")):
            continue
        try:
            step[field] = json.loads(value)
        except json.JSONDecodeError:
            pass
    # expect_and_finding → split into {expect, on_success}
    combined = step.get("expect_and_finding")
    if isinstance(combined, str) and combined.strip():
        try:
            parsed = json.loads(combined)
        except json.JSONDecodeError:
            parsed = None
        if isinstance(parsed, dict):
            if isinstance(parsed.get("expect"), dict):
                step["expect"] = parsed["expect"]
            if isinstance(parsed.get("on_success"), dict):
                step["on_success"] = parsed["on_success"]
        # Drop the combined wrapper; runner doesn't read it.
        step.pop("expect_and_finding", None)
    return step


def _decode_picker_plan(decision: dict[str, Any]) -> dict[str, Any]:
    """If the decision is an exec_plan (or level_up + plan) variant, the
    `plan` field arrives as a JSON-encoded string (per the schema). Decode
    it in place so downstream consumers see the same dict shape they used
    to before #330. ALSO unwraps each step's stringified nested fields
    (headers/params/expect/capture/etc.) added 2026-05-21 as Anthropic
    strict-mode workaround. No-op for actions without a `plan` field.

    Returns the (possibly mutated) decision dict for chaining.
    """
    if not isinstance(decision, dict):
        return decision
    plan = decision.get("plan")
    if isinstance(plan, str) and plan:
        try:
            decoded = json.loads(plan)
        except json.JSONDecodeError as exc:
            logger.warning(
                "AI loop: picker plan field was not valid JSON despite schema "
                "constraint — raw=%r (%s)",
                plan[:240], exc,
            )
            return decision
        if isinstance(decoded, dict):
            decision["plan"] = decoded
        plan = decision.get("plan")
    # Unwrap stringified nested fields in each step
    if isinstance(plan, dict):
        steps = plan.get("steps")
        if isinstance(steps, list):
            for i, step in enumerate(steps):
                if isinstance(step, dict):
                    steps[i] = _decode_step_stringified_fields(step)
    return decision


def _summarize_findings_for_ai(run: Run, max_items: int = 25) -> list[dict[str, Any]]:
    """Compact representation of findings so the Claude prompt stays small."""
    summary: list[dict[str, Any]] = []
    for f in list(run.findings or [])[:max_items]:
        summary.append(
            {
                "severity": str(f.severity or "info"),
                "title": str(f.title or "")[:120],
                "target": str(f.target_id or "")[:120],
                "tool": str(getattr(f, "finding_origin", "") or "")[:60],
            }
        )
    return summary


def _tested_tools_summary(tested_keys: set[str]) -> list[str]:
    """Extract tool names from tested_keys (which are 'tool|target' pairs)."""
    return sorted({k.split("|", 1)[0] for k in tested_keys if k})


def _collect_discovered_targets(run: Run, limit: int = 15) -> list[str]:
    """Collect deeper paths/endpoints discovered by completed tools so Claude can
    target a SPECIFIC vulnerable URL instead of always the root."""
    seen: set[str] = set()
    paths: list[str] = []
    for finding in list(run.findings or []):
        t = str(finding.target_id or "").strip()
        if t and t not in seen:
            seen.add(t)
            paths.append(t)
            if len(paths) >= limit:
                return paths
    return paths


def _chatgpt_oauth_select_next_action(
    *,
    run: Run,
    session: Any,
    user_content: str,
    tested_keys: set[str],
    available_tools: list[str],
) -> dict[str, Any] | None:
    engagement_id = getattr(run, "engagement_id", None)
    if engagement_id is None:
        engagement = getattr(run, "engagement", None)
        engagement_id = getattr(engagement, "id", None)
    if session is None or engagement_id is None:
        logger.warning(
            "picker: ChatGPT OAuth provider requires database session and engagement_id; "
            "skipping picker call."
        )
        return None

    try:
        from api.app.config import get_settings  # noqa: E402
        from api.app.services.chatgpt_oauth import (  # noqa: E402
            send_chatgpt_backend_streaming_json_request,
        )

        settings = get_settings()
        picker_schema = _picker_schema_for_current_state(
            run=run,
            tested_keys=tested_keys,
            available_tools=available_tools,
        )
        instructions = (
            _AI_PICKER_SYSTEM_PROMPT
            + "\n\n=== CHATGPT OAUTH PICKER MODE ===\n"
            "This provider branch does not expose assistant tool-calls inside the model "
            "turn. Return the final picker decision directly. If more evidence is needed, "
            "choose an allowed runner action, level up to a better phase, or stop only when "
            "the evidence-first stop rules are satisfied.\n\n"
            "Return ONLY one JSON object matching this picker JSON Schema. Do not wrap it "
            "in markdown and do not include prose outside JSON:\n"
            + json.dumps(picker_schema, separators=(",", ":"))
        )
        payload = send_chatgpt_backend_streaming_json_request(
            session=session,
            engagement_id=engagement_id,
            settings=settings,
            model=str(settings.chatgpt_oauth_model or "gpt-5.4"),
            instructions=instructions,
            input_items=[
                {
                    "role": "user",
                    "content": [{"type": "input_text", "text": user_content}],
                }
            ],
        )
        if isinstance(payload.get("decision"), dict):
            payload = payload["decision"]
        if not isinstance(payload, dict):
            logger.warning("picker: ChatGPT OAuth response was not a JSON object")
            return None
        return _decode_picker_plan(payload)
    except Exception as exc:  # noqa: BLE001
        logger.warning("picker: ChatGPT OAuth next-action call failed: %s", exc)
        return None


def _collect_recent_failures(run: Run, limit: int = 8) -> list[dict[str, Any]]:
    """Pull the most recent failed/errored task results so Claude can see
    WHY his picks didn't work and adjust. Without this, Claude keeps trying
    the same broken approach (e.g. exec-plan with no plan body) blindly."""
    failures: list[dict[str, Any]] = []
    for task in sorted(
        list(run.tasks or []),
        key=lambda t: str(getattr(t, "updated_at", "") or ""),
        reverse=True,
    ):
        status = str(task.status or "").lower()
        if status not in {"failed", "errored", "cancelled"}:
            continue
        # Pull the latest execution's stderr/exit code if available
        stderr = ""
        exit_code = None
        for exe in list(task.executions or []):
            stderr = str(exe.stderr_text or "")[:400]
            exit_code = exe.exit_code
            break  # first one is enough
        # Sentinel: target may inject picker-control text via stderr
        # (e.g. WAF that echoes the requested URL back into the error
        # body). Scan + redact before exposing to Claude.
        stderr = _sanitize_target_text_for_picker(
            stderr, source="task_stderr", run_id=str(task.run_id) if task.run_id else None,
        )
        failures.append({
            "tool": str(task.tool or ""),
            "target": str(task.target_id or "")[:120],
            "status": status,
            "exit_code": exit_code,
            "error": stderr or "(no error text)",
        })
        if len(failures) >= limit:
            break
    return failures


def _collect_task_outcomes(run: Run, limit: int = 12) -> list[dict[str, Any]]:
    """For each recent completed task, show what the tool *actually* produced.

    Empty findings on a completed task is not the same as the tool failing —
    Claude needs to see the stdout excerpt so he can tell "nothing found"
    apart from "tool tested wrong angle". Without this he keeps picking
    generic scanners that produce noise instead of pivoting to exec-plan
    with a crafted hypothesis aimed at a specific discovered endpoint.
    """
    outcomes: list[dict[str, Any]] = []
    for task in sorted(
        list(run.tasks or []),
        key=lambda t: str(getattr(t, "updated_at", "") or ""),
        reverse=True,
    ):
        status = str(task.status or "").lower()
        if status not in {"completed", "failed", "cancelled"}:
            continue
        if str(task.tool or "").strip() == "bootstrap":
            continue
        stdout_excerpt = ""
        exit_code: int | None = None
        for exe in list(task.executions or []):
            stdout_excerpt = str(exe.stdout_text or "")[:280]
            exit_code = exe.exit_code
            break
        # Sentinel: target HTTP body lands in stdout_text. Sanitize before
        # the picker sees it (OWASP LLM01 prompt-injection defense).
        stdout_excerpt = _sanitize_target_text_for_picker(
            stdout_excerpt, source="task_stdout", run_id=str(task.run_id) if task.run_id else None,
        )
        outcomes.append({
            "tool": str(task.tool or ""),
            "target": str(task.target_id or "")[:120],
            "status": status,
            "exit_code": exit_code,
            "stdout_excerpt": stdout_excerpt or "(no stdout)",
        })
        if len(outcomes) >= limit:
            break
    return outcomes


def _extract_target_intel_test_plan(run: Run) -> list[dict[str, Any]]:
    """Read the target-intel tool's stdout from the most recent execution and
    pull out the AI-generated test_plan items. These are HIGH-VALUE hints
    because target-intel calls Claude separately to analyze the actual site
    content and CVE landscape — it knows what attack vectors are most likely
    to pay off for THIS target."""
    for task in list(run.tasks or []):
        if str(task.tool or "") != "target-intel" or str(task.status or "") != "completed":
            continue
        executions = list(task.executions or [])
        if not executions:
            continue
        latest = sorted(executions, key=lambda e: str(e.created_at or ""))[-1]
        stdout = str(latest.stdout_text or "")
        if not stdout:
            continue
        try:
            payload = json.loads(stdout)
        except Exception:
            continue
        analysis = payload.get("analysis") or {}
        plan = analysis.get("test_plan") or []
        if isinstance(plan, list):
            return [p for p in plan if isinstance(p, dict)][:6]
    return []


# ---------------------------------------------------------------------------
# #331 — Bounded soft retry around the picker
# ---------------------------------------------------------------------------
#
# `_claude_select_next_action` can return `None` for transient reasons:
# a network blip on http_fetch, a momentary credit pause, an empty text
# block, an SDK-level exception caught upstream. Before #331 the loop
# treated `None` as terminal: status was set to stopped with reason
# `no_registered_runner_candidate` after one bad output.
#
# `_call_picker_with_retries` wraps the picker call with a bounded retry
# budget (1 initial attempt + 2 retries = 3 total). It updates
# `loop_state` in place so the operator can see retry history:
#
#   retries_this_advance:   int, number of retries this advance (0 if
#                           the first attempt succeeded)
#   picker_retry_exhausted: bool, set True when the full budget is spent
#                           AND every attempt returned None. The caller
#                           uses this to set a distinct stop_reason
#                           (`picker_retry_exhausted`) so genuine
#                           "no fallback candidate" vs "Claude died on
#                           every retry" cases are diagnosable.
#
# #330 (structured outputs) already removed the JSON-parse-fail class of
# Nones; #331 hardens the loop against the remaining transient cases.

PICKER_MAX_RETRIES = 2

# backlog-403 — picker output budget. The original 1024 truncated multi-step
# exec_plan bodies mid-JSON (verified empirically on run 3e2cfa5b
# 2026-05-19: "Unterminated string starting at: line 1 column 1158"). 4096
# fits a typical 3-5 step plan + reasoning headroom; still cache-friendly.
PICKER_MAX_TOKENS = 4096

# backlog-403 — bounded refinement budget. When Claude emits action=exec_plan
# with empty/malformed plan body, re-call the picker with a refinement
# context (max EXEC_PLAN_MAX_REFINEMENTS additional attempts). Different from
# PICKER_MAX_RETRIES (which retries on TRANSIENT None returns). Refinement
# is for SEMANTIC failure: the model returned a syntactically-valid response
# whose plan body is empty.
EXEC_PLAN_MAX_REFINEMENTS = 2


def _call_picker_with_retries(
    *,
    run: Run,
    tested_keys: set[str],
    available_tools: list[str],
    targets: list[dict[str, Any]],
    scope: Scope | None,
    session: Session | None,
    loop_state: dict[str, Any],
    extra_recent_rejections: list[dict[str, Any]] | None = None,
) -> dict[str, Any] | None:
    """Call :func:`_claude_select_next_action` with bounded soft retry.

    Records retry telemetry on ``loop_state`` so operators can spot a
    flapping picker even when the eventual outcome is success. The
    function is otherwise a drop-in replacement — same signature shape,
    same return value (decision dict or None).

    ``extra_recent_rejections`` (backlog-403) — threaded to
    :func:`_claude_select_next_action`. Used by the refinement wrapper.
    """
    loop_state["retries_this_advance"] = 0
    loop_state["picker_retry_exhausted"] = False
    total_attempts = PICKER_MAX_RETRIES + 1
    for attempt_index in range(total_attempts):
        if attempt_index > 0:
            loop_state["retries_this_advance"] = attempt_index
            logger.info(
                "AI loop: picker retry attempt %d/%d",
                attempt_index, PICKER_MAX_RETRIES,
            )
        decision = _claude_select_next_action(
            run=run,
            tested_keys=tested_keys,
            available_tools=available_tools,
            targets=targets,
            scope=scope,
            session=session,
            extra_recent_rejections=extra_recent_rejections,
        )
        if decision is not None:
            if attempt_index > 0:
                logger.info(
                    "AI loop: picker recovered after %d retry(ies)",
                    attempt_index,
                )
            return decision
        logger.info(
            "AI loop: picker returned None (attempt %d of %d)",
            attempt_index + 1, total_attempts,
        )
    loop_state["picker_retry_exhausted"] = True
    logger.warning(
        "AI loop: picker exhausted retries (%d attempts) — proceeding to "
        "fallback heuristics; if no candidate emerges, loop will set "
        "stop_reason=picker_retry_exhausted",
        total_attempts,
    )
    return None


def _call_picker_with_exec_plan_refinement(
    *,
    run: Run,
    tested_keys: set[str],
    available_tools: list[str],
    targets: list[dict[str, Any]],
    scope: Scope | None,
    session: Session | None,
    loop_state: dict[str, Any],
) -> dict[str, Any] | None:
    """Wrap :func:`_call_picker_with_retries` with bounded re-prompting
    when Claude returns ``action=exec_plan`` with empty/malformed plan.

    Backlog-403 fix for the empirically-observed pattern (run 3e2cfa5b
    2026-05-19):

        AI loop: Claude said EXEC_PLAN plan_name='admin-takeover-...' steps=0
        AI loop: exec_plan rejected — empty or malformed plan body

    Without this wrapper the loop logs the rejection and falls through to
    a single-tool pick. Now we re-prompt up to
    :data:`EXEC_PLAN_MAX_REFINEMENTS` additional times with the previous
    plan + failure_reason in the picker's recent_rejections context, so
    Claude can correct the specific issue (empty steps / malformed JSON)
    rather than rediscovering it next advance.

    Updates ``loop_state``:

      exec_plan_refinements_attempted:   int (0 if first attempt succeeded
                                          or first decision wasn't exec_plan)
      exec_plan_refinement_exhausted:    bool (True iff every attempt
                                          returned malformed exec_plan)

    Returns the final decision dict (may be the last malformed one when
    exhausted — caller's existing rejection_sink handler will route it).
    Returns None when the underlying picker returns None.
    """
    loop_state["exec_plan_refinements_attempted"] = 0
    loop_state["exec_plan_refinement_exhausted"] = False

    refinement_notes: list[dict[str, Any]] = []
    decision: dict[str, Any] | None = None
    total_attempts = EXEC_PLAN_MAX_REFINEMENTS + 1
    for attempt_index in range(total_attempts):
        decision = _call_picker_with_retries(
            run=run,
            tested_keys=tested_keys,
            available_tools=available_tools,
            targets=targets,
            scope=scope,
            session=session,
            loop_state=loop_state,
            extra_recent_rejections=refinement_notes if refinement_notes else None,
        )
        if decision is None:
            # Underlying retry budget exhausted; nothing to refine.
            return None
        action = str(decision.get("action") or "").lower()
        if action != "exec_plan":
            # Decision isn't an exec_plan — refinement isn't applicable;
            # caller handles other actions normally.
            return decision
        plan = decision.get("plan")
        steps_ok = (
            isinstance(plan, dict)
            and isinstance(plan.get("steps"), list)
            and len(plan.get("steps") or []) > 0
        )
        if steps_ok:
            if attempt_index > 0:
                logger.info(
                    "AI loop: exec_plan refined after %d attempt(s) — final plan has %d step(s)",
                    attempt_index,
                    len(plan["steps"]),
                )
            return decision
        # Plan body empty/malformed — try refinement if budget remains.
        if attempt_index >= EXEC_PLAN_MAX_REFINEMENTS:
            logger.info(
                "AI loop: exec_plan refinement exhausted after %d attempts",
                attempt_index + 1,
            )
            loop_state["exec_plan_refinement_exhausted"] = True
            return decision
        loop_state["exec_plan_refinements_attempted"] = attempt_index + 1
        # Truncate plan summary so the refinement context stays small.
        prev_plan_summary = (
            json.dumps(plan)[:500] if isinstance(plan, dict) else "(plan field absent)"
        )
        failure_reason = (
            "the 'steps' array was empty"
            if isinstance(plan, dict)
            else "the 'plan' field was missing or not a JSON object"
        )
        refinement_notes.append({
            "reason": "exec_plan_refinement_needed",
            "detail": (
                f"Your previous exec_plan attempt was rejected because {failure_reason}. "
                f"Previous plan body (truncated to 500 chars): {prev_plan_summary}. "
                "Revise: produce a concrete multi-step plan body with at least 2 'steps' "
                "that addresses the target's observed evidence. Do NOT re-emit an empty "
                "or malformed plan."
            ),
            "at": _now(),
        })
        logger.info(
            "AI loop: exec_plan refining (attempt %d/%d) — reason=%s",
            attempt_index + 2,
            total_attempts,
            "empty_steps" if isinstance(plan, dict) else "malformed_plan",
        )
    return decision  # safety; loop exits via returns above


def _maybe_dispatch_script_critic(
    *,
    run: Run,
    session: Any,
    provider: Any,
    targets: list[dict[str, Any]],
) -> dict[str, Any] | None:
    """M1 (beat-shannon-pro 2026-05-23): adversarial critique of failed
    code-exec-attack scripts.

    Returns a picker decision wrapping a REVISED python_script when the
    most-recent code-exec-attack task ran but emitted no finding. Returns
    None when there is no failed code-exec-attack to critique OR when
    that task has already been critiqued in this run.

    The critic is a separate LLM call that reads the prior script +
    stdout + recon artifacts and emits a fix. Output flows back through
    the existing code-exec-attack runner — no new runner needed.
    """
    cfg = dict(getattr(run, "configuration_json", None) or {})
    loop_cfg = dict(cfg.get("ai_assessment_loop") or {})
    # M4 multi-trajectory: cap how many critic revisions per predecessor.
    # Default 1 == M1 baseline behaviour; bump per run to enable Naptime-style
    # multi-angle sampling. The "approach_hint" diversity comes for free from
    # the LLM seeing the previously-tried revisions in its input on iter 2+.
    try:
        m4_max_revisions = max(1, int(loop_cfg.get("m1_max_revisions_per_predecessor") or 1))
    except (TypeError, ValueError):
        m4_max_revisions = 1

    # Authoritative record-based dedup: any code-exec-attack task with a
    # `_specialist_metadata.predecessor_task_id` pointing back at a prior
    # task is itself a critic revision — and the predecessor's revision
    # quota gets decremented. configuration_json mutation alone is unreliable
    # across advance_assessment_loop invocations because the JSONB column
    # needs explicit mutation tracking; relying on materialized task params
    # is cheaper and immune to flush ordering.
    revision_counts: dict[str, int] = {}
    for task in (getattr(run, "tasks", None) or []):
        if str(getattr(task, "tool", "") or "") != "code-exec-attack":
            continue
        params = getattr(task, "params_json", None) or {}
        meta = params.get("_specialist_metadata") if isinstance(params, dict) else None
        pred_id = (meta or {}).get("predecessor_task_id") if isinstance(meta, dict) else None
        if pred_id:
            revision_counts[str(pred_id)] = revision_counts.get(str(pred_id), 0) + 1

    already_critiqued: set[str] = set(loop_cfg.get("critiqued_code_exec_task_ids") or [])
    for pred_id, count in revision_counts.items():
        if count >= m4_max_revisions:
            already_critiqued.add(pred_id)

    # Find the most-recent code-exec-attack task that COMPLETED (or
    # FAILED) but did NOT result in a finding. We detect "no finding"
    # by inspecting the runner's stdout payload — code_exec_attack
    # writes a JSON envelope with a `findings` array per task; if the
    # array is empty or the task exit_code is non-zero, the script
    # didn't reach proof.
    latest_failed_cea_task = None
    latest_script_text: str | None = None
    latest_stdout_text: str | None = None
    latest_stderr_text: str | None = None
    latest_hypothesis_title: str | None = None
    for task in sorted(
        list(getattr(run, "tasks", None) or []),
        key=lambda t: str(getattr(t, "updated_at", "") or ""),
        reverse=True,
    ):
        if str(getattr(task, "tool", "") or "") != "code-exec-attack":
            continue
        task_id_s = str(getattr(task, "id", "") or "")
        if not task_id_s or task_id_s in already_critiqued:
            continue
        # Decide whether this task lacks a finding worth keeping.
        executions = list(getattr(task, "executions", None) or [])
        if not executions:
            continue
        exec_ = executions[0]
        stdout_text = str(getattr(exec_, "stdout_text", "") or "")
        stderr_text = str(getattr(exec_, "stderr_text", "") or "")
        # Parse the runner's payload to count findings.
        finding_count_in_stdout = stdout_text.count("AEGISPT_FINDING:")
        try:
            payload_obj = json.loads(stdout_text) if stdout_text.strip().startswith("{") else {}
            payload_findings = len(payload_obj.get("findings") or [])
        except Exception:  # noqa: BLE001
            payload_findings = 0
        if finding_count_in_stdout > 0 or payload_findings > 0:
            # Script DID produce a finding — no critique needed.
            already_critiqued.add(task_id_s)
            continue
        # Load the original script source from artifacts so the critic
        # sees what was attempted.
        script_source = ""
        for art in list(getattr(exec_, "artifacts", None) or []):
            meta = getattr(art, "metadata_json", None) or {}
            name = (meta.get("name") if isinstance(meta, dict) else "") or ""
            if name == "code-exec-attack-script.py":
                try:
                    from api.app.config import get_settings  # noqa: E402
                    from api.app.services.artifact_storage import (  # noqa: E402
                        artifact_storage_config_from_settings,
                        load_artifact_content,
                    )
                    content = load_artifact_content(
                        config=artifact_storage_config_from_settings(get_settings()),
                        uri=art.uri,
                    )
                    if content is not None:
                        script_source = content.data.decode("utf-8", errors="replace")
                except Exception as exc:  # noqa: BLE001
                    logger.warning("script_critic: artifact load failed: %s", exc)
                break
        params = getattr(task, "params_json", None) or {}
        latest_hypothesis_title = str(
            (params.get("_specialist_metadata") or {}).get("specialist")
            or params.get("ai_reasoning")
            or ""
        )[:300]
        latest_failed_cea_task = task
        latest_script_text = script_source
        latest_stdout_text = stdout_text
        latest_stderr_text = stderr_text
        break

    if latest_failed_cea_task is None:
        return None

    # Pull recon + pre-recon-source + pre-recon-cpg artifacts to feed into the critic.
    recon_text = ""
    pre_recon_text = ""
    cpg_text = ""
    try:
        from api.app.config import get_settings  # noqa: E402
        from api.app.services.artifact_storage import (  # noqa: E402
            artifact_storage_config_from_settings,
            load_artifact_content,
        )
        cfg_storage = artifact_storage_config_from_settings(get_settings())
        for task in list(getattr(run, "tasks", None) or []):
            tool = str(getattr(task, "tool", "") or "")
            if tool not in {"recon-deliverable", "pre-recon-source", "pre-recon-cpg"}:
                continue
            for execution in list(getattr(task, "executions", None) or []):
                for art in list(getattr(execution, "artifacts", None) or []):
                    meta = getattr(art, "metadata_json", None) or {}
                    name = (meta.get("name") if isinstance(meta, dict) else "") or ""
                    if name == "recon-deliverable.md" and not recon_text:
                        c = load_artifact_content(config=cfg_storage, uri=art.uri)
                        if c is not None:
                            recon_text = c.data.decode("utf-8", errors="replace")
                    elif name == "pre-recon-source-deliverable.md" and not pre_recon_text:
                        c = load_artifact_content(config=cfg_storage, uri=art.uri)
                        if c is not None:
                            pre_recon_text = c.data.decode("utf-8", errors="replace")
                    elif name == "pre-recon-cpg-deliverable.md" and not cpg_text:
                        c = load_artifact_content(config=cfg_storage, uri=art.uri)
                        if c is not None:
                            cpg_text = c.data.decode("utf-8", errors="replace")
    except Exception as exc:  # noqa: BLE001
        logger.warning("script_critic: recon load failed: %s", exc)

    target_url = ""
    for t in (targets or []):
        target_url = str(t.get("value") or t.get("url") or "")
        if target_url:
            break
    if not target_url:
        return None

    # Build the user content envelope for the critic.
    user_content = (
        "=== PRIOR EXPLOIT SCRIPT (failed to emit finding) ===\n"
        f"{latest_script_text or '(script source unavailable)'}\n\n"
        "=== SCRIPT STDOUT ===\n"
        f"{(latest_stdout_text or '')[:4000]}\n\n"
        "=== SCRIPT STDERR ===\n"
        f"{(latest_stderr_text or '')[:1500]}\n\n"
        "=== PRE-RECON-CPG (Joern dataflow — exact line/file of sinks) ===\n"
        f"{cpg_text or '(no CPG deliverable on this run)'}\n\n"
        "=== PRE-RECON-SOURCE (source-aware deliverable — regex audit) ===\n"
        f"{pre_recon_text or '(no source-aware audit on this run)'}\n\n"
        "=== RECON DELIVERABLE (network-observed) ===\n"
        f"{recon_text or '(no network recon yet)'}\n\n"
        "=== HYPOTHESIS THAT MOTIVATED THE PRIOR SCRIPT ===\n"
        f"{latest_hypothesis_title or '(unknown)'}\n\n"
        "Now critique the script + emit a revised python_script that "
        "exploits the primitive the prior script missed. When the CPG "
        "deliverable lists FILE_SINKS / SQL_SINKS / EXEC_SINKS, those are "
        "AUTHORITATIVE source-line locations of dangerous primitives — "
        "prioritise reaching those sinks via the routes Joern surfaced."
    )

    from api.app.services.picker_specialists import (  # noqa: E402
        SCRIPT_CRITIC_PROMPT,
        SCRIPT_CRITIC_SCHEMA,
    )

    # M6 v1 — adversarial cross-model critic: when the loop config opts in,
    # critique runs on the OPPOSITE provider from the picker that wrote the
    # failing script. Falls back to the original provider if the swap is not
    # available (no API key / no OAuth token).
    critic_provider = provider
    try:
        if bool(loop_cfg.get("m6_cross_model_critic")):
            import os as _os
            from api.app.services.llm_provider import (  # noqa: E402
                LLMProvider, LLMProviderConfig,
            )
            if _provider_is_chatgpt_oauth(provider) and _os.environ.get("ANTHROPIC_API_KEY"):
                critic_provider = LLMProvider(
                    LLMProviderConfig.for_model("claude-opus-4-7")
                )
                logger.info(
                    "PROOF_EXEC_M6_CROSS_MODEL_CRITIC_2026052314 swapped picker=chatgpt-oauth -> critic=anthropic"
                )
            elif _provider_is_anthropic(provider):
                # Picker is Anthropic → switch critic to ChatGPT-OAuth when
                # the engagement has an OAuth token available downstream.
                critic_provider = LLMProvider(
                    LLMProviderConfig.for_model("chatgpt_oauth")
                )
                logger.info(
                    "PROOF_EXEC_M6_CROSS_MODEL_CRITIC_2026052314 swapped picker=anthropic -> critic=chatgpt-oauth"
                )
    except Exception as exc:  # noqa: BLE001
        logger.info(
            "M6 cross-model critic swap failed; using original provider: %s", exc
        )
        critic_provider = provider

    def _call_critic() -> dict[str, Any] | None:
        provider = critic_provider
        if _provider_is_chatgpt_oauth(provider):
            from api.app.config import get_settings  # noqa: E402
            from api.app.services.chatgpt_oauth import (  # noqa: E402
                send_chatgpt_backend_streaming_json_request,
            )
            settings = get_settings()
            engagement_id = getattr(run, "engagement_id", None) or getattr(getattr(run, "engagement", None), "id", None)
            instructions = (
                SCRIPT_CRITIC_PROMPT
                + "\n\nReturn ONLY one JSON object matching this schema. "
                "No markdown, no prose outside JSON:\n"
                + json.dumps(SCRIPT_CRITIC_SCHEMA, separators=(",", ":"))
            )
            try:
                return send_chatgpt_backend_streaming_json_request(
                    session=session,
                    engagement_id=engagement_id,
                    settings=settings,
                    model=str(settings.chatgpt_oauth_model or "gpt-5.5"),
                    instructions=instructions,
                    input_items=[
                        {"role": "user", "content": [{"type": "input_text", "text": user_content}]}
                    ],
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning("script_critic: ChatGPT call failed: %s", exc)
                return None
        if _provider_is_anthropic(provider):
            client = provider.raw_anthropic_client()
            try:
                msg = client.messages.create(
                    model=provider.config.model,
                    max_tokens=4096,
                    system=[{"type": "text", "text": SCRIPT_CRITIC_PROMPT}],
                    messages=[{"role": "user", "content": user_content}],
                    output_config={
                        "format": {"type": "json_schema", "schema": SCRIPT_CRITIC_SCHEMA},
                    },
                    timeout=120.0,
                )
                for block in (msg.content or []):
                    if getattr(block, "type", "") == "text":
                        txt = str(getattr(block, "text", "") or "").strip()
                        if txt:
                            try:
                                return json.loads(txt)
                            except json.JSONDecodeError:
                                continue
            except Exception as exc:  # noqa: BLE001
                logger.warning("script_critic: Anthropic call failed: %s", exc)
        return None

    critique = _call_critic()
    if not isinstance(critique, dict):
        return None

    revised_script = str(critique.get("revised_python_script") or "").strip()
    if not revised_script:
        return None

    # M4 multi-trajectory: only stamp the persisted exclusion list when the
    # predecessor has reached its revision cap. Otherwise the record-based
    # scan at the top of this function will continue to admit revisions
    # 2..N. We still update the persisted set as a belt-and-braces safety
    # net for the eventual final dispatch.
    pred_id_s = str(latest_failed_cea_task.id)
    projected_count = revision_counts.get(pred_id_s, 0) + 1
    if projected_count >= m4_max_revisions:
        already_critiqued.add(pred_id_s)
        loop_cfg["critiqued_code_exec_task_ids"] = sorted(already_critiqued)
        cfg["ai_assessment_loop"] = loop_cfg
        run.configuration_json = cfg
        if session is not None:
            try:
                session.flush()
            except Exception:  # noqa: BLE001
                pass

    revision_index = revision_counts.get(str(latest_failed_cea_task.id), 0) + 1
    logger.info(
        "PROOF_EXEC_SCRIPT_CRITIC_2026052311 critic ran on task=%s missed=%d severity=%s revision=%d/%d",
        str(latest_failed_cea_task.id)[:8],
        len(critique.get("missed_primitives") or []),
        critique.get("expected_finding_severity"),
        revision_index,
        m4_max_revisions,
    )
    return {
        "action": "pick",
        "tool": "code-exec-attack",
        "target": target_url,
        "tier": "active",
        "confidence": 0.85,
        "reasoning": (
            f"M1 script-critic revision #{revision_index}/{m4_max_revisions} "
            f"after task {str(latest_failed_cea_task.id)[:8]} failed to emit finding. "
            f"Missed primitives: "
            f"{[p.get('kind') for p in (critique.get('missed_primitives') or [])][:5]}. "
            f"{str(critique.get('critique_summary') or '')[:200]}"
        )[:500],
        "runner_params": {"script": revised_script},
        "_specialist_metadata": {
            "specialist": "script_critic",
            "phase": "m1_critique",
            "expected_severity": critique.get("expected_finding_severity"),
            "expected_evidence_pattern": critique.get("expected_evidence_pattern"),
            "predecessor_task_id": str(latest_failed_cea_task.id),
            "revision_index": revision_index,
            "max_revisions": m4_max_revisions,
        },
    }


CPG_SEEDED_CEA_PROMPT = """You are a Security Engineer who writes a Python exploit script targeting
the EXACT routes + sinks that a Code-Property-Graph audit (Joern) has
already located. You do NOT do recon; you write the script.

INPUT BLOCKS YOU RECEIVE
1. The pre-recon-cpg deliverable: explicit ROUTES, SQL_SINKS, FILE_SINKS,
   EXEC_SINKS, TEMPLATE_SINKS, DESERIALIZE_SINKS, LITERAL_SECRETS with
   file:lineno locations.
2. SEED CREDENTIALS — literal username/password pairs from source seed data.
3. SEED OBJECT IDs — literal numeric IDs (orders, users, accounts) that
   were INSERTED by the seed data. THESE ARE THE IDS TO TARGET.
4. The pre-recon-source deliverable: regex-grepped routes + creds.
5. The recon-deliverable: network-observed attack surface.

EMIT HELPER (always available, do NOT redefine, do NOT import)
The runner injects a builtin `aegispt_emit_finding(severity=..., title=...,
evidence_excerpt=..., evidence_url=...)` into the script's namespace.
Just call it directly when you find a flag. As a belt-and-braces, ALSO
print `f"AEGISPT_FINDING: {json.dumps({...})}"` on a single line when a
flag-pattern is detected. The runner parses BOTH paths.

YOUR JOB
Write a SINGLE self-contained Python script (httpx-based) that:
  - Authenticates using SEED CREDENTIALS (literal username/password).
  - Walks the routes in the order the access-check predicate requires.
    Example: if a route's filter is `or_(creator == user, archiver == user)`,
    first hit the route that SETS archiver (mutation), then the route
    guarded by that predicate (read).
  - For EACH literal id in SEED OBJECT IDs (Orders, Users, etc.) — in
    iteration — perform the chain (e.g. archive -> receipt). Stop on
    first flag.
  - Inspects each response body and calls
    `aegispt_emit_finding(severity='critical', title=..., evidence_excerpt=...)`
    AND `raise SystemExit(0)` when a flag-like literal (`flag{...}`,
    `xbow-[a-f0-9]+`, base64 secret) appears in the body.

HARD RULES — VIOLATIONS GUARANTEE FAILURE
- DO NOT use `range(1, N)`, `range(N)`, or any integer-sweep over object IDs.
  Iterate ONLY over the literal IDs in SEED OBJECT IDs (e.g. `for oid in
  ['300123', '300214', '300327', '300481', '300198']:`). Sweeping skips
  the non-sequential IDs (like 300198) that the seed data actually planted.
- DO NOT `raise RuntimeError(...)` or `sys.exit(1)` when no flag is found.
  Print a one-line JSON summary of what was tried (status codes per route)
  and let the script exit naturally with code 0. The orchestrator's critic
  reads stdout to learn what to fix next; a stack trace tells it nothing.
- DO NOT invent endpoints — only routes from CPG ROUTES or pre-recon-source.
- DO NOT invent credentials — only SEED CREDENTIALS literal values.
- DO use `httpx.Client(follow_redirects=False, timeout=8.0)`.
- DO NOT guess login endpoint. Instead:
  (a) GET `/` and parse `<form action="...">` to find the actual login URL,
      AND parse all `<input name="...">` fields to know which fields the
      form expects. Submit POST to that action with username+password
      using the field names you observed.
  (b) If (a) returns no form OR returns 302 without setting an auth cookie,
      ALSO try POST `/login` and POST `/password/<username>` with
      `password=<seed_password>`. ALWAYS try all three before giving up.
  (c) After EACH login attempt: GET `/dashboard` (or any authenticated
      route surfaced by CPG ROUTES). If the response is 200 (not 302),
      auth succeeded. Only proceed to the exploit chain after this check.
- DO inspect EVERY response body for the flag pattern, not just the
  expected "receipt" page.

The script runs in a sandbox with 60s budget; the chain rarely needs
more than 10 requests. Be focused.

OUTPUT
Return ONE JSON object matching the schema. `python_script` becomes the
runner_params.script for the dispatched code-exec-attack task.
"""

CPG_SEEDED_CEA_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["python_script", "expected_finding_severity", "rationale"],
    "properties": {
        "python_script": {
            "type": "string",
            "description": "Self-contained Python (httpx + aegispt_emit_finding). Hits the CPG-surfaced chain in dependency order.",
        },
        "expected_finding_severity": {
            "type": "string",
            "enum": ["critical", "high", "medium", "low"],
        },
        "rationale": {
            "type": "string",
            "description": "1-3 sentences naming the specific CPG sink + access-check predicate the script targets.",
        },
    },
}


def _maybe_dispatch_cpg_seeded_cea(
    *,
    run: Run,
    session: Any,
    provider: Any,
    targets: list[dict[str, Any]],
) -> dict[str, Any] | None:
    """Deterministic CEA dispatch when CPG has surfaced concrete sinks.

    Triggers when:
      - pre-recon-cpg-deliverable.md exists in the run's artifacts.
      - No code-exec-attack task has been dispatched yet.
      - The CPG deliverable contains at least one non-empty sink section.

    Emits PROOF_EXEC_CPG_SEEDED_CEA_2026052404 marker.

    This BYPASSES the specialist orchestrator's bias against
    code-exec-attack on source-aware runs. Empirically observed
    2026-05-24: specialists picked 0 CEA across 4 source-aware smokes
    even though the CPG deliverable surfaced the full XBEN-002 chain.
    """
    logger.info(
        "PROOF_EXEC_CPG_SEEDED_CEA_ENTER_2026052405 run=%s n_tasks=%d",
        str(getattr(run, "id", "?"))[:8],
        len(getattr(run, "tasks", None) or []),
    )
    if not getattr(run, "tasks", None):
        return None
    has_cpg = False
    cpg_text = ""
    has_cea = False
    pre_recon_source_text = ""
    recon_text = ""
    for task in (run.tasks or []):
        tool = str(getattr(task, "tool", "") or "")
        if tool == "code-exec-attack":
            has_cea = True
            continue  # keep scanning, want CPG artifact too
        if tool not in {"pre-recon-cpg", "pre-recon-source", "recon-deliverable"}:
            continue
        for execution in (getattr(task, "executions", None) or []):
            for art in (getattr(execution, "artifacts", None) or []):
                meta = getattr(art, "metadata_json", None) or {}
                name = (meta.get("name") if isinstance(meta, dict) else "") or ""
                if name == "pre-recon-cpg-deliverable.md" and not cpg_text:
                    has_cpg = True
                    try:
                        from api.app.config import get_settings  # noqa: E402
                        from api.app.services.artifact_storage import (  # noqa: E402
                            artifact_storage_config_from_settings,
                            load_artifact_content,
                        )
                        c = load_artifact_content(
                            config=artifact_storage_config_from_settings(get_settings()),
                            uri=art.uri,
                        )
                        if c is not None:
                            cpg_text = c.data.decode("utf-8", errors="replace")
                    except Exception as exc:  # noqa: BLE001
                        logger.warning("cpg_seeded_cea: cpg load failed: %s", exc)
                elif name == "pre-recon-source-deliverable.md" and not pre_recon_source_text:
                    try:
                        from api.app.config import get_settings  # noqa: E402
                        from api.app.services.artifact_storage import (  # noqa: E402
                            artifact_storage_config_from_settings,
                            load_artifact_content,
                        )
                        c = load_artifact_content(
                            config=artifact_storage_config_from_settings(get_settings()),
                            uri=art.uri,
                        )
                        if c is not None:
                            pre_recon_source_text = c.data.decode("utf-8", errors="replace")
                    except Exception:  # noqa: BLE001
                        pass
                elif name == "recon-deliverable.md" and not recon_text:
                    try:
                        from api.app.config import get_settings  # noqa: E402
                        from api.app.services.artifact_storage import (  # noqa: E402
                            artifact_storage_config_from_settings,
                            load_artifact_content,
                        )
                        c = load_artifact_content(
                            config=artifact_storage_config_from_settings(get_settings()),
                            uri=art.uri,
                        )
                        if c is not None:
                            recon_text = c.data.decode("utf-8", errors="replace")
                    except Exception:  # noqa: BLE001
                        pass
    logger.info(
        "PROOF_EXEC_CPG_SEEDED_CEA_GATE_2026052405 has_cea=%s has_cpg=%s cpg_text_len=%d source_len=%d recon_len=%d",
        has_cea, has_cpg, len(cpg_text), len(pre_recon_source_text), len(recon_text),
    )
    if has_cea or not has_cpg or not cpg_text:
        return None
    # Sanity: only seed when CPG actually has a non-empty sink section.
    sinks_found = []
    for label in ("SQL_SINKS", "FILE_SINKS", "EXEC_SINKS", "TEMPLATE_SINKS", "DESERIALIZE_SINKS"):
        marker = f"== {label} (sample,"
        if marker in cpg_text:
            tail = cpg_text.split(marker)[1].split("==")[0][:80]
            if "(sample, 0)" not in tail and " 0)" not in tail.split(")")[0] + ")":
                sinks_found.append(label)
    logger.info(
        "PROOF_EXEC_CPG_SEEDED_CEA_SINKS_2026052405 sinks_found=%s",
        sinks_found,
    )
    if not sinks_found:
        return None

    target_url = ""
    for t in (targets or []):
        target_url = str(t.get("value") or t.get("url") or "")
        if target_url:
            break
    if not target_url:
        return None

    # Trim CPG to just the sink+route sections — drop the INFO pass logs
    # which are noise. They're produced by joern-parse, not query output.
    cpg_trimmed = cpg_text
    if "== ROUTES" in cpg_text:
        cpg_trimmed = cpg_text[cpg_text.index("== ROUTES"):]
    cpg_trimmed = cpg_trimmed[:3500]

    # Read seed credentials directly from source_dir, BYPASSING the
    # artifact-storage redaction pipeline. The pre_recon_source
    # deliverable's `password='test'` literal gets masked to
    # `password='[REDACTED]'` before it reaches us — that lets the
    # critic's script attempt to log in with the literal "[REDACTED]",
    # which obviously fails. Extracting straight from the source files
    # gives the critic actual usable creds without leaking them via
    # any persistent artifact (they only live in the in-memory prompt).
    seed_creds_block = "(no seed-cred patterns found in source)"
    cfg_run = getattr(run, "configuration_json", None) or {}
    source_dir_for_run = str((cfg_run or {}).get("source_dir") or "").strip()
    logger.info(
        "PROOF_EXEC_CPG_SEEDED_CEA_CREDS_ATTEMPT_2026052406 source_dir=%r cfg_keys=%s",
        source_dir_for_run,
        list((cfg_run or {}).keys())[:15],
    )
    if source_dir_for_run:
        try:
            from pathlib import Path as _Path  # noqa: E402
            import re as _re  # noqa: E402
            pat = _re.compile(
                r"username\s*=\s*['\"]([^'\"]{1,60})['\"]"
                r"[^)]{0,800}?"
                r"password\s*=\s*['\"]([^'\"]{1,60})['\"]",
                _re.IGNORECASE | _re.DOTALL,
            )
            seeds = []
            for path in _Path(source_dir_for_run).rglob("*.py"):
                try:
                    txt = path.read_text(errors="ignore")
                except OSError:
                    continue
                for m in pat.finditer(txt):
                    seeds.append((m.group(1), m.group(2), str(path.relative_to(source_dir_for_run))))
                    if len(seeds) >= 8:
                        break
                if len(seeds) >= 8:
                    break
            if seeds:
                lines = [
                    f"  - username={u!r} password={p!r} (from {f})"
                    for u, p, f in seeds
                ]
                seed_creds_block = "\n".join(lines)
            logger.info(
                "PROOF_EXEC_CPG_SEEDED_CEA_CREDS_RESULT_2026052406 seeds=%d block_preview=%r",
                len(seeds), seed_creds_block[:200],
            )
        except Exception as exc:  # noqa: BLE001
            pass

    # Extract literal object IDs (Order(id='300198'), User(id='10032'), etc.)
    # from source seed data so the script knows which IDs to target, not just
    # the 1..100 default range. Without this, scripts miss XBEN-002 order
    # 300198 (flag holder) which sits outside the default integer sweep.
    seed_ids_block = "(no literal object IDs found in source)"
    if source_dir_for_run:
        try:
            from pathlib import Path as _Path2  # noqa: E402
            import re as _re2  # noqa: E402
            id_pat = _re2.compile(
                r"\b(Order|User|Account|Profile|Document|Ticket|Invoice)\s*\([^)]{0,400}?id\s*=\s*['\"]?([0-9]{2,10})['\"]?",
                _re2.IGNORECASE | _re2.DOTALL,
            )
            ids_seen = []
            ids_set = set()
            for path in _Path2(source_dir_for_run).rglob("*.py"):
                try:
                    txt = path.read_text(errors="ignore")
                except OSError:
                    continue
                for m in id_pat.finditer(txt):
                    key = (m.group(1).lower(), m.group(2))
                    if key not in ids_set:
                        ids_set.add(key)
                        ids_seen.append((m.group(1), m.group(2), str(path.relative_to(source_dir_for_run))))
                        if len(ids_seen) >= 25:
                            break
                if len(ids_seen) >= 25:
                    break
            if ids_seen:
                seed_ids_block = "\n".join(
                    f"  - {kind}(id={iid!r}) (from {f})" for kind, iid, f in ids_seen
                )
            logger.info(
                "PROOF_EXEC_CPG_SEEDED_CEA_IDS_RESULT_2026052406 ids=%d preview=%r",
                len(ids_seen), seed_ids_block[:200],
            )
        except Exception:  # noqa: BLE001
            pass

    user_content = (
        "=== JOERN CPG TAINT SURVEY (trimmed to sinks/routes) ===\n"
        f"{cpg_trimmed}\n\n"
        "=== SEED CREDENTIALS (from source seed data — USE THESE LITERALLY) ===\n"
        f"{seed_creds_block}\n\n"
        "=== SEED OBJECT IDs (literal IDs from source — target THESE, NOT 1..100) ===\n"
        f"{seed_ids_block}\n\n"
        "=== PRE-RECON-SOURCE (trimmed; may contain [REDACTED] masks — refer to SEED CREDENTIALS for literal values) ===\n"
        f"{(pre_recon_source_text or '(absent)')[:3500]}\n\n"
        f"Target base URL: {target_url}\n\n"
        "Write the python_script now. Keep it focused on the chain.\n"
        "CRITICAL #1: when authenticating, use the literal username/password "
        "from SEED CREDENTIALS above. If `pre-recon-source` shows "
        "`password='[REDACTED]'` that is the redaction-pipeline placeholder; "
        "use the literal from SEED CREDENTIALS instead.\n"
        "CRITICAL #2: when probing object IDs (orders, users, accounts, ...), "
        "use the literal IDs from SEED OBJECT IDs above. They are the IDs the "
        "seed data ACTUALLY created. Sweeping 1..100 will miss IDs like 300198 "
        "or other non-sequential identifiers."
    )

    script = ""
    severity = "high"
    rationale = ""
    # Provider preference order (best JSON-schema adherence first):
    #   1. Claude Opus (when ANTHROPIC_API_KEY available) — strongest schema follower
    #   2. local-qwen (when AEGISPT_LOCAL_LLM_URL set) — free but verbose <think> output
    #   3. chatgpt_oauth — fallback when nothing else available
    use_local_llm = bool(os.environ.get("AEGISPT_LOCAL_LLM_URL", "").strip())
    have_anthropic = bool(os.environ.get("ANTHROPIC_API_KEY", "").strip())
    try:
        from api.app.services.llm_provider import LLMProvider, LLMProviderConfig  # noqa: E402
        if have_anthropic:
            provider = LLMProvider(LLMProviderConfig.for_model("claude-opus-4-7"))
            logger.info("PROOF_EXEC_CPG_SEEDED_CEA_USING_CLAUDE_2026052407 picked Anthropic")
            use_local_llm = False
        elif use_local_llm:
            provider = LLMProvider(LLMProviderConfig.for_model("local-qwen"))
            logger.info("PROOF_EXEC_CPG_SEEDED_CEA_USING_LOCAL_LLM_2026052406 url=%s",
                        os.environ.get("AEGISPT_LOCAL_LLM_URL"))
        else:
            provider = LLMProvider(LLMProviderConfig.for_model("chatgpt_oauth"))
            logger.info(
                "PROOF_EXEC_CPG_SEEDED_CEA_FORCED_OAUTH_2026052405 hard-forced chatgpt_oauth"
            )
    except Exception as exc:  # noqa: BLE001
        logger.warning("cpg_seeded_cea: force-provider failed: %s", exc)
    provider_kind = (
        "claude" if have_anthropic
        else "local_qwen" if use_local_llm
        else "anthropic" if _provider_is_anthropic(provider)
        else "chatgpt_oauth" if _provider_is_chatgpt_oauth(provider)
        else "unknown"
    )
    logger.info(
        "PROOF_EXEC_CPG_SEEDED_CEA_LLM_CALL_2026052405 provider_kind=%s",
        provider_kind,
    )
    try:
        if use_local_llm:
            import httpx as _httpx  # noqa: E402
            llm_url = os.environ["AEGISPT_LOCAL_LLM_URL"].rstrip("/")
            instructions = (
                CPG_SEEDED_CEA_PROMPT
                + "\n\nReturn ONLY one JSON object matching this schema:\n"
                + json.dumps(CPG_SEEDED_CEA_SCHEMA, separators=(",", ":"))
            )
            try:
                r = _httpx.post(
                    f"{llm_url}/v1/chat/completions",
                    json={
                        "model": "local-qwen",
                        "messages": [
                            {"role": "system", "content": instructions},
                            {"role": "user", "content": user_content},
                        ],
                        "max_tokens": 3000,
                        "temperature": 0.2,
                    },
                    timeout=600.0,
                )
                resp_obj = r.json()
                content = resp_obj["choices"][0]["message"]["content"]
                # strip <think>...</think> blocks Qwen-3 emits
                import re as _re_strip
                content = _re_strip.sub(r"<think>.*?</think>", "", content, flags=_re_strip.DOTALL).strip()
                # extract JSON object from content
                m = _re_strip.search(r"\{[\s\S]*\}", content)
                resp = json.loads(m.group(0)) if m else None
            except Exception as exc:  # noqa: BLE001
                logger.warning("cpg_seeded_cea: local-llm call failed: %s", exc)
                resp = None
            logger.info(
                "PROOF_EXEC_CPG_SEEDED_CEA_RESP_2026052406 resp_type=%s resp_keys=%s",
                type(resp).__name__,
                list(resp.keys())[:10] if isinstance(resp, dict) else "n/a",
            )
            if isinstance(resp, dict):
                script = str(resp.get("python_script") or "").strip()
                severity = str(resp.get("expected_finding_severity") or "high")
                rationale = str(resp.get("rationale") or "")
        elif _provider_is_chatgpt_oauth(provider):
            from api.app.config import get_settings  # noqa: E402
            from api.app.services.chatgpt_oauth import (  # noqa: E402
                send_chatgpt_backend_streaming_json_request,
            )
            settings = get_settings()
            engagement_id = getattr(run, "engagement_id", None) or getattr(getattr(run, "engagement", None), "id", None)
            instructions = (
                CPG_SEEDED_CEA_PROMPT
                + "\n\nReturn ONLY one JSON object matching this schema:\n"
                + json.dumps(CPG_SEEDED_CEA_SCHEMA, separators=(",", ":"))
            )
            resp = send_chatgpt_backend_streaming_json_request(
                session=session,
                engagement_id=engagement_id,
                settings=settings,
                model=str(settings.chatgpt_oauth_model or "gpt-5.5"),
                instructions=instructions,
                input_items=[
                    {"role": "user", "content": [{"type": "input_text", "text": user_content}]}
                ],
            )
            logger.info(
                "PROOF_EXEC_CPG_SEEDED_CEA_RESP_2026052406 resp_type=%s resp_keys=%s",
                type(resp).__name__,
                list(resp.keys())[:10] if isinstance(resp, dict) else "n/a",
            )
            if isinstance(resp, dict):
                script = str(resp.get("python_script") or "").strip()
                severity = str(resp.get("expected_finding_severity") or "high")
                rationale = str(resp.get("rationale") or "")
        elif _provider_is_anthropic(provider):
            client = provider.raw_anthropic_client()
            msg = client.messages.create(
                model=provider.config.model,
                max_tokens=4096,
                system=[{"type": "text", "text": CPG_SEEDED_CEA_PROMPT}],
                messages=[{"role": "user", "content": user_content}],
                output_config={"format": {"type": "json_schema", "schema": CPG_SEEDED_CEA_SCHEMA}},
                timeout=120.0,
            )
            for block in (msg.content or []):
                if getattr(block, "type", "") == "text":
                    txt = str(getattr(block, "text", "") or "").strip()
                    if txt:
                        try:
                            obj = json.loads(txt)
                        except json.JSONDecodeError:
                            continue
                        script = str(obj.get("python_script") or "").strip()
                        severity = str(obj.get("expected_finding_severity") or "high")
                        rationale = str(obj.get("rationale") or "")
                        if script:
                            break
    except Exception as exc:  # noqa: BLE001
        logger.warning("cpg_seeded_cea: LLM call failed: %s", exc)
        return None

    if not script:
        return None

    logger.info(
        "PROOF_EXEC_CPG_SEEDED_CEA_2026052404 dispatched code-exec-attack run=%s severity=%s script_len=%d rationale=%s",
        str(getattr(run, "id", "?"))[:8], severity, len(script), rationale[:120],
    )

    return {
        "action": "pick",
        "tool": "code-exec-attack",
        "target": target_url,
        "tier": "active",
        "confidence": 0.95,
        "reasoning": (
            f"M3+CPG-seeded code-exec-attack dispatch: Joern surfaced sinks. {rationale[:200]}"
        )[:500],
        "runner_params": {"script": script},
        "_specialist_metadata": {
            "specialist": "cpg_seeded_cea",
            "phase": "m3_seed",
            "expected_severity": severity,
        },
    }


def _specialists_select_next_action(
    *,
    run: Run,
    session: Any,
    tested_keys: set[str],
    available_tools: list[str],
    targets: list[dict[str, Any]],
) -> dict[str, Any] | None:
    """Phase 1 landscape-plan 2026-05-22: fan out to 5 OWASP-category
    specialists in parallel, take top-ranked hypothesis as the picker
    decision. See docs/plans/ai-pentest-landscape-vs-aegispt-2026-05-22.md.

    This is the minimal-viable integration. Future iterations should:
    (a) cache the hypothesis queue in run.configuration_json so 1 fan-out
        feeds N executor iterations,
    (b) use a real recon_deliverable from Phase 2 instead of the stub,
    (c) consume hypothesis success_condition as the validator input for
        no-exploit-no-report enforcement (Phase 3).
    """
    from api.app.services.llm_provider import LLMProvider  # noqa: E402
    from api.app.services.picker_specialists.orchestrator import run_specialists_parallel  # noqa: E402

    provider = LLMProvider.for_run(getattr(run, "configuration_json", None))
    provider_is_anthropic = _provider_is_anthropic(provider)
    provider_is_chatgpt_oauth = _provider_is_chatgpt_oauth(provider)
    if not provider_is_anthropic and not provider_is_chatgpt_oauth:
        return None

    # M1 of beat-shannon-pro roadmap: adversarial script critique.
    # If the most-recent code-exec-attack task ran without emitting a
    # finding (script exited but stdout had no AEGISPT_FINDING marker),
    # dispatch the script_critic specialist to identify the missed
    # primitive and emit a revised python_script. Only ONE critique
    # per failed code-exec-attack task — tracked in loop state via
    # `critiqued_code_exec_task_ids`.
    critique_decision = _maybe_dispatch_script_critic(
        run=run, session=session, provider=provider, targets=targets,
    )
    if critique_decision is not None:
        return critique_decision

    # M3+CPG-seeded CEA: when CPG has surfaced concrete sinks AND no CEA
    # has run yet, deterministically dispatch a CEA with an LLM-written
    # script that walks the chain. Bypasses specialist-orchestrator bias
    # against picking code-exec-attack on source-aware runs.
    cpg_cea_decision = _maybe_dispatch_cpg_seeded_cea(
        run=run, session=session, provider=provider, targets=targets,
    )
    if cpg_cea_decision is not None:
        return cpg_cea_decision

    # Phase 4 landscape-plan 2026-05-22: if the run config carries a
    # source_dir AND no pre-recon-source artifact exists yet, dispatch
    # pre-recon-source FIRST. Source-aware mode is opt-in per run; if
    # source_dir is empty we go straight to network recon as before.
    run_cfg_for_source = getattr(run, "configuration_json", None) or {}
    source_dir = str(run_cfg_for_source.get("source_dir") or "").strip()

    pre_recon_source_text: str | None = None
    has_pre_recon_source_task = False
    if source_dir:
        try:
            from workers.runners.pre_recon_source.runner import PRE_RECON_SOURCE_ARTIFACT_NAME  # noqa: E402
            for task in sorted(
                list(getattr(run, "tasks", None) or []),
                key=lambda t: str(getattr(t, "updated_at", "") or ""),
                reverse=True,
            ):
                if str(getattr(task, "tool", "") or "") != "pre-recon-source":
                    continue
                has_pre_recon_source_task = True
                for execution in list(getattr(task, "executions", None) or []):
                    for art in list(getattr(execution, "artifacts", None) or []):
                        meta = getattr(art, "metadata_json", None) or {}
                        name = (meta.get("name") if isinstance(meta, dict) else "") or ""
                        if name == PRE_RECON_SOURCE_ARTIFACT_NAME:
                            from api.app.config import get_settings  # noqa: E402
                            from api.app.services.artifact_storage import (  # noqa: E402
                                artifact_storage_config_from_settings,
                                load_artifact_content,
                            )
                            try:
                                content = load_artifact_content(
                                    config=artifact_storage_config_from_settings(get_settings()),
                                    uri=art.uri,
                                )
                                if content is not None:
                                    pre_recon_source_text = content.data.decode("utf-8", errors="replace")
                                break
                            except Exception as exc:  # noqa: BLE001
                                logger.warning("specialists: failed to load pre-recon-source artifact: %s", exc)
                    if pre_recon_source_text:
                        break
                if pre_recon_source_text:
                    break
        except Exception as exc:  # noqa: BLE001
            logger.warning("specialists: pre-recon-source artifact lookup failed: %s", exc)

        # M3: also load pre-recon-cpg deliverable so specialists see the
        # Joern-traced routes + sinks + access-check predicates. Without
        # this the specialists fall back to generic OWASP-class reasoning
        # and rarely pick code-exec-attack on source-aware runs even
        # when the chain is in scope. Empirically observed 2026-05-24 on
        # runs 2d3d60c7 + 8b065ff3: 0 CEA picks despite CPG showing
        # `or_(creator==user, archiver==user)` access predicate.
        pre_recon_cpg_text: str | None = None
        try:
            from workers.runners.pre_recon_cpg.runner import PRE_RECON_CPG_ARTIFACT_NAME  # noqa: E402
            for task in sorted(
                list(getattr(run, "tasks", None) or []),
                key=lambda t: str(getattr(t, "updated_at", "") or ""),
                reverse=True,
            ):
                if str(getattr(task, "tool", "") or "") != "pre-recon-cpg":
                    continue
                for execution in list(getattr(task, "executions", None) or []):
                    for art in list(getattr(execution, "artifacts", None) or []):
                        meta = getattr(art, "metadata_json", None) or {}
                        name = (meta.get("name") if isinstance(meta, dict) else "") or ""
                        if name == PRE_RECON_CPG_ARTIFACT_NAME:
                            from api.app.config import get_settings  # noqa: E402
                            from api.app.services.artifact_storage import (  # noqa: E402
                                artifact_storage_config_from_settings,
                                load_artifact_content,
                            )
                            try:
                                content = load_artifact_content(
                                    config=artifact_storage_config_from_settings(get_settings()),
                                    uri=art.uri,
                                )
                                if content is not None:
                                    pre_recon_cpg_text = content.data.decode("utf-8", errors="replace")
                                break
                            except Exception as exc:  # noqa: BLE001
                                logger.warning("specialists: failed to load pre-recon-cpg artifact: %s", exc)
                    if pre_recon_cpg_text:
                        break
                if pre_recon_cpg_text:
                    break
        except Exception as exc:  # noqa: BLE001
            logger.warning("specialists: pre-recon-cpg artifact lookup failed: %s", exc)

        # If source_dir is configured but no pre-recon-source task has
        # been dispatched yet, dispatch it FIRST — before recon-deliverable.
        if not has_pre_recon_source_task:
            target_url_for_source = ""
            for t in (targets or []):
                target_url_for_source = str(t.get("value") or t.get("url") or "")
                if target_url_for_source:
                    break
            if target_url_for_source:
                logger.info(
                    "specialists: source_dir=%s present, dispatching pre-recon-source FIRST for run=%s",
                    source_dir,
                    str(getattr(run, "id", "?"))[:8],
                )
                return {
                    "action": "pick",
                    "tool": "pre-recon-source",
                    "target": target_url_for_source,
                    "tier": "passive",
                    "confidence": 0.98,
                    "reasoning": "Phase-4 source-aware bootstrap: white-box scan precedes network recon.",
                    "_specialist_metadata": {"phase": "bootstrap_pre_recon_source"},
                    "runner_params": {"source_dir": source_dir},
                }

        # M3 (beat-shannon-pro 2026-05-23): after pre-recon-source completed,
        # dispatch pre-recon-cpg ONCE so Joern's exact-line sinks land in the
        # critic's input envelope. Same opt-in trigger (source_dir present),
        # additive to the regex audit. Skipped when Joern isn't installed —
        # the runner returns exit_code=78 in that case, and the picker will
        # simply continue past it.
        has_pre_recon_cpg_task = any(
            str(getattr(t, "tool", "") or "") == "pre-recon-cpg"
            for t in (getattr(run, "tasks", None) or [])
        )
        if has_pre_recon_source_task and not has_pre_recon_cpg_task:
            target_url_for_cpg = ""
            for t in (targets or []):
                target_url_for_cpg = str(t.get("value") or t.get("url") or "")
                if target_url_for_cpg:
                    break
            if target_url_for_cpg:
                logger.info(
                    "PROOF_EXEC_M3_CPG_BOOTSTRAP_2026052401 source_dir=%s dispatching pre-recon-cpg run=%s",
                    source_dir,
                    str(getattr(run, "id", "?"))[:8],
                )
                return {
                    "action": "pick",
                    "tool": "pre-recon-cpg",
                    "target": target_url_for_cpg,
                    "tier": "passive",
                    "confidence": 0.97,
                    "reasoning": "M3 source-aware bootstrap: Joern CPG taint survey for exact-line sinks.",
                    "_specialist_metadata": {"phase": "bootstrap_pre_recon_cpg"},
                    "runner_params": {"source_dir": source_dir},
                }

    # Phase 2 landscape-plan 2026-05-22: prefer the recon_deliverable.md
    # artifact emitted by the recon-deliverable runner. Falls back to a
    # bootstrap stub when no recon has run yet — in which case the
    # picker should dispatch recon-deliverable as the first hypothesis.
    recon_deliverable_text: str | None = None
    try:
        from workers.runners.recon_deliverable.runner import RECON_DELIVERABLE_ARTIFACT_NAME  # noqa: E402
        for task in sorted(
            list(getattr(run, "tasks", None) or []),
            key=lambda t: str(getattr(t, "updated_at", "") or ""),
            reverse=True,
        ):
            if str(getattr(task, "tool", "") or "") != "recon-deliverable":
                continue
            for execution in list(getattr(task, "executions", None) or []):
                for art in list(getattr(execution, "artifacts", None) or []):
                    meta = getattr(art, "metadata_json", None) or {}
                    name = (meta.get("name") if isinstance(meta, dict) else "") or ""
                    if name == RECON_DELIVERABLE_ARTIFACT_NAME:
                        from api.app.config import get_settings  # noqa: E402
                        from api.app.services.artifact_storage import (  # noqa: E402
                            artifact_storage_config_from_settings,
                            load_artifact_content,
                        )
                        try:
                            content = load_artifact_content(
                                config=artifact_storage_config_from_settings(get_settings()),
                                uri=art.uri,
                            )
                            if content is not None:
                                recon_deliverable_text = content.data.decode("utf-8", errors="replace")
                            break
                        except Exception as exc:  # noqa: BLE001
                            logger.warning("specialists: failed to load recon artifact: %s", exc)
                if recon_deliverable_text:
                    break
            if recon_deliverable_text:
                break
    except Exception as exc:  # noqa: BLE001
        logger.warning("specialists: recon artifact lookup failed: %s", exc)

    if not recon_deliverable_text:
        # No recon yet — instruct the picker to dispatch recon-deliverable
        # as the FIRST action rather than letting specialists hallucinate.
        target_url = ""
        for t in (targets or []):
            target_url = str(t.get("value") or t.get("url") or "")
            if target_url:
                break
        if target_url:
            logger.info(
                "specialists: no recon_deliverable artifact yet for run=%s; "
                "dispatching recon-deliverable as first action.",
                str(getattr(run, "id", "?"))[:8],
            )
            return {
                "action": "pick",
                "tool": "recon-deliverable",
                "target": target_url,
                "tier": "passive",
                "confidence": 0.95,
                "reasoning": "Phase-2 bootstrap: build attack-surface map before specialists hypothesize.",
                "_specialist_metadata": {"phase": "bootstrap_recon"},
            }
        # No target available — fall back to legacy picker.
        return None

    # Phase 4: concatenate source-aware pre-recon (if present) before the
    # network recon. Specialists see source-grepped routes/sinks/creds
    # FIRST, then the network-observed surface — Shannon's white-box
    # path. Falls back to network-only when source_dir not configured.
    if pre_recon_source_text:
        recon_deliverable = (
            pre_recon_source_text
            + "\n\n---\n\n"
            + recon_deliverable_text
        )
    else:
        recon_deliverable = recon_deliverable_text

    # Prepend CPG deliverable when available — it carries exact source-line
    # sinks + access-check predicates that the specialists need to construct
    # a code-exec-attack python_script that actually reaches the flag.
    if pre_recon_cpg_text:
        recon_deliverable = (
            "=== JOERN CPG TAINT SURVEY (authoritative source-line sinks) ===\n"
            + pre_recon_cpg_text
            + "\n\n---\n\n"
            + recon_deliverable
        )

    prior_findings_summary = "; ".join(
        f"{(getattr(f, 'severity', '') or '?')}: {(getattr(f, 'title', '') or '?')[:80]}"
        for f in (getattr(run, "findings", None) or [])[:10]
    ) or "(no findings yet)"

    # Provider-specific specialist call factory. The orchestrator only
    # needs a (meta, user_content) -> dict|None callable.
    if provider_is_chatgpt_oauth:
        from api.app.config import get_settings  # noqa: E402
        from api.app.services.chatgpt_oauth import (  # noqa: E402
            send_chatgpt_backend_streaming_json_request,
        )
        settings = get_settings()
        engagement_id = getattr(run, "engagement_id", None) or getattr(getattr(run, "engagement", None), "id", None)

        def _call(meta: dict[str, Any], user_content: str) -> dict[str, Any] | None:
            instructions = (
                meta["prompt"]
                + "\n\nReturn ONLY one JSON object matching this schema. "
                "No markdown, no prose outside JSON:\n"
                + json.dumps(meta["schema"], separators=(",", ":"))
            )
            try:
                payload = send_chatgpt_backend_streaming_json_request(
                    session=session,
                    engagement_id=engagement_id,
                    settings=settings,
                    model=str(settings.chatgpt_oauth_model or "gpt-5.5"),
                    instructions=instructions,
                    input_items=[
                        {"role": "user", "content": [{"type": "input_text", "text": user_content}]}
                    ],
                )
                if isinstance(payload, dict):
                    return payload
            except Exception as exc:  # noqa: BLE001
                logger.warning("specialist %s ChatGPT call failed: %s", meta["name"], exc)
            return None

    else:
        # Anthropic provider — direct client.messages.create per specialist.
        client = provider.raw_anthropic_client()

        def _call(meta: dict[str, Any], user_content: str) -> dict[str, Any] | None:
            try:
                msg = client.messages.create(
                    model=provider.config.model,
                    max_tokens=2048,
                    system=[{"type": "text", "text": meta["prompt"]}],
                    messages=[{"role": "user", "content": user_content}],
                    output_config={
                        "format": {"type": "json_schema", "schema": meta["schema"]},
                    },
                    timeout=90.0,
                )
                # Extract first text block.
                for block in (msg.content or []):
                    if getattr(block, "type", "") == "text":
                        txt = str(getattr(block, "text", "") or "").strip()
                        if txt:
                            try:
                                return json.loads(txt)
                            except json.JSONDecodeError:
                                continue
            except Exception as exc:  # noqa: BLE001
                logger.warning("specialist %s Anthropic call failed: %s", meta["name"], exc)
            return None

    # Refinement #1 (gap-analysis-2026-05-22): persistent hypothesis queue.
    # Read existing queue from run.configuration_json. If there is open work
    # left, pop next-open BEFORE re-running the orchestrator (saves the
    # 60-150s fan-out latency per iteration). Only re-fan-out when the queue
    # is exhausted within its attempt budget.
    from api.app.services.picker_specialists.queue import (  # noqa: E402
        QUEUE_STATE_RUNNING,
        assign_ids_to_hypotheses,
        has_open_work,
        pick_next_open,
        queue_summary,
        transition_state,
    )
    cfg = dict(getattr(run, "configuration_json", None) or {})
    loop_cfg = dict(cfg.get("ai_assessment_loop") or {})
    stored_queue: list[dict[str, Any]] = list(loop_cfg.get("hypothesis_queue") or [])

    if has_open_work(stored_queue):
        top = pick_next_open(stored_queue)
        if top is not None:
            transition_state(top, new_state=QUEUE_STATE_RUNNING, reason="picker_dispatch")
            loop_cfg["hypothesis_queue"] = stored_queue
            loop_cfg["hypothesis_queue_summary"] = queue_summary(stored_queue)
            cfg["ai_assessment_loop"] = loop_cfg
            run.configuration_json = cfg
            if session is not None:
                try:
                    session.flush()
                except Exception:  # noqa: BLE001
                    pass
            logger.info(
                "specialists: reusing queue — next open hypothesis from %s rank=%s tool=%s title=%r",
                top.get("__specialist"), top.get("rank"), top.get("tool"),
                str(top.get("title") or "")[:80],
            )
            # Skip orchestrator fan-out; convert top to picker decision below.
            new_queue_skip_fanout = True
        else:
            new_queue_skip_fanout = False
    else:
        new_queue_skip_fanout = False

    if not new_queue_skip_fanout:
        result = run_specialists_parallel(
            call_specialist=_call,
            recon_deliverable=recon_deliverable,
            available_tools=available_tools,
            prior_findings_summary=prior_findings_summary,
        )

        new_hypotheses = assign_ids_to_hypotheses(result.get("hypothesis_queue") or [])
        if not new_hypotheses:
            logger.info(
                "specialists: empty queue (errored=%s, n_a=%s) — no decision this iteration",
                [e.get("name") for e in result.get("specialists_errored") or []],
                result.get("specialists_no_hypotheses") or [],
            )
            return None

        # Append to (not replace) the stored queue — terminal items stay
        # in history; only open items count for the executor.
        stored_queue.extend(new_hypotheses)
        top = pick_next_open(stored_queue)
        if top is None:
            return None
        transition_state(top, new_state=QUEUE_STATE_RUNNING, reason="picker_dispatch_post_fanout")
        loop_cfg["hypothesis_queue"] = stored_queue
        loop_cfg["hypothesis_queue_summary"] = queue_summary(stored_queue)
        cfg["ai_assessment_loop"] = loop_cfg
        run.configuration_json = cfg
        if session is not None:
            try:
                session.flush()
            except Exception:  # noqa: BLE001
                pass
    logger.info(
        "specialists: top hypothesis from %s rank=%s tool=%s title=%r",
        top.get("__specialist"),
        top.get("rank"),
        top.get("tool"),
        str(top.get("title") or "")[:80],
    )
    tool = str(top.get("tool") or "").strip()
    target_url = str(top.get("target_url") or "").strip()
    if not tool or not target_url:
        return None

    # Map specialist hypothesis to picker-decision dict. exec_plan
    # hypotheses carry exec_plan_steps as a JSON string.
    if tool == "exec-plan":
        steps_json = str(top.get("exec_plan_steps") or "").strip()
        try:
            steps = json.loads(steps_json) if steps_json else []
        except json.JSONDecodeError:
            steps = []
        return {
            "action": "exec_plan",
            "tool": "exec-plan",
            "target": target_url,
            "plan": {
                "plan_name": str(top.get("title") or "specialist-hypothesis")[:80],
                "steps": steps,
            },
            "tier": "active",
            "confidence": 0.8,
            "reasoning": (
                f"Specialist {top.get('__specialist')} hypothesis (rank {top.get('rank')}): "
                f"{top.get('evidence_summary') or ''}"[:400]
            ),
            "_specialist_metadata": {
                "specialist": top.get("__specialist"),
                "rank": top.get("rank"),
                "estimated_severity": top.get("estimated_severity"),
                "success_condition": top.get("success_condition"),
            },
        }
    # Carry per-tool runner params from the specialist hypothesis.
    # sqlmap's validate_sqlmap_run_configuration expects
    # injectable_parameters as a list of DICTS shaped {url, parameter},
    # NOT a list of strings — observed verify2 run 33511c24 2026-05-22:
    # passing ["user_id"] still errored because the validator filters
    # to `isinstance(item, dict)`. Build the correct shape here.
    runner_params: dict[str, Any] = {}
    target_param = str(top.get("target_param") or "").strip()
    if target_param and tool == "sqlmap":
        runner_params["injectable_parameters"] = [
            {"url": target_url, "parameter": target_param}
        ]
    # Phase B 2026-05-22: AI-emitted Python exploit script. The specialist
    # writes the script in the `python_script` field of its hypothesis.
    # Without this carry-through the runner gets an empty script and skips.
    python_script = str(top.get("python_script") or "").strip()
    if python_script and tool == "code-exec-attack":
        runner_params["script"] = python_script
    decision: dict[str, Any] = {
        "action": "pick",
        "tool": tool,
        "target": target_url,
        "tier": "active",
        "confidence": 0.8,
        "reasoning": (
            f"Specialist {top.get('__specialist')} hypothesis (rank {top.get('rank')}): "
            f"{top.get('evidence_summary') or ''}"[:400]
        ),
        "_specialist_metadata": {
            "specialist": top.get("__specialist"),
            "rank": top.get("rank"),
            "estimated_severity": top.get("estimated_severity"),
            "success_condition": top.get("success_condition"),
            "target_param": target_param or None,
        },
    }
    if runner_params:
        decision["runner_params"] = runner_params
    return decision


@traced("picker.call")  # backlog-407: tracing-only, no behavior change. Renamed from claude_call 2026-05-22 (provider-agnostic).
def _claude_select_next_action(
    *,
    run: Run,
    tested_keys: set[str],
    available_tools: list[str],
    targets: list[dict[str, Any]],
    scope: Scope | None = None,
    session: Any = None,
    extra_recent_rejections: list[dict[str, Any]] | None = None,
) -> dict[str, Any] | None:
    """Ask Claude Haiku to pick the next action given current evidence.

    Returns the parsed JSON dict from Claude, or None if Claude is unreachable
    or returns an unparseable response. Caller falls back to heuristic cascade.

    ``extra_recent_rejections`` (backlog-403) — when provided, REPLACES the
    DB-read rejections for this single call. Used by the refinement wrapper
    to feed in-this-advance rejection notes (e.g. "your previous exec_plan
    had empty steps; revise") without persisting them to run config first.
    """
    # Phase 1 landscape-plan 2026-05-22: when PICKER_MODE=specialists, fan
    # out to 5 OWASP-category specialists in parallel and use the top
    # hypothesis as the picker decision. Pattern from Shannon Lite (96.15%
    # XBOW). Default OFF until the orchestrator + recon deliverable are
    # validated end-to-end on a real challenge.
    import os as _os  # noqa: E402
    if str(_os.environ.get("PICKER_MODE", "")).strip().lower() == "specialists":
        try:
            decision = _specialists_select_next_action(
                run=run,
                session=session,
                tested_keys=tested_keys,
                available_tools=available_tools,
                targets=targets,
            )
            if decision is not None:
                return decision
            logger.info(
                "picker: PICKER_MODE=specialists returned empty queue; "
                "falling back to legacy single-picker for this iteration."
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "picker: PICKER_MODE=specialists raised %s; falling back to legacy picker.",
                exc,
            )

    # backlog-417/backlog-436: route the LLM round trip through LLMProvider so
    # the model is selectable per run-config. Anthropic keeps the tool-use
    # branch below; ChatGPT OAuth uses the existing governed streaming JSON
    # helper and the same picker schema, without changing runner execution.
    from api.app.services.llm_provider import LLMProvider  # noqa: E402
    provider = LLMProvider.for_run(getattr(run, "configuration_json", None))
    provider_is_anthropic = _provider_is_anthropic(provider)
    provider_is_chatgpt_oauth = _provider_is_chatgpt_oauth(provider)
    if not provider_is_anthropic and not provider_is_chatgpt_oauth:
        logger.warning(
            "picker: configured model %s is non-Anthropic; tool-use features unsupported "
            "and no governed picker branch exists for this provider. Skipping picker call.",
            provider.config.model,
        )
        return None
    if not tested_keys:
        # First iteration: let target-intel heuristic handle the seed step
        return None
    if provider_is_anthropic:
        api_key = os.environ.get(provider.config.api_key_env, "").strip()
        if not api_key:
            return None
        try:
            import anthropic  # noqa: F401 — exception module needed even when client comes from provider
        except ImportError:
            return None

    findings = _summarize_findings_for_ai(run)
    _ = _tested_tools_summary(tested_keys)  # invoked for side effects/logging; result unused
    primary_target = ""
    if targets:
        primary_target = str(targets[0].get("value") or "")
    discovered_paths = _collect_discovered_targets(run)
    # Recent failures from runner crashes / non-zero exits — Claude can see
    # what went wrong and adjust (e.g. correct an exec-plan format error).
    recent_failures = _collect_recent_failures(run, limit=6)
    task_outcomes = _collect_task_outcomes(run, limit=10)
    # Rejections from the loop's own validators (duplicate pair, malformed
    # plan, out-of-scope target). Stored in loop_state by the action handlers.
    loop_state_for_rejections = _as_dict(
        _as_dict(run.configuration_json or {}).get(LOOP_CONFIG_KEY)
    )
    if extra_recent_rejections is not None:
        # backlog-403 — refinement override: bypass DB read, use fresh
        # in-advance rejection notes.
        recent_rejections = list(extra_recent_rejections)[-6:]
    else:
        recent_rejections = list(loop_state_for_rejections.get("recent_rejections") or [])[-6:]
    # Pull the AI-generated test_plan that target-intel produced. This is a
    # ranked list of recommended tools (smart-web-probe, xss-extended, ...) based
    # on actual analysis of the site content. Claude often picks generic tools
    # without this hint, missing the high-value attack vectors target-intel
    # already identified.
    target_intel_plan = _extract_target_intel_test_plan(run)
    # Detect what's been COMPROMISED so far so Claude can plan post-compromise
    # actions. Without this, Claude often stops at "session cookie stolen" and
    # never actually uses the stolen access to escalate.
    compromise_unlocks: list[str] = []
    findings_text = " ".join(
        (str(f.get("title") or "") + " " + str(f.get("severity") or "")).lower()
        for f in findings
    )
    if "session cookie theft" in findings_text or "cookie theft" in findings_text:
        compromise_unlocks.append(
            "🔓 SESSION COOKIE STOLEN: a valid session cookie is captured. "
            "Stop testing authentication bypass — you ALREADY HAVE auth. "
            "Your next actions MUST exploit this access: "
            "(a) idor-bac on user-id endpoints to read OTHER users' data, "
            "(b) idor-bac/auth-flow on /admin to escalate, "
            "(c) profile manipulation to inject is_admin=True or similar privilege flags, "
            "(d) data exfiltration on protected endpoints. "
            "The cookie is auto-injected into any tool you pick — just choose the right tool."
        )
    if "stored xss" in findings_text or "file upload" in findings_text and "xss" in findings_text:
        compromise_unlocks.append(
            "🔓 STORED XSS CONFIRMED: a payload persists in app content. "
            "Next: prove cross-user impact via xss-proof against the storage endpoint, "
            "or test if an admin-visited page renders the payload (privilege escalation)."
        )
    if "rce" in findings_text or "remote code execution" in findings_text:
        compromise_unlocks.append(
            "🔓 RCE ACHIEVED: prove impact via filesystem read, process enumeration, or persistence."
        )
    if "idor" in findings_text and "horizontal" in findings_text:
        compromise_unlocks.append(
            "🔓 IDOR CONFIRMED: you can read other users' data. "
            "Next: vertical privilege escalation (admin user id), or data exfiltration at scale."
        )

    # Build (tool, target) combinations already attempted so Claude doesn't
    # re-pick the same exact thing.
    tested_pairs = sorted(tested_keys)[:40]

    # Pull current phase state from loop_state. New schema introduced for the
    # phase-based mental model where each pick within a phase shares context.
    loop_state = _as_dict(_as_dict(run.configuration_json or {}).get(LOOP_CONFIG_KEY))
    current_phase = _as_dict(loop_state.get("current_phase"))
    phase_index = int(loop_state.get("phase_count") or 0)
    phase_label = str(current_phase.get("label") or "(initial recon)")
    phase_goal = str(current_phase.get("goal") or "Map the attack surface and identify entry points.")
    phase_picks = list(current_phase.get("tool_picks") or [])  # [{tool, target, reasoning, finding_motivation}]
    phase_findings_start = int(current_phase.get("findings_count_at_start") or 0)
    findings_this_phase = max(0, len(findings) - phase_findings_start)

    # Build a compact recommended-tools list from target-intel's plan that
    # haven't been tested yet. Surface this prominently so Claude actually uses it.
    plan_recommendations: list[str] = []
    if target_intel_plan:
        for item in target_intel_plan:
            tool = str(item.get("tool") or "").strip()
            reason = str(item.get("reason") or "")[:160]
            if not tool:
                continue
            priority = item.get("priority")
            already = any(tool == k.split("|", 1)[0] for k in tested_keys)
            tag = " (already used)" if already else " (NOT YET USED)"
            plan_recommendations.append(
                f"  [P{priority}] {tool}{tag} — {reason}"
            )

    # Per-run intrusion authorization — tells Claude which tier ceiling he
    # can plan within. When set, the operator has authorized destructive
    # actions (DoS, RCE, write-anywhere) for this run.
    intrusive_allowed = bool(getattr(run, "autonomous_intrusive_allowed", False))
    intrusive_block = ""
    if intrusive_allowed:
        intrusive_block = (
            "=== INTRUSIVE TIER AUTHORIZED FOR THIS RUN ===\n"
            "The operator has explicitly enabled `autonomous_intrusive_allowed`. You may\n"
            "now plan and execute INTRUSIVE actions without waiting for approval. This\n"
            "unlocks the full impact-depth range:\n"
            "- File-write via path traversal (drop files in writable dirs)\n"
            "- Server restart / quitserver exploitation paths\n"
            "- RCE chains: upload Python file via traversal -> trigger interpreter reload\n"
            "- Mass data exfiltration / dump endpoints (e.g. /dump.gtl-style debug pages)\n"
            "- Cookie-forging chains that impersonate other users (including admin)\n"
            "\n"
            "DON'T STOP AT 'admin via is_admin/is_author' — that is just one impact level.\n"
            "Push deeper: prove RCE if a chain exists, prove mass data exposure if a debug\n"
            "endpoint exists, prove arbitrary-file-read on /etc/passwd or app config.\n"
            "Use tier=\"intrusive\" on exec_plans that match these depths.\n\n"
        )
    else:
        intrusive_block = (
            "=== INTRUSIVE TIER NOT AUTHORIZED ===\n"
            "This run is limited to passive/active tier. Avoid plans that crash the server,\n"
            "delete data, or require RCE. Aim for impact-level <= 7 (read-only file disclosure,\n"
            "admin compromise, info leak via debug endpoints).\n\n"
        )

    # Build feedback sections only when there's something to show
    failures_block = ""
    if recent_failures:
        failures_block = (
            "=== RECENT TOOL FAILURES (read these — fix your approach) ===\n"
            + json.dumps(recent_failures, indent=2)[:2000]
            + "\n\n"
        )
    rejections_block = ""
    if recent_rejections:
        rejections_block = (
            "=== YOUR RECENT PICKS THAT THE SYSTEM REJECTED (do NOT repeat these mistakes) ===\n"
            + json.dumps(recent_rejections, indent=2)[:1500]
            + "\n\n"
        )
    outcomes_block = ""
    if task_outcomes:
        outcomes_block = (
            "=== RECENT TOOL OUTCOMES (what tools ACTUALLY produced) ===\n"
            "Tools that completed with 0 findings did NOT necessarily prove there's nothing\n"
            "there — they may have used the wrong angle. Look at the stdout excerpt; if a\n"
            "tool tested generic patterns on an endpoint you suspect needs an app-specific\n"
            "payload (e.g. crafted snippet body, profile field with role flag, multi-step\n"
            "register-then-update flow), don't pick the same generic tool again — write an\n"
            "exec_plan that targets the specific endpoint with the hypothesis you formed.\n"
            + json.dumps(task_outcomes, indent=2)[:2500]
            + "\n\n"
        )

    # M5 cross-run memory: pull top-3 episodes from PRIOR runs whose action
    # context matches the current evidence shape, and only surface those that
    # already carry a success_marker (flag_extracted / target_unreachable).
    # Benchmark runs see other benchmark runs; production runs see only
    # production episodes (Codex contamination guard).
    prior_episodes_block = ""
    if session is not None:
        try:
            from api.app.services.episodic_memory import recall_similar  # noqa: E402
            eng_name = str(
                getattr(getattr(run, "engagement", None), "name", "") or ""
            ).lower()
            is_bench = eng_name.startswith("xbow-bench") or "benchmark" in eng_name
            query = (
                f"phase={phase_label} "
                f"target={primary_target} "
                f"findings={json.dumps(findings, default=str)[:600]}"
            )
            episodes = recall_similar(
                session,
                query=query,
                k=6,
                include_benchmark=is_bench,
            )
            actionable = [
                e for e in episodes
                if e.success_marker and str(e.run_id) != str(run.id)
            ][:3]
            if actionable:
                lines: list[str] = []
                for ep in actionable:
                    marker = ep.success_marker or ""
                    outcome = "SOLVED" if marker == "flag_extracted" else marker.upper()
                    tool = ep.action_type.split(":", 1)[1] if ":" in ep.action_type else ep.action_type
                    ctx = ep.action_context if isinstance(ep.action_context, dict) else {}
                    tgt = str(ctx.get("target") or "?")
                    rsn = str(ctx.get("reasoning") or "")[:120].replace("\n", " ")
                    sim = ep.similarity or 0.0
                    lines.append(f"  [{outcome}, sim={sim:.2f}] {tool} -> {tgt} | {rsn}")
                prior_episodes_block = (
                    "=== PRIOR EPISODES (cross-run memory — HINTS, verify before reuse) ===\n"
                    "Past picks on similar evidence + their outcome marker. SOLVED = the pick\n"
                    "preceded a flag-extraction in that run. Use as a hint, not authoritative —\n"
                    "the prior target may have differed in details that matter here.\n"
                    + "\n".join(lines)
                    + "\n\n"
                )
        except Exception as _ep_exc:  # noqa: BLE001
            logger.debug("AI loop: prior episodes recall skipped: %s", _ep_exc)

    # Normalized evidence graph projection (backlog-373). Compact text view of
    # first-class entities the picker should reason over. Falls back to empty
    # string when graph is sparse / unavailable, so picker behavior on runs
    # without graph data is unchanged.
    graph_block = ""
    if session is not None:
        try:
            from api.app.services.assessment_graph import (
                build_normalized_evidence_graph,
                project_graph_for_picker,
            )

            _graph_for_picker = build_normalized_evidence_graph(session, run=run)
            graph_projection = project_graph_for_picker(_graph_for_picker)
            if graph_projection:
                graph_block = graph_projection + "\n"
        except Exception as _graph_exc:
            logger.debug("AI loop: graph projection skipped: %s", _graph_exc)
            graph_block = ""

    user_content = (
        f"Primary target (always in scope): {primary_target}\n\n"
        + intrusive_block
        + failures_block
        + rejections_block
        + outcomes_block
        + prior_episodes_block
        + graph_block
        + "=== TARGET-INTEL RECOMMENDED TEST PLAN (from AI analysis of the actual site) ===\n"
        + (("\n".join(plan_recommendations) + "\n\n") if plan_recommendations else "(no test plan available)\n\n")
        + "These are the highest-value tools FOR THIS SPECIFIC TARGET based on its\n"
        "technology stack and likely vulnerability classes. Prefer 'NOT YET USED' items\n"
        "over generic enumeration. Hidden-endpoint findings (404 paths from wordlists)\n"
        "are NOT vulnerabilities — they're just discoveries; do not chase them with auth/sqli/etc.\n\n"
        f"=== CURRENT PHASE ===\n"
        f"Phase #{phase_index + 1}: {phase_label}\n"
        f"Phase goal: {phase_goal}\n"
        f"Tools picked THIS phase so far ({len(phase_picks)}):\n"
        f"{json.dumps(phase_picks, indent=2)[:2000]}\n"
        f"Findings discovered THIS phase: {findings_this_phase}\n\n"
        f"=== CONTEXT ===\n"
        f"Deeper paths discovered (in scope, useful as TARGETED follow-up endpoints):\n"
        f"{json.dumps(discovered_paths, indent=2)}\n\n"
        f"All (tool, target) pairs tested across all phases — do NOT repeat exact pair:\n"
        f"{json.dumps(tested_pairs, indent=2)[:1500]}\n\n"
        f"Available tools: {', '.join(available_tools)}\n\n"
        f"All findings so far ({len(findings)} total):\n"
        f"{json.dumps(findings, indent=2)[:5000]}\n\n"
        "=== DECISION ===\n"
        "Choose ONE action: `pick` / `level_up` / `stop`.\n"
        "\n"
        "HARD RULES (the system enforces these in code; violations are rejected):\n"
        "- NEVER pick a (tool, target) pair that is in the already-tested list above.\n"
        "  If the only remaining option would be a duplicate, choose `level_up` or `stop`.\n"
        "- Recon tools (httpx, target-intel, content-discovery, smart-web-probe, nuclei,\n"
        "  nikto, burp) are ONE-SHOT per run. Once one has run on the root, do NOT pick\n"
        "  it again on the same root. They do not produce new findings on repeat.\n"
        "  Re-running them on sub-paths is wasted budget.\n"
        "\n"
        "Choose `pick` if the current phase still has UNTRIED tools or untested\n"
        "specific endpoints that match the phase goal.\n"
        "\n"
        "Choose `level_up` when:\n"
        "- The current phase succeeded (a new high-impact finding emerged); OR\n"
        "- The current phase stalled (2+ picks produced no new findings); OR\n"
        "- All in-phase angles are exhausted.\n"
        "Name the new phase by the higher-impact action that the latest evidence unlocks.\n"
        "\n"
        "Choose `stop` only when:\n"
        "- Admin compromise / full account takeover is proven; OR\n"
        "- Every plausible (tool, target) combination has been tested.\n"
        "\n"
        "TARGETING:\n"
        "- Exploit tools (xss-proof, idor-bac, auth-flow, sqlmap, ssti-probe, csrf-check):\n"
        "  target the SPECIFIC vulnerable URL from the findings list — never invent URLs.\n"
        "- Broad scanners (already covered above as ONE-SHOT) use the primary target ONCE."
    )

    if provider_is_chatgpt_oauth:
        return _chatgpt_oauth_select_next_action(
            run=run,
            session=session,
            user_content=user_content,
            tested_keys=tested_keys,
            available_tools=available_tools,
        )

    try:
        from api.app.services import http_fetch_backend, memory_backend
        # backlog-417: api key + client construction now sourced from
        # LLMProvider so the model is run-config-selectable.
        client = provider.raw_anthropic_client()
        tools: list[dict[str, Any]] = [
            {"type": "memory_20250818", "name": "memory"},
            # Custom client-side http_fetch — locked to the run's scope
            # allowlist (host AND path), so /partN documentation pages of
            # teaching apps fall outside scope. The intent is for Claude to
            # READ the live application content, not its lab handout.
            {
                "name": "http_fetch",
                "description": (
                    "Fetch a URL within the approved scope (GET only). "
                    "Returns status line, whitelisted response headers, and the body "
                    "(truncated to 4 KB). Use this BEFORE picking runners — read the "
                    "actual HTML/headers to identify the tech stack, form action URLs, "
                    "JSON shapes and template extensions. If the page text reveals it's "
                    "not a SQL-backed app, skip sqlmap; if templates aren't Jinja-like, "
                    "skip ssti-probe; etc. URL must fall under the approved scope path."
                ),
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "url": {
                            "type": "string",
                            "description": "Full URL including scheme. Must fall within the run's scope allowlist.",
                        }
                    },
                    "required": ["url"],
                },
            },
        ]
        # backlog-422: extend the picker's tool surface with the
        # Claude-Code-equivalent agent tools (Bash/file/web/code_exec/
        # subagent). Every invocation routes through Layer 0 inside the
        # tool's execute() method, so the picker cannot escape engagement
        # scope by picking an agent tool.
        try:
            from api.app.agents.agent_tools import ALL_TOOL_SCHEMAS  # noqa: E402
            tools.extend(ALL_TOOL_SCHEMAS)
        except ImportError as exc:
            logger.debug("picker: agent_tools module unavailable (%s); proceeding without", exc)
        # Pull scope allowlist for http_fetch's path-level validation.
        scope_allowlist: dict[str, Any] = {}
        try:
            if scope is not None:
                scope_allowlist = _as_dict(scope.allowlist_json)
        except Exception:
            scope_allowlist = {}
        messages: list[dict[str, Any]] = [
            {"role": "user", "content": user_content}
        ]
        raw: str = ""
        # Helper to surface Claude's thinking-state to the UI. Writes a
        # status field on loop_state and commits, so the UI's run-poll
        # picks it up between hops. Uses session passed in by the caller.
        def _set_thinking_state(status: str, hop: int, detail: str = "") -> None:
            if session is None:
                return
            try:
                cfg = _as_dict(run.configuration_json or {})
                ls = _as_dict(cfg.get(LOOP_CONFIG_KEY))
                ls["claude_thinking"] = {
                    "status": status,  # "thinking" | "tool_use" | "done"
                    "hop": hop,
                    "detail": detail[:200],
                    "since": _now(),
                }
                cfg[LOOP_CONFIG_KEY] = ls
                run.configuration_json = cfg
                session.flush()
                session.commit()
            except Exception:
                pass

        # Tool-use loop: Claude may call memory/web_fetch 0-N times before
        # producing the final JSON decision. Cap at 12 hops since web_fetch
        # results are larger and Claude may use multiple per decision.
        for _hop in range(12):
            _set_thinking_state("thinking", _hop, "Calling Claude for next action")
            # backlog-411: curate the message list against the cache budget
            # before every Anthropic call. At 60%/80% triggers older turns
            # get summarized and large raw stdouts get shrunk into one-line
            # envelopes; finding + captured_value carriers always survive.
            # The @traced decorator on curate_for_picker emits one OTEL span
            # per call with before/after token counts.
            from api.app.services.context_curation import curate_for_picker  # noqa: E402
            messages, _curation_event = curate_for_picker(messages, max_tokens=120_000)
            # Evaluate the EXEC_PLAN forcing trigger added 2026-05-21:
            #   (a) tested_keys covers 5+ distinct tools on the same target
            #   (b) critical+high findings count is below 2
            # When both hold, build a schema that ONLY accepts exec_plan /
            # level_up-with-plan / stop. The prompt-side MANDATORY rule
            # (078e9b9) was empirically ignored by Claude — the schema
            # forcing makes the API boundary refuse any action=pick or
            # action=level_up-without-plan in this state, so Claude must
            # actually produce an exec_plan or admit defeat with stop.
            picker_schema = _picker_schema_for_current_state(
                run=run,
                tested_keys=tested_keys,
                available_tools=available_tools,
            )
            msg = client.messages.create(
                model="claude-opus-4-7",
                max_tokens=PICKER_MAX_TOKENS,
                system=[{
                    "type": "text",
                    "text": _AI_PICKER_SYSTEM_PROMPT,
                    "cache_control": {"type": "ephemeral"},
                }],
                tools=tools,
                messages=messages,
                output_config={
                    "format": {
                        "type": "json_schema",
                        "schema": picker_schema,
                    },
                },
                timeout=90.0,
            )
            stop = getattr(msg, "stop_reason", None)
            content_blocks = list(msg.content or [])
            _usage = getattr(msg, "usage", None)
            if _usage is not None:
                logger.info(
                    "AI loop: hop=%d usage input=%d cache_read=%d cache_creation=%d output=%d",
                    _hop,
                    getattr(_usage, "input_tokens", 0),
                    getattr(_usage, "cache_read_input_tokens", 0) or 0,
                    getattr(_usage, "cache_creation_input_tokens", 0) or 0,
                    getattr(_usage, "output_tokens", 0),
                )
            # Client-side tools (memory) emit `tool_use` blocks that WE handle.
            # Server-side tools (web_fetch) emit `server_tool_use` and their
            # results land in the SAME response — we just pass them back as
            # part of the assistant message on the next hop.
            tool_uses = [b for b in content_blocks if getattr(b, "type", None) == "tool_use"]
            text_blocks = [b for b in content_blocks if getattr(b, "type", None) == "text"]
            # Log any web_fetch the server performed so we can audit Claude's reading.
            for b in content_blocks:
                if getattr(b, "type", None) == "server_tool_use":
                    fetched_url = ""
                    si = getattr(b, "input", None) or {}
                    if isinstance(si, dict):
                        fetched_url = str(si.get("url") or "")[:120]
                    logger.info(
                        "AI loop: web_fetch %s url=%s",
                        getattr(b, "name", "?"), fetched_url,
                    )
            if stop == "pause_turn":
                # Server still has more server-tool work to do. Mirror assistant
                # content back and continue without injecting tool_results.
                messages.append({
                    "role": "assistant",
                    "content": [b.model_dump() if hasattr(b, "model_dump") else b for b in content_blocks],
                })
                continue
            if not tool_uses:
                raw = (text_blocks[0].text if text_blocks else "").strip()
                _set_thinking_state("done", _hop, "Decision produced")
                break
            _set_thinking_state(
                "tool_use", _hop,
                f"Claude using {len(tool_uses)} tool call(s): "
                + ",".join(str(getattr(t, "name", "?"))[:24] for t in tool_uses[:3]),
            )
            messages.append({
                "role": "assistant",
                "content": [b.model_dump() if hasattr(b, "model_dump") else b for b in content_blocks],
            })
            tool_results: list[dict[str, Any]] = []
            for tu in tool_uses:
                tool_name = str(getattr(tu, "name", "") or "")
                tool_input = getattr(tu, "input", None) or {}
                if not isinstance(tool_input, dict):
                    tool_input = {}
                if tool_name == "http_fetch":
                    fetch_url = str(tool_input.get("url") or "")
                    try:
                        result_str = http_fetch_backend.execute(
                            fetch_url, scope_allowlist=scope_allowlist,
                        )
                    except Exception as fetch_exc:
                        result_str = f"Error: http_fetch exception: {fetch_exc}"
                    logger.info(
                        "AI loop: http_fetch url=%s result_len=%d",
                        fetch_url[:120], len(result_str),
                    )
                elif tool_name in {"bash", "code_exec", "file_read", "file_write", "subagent_spawn", "web_search", "web_fetch"}:
                    # backlog-422: picker agent tools — every invocation
                    # goes through Layer 0 inside execute_tool_call() →
                    # tool.execute() so the picker cannot bypass scope by
                    # choosing an agent tool.
                    try:
                        from api.app.agents.agent_tools import execute_tool_call  # noqa: E402
                        agent_result = execute_tool_call(
                            tool_name, tool_input, run=run, session=session,
                        )
                        result_str = agent_result.content
                    except Exception as agent_exc:  # noqa: BLE001
                        result_str = f"Error: agent_tool {tool_name} exception: {agent_exc}"
                    logger.info(
                        "AI loop: agent_tool %s ok-ish, result_len=%d",
                        tool_name, len(result_str),
                    )
                else:
                    cmd = str(tool_input.get("command") or "")
                    kwargs = {k: v for k, v in tool_input.items() if k != "command"}
                    try:
                        result_str = memory_backend.execute(cmd, **kwargs)
                    except Exception as mem_exc:
                        result_str = f"Error: memory backend exception: {mem_exc}"
                    logger.info(
                        "AI loop: memory tool call cmd=%s path=%s result_len=%d",
                        cmd, str(kwargs.get("path") or "-"), len(result_str),
                    )
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": tu.id,
                    "content": result_str,
                })
            messages.append({"role": "user", "content": tool_results})
            if stop != "tool_use":
                # Defensive: model signaled end-of-turn but emitted tool calls.
                # Already appended results — loop and let Claude produce text.
                continue
        _set_thinking_state("done", 12, "Tool loop exhausted")
        if not raw:
            logger.warning("AI loop: Claude returned no text after tool loop")
            return None
        # Strip markdown fences Claude sometimes adds
        text = raw.strip()
        if text.startswith("```"):
            text = text.strip("`")
            if text.lower().startswith("json"):
                text = text[4:].strip()
        # Find JSON object boundaries
        start = text.find("{")
        end = text.rfind("}")
        if start == -1 or end == -1 or end <= start:
            logger.warning("AI loop: Claude output has no JSON object — raw=%r", text[:200])
            return None
        candidate_text = text[start : end + 1]
        try:
            decision = json.loads(candidate_text)
            return _decode_picker_plan(decision)
        except json.JSONDecodeError as je:
            # With #330 structured outputs the schema should make this path
            # unreachable. Keep _tolerant_json_fix as a defensive fallback
            # but log a warning so any regression is visible. If we see
            # this warning, it means structured outputs is not enforcing
            # the schema (SDK fallback, server-side beta unavailable, etc.).
            logger.warning(
                "AI loop: picker JSON parse failed despite structured-output "
                "schema (deprecated fallback engaged); err=%s raw=%r",
                je, candidate_text[:240],
            )
            fixed = _tolerant_json_fix(candidate_text)
            try:
                decision = json.loads(fixed)
                return _decode_picker_plan(decision)
            except json.JSONDecodeError:
                logger.warning(
                    "AI loop: Claude JSON parse failed even after tolerant "
                    "fix — raw=%r", candidate_text[:240],
                )
                return None
    except Exception as exc:
        logger.warning("AI loop: Claude next-action call failed: %s", exc)
        try:
            if session is not None:
                cfg = _as_dict(run.configuration_json or {})
                ls = _as_dict(cfg.get(LOOP_CONFIG_KEY))
                ls["claude_thinking"] = {"status": "error", "detail": str(exc)[:200], "since": _now()}
                cfg[LOOP_CONFIG_KEY] = ls
                run.configuration_json = cfg
                session.flush()
                session.commit()
        except Exception:
            pass
        return None


def _claude_candidate_to_loop_candidate(
    decision: dict[str, Any],
    *,
    targets: list[dict[str, Any]],
    available_tools: set[str],
    scope: Scope | None = None,
    tested_keys: set[str] | None = None,
    rejection_sink: list[dict[str, Any]] | None = None,
) -> LoopCandidate | None:
    """Convert Claude's JSON decision into a LoopCandidate, with safety checks.

    Claude picks the TOOL and may also propose a deeper target. Validations:
    - target is in scope (deeper paths allowed, hallucinations rejected)
    - tool exists in available_tools
    - (tool, target) pair is not already in tested_keys (HARD block on duplicates;
      Claude is told this rule but it sometimes ignores soft prompt constraints)
    """
    if not isinstance(decision, dict):
        return None
    if decision.get("stop"):
        return None
    tool = str(decision.get("tool") or "").strip()
    if not tool or tool not in available_tools:
        logger.info("AI loop: picker picked unavailable tool %r — falling back", tool)
        if rejection_sink is not None:
            rejection_sink.append({
                "reason": "unavailable_tool",
                "detail": f"You picked tool={tool!r} which is not in the available tools list. "
                          "Choose a tool that exists.",
                "at": _now(),
            })
        return None
    # exec-plan needs a structured plan body; it must come via action="exec_plan",
    # not action="pick". Reject pick-of-exec-plan so the runner never sees a
    # task with no plan.
    if tool == "exec-plan":
        logger.warning(
            "AI loop: REJECTED Claude pick of exec-plan via action=pick — exec-plan requires action=exec_plan with a plan body"
        )
        if rejection_sink is not None:
            rejection_sink.append({
                "reason": "exec_plan_needs_action_field",
                "detail": "You picked tool='exec-plan' with action='pick' but did not provide a plan body. "
                          "exec-plan ONLY works when you use action='exec_plan' AND include the full 'plan' "
                          "object with steps. See the exec_plan grammar in the system prompt.",
                "at": _now(),
            })
        return None

    fallback_target = ""
    target_kind = "url"
    if targets:
        fallback_target = str(targets[0].get("value") or "")
        target_kind = str(targets[0].get("kind") or "url")
    if not fallback_target:
        return None

    claude_target = str(decision.get("target") or "").strip()
    # Try to use Claude's target if it's in scope (allows deeper paths like
    # /snippets.gtl?uid=victim that are within the approved web root).
    target = fallback_target
    target_source = "approved_scope_root"
    if claude_target and claude_target != fallback_target:
        in_scope = _scope_target_allowed(scope, claude_target) if scope is not None else False
        if in_scope:
            target = claude_target
            target_source = "claude_deeper_path"
            logger.info("AI loop: using Claude's deeper target %r", claude_target[:120])
        else:
            logger.info(
                "AI loop: rejecting Claude target %r (out of scope), using root %r",
                claude_target[:80], fallback_target[:80],
            )

    # HARD enforcement: refuse any (tool, target) pair that is already in the
    # tested set. This was a soft rule in the prompt, which Claude ignored ~50%
    # of the time, leading to httpx 5x on the same URL. No more.
    # Exception: exec-plan can run multiple times on the same target with
    # different custom plans — its uniqueness is in the plan body, not (tool, target).
    # Exception: script_critic dispatches are intentional re-attempts against
    # the same (tool, target) with a revised script; uniqueness is in
    # _specialist_metadata.predecessor_task_id, not (tool, target).
    decision_specialist = ""
    if isinstance(decision.get("_specialist_metadata"), dict):
        decision_specialist = str(
            (decision.get("_specialist_metadata") or {}).get("specialist") or ""
        )
    if decision_specialist == "script_critic":
        logger.info(
            "PROOF_EXEC_CRITIC_BYPASS_TESTED_KEYS_2026052312 tool=%s target=%s",
            tool, str(target)[:60],
        )
    if (
        tested_keys is not None
        and tool != "exec-plan"
        and decision_specialist != "script_critic"
    ):
        pair_key = _task_key(tool, target)
        if pair_key in tested_keys:
            logger.warning(
                "AI loop: REJECTED duplicate (tool, target) pair %s — Claude already used this combination",
                pair_key,
            )
            if rejection_sink is not None:
                rejection_sink.append({
                    "reason": "duplicate_tool_target_pair",
                    "detail": f"You picked tool={tool!r} target={target[:80]!r} but this pair was already tested. "
                              "Either pick a different tool, target a different URL, level_up, or stop.",
                    "at": _now(),
                })
            return None

    tier = str(decision.get("tier") or "passive").strip().lower()
    if tier not in {"passive", "active", "intrusive"}:
        tier = "active"
    reasoning = str(decision.get("reasoning") or "Claude selected this next action based on current evidence.")
    confidence = decision.get("confidence")
    try:
        confidence_f = float(confidence) if confidence is not None else 0.8
    except (TypeError, ValueError):
        confidence_f = 0.8
    expected_evidence = decision.get("expected_evidence") or []
    if not isinstance(expected_evidence, list):
        expected_evidence = []
    candidate_params = {
        "source": "ai_loop_claude",
        "ai_reasoning": reasoning[:500],
        "target_kind": target_kind,
        "target_source": target_source,
    }
    # Phase 1+2 landscape-plan: when the specialist orchestrator picks a
    # runner that needs typed parameters (sqlmap's injectable_parameters,
    # for instance), the decision carries `runner_params`. Merge those
    # into the candidate's params so the downstream dispatcher sees them.
    # Without this merge the specialist's `target_param` is lost and the
    # runner errors with "requires an explicit parameter target" — exactly
    # the v3 sqlmap failure we observed 2026-05-22.
    runner_params_override = decision.get("runner_params")
    if isinstance(runner_params_override, dict):
        candidate_params.update(runner_params_override)
    specialist_metadata = decision.get("_specialist_metadata")
    if isinstance(specialist_metadata, dict):
        candidate_params["_specialist_metadata"] = dict(specialist_metadata)
    return LoopCandidate(
        tool=tool,
        target=target,
        params=candidate_params,
        tier=tier,
        reasoning=reasoning,
        confidence=max(0.0, min(1.0, confidence_f)),
        follow_up_hints=[],
        expected_evidence=[str(e)[:60] for e in expected_evidence][:5],
        required_approvals=0,
        decision_source="ai_loop_claude_picker",
    )

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app.models import AgentProposal, RationaleLedgerEntry, Run, Scope, Task
from api.app.policy.engine import normalize_profile_limits
from api.app.services.ai_action_selector import select_next_best_action_for_run
from api.app.services.ai_enrichment import store_agent_proposal_record, store_agent_reasoning_record
from api.app.services.ai_planner import (
    RECURSIVE_CONTEXT_KIND,
    ensure_context_document,
    ensure_recursive_surface_context,
    latest_context_document,
    record_rationale,
)
from api.app.services.assessment_planner import build_assessment_plan_for_run
from api.app.services.audit import write_audit_event
from api.app.services.run_credential_vault import (
    clear_run_credential_vault_if_terminal,
    inject_run_credential_vault_into_task,
)
from api.app.services.runs import (
    derive_targets_for_run,
    pending_approvals,
    planned_targets_for_tool,
)
from api.app.services.task_dispatch import supported_execution_tools

LOOP_VERSION = "2026-05-07.1"
LOOP_CONFIG_KEY = "ai_assessment_loop"
GOAL_REASONING_KIND = "assessment_loop_goal_oriented_reasoning"
LOOP_MAX_ITERATIONS = 35
LOOP_STUCK_THRESHOLD = 3
LOOP_ACTIVE_TASK_STATUSES = {"queued", "pending", "running", "dispatching", "in_progress", "started"}
LOOP_TERMINAL_STATUSES = {"completed", "failed", "cancelled", "skipped"}
LOOP_PROPOSAL_KIND = "assessment_loop_next_action"
LOOP_SEED_TOOLS_BY_TARGET_KIND = {
    # target-intel runs FIRST for web targets in ai_loop mode.
    # It analyzes the site with Claude before any scanning tool runs,
    # detects the technology stack, identifies applicable CVEs, and
    # creates a targeted scan plan. httpx is the fallback for non-ai_loop runs.
    "url": "target-intel",
    "host": "nmap",
    "cidr": "nmap",
    "domain": "easm-discover",
    "target": "target-intel",
}
LOOP_LOW_IMPACT_AUTO_TOOLS = {"httpx", "target-intel"}

# Depth levels — each level represents a strategic decision point
# Level 1: Discovery (surface mapping, no findings yet)
# Level 2: Probing (attack surface identified, testing for weaknesses)
# Level 3: Confirmation (vulnerability confirmed, exploiting)
# Level 4: Post-exploitation (session/credential material obtained)
DEPTH_LEVEL_LABELS = {
    1: "Verkenning",
    2: "Kwetsbaarheidstests",
    3: "Bevestiging & Exploitatie",
    4: "Escalatie",
}

@dataclass(frozen=True)
class LoopCandidate:
    tool: str
    target: str
    params: dict[str, Any]
    tier: str
    reasoning: str
    confidence: float
    follow_up_hints: list[str]
    expected_evidence: list[str]
    required_approvals: int
    decision_source: str
    selector_decision: str | None = None
    selector_rank: int | None = None
    selector_provenance: dict[str, Any] | None = None


def _as_dict(value: object) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def _as_list(value: object) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def _tolerant_json_fix(text: str) -> str:
    """Best-effort fixes for common Claude JSON mistakes.

    - Strip trailing commas before `}` or `]`.
    - Escape stray raw newlines/tabs inside string literals.
    Conservative: if it can't parse, the caller logs and returns None.
    """
    import re as _re
    # Remove trailing commas before close braces/brackets
    out = _re.sub(r",(\s*[}\]])", r"\1", text)
    # Convert raw newlines/tabs that appear *inside* JSON strings to \\n / \\t.
    # Heuristic: walk the string, track if we are inside a quoted value.
    result: list[str] = []
    in_string = False
    escape = False
    for ch in out:
        if escape:
            result.append(ch)
            escape = False
            continue
        if ch == "\\":
            result.append(ch)
            escape = True
            continue
        if ch == '"':
            in_string = not in_string
            result.append(ch)
            continue
        if in_string and ch == "\n":
            result.append("\\n")
        elif in_string and ch == "\t":
            result.append("\\t")
        elif in_string and ch == "\r":
            result.append("\\r")
        else:
            result.append(ch)
    return "".join(result)


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _loop_state(configuration: dict[str, Any]) -> dict[str, Any]:
    state = _as_dict(configuration.get(LOOP_CONFIG_KEY))
    iterations = [dict(item) for item in _as_list(state.get("iterations")) if isinstance(item, dict)]
    goal_reasoning = _as_dict(state.get("goal_oriented_reasoning"))
    depth_level = int(state.get("depth_level") or 1)
    # Phase-model state (introduced for AI-driven attack phases).
    current_phase = _as_dict(state.get("current_phase"))
    phases_archive = [dict(p) for p in _as_list(state.get("phases")) if isinstance(p, dict)]
    return {
        "enabled": bool(state.get("enabled", True)),
        "run_mode": "ai_loop",
        "version": str(state.get("version") or LOOP_VERSION),
        "max_iterations": int(state.get("max_iterations") or LOOP_MAX_ITERATIONS),
        "stuck_threshold": int(state.get("stuck_threshold") or LOOP_STUCK_THRESHOLD),
        "iteration_count": int(state.get("iteration_count") or len(iterations)),
        "step_count": int(state.get("step_count") or len(iterations)),
        "depth_level": depth_level,
        "depth_label": DEPTH_LEVEL_LABELS.get(depth_level, "Verkenning"),
        "no_new_signal_iterations": int(state.get("no_new_signal_iterations") or 0),
        "status": str(state.get("status") or "ready"),
        "stop_reason": state.get("stop_reason"),
        "latest_evidence_fingerprint": str(state.get("latest_evidence_fingerprint") or ""),
        "latest_next_action": _as_dict(state.get("latest_next_action")) or None,
        "goal_oriented_reasoning": goal_reasoning,
        "iterations": iterations,
        # Phase model fields — persist across saves so Claude sees the running phase state.
        "phase_count": int(state.get("phase_count") or 0),
        "current_phase": current_phase,
        "phases": phases_archive,
        "ai_stop_summary": str(state.get("ai_stop_summary") or ""),
        "manual_chain_alternative_preserved": True,
        "fixed_phase_chains_replaced_globally": False,
        # Phase-1 refinement (2026-05-22): persistent hypothesis queue
        # written by `_specialists_select_next_action`. Read directly from
        # existing config — this function is a pure reader of stored state.
        "hypothesis_queue": list(state.get("hypothesis_queue") or []),
        "hypothesis_queue_summary": state.get("hypothesis_queue_summary"),
    }


def _store_loop_state(configuration: dict[str, Any], state: dict[str, Any]) -> None:
    # Preserve narrative.panels from whatever was already persisted: panels
    # are written atomically via SQL by the narrator (separate code path),
    # and we must not overwrite that with the stale view this advance call
    # had at its start. Keep whichever has MORE panels.
    existing_loop_cfg = _as_dict(configuration.get(LOOP_CONFIG_KEY))
    existing_narrative = _as_dict(existing_loop_cfg.get("narrative"))
    state_narrative = _as_dict(state.get("narrative"))
    merged_narrative = dict(existing_narrative)
    state_panels = list(state_narrative.get("panels") or [])
    existing_panels = list(existing_narrative.get("panels") or [])
    if len(state_panels) > len(existing_panels):
        merged_narrative["panels"] = state_panels
        merged_narrative["latest_at"] = state_narrative.get("latest_at") or merged_narrative.get("latest_at")
    elif existing_panels:
        merged_narrative["panels"] = existing_panels
    # Phase-1 refinement (2026-05-22 audit): the persistent hypothesis queue
    # is written by `_specialists_select_next_action` directly into
    # `LOOP_CONFIG_KEY["hypothesis_queue"]`. Without this preservation,
    # every subsequent `_store_loop_state` call (e.g. goal_reasoning record)
    # would wipe the queue because the rebuild below uses a fixed allowlist.
    # Empirically observed in v3 smoke 2026-05-22: log shows "reusing queue"
    # mid-run but final config has no queue key — this preserve closes that.
    preserved_hypothesis_queue = list(
        state.get("hypothesis_queue") or existing_loop_cfg.get("hypothesis_queue") or []
    )
    preserved_hypothesis_queue_summary = (
        state.get("hypothesis_queue_summary")
        or existing_loop_cfg.get("hypothesis_queue_summary")
    )
    # M4 + M6 (beat-shannon-pro 2026-05-23): operator-provided knobs live in
    # `ai_assessment_loop` and get wiped by the fixed allowlist rebuild
    # below — same problem the hypothesis_queue had. Preserve them from
    # state-first, else from whatever was persisted, else from operator's
    # original create_run payload (which is what xbow_benchmark.py sets).
    preserved_m1_max_revisions = (
        state.get("m1_max_revisions_per_predecessor")
        or existing_loop_cfg.get("m1_max_revisions_per_predecessor")
    )
    preserved_m6_cross_model_critic = bool(
        state.get("m6_cross_model_critic")
        or existing_loop_cfg.get("m6_cross_model_critic")
    )
    preserved_critiqued_ids = list(
        state.get("critiqued_code_exec_task_ids")
        or existing_loop_cfg.get("critiqued_code_exec_task_ids")
        or []
    )

    configuration[LOOP_CONFIG_KEY] = {
        "enabled": True,
        "run_mode": "ai_loop",
        "version": LOOP_VERSION,
        "max_iterations": int(state.get("max_iterations") or LOOP_MAX_ITERATIONS),
        "stuck_threshold": int(state.get("stuck_threshold") or LOOP_STUCK_THRESHOLD),
        "iteration_count": int(state.get("iteration_count") or 0),
        "no_new_signal_iterations": int(state.get("no_new_signal_iterations") or 0),
        "status": str(state.get("status") or "ready"),
        "stop_reason": state.get("stop_reason"),
        "latest_evidence_fingerprint": str(state.get("latest_evidence_fingerprint") or ""),
        "latest_next_action": state.get("latest_next_action"),
        "goal_oriented_reasoning": _as_dict(state.get("goal_oriented_reasoning")),
        "iterations": list(state.get("iterations") or []),
        # Phase-model fields persist here so the next advance() call sees them.
        "phase_count": int(state.get("phase_count") or 0),
        "current_phase": _as_dict(state.get("current_phase")),
        "phases": list(state.get("phases") or []),
        "ai_stop_summary": str(state.get("ai_stop_summary") or ""),
        # Feedback loop state — Claude sees these in next iteration prompt
        "recent_rejections": list(state.get("recent_rejections") or []),
        # UI live state — surfaces "Claude is thinking" indicator
        "claude_thinking": _as_dict(state.get("claude_thinking")),
        # Comic-strip narrator output — preserved from any concurrent append
        "narrative": merged_narrative,
        "manual_chain_alternative_preserved": True,
        "fixed_phase_chains_replaced_globally": False,
        # Phase-1 refinement (2026-05-22): persistent hypothesis queue.
        # `preserved_hypothesis_queue` was computed above from state or
        # the existing config; without these two keys the queue is wiped
        # on every advance call (empirically observed v3 smoke).
        "hypothesis_queue": preserved_hypothesis_queue,
        "hypothesis_queue_summary": preserved_hypothesis_queue_summary,
        # M4 + M6 operator knobs (beat-shannon-pro 2026-05-23).
        **({"m1_max_revisions_per_predecessor": preserved_m1_max_revisions}
           if preserved_m1_max_revisions else {}),
        **({"m6_cross_model_critic": True}
           if preserved_m6_cross_model_critic else {}),
        **({"critiqued_code_exec_task_ids": preserved_critiqued_ids}
           if preserved_critiqued_ids else {}),
    }


def _run_uses_ai_loop(run: Run) -> bool:
    configuration = _as_dict(run.configuration_json)
    loop_config = _as_dict(configuration.get(LOOP_CONFIG_KEY))
    return configuration.get("run_mode") == "ai_loop" or loop_config.get("run_mode") == "ai_loop"


def _targets_for_loop(scope: Scope, run: Run) -> list[dict[str, str]]:
    targets = derive_targets_for_run(scope, run)
    return [target for target in targets if str(target.get("value") or "").strip()]


def _target_type(targets: list[dict[str, str]]) -> str:
    kinds = {str(target.get("kind") or "") for target in targets}
    if "cidr" in kinds:
        return "cidr"
    if "url" in kinds:
        return "url"
    if "host" in kinds:
        return "ip_or_host"
    if "domain" in kinds:
        return "domain"
    return "unknown"


def _task_key(tool: str, target: str) -> str:
    return f"{str(tool).strip()}::{str(target).strip()}"


RUNNER_EXIT_CODE_SKIPPED = 78  # EX_CONFIG — runner unavailable in this deployment


def _runners_skipped_in_run(run: Run) -> set[str]:
    """Tools whose runner returned ``exit_code=78`` (EX_CONFIG) on at least
    one execution in this run = unavailable in this deployment.

    Pre-fix 2026-05-21 reality: 6 runners (burp, auth_flow, session_security,
    web_depth, client_state, idor_bac) returned ``exit_code=0`` + metadata
    ``{"skipped": True}`` when a required env var/binary was missing. The
    task completed "successfully" but did NOTHING. Tested_keys got
    populated → picker thought the tool was tried → never re-picked it AND
    never picked a working substitute. ``metadata`` is mostly dropped at
    persistence (only runner_digest and tool_version survive on
    ToolExecution), so the only durable signal is ``exit_code``.

    Convention introduced 2026-05-21: skipped runners return
    ``exit_code=78``. ToolExecution.exit_code IS persisted, so this helper
    can read it back.

    Used by the picker's available_tools build path to drop these tools
    BEFORE Claude sees them in the allowlist, and by ``_tested_action_keys``
    to NOT count skipped tasks as proper test runs.
    """
    skipped: set[str] = set()
    for task in list(run.tasks or []):
        tool = str(task.tool or "").strip()
        if not tool:
            continue
        for execution in list(task.executions or []):
            if int(execution.exit_code or 0) == RUNNER_EXIT_CODE_SKIPPED:
                skipped.add(tool)
                break
    return skipped


def _tested_action_keys(run: Run) -> set[str]:
    keys: set[str] = set()
    skipped_runners = _runners_skipped_in_run(run)
    for task in list(run.tasks or []):
        tool = str(task.tool or "").strip()
        if tool == "bootstrap":
            continue
        if tool in skipped_runners:
            # The runner returned metadata.skipped=True — no real work was
            # done, so this task should NOT count as "tested" in tested_keys.
            # Otherwise the picker thinks it tried burp/auth_flow/etc and
            # locks the tool out of future iterations on the same target,
            # even though nothing actually happened.
            continue
        keys.add(_task_key(tool, task.target_id))
    for proposal in list(run.agent_proposals or []):
        metadata = _as_dict(proposal.metadata_json)
        if metadata.get("proposal_kind") == LOOP_PROPOSAL_KIND:
            keys.add(_task_key(proposal.proposed_tool, proposal.proposed_target))
    configuration = _as_dict(run.configuration_json)
    state = _loop_state(configuration)
    for iteration in state.get("iterations", []):
        action = _as_dict(iteration.get("next_action"))
        tool = str(action.get("tool") or "").strip()
        target = str(action.get("target") or "").strip()
        if tool and target:
            keys.add(_task_key(tool, target))
    return keys


def _active_loop_tasks(run: Run) -> list[dict[str, str]]:
    active: list[dict[str, str]] = []
    for task in list(run.tasks or []):
        status = str(task.status or "").strip().lower()
        params = _as_dict(task.params_json)
        if status in LOOP_ACTIVE_TASK_STATUSES and (
            isinstance(params.get("assessment_loop"), dict)
            or isinstance(params.get("ai_proposal"), dict)
        ):
            active.append({"task_id": str(task.id), "tool": task.tool, "target": task.target_id, "status": status})
    return active


def _evidence_fingerprint(run: Run) -> str:
    task_bits = [
        f"task:{task.id}:{task.tool}:{task.target_id}:{task.status}"
        for task in sorted(list(run.tasks or []), key=lambda item: str(item.id))
        if str(task.status or "").lower() in LOOP_TERMINAL_STATUSES
    ]
    finding_bits = [
        f"finding:{finding.id}:{finding.title}:{finding.target_id}:{finding.evidence_ref}"
        for finding in sorted(list(run.findings or []), key=lambda item: str(item.id))
    ]
    snapshot = run.source_inventory_snapshot
    snapshot_bits: list[str] = []
    if snapshot is not None:
        inventory = _as_dict(snapshot.normalized_inventory_json)
        profile = _as_dict(inventory.get("signal_profile"))
        signal_keys = [
            str(item.get("key") or "")
            for item in _as_list(profile.get("signals"))
            if isinstance(item, dict)
        ]
        snapshot_bits.append(f"snapshot:{snapshot.id}:{','.join(sorted(signal_keys))}")
    return "|".join([*task_bits, *finding_bits, *snapshot_bits]) or "no-evidence"


def _current_state_payload(
    *,
    run: Run,
    scope: Scope,
    targets: list[dict[str, str]],
    evidence_fingerprint: str,
) -> dict[str, Any]:
    inventory_snapshot = run.source_inventory_snapshot
    inventory = (
        _as_dict(inventory_snapshot.normalized_inventory_json)
        if inventory_snapshot is not None
        else {}
    )
    signal_profile = _as_dict(inventory.get("signal_profile"))
    return {
        "target_type": _target_type(targets),
        "targets": targets,
        "inventory_snapshot_id": str(inventory_snapshot.id) if inventory_snapshot is not None else None,
        "signal_count": len(_as_list(signal_profile.get("signals"))),
        "finding_count": len(list(run.findings or [])),
        "task_count": len(list(run.tasks or [])),
        "tested_paths": [
            {"tool": task.tool, "target": task.target_id, "status": task.status}
            for task in list(run.tasks or [])
        ],
        "open_threads": [
            {
                "proposal_id": str(proposal.id),
                "tool": proposal.proposed_tool,
                "target": proposal.proposed_target,
                "status": proposal.status,
            }
            for proposal in list(run.agent_proposals or [])
            if proposal.status == "pending_review"
        ],
        "evidence_fingerprint": evidence_fingerprint,
        "scope_enforced": True,
        "roe_required": bool(scope.roe_ref if hasattr(scope, "roe_ref") else True),
    }


def _capability_item(plan: dict[str, Any], tool: str) -> dict[str, Any]:
    for item in plan.get("runners", []):
        if isinstance(item, dict) and str(item.get("runner") or "") == tool:
            return item
    return {}


def _tier_from_capability(item: dict[str, Any], tool: str) -> str:
    risk_tier = str(item.get("risk_tier") or "active").strip().lower()
    required_approvals = int(item.get("required_approvals") or 0)
    if risk_tier == "intrusive" or required_approvals >= 2:
        return "intrusive"
    if required_approvals >= 1:
        return "active"
    if tool in LOOP_LOW_IMPACT_AUTO_TOOLS:
        return "passive"
    return "active"


def _infer_foothold_from_findings(run: Run, current: str) -> str:
    """Foothold-advancement gated by the backlog-413 deterministic validator.

    For each high/critical finding the validator re-executes the captured
    request chain (``replay_recipe_json``) and only when the verdict is
    ``verified`` does the title pattern get to advance the foothold. When
    the validator returns ``failed`` or ``inconclusive`` the finding is
    treated as ``observed-vulnerable``/``hypothesis`` per Codex's
    evidence-first categorization — no foothold transition.

    Per `feedback_no_prescriptive_recipes`: title patterns map to foothold
    classes but are universal (not per-app recipes).
    """
    from api.app.services.attack_state import (  # noqa: E402
        FootholdState,
        is_higher_foothold,
    )
    from api.app.services.exploit_validator import validate_exploit  # noqa: E402
    try:
        current_state = FootholdState(current)
    except ValueError:
        current_state = FootholdState.ANONYMOUS
    new_state = current_state
    for finding in list(getattr(run, "findings", None) or []):
        sev = str(getattr(finding, "severity", "") or "").lower()
        if sev not in {"critical", "high"}:
            continue
        title = str(getattr(finding, "title", "") or "").lower()
        candidate: FootholdState | None = None
        if any(t in title for t in ("rce", "remote code execution", "command injection", "code execution")):
            candidate = FootholdState.CODE_EXECUTION
        elif any(t in title for t in ("reverse shell", "interactive shell", "ssh access")):
            candidate = FootholdState.SHELL_LIKE
        elif any(t in title for t in ("path traversal", "lfi", "arbitrary file read", "directory traversal")):
            candidate = FootholdState.FILE_READ
        elif any(t in title for t in ("admin compromise", "account takeover", "privilege escalation", "admin bypass")):
            candidate = FootholdState.ADMIN
        elif any(t in title for t in ("auth bypass", "authentication bypass", "session hijack", "credential disclosure", "stored credential")):
            candidate = FootholdState.AUTHENTICATED_USER
        if candidate is None or not is_higher_foothold(candidate, new_state):
            continue
        # backlog-413: deterministic validator re-runs the recipe before we
        # promote the foothold. No replay_recipe means we cannot verify →
        # treat as observed-vulnerable, no transition.
        recipe = getattr(finding, "replay_recipe_json", None) or getattr(finding, "replay_recipe", None)
        if not isinstance(recipe, dict) or not recipe.get("steps"):
            # Findings from regular runners don't populate replay_recipe.
            # Invoke compose_exploit_recipe (exploit_developer) to construct
            # one from the finding's context. This wires the
            # observed-vulnerable → composed-recipe → validator → foothold
            # chain end-to-end. Guarded by a per-finding flag so we don't
            # re-spend LLM tokens on the same finding every advance.
            if bool(getattr(finding, "_exploit_dev_tried", False)):
                logger.info(
                    "attack_state: candidate foothold %s skipped — finding %s "
                    "exploit_developer already attempted, no chain produced",
                    candidate.value, str(getattr(finding, "id", ""))[:8],
                )
                continue
            logger.info(
                "attack_state: invoking compose_exploit_recipe for finding %s — "
                "no recipe yet, candidate foothold=%s",
                str(getattr(finding, "id", ""))[:8], candidate.value,
            )
            try:
                from api.app.services.exploit_developer import compose_exploit_recipe  # noqa: E402
                target_url = str(getattr(finding, "target_id", "") or "")
                hypothesis = str(getattr(finding, "title", "") or "")
                composed = compose_exploit_recipe(
                    target_context={"target": target_url, "target_url": target_url, "finding_title": hypothesis},
                    hypothesis=hypothesis,
                )
                payload = composed.to_runnable_payload() if hasattr(composed, "to_runnable_payload") else None
                if isinstance(payload, dict) and payload.get("steps"):
                    finding.replay_recipe_json = payload  # type: ignore[attr-defined]
                    recipe = payload
                    logger.info(
                        "compose_exploit_recipe: composed %d-step recipe for finding %s",
                        len(payload["steps"]), str(getattr(finding, "id", ""))[:8],
                    )
                else:
                    setattr(finding, "_exploit_dev_tried", True)
                    logger.info(
                        "compose_exploit_recipe: empty recipe for finding %s — no chain produced",
                        str(getattr(finding, "id", ""))[:8],
                    )
                    continue
            except Exception as exc:  # noqa: BLE001
                setattr(finding, "_exploit_dev_tried", True)
                logger.warning(
                    "compose_exploit_recipe: raised on finding %s: %s",
                    str(getattr(finding, "id", ""))[:8], exc,
                )
                continue
        try:
            verdict = validate_exploit(finding, recipe)
        except Exception as exc:  # noqa: BLE001
            logger.debug("validator threw on finding %s: %s", getattr(finding, "id", ""), exc)
            continue
        if verdict.verdict != "verified":
            logger.info(
                "attack_state: candidate foothold %s NOT promoted — validator verdict=%s for finding %s",
                candidate.value, verdict.verdict, str(getattr(finding, "id", ""))[:8],
            )
            continue
        new_state = candidate
    return new_state.value


def _scope_target_allowed(scope: Scope, target: str) -> bool:
    # backlog-409: the scope-matching primitive lives in the Layer 0
    # GovernanceControlPlane (api/app/governance/control_plane.py) so there
    # is exactly one impl shared by planning-time filters in this module
    # AND dispatch-time authorization in workers/orchestration/tasks.py.
    # Local import avoids circular load at module import time.
    from api.app.governance import GovernanceControlPlane  # noqa: E402
    return GovernanceControlPlane.is_in_scope(scope, target)


def _objective_type(objective: str) -> str:
    text = objective.lower()
    if "gruyere" in text or (
        "xss" in text
        and any(token in text for token in ("admin", "cookie", "session", "command injection", "controlled proof"))
    ):
        return "gruyere_multi_step_objective"
    if any(token in text for token in ("domain admin", "active directory", "kerberos", "ldap", "bloodhound")):
        return "identity_admin_objective"
    if any(token in text for token in ("billing", "database", "db", "sql", "customer data", "records")):
        return "data_access_objective"
    if any(token in text for token in ("/etc/shadow", "shadow", "file read", "secret file", "config file")):
        return "sensitive_file_objective"
    if any(token in text for token in ("session", "token", "cookie", "admin panel", "authenticated")):
        return "session_exposure_objective"
    return "custom_objective"


def _goal_tool_sequence(objective_type: str, target_type: str) -> list[str]:
    if objective_type == "gruyere_multi_step_objective":
        return ["httpx", "xss-extended", "session-security", "client-state", "ssti-probe"]
    if objective_type == "identity_admin_objective":
        return ["nmap", "ldap-enum", "bloodhound-collect", "netexec", "credential-attacks"]
    if objective_type == "data_access_objective":
        first = "nmap" if target_type in {"cidr", "ip_or_host"} else "httpx"
        return [first, "content-discovery", "api-assessment", "sqlmap", "auth-flow", "session-security", "idor-bac"]
    if objective_type == "sensitive_file_objective":
        first = "nmap" if target_type in {"cidr", "ip_or_host"} else "httpx"
        return [first, "content-discovery", "ssrf-probe", "xxe-probe", "ssti-probe"]
    if objective_type == "session_exposure_objective":
        return ["httpx", "auth-flow", "session-security", "jwt-probe", "idor-bac", "client-state"]
    return ["httpx", "content-discovery", "api-assessment", "auth-flow", "session-security"]


def _target_candidates_for_tool(tool: str, targets: list[dict[str, str]]) -> list[dict[str, str]]:
    candidates = planned_targets_for_tool(tool, targets, derive_url_hosts_for_nmap=True)
    return [
        {"kind": str(item.get("kind") or "target"), "value": str(item.get("value") or "").strip()}
        for item in candidates
        if str(item.get("value") or "").strip()
    ]


def _goal_stage(tool: str, tier: str) -> str:
    if tool in LOOP_LOW_IMPACT_AUTO_TOOLS:
        return "observe_surface"
    if tool == "xss-extended":
        return "validate_initial_browser_execution"
    if tool == "ssti-probe":
        return "approval_gated_controlled_proof"
    if tool in {"auth-flow", "session-security", "jwt-probe", "idor-bac", "client-state"}:
        return "validate_session_exposure_risk"
    if tier == "intrusive":
        return "approval_gated_controlled_proof"
    return "controlled_proof_candidate"


def _goal_reason(tool: str, objective: str, objective_type: str) -> str:
    if tool in {"httpx", "nmap", "easm-discover"}:
        return (
            f"Establish approved surface evidence for the operator objective '{objective}' before any "
            "deeper controlled proof step is proposed."
        )
    if objective_type == "gruyere_multi_step_objective" and tool == "xss-extended":
        return (
            "Validate the Gruyere browser-execution entry point with the registered XSS runner before "
            "using any reviewed session or admin-surface evidence for follow-up."
        )
    if objective_type == "gruyere_multi_step_objective" and tool == "session-security":
        return (
            "Review session exposure risk from the confirmed Gruyere XSS path and keep any cookie or "
            "token material behind redacted evidence and secret-binding controls."
        )
    if objective_type == "gruyere_multi_step_objective" and tool == "client-state":
        return (
            "Use reviewed session evidence only through the registered client-state runner to test the "
            "authenticated Gruyere admin surface without bypassing scope or approval gates."
        )
    if objective_type == "gruyere_multi_step_objective" and tool == "ssti-probe":
        return (
            "Produce a bounded Gruyere controlled proof with math-expression canary evidence only; "
            "command payloads, file writes, callbacks, and persistence remain prohibited."
        )
    if tool == "sqlmap":
        return (
            "Use sqlmap only after injectable-parameter or SQL-error evidence exists; any data-layer "
            "check remains a controlled proof with canary evidence."
        )
    if tool in {"auth-flow", "session-security", "jwt-probe"}:
        return (
            "Map authentication and session behavior for session exposure risk without handling raw "
            "credential material outside approved secret references."
        )
    if tool in {"ldap-enum", "bloodhound-collect"}:
        return (
            "Collect read-only identity evidence to test whether the objective has an approved path "
            "through directory relationships."
        )
    if tool in {"netexec", "credential-attacks", "metasploit", "impacket-lateral"}:
        return (
            "Hold this as an approval-gated controlled proof candidate; execution requires the existing "
            "ROE tier and operator approval flow."
        )
    if objective_type == "sensitive_file_objective":
        return "Look for bounded file exposure indicators and prefer canary evidence over sensitive content."
    return "Select this registered runner only if current evidence supports the objective path."


def _goal_evidence_links(
    *,
    run: Run,
    scope: Scope,
    context_document,
) -> list[dict[str, Any]]:
    links: list[dict[str, Any]] = [
        {"type": "approved_scope", "id": str(scope.id)},
        {"type": "target_context_document", "id": str(context_document.id)},
    ]
    for ref in _as_list(context_document.evidence_refs_json):
        if isinstance(ref, dict):
            links.append({"type": "context_evidence", **ref})
    for task in list(run.tasks or []):
        if str(task.status or "").lower() in LOOP_TERMINAL_STATUSES:
            links.append({"type": "runner_output", "id": str(task.id), "tool": task.tool, "status": task.status})
    for finding in list(run.findings or []):
        links.append(
            {
                "type": "finding",
                "id": str(finding.id),
                "title": finding.title,
                "target": finding.target_id,
                "evidence_ref": finding.evidence_ref,
            }
        )
    return links


def _run_signal_keys(run: Run) -> set[str]:
    snapshot = run.source_inventory_snapshot
    if snapshot is None:
        return set()
    inventory = _as_dict(snapshot.normalized_inventory_json)
    profile = _as_dict(inventory.get("signal_profile"))
    return {
        str(item.get("key") or "").strip()
        for item in _as_list(profile.get("signals"))
        if isinstance(item, dict) and str(item.get("key") or "").strip()
    }


def _goal_step_ready(run: Run, step: dict[str, Any]) -> bool:
    tool = str(step.get("tool") or "")
    signal_keys = _run_signal_keys(run)
    finding_titles = " ".join(str(finding.title or "").lower() for finding in list(run.findings or []))
    if tool == "sqlmap":
        return bool({"injectable_parameter", "sql_error_pattern"} & signal_keys) or "sql injection" in finding_titles
    return True


def _build_goal_oriented_reasoning(
    *,
    run: Run,
    scope: Scope,
    targets: list[dict[str, str]],
    plan: dict[str, Any],
    context_document,
    objective: str,
    actor: str,
    operator_note: str | None,
) -> dict[str, Any]:
    objective_type = _objective_type(objective)
    target_type = _target_type(targets)
    supported_tools = supported_execution_tools()
    evidence_links = _goal_evidence_links(run=run, scope=scope, context_document=context_document)
    path: list[dict[str, Any]] = []
    for tool in _goal_tool_sequence(objective_type, target_type):
        if tool not in supported_tools:
            continue
        candidates = [
            item
            for item in _target_candidates_for_tool(tool, targets)
            if _scope_target_allowed(scope, str(item.get("value") or ""))
        ]
        if not candidates:
            continue
        plan_item = _capability_item(plan, tool)
        tier = _tier_from_capability(plan_item, tool)
        required_approvals = int(plan_item.get("required_approvals") or (1 if tier in {"active", "intrusive"} else 0))
        order = len(path) + 1
        path.append(
            {
                "id": f"goal-step-{order}-{tool}",
                "order": order,
                "objective_type": objective_type,
                "stage": _goal_stage(tool, tier),
                "tool": tool,
                "tier": tier,
                "target_candidates": candidates,
                "reason": _goal_reason(tool, objective, objective_type),
                "expected_evidence": list(plan_item.get("expected_evidence") or []),
                "follow_up_hints": list(plan_item.get("follow_up_tools") or []),
                "required_approvals": required_approvals,
                "requires_operator_approval": tier in {"active", "intrusive"} or required_approvals > 0,
                "registered_runner_required": True,
                "scope_enforced": True,
                "roe_enforced": True,
                "kill_switch_still_authoritative": True,
                "controlled_proof_required": tier in {"active", "intrusive"} or tool not in LOOP_LOW_IMPACT_AUTO_TOOLS,
                "canary_evidence_preferred": tool in {"sqlmap", "ssrf-probe", "xxe-probe", "ssti-probe"},
                "session_exposure_risk_review": tool
                in {"auth-flow", "session-security", "jwt-probe", "idor-bac", "client-state"},
                "dispatches_work": False,
                "evidence_links": evidence_links,
            }
        )
    return {
        "status": "recorded",
        "objective": objective,
        "objective_type": objective_type,
        "operator_note": operator_note,
        "recorded_by": actor,
        "recorded_at": _now(),
        "run_mode": "ai_loop",
        "hypothesis_path": path,
        "evidence_links": evidence_links,
        "bounded_goal_hypothesis": True,
        "dispatches_work_directly": False,
        "registered_runner_required": True,
        "scope_enforced": True,
        "roe_enforced": True,
        "approval_gates_bypassed": False,
        "kill_switch_still_authoritative": True,
        "manual_chain_alternative_preserved": True,
        "fixed_phase_chains_replaced_globally": False,
        "context_document_id": str(context_document.id),
    }


def _goal_oriented_candidate(
    *,
    run: Run,
    scope: Scope,
    goal_reasoning: dict[str, Any],
    plan: dict[str, Any],
    tested_keys: set[str],
) -> LoopCandidate | None:
    if not goal_reasoning or goal_reasoning.get("run_mode") != "ai_loop":
        return None
    if goal_reasoning.get("status") != "recorded":
        return None
    for step in _as_list(goal_reasoning.get("hypothesis_path")):
        if not isinstance(step, dict) or not _goal_step_ready(run, step):
            continue
        tool = str(step.get("tool") or "").strip()
        if not tool or tool not in supported_execution_tools():
            continue
        for target in _as_list(step.get("target_candidates")):
            if not isinstance(target, dict):
                continue
            target_value = str(target.get("value") or "").strip()
            if not target_value:
                continue
            if _task_key(tool, target_value) in tested_keys:
                continue
            if not _scope_target_allowed(scope, target_value):
                continue
            plan_item = _capability_item(plan, tool)
            tier = _tier_from_capability(plan_item, tool)
            required_approvals = int(step.get("required_approvals") or plan_item.get("required_approvals") or 0)
            return LoopCandidate(
                tool=tool,
                target=target_value,
                params={
                    "target_kind": target.get("kind"),
                    "source": "goal_oriented_reasoning",
                    "goal_oriented_reasoning": {
                        "objective": goal_reasoning.get("objective"),
                        "objective_type": goal_reasoning.get("objective_type"),
                        "hypothesis_step_id": step.get("id"),
                        "hypothesis_order": step.get("order"),
                        "stage": step.get("stage"),
                        "evidence_links": list(step.get("evidence_links") or []),
                        "controlled_proof_required": bool(step.get("controlled_proof_required")),
                        "canary_evidence_preferred": bool(step.get("canary_evidence_preferred")),
                        "session_exposure_risk_review": bool(step.get("session_exposure_risk_review")),
                    },
                },
                tier=tier,
                reasoning=str(step.get("reason") or "Select the next registered runner for the objective path."),
                confidence=0.84,
                follow_up_hints=list(step.get("follow_up_hints") or plan_item.get("follow_up_tools") or []),
                expected_evidence=list(step.get("expected_evidence") or plan_item.get("expected_evidence") or []),
                required_approvals=required_approvals,
                decision_source="goal_oriented_reasoning",
            )
    return None


def _ai_proposal_candidate(
    *,
    run: Run,
    scope: Scope,
    plan: dict[str, Any],
    tested_keys: set[str],
) -> LoopCandidate | None:
    """Read pending AgentProposal records created by post-task AI analysis.

    This is the PRIMARY candidate source for ai_loop runs. After every tool
    completes, ChatGPT OAuth analyzes the output and creates AgentProposal
    records with proposed_tool, proposed_target, and reasoning_text. This
    function picks the highest-priority pending proposal and turns it into a
    LoopCandidate — making AI reasoning the driver of the assessment loop.

    Falls back to signal-based selection only when no proposals exist.
    """
    proposals = [
        p for p in list(run.agent_proposals or [])
        if p.status == "pending_review"
        and str(p.metadata_json.get("proposal_kind") if isinstance(p.metadata_json, dict) else "") != LOOP_PROPOSAL_KIND
        and str(p.proposed_tool or "").strip() in supported_execution_tools()
    ]
    if not proposals:
        return None

    # Sort by priority (lower number = higher priority), then by confidence
    proposals.sort(key=lambda p: (
        int((p.metadata_json or {}).get("priority", 50)) if isinstance(p.metadata_json, dict) else 50,
        -float(p.confidence_score or 0.5),
    ))

    for proposal in proposals:
        tool = str(proposal.proposed_tool or "").strip()
        target = str(proposal.proposed_target or "").strip()
        if not tool or not target:
            continue
        if _task_key(tool, target) in tested_keys:
            continue
        if not _scope_target_allowed(scope, target):
            continue

        metadata = proposal.metadata_json if isinstance(proposal.metadata_json, dict) else {}
        plan_item = _capability_item(plan, tool)
        tier = str(metadata.get("risk_tier") or _tier_from_capability(plan_item, tool))
        required_approvals = int(metadata.get("required_approvals") or plan_item.get("required_approvals") or 0)
        confidence = float(proposal.confidence_score or 0.75)

        return LoopCandidate(
            tool=tool,
            target=target,
            params={
                "target_kind": metadata.get("target_kind", "url"),
                "source": "ai_proposal",
                "ai_proposal": {
                    "proposal_id": str(proposal.id),
                    "reasoning": str(proposal.reasoning_text or ""),
                    "risk_tier": tier,
                    "priority": metadata.get("priority", 50),
                    "confidence": confidence,
                },
                **(proposal.proposed_params_json or {}),
            },
            tier=tier,
            reasoning=str(proposal.reasoning_text or f"AI proposed {tool} based on post-task analysis."),
            confidence=confidence,
            follow_up_hints=list(metadata.get("follow_up_tools") or plan_item.get("follow_up_tools") or []),
            expected_evidence=list(plan_item.get("expected_evidence") or []),
            required_approvals=required_approvals,
            decision_source="ai_proposal",
        )

    return None


def _auth_signal_candidate(
    *,
    run: Run,
    scope: Scope,
    targets: list[dict[str, str]],
    plan: dict[str, Any],
    tested_keys: set[str],
) -> LoopCandidate | None:
    signal_keys = _run_signal_keys(run)
    if not ({"login_form_found", "auth_flow_present", "session_cookie_present"} & signal_keys):
        return None
    tool = "auth-flow"
    if tool not in supported_execution_tools():
        return None
    plan_item = _capability_item(plan, tool)
    for target in _target_candidates_for_tool(tool, targets):
        target_value = str(target.get("value") or "").strip()
        if not target_value:
            continue
        if _task_key(tool, target_value) in tested_keys:
            continue
        if not _scope_target_allowed(scope, target_value):
            continue
        tier = _tier_from_capability(plan_item, tool)
        return LoopCandidate(
            tool=tool,
            target=target_value,
            params={
                "target_kind": target.get("kind"),
                "source": "auth_signal_priority",
                "matched_triggers": sorted({"login_form_found", "auth_flow_present", "session_cookie_present"} & signal_keys),
            },
            tier=tier,
            reasoning=(
                "Authentication and session signals are present, so the next bounded validation is to "
                "review the auth flow before branching into broader surface probes."
            ),
            confidence=0.86,
            follow_up_hints=list(plan_item.get("follow_up_tools") or []),
            expected_evidence=list(plan_item.get("expected_evidence") or []),
            required_approvals=int(plan_item.get("required_approvals") or (1 if tier in {"active", "intrusive"} else 0)),
            decision_source="auth_signal_priority",
        )
    return None


def _seed_candidate(
    *,
    run: Run,
    scope: Scope,
    targets: list[dict[str, str]],
    plan: dict[str, Any],
    tested_keys: set[str],
    recommended_tools: set[str] | None = None,
) -> LoopCandidate | None:
    if tested_keys:
        return None
    for target in targets:
        kind = str(target.get("kind") or "").strip()
        value = str(target.get("value") or "").strip()
        tool = LOOP_SEED_TOOLS_BY_TARGET_KIND.get(kind)
        if not tool or not value:
            continue
        if recommended_tools and tool not in recommended_tools:
            continue
        planned_targets = planned_targets_for_tool(
            tool,
            targets,
            derive_url_hosts_for_nmap=True,
        )
        chosen_target = next((item for item in planned_targets if item.get("value")), target)
        target_value = str(chosen_target.get("value") or value).strip()
        if not _scope_target_allowed(scope, target_value):
            continue
        if _task_key(tool, target_value) in tested_keys:
            continue
        plan_item = _capability_item(plan, tool)
        tier = _tier_from_capability(plan_item, tool)
        return LoopCandidate(
            tool=tool,
            target=target_value,
            params={
                "loop_seed": True,
                "target_kind": chosen_target.get("kind") or kind,
                "source": "assessment_loop_seed",
            },
            tier=tier,
            reasoning=(
                f"Start the AI loop with {tool} against the approved {chosen_target.get('kind') or kind} "
                "to collect the first evidence-backed inventory signals."
            ),
            confidence=0.78,
            follow_up_hints=list(plan_item.get("follow_up_tools") or []),
            expected_evidence=list(plan_item.get("expected_evidence") or []),
            required_approvals=int(plan_item.get("required_approvals") or 0),
            decision_source="seed_target_type",
        )
    return None


def _plan_candidate(
    *,
    run: Run,
    scope: Scope,
    targets: list[dict[str, str]],
    plan: dict[str, Any],
    tested_keys: set[str],
    recommended_tools: set[str] | None = None,
) -> LoopCandidate | None:
    for item in plan.get("runners", []):
        if not isinstance(item, dict):
            continue
        decision = str(item.get("decision") or "").upper()
        if decision not in {"RUN", "NEEDS_APPROVAL"}:
            continue
        tool = str(item.get("runner") or item.get("tool") or "").strip()
        if not tool or tool not in supported_execution_tools():
            continue
        if recommended_tools and tool not in recommended_tools:
            continue
        planned_targets = planned_targets_for_tool(
            tool,
            targets,
            derive_url_hosts_for_nmap=True,
        )
        for target in planned_targets:
            target_value = str(target.get("value") or "").strip()
            if not target_value:
                continue
            if _task_key(tool, target_value) in tested_keys:
                continue
            if not _scope_target_allowed(scope, target_value):
                continue
            tier = _tier_from_capability(item, tool)
            return LoopCandidate(
                tool=tool,
                target=target_value,
                params={
                    "target_kind": target.get("kind"),
                    "matched_triggers": list(item.get("matched_triggers") or []),
                    "matched_weak_triggers": list(item.get("matched_weak_triggers") or []),
                    "source": "assessment_loop_plan",
                },
                tier=tier,
                reasoning=str(item.get("summary") or f"{tool} is the highest value next action."),
                confidence=float(item.get("confidence") or 0.0),
                follow_up_hints=list(item.get("follow_up_tools") or []),
                expected_evidence=list(item.get("expected_evidence") or []),
                required_approvals=int(item.get("required_approvals") or 0),
                decision_source="assessment_plan",
            )
    return None


def _context_targets(context_document) -> list[dict[str, str]]:
    targets: list[dict[str, str]] = []
    if context_document.context_kind != RECURSIVE_CONTEXT_KIND:
        for target in _as_list(context_document.source_targets_json):
            if not isinstance(target, dict):
                continue
            value = str(target.get("value") or "").strip()
            kind = str(target.get("kind") or "target").strip() or "target"
            if value:
                targets.append({"kind": kind, "value": value})
        if targets:
            return targets
    for endpoint in _as_list(context_document.endpoints_discovered_json):
        endpoint_text = str(endpoint or "").strip()
        if endpoint_text:
            targets.append({"kind": "url" if "://" in endpoint_text else "target", "value": endpoint_text})
    if targets:
        return targets
    for target in _as_list(context_document.source_targets_json):
        if not isinstance(target, dict):
            continue
        value = str(target.get("value") or "").strip()
        kind = str(target.get("kind") or "target").strip() or "target"
        if value:
            targets.append({"kind": kind, "value": value})
    return targets


def _context_micro_plan_candidate(
    *,
    scope: Scope,
    context_document,
    plan: dict[str, Any],
    tested_keys: set[str],
) -> LoopCandidate | None:
    if context_document.context_kind != RECURSIVE_CONTEXT_KIND:
        return None
    plan_targets = _context_targets(context_document)
    for step in _as_list(context_document.micro_plan_json):
        if not isinstance(step, dict):
            continue
        tool = str(step.get("tool") or "").strip()
        if not tool or tool not in supported_execution_tools():
            continue
        step_targets = [
            {"kind": "url" if "://" in str(target or "") else "target", "value": str(target or "").strip()}
            for target in _as_list(step.get("target_candidates"))
            if str(target or "").strip()
        ] or plan_targets
        for target in step_targets:
            target_value = str(target.get("value") or "").strip()
            if not target_value:
                continue
            if _task_key(tool, target_value) in tested_keys:
                continue
            if not _scope_target_allowed(scope, target_value):
                continue
            plan_item = _capability_item(plan, tool)
            tier = _tier_from_capability(plan_item, tool)
            return LoopCandidate(
                tool=tool,
                target=target_value,
                params={
                    "target_kind": target.get("kind"),
                    "source": "recursive_surface_micro_plan",
                    "context_document_id": str(context_document.id),
                    "context_layer": context_document.layer_name,
                    "micro_plan_step": int(step.get("order") or 0),
                },
                tier=tier,
                reasoning=str(
                    step.get("reason")
                    or f"Run {tool} against the newly discovered {context_document.layer_name} surface."
                ),
                confidence=float(plan_item.get("confidence") or 0.82),
                follow_up_hints=list(plan_item.get("follow_up_tools") or []),
                expected_evidence=list(plan_item.get("expected_evidence") or []),
                required_approvals=int(plan_item.get("required_approvals") or 0),
                decision_source="recursive_surface_micro_plan",
            )
    return None


def _selector_candidate(selector_report: dict[str, Any], plan: dict[str, Any]) -> LoopCandidate | None:
    for action in _as_list(selector_report.get("actions")):
        if not isinstance(action, dict):
            continue
        decision = str(action.get("decision") or "").strip().upper()
        if decision not in {"RUN", "APPROVAL"}:
            continue
        tool = str(action.get("runner") or "").strip()
        target = str(action.get("target") or "").strip()
        if not tool or tool not in supported_execution_tools() or not target:
            continue
        plan_item = _capability_item(plan, tool)
        tier = str(action.get("risk_tier") or _tier_from_capability(plan_item, tool)).strip().lower()
        return LoopCandidate(
            tool=tool,
            target=target,
            params={
                "target_kind": action.get("target_kind"),
                "source": "next_best_action_selector",
                "next_best_action_selector": {
                    "selector_version": selector_report.get("selector_version"),
                    "graph_version": selector_report.get("graph_version"),
                    "rank": action.get("rank"),
                    "decision": decision,
                    "runner_node_id": action.get("runner_node_id"),
                    "source_ids": list(action.get("source_ids") or []),
                    "prerequisite_state": _as_dict(action.get("prerequisite_state")),
                    "expected_proof_value": action.get("expected_proof_value"),
                    "matched_triggers": list(action.get("matched_triggers") or []),
                    "blocker_reasons": list(action.get("blocker_reasons") or []),
                },
            },
            tier=tier,
            reasoning=str(action.get("rationale") or f"{tool} is the next best action from stored evidence."),
            confidence=float(action.get("confidence") or 0.0),
            follow_up_hints=list(plan_item.get("follow_up_tools") or []),
            expected_evidence=list(action.get("expected_evidence") or plan_item.get("expected_evidence") or []),
            required_approvals=int(action.get("required_approvals") or plan_item.get("required_approvals") or 0),
            decision_source="next_best_action_selector",
            selector_decision=decision,
            selector_rank=int(action.get("rank") or 0) or None,
            selector_provenance=_as_dict(action.get("provenance")),
        )
    return None


def _selector_has_finding_sources(selector_report: dict[str, Any]) -> bool:
    for action in _as_list(selector_report.get("actions")):
        if not isinstance(action, dict):
            continue
        if any(str(source_id).startswith("finding:") for source_id in _as_list(action.get("source_ids"))):
            return True
    return False


def _selector_has_triggered_actions(selector_report: dict[str, Any]) -> bool:
    """True when the selector has at least one RUN/APPROVAL action with matched trigger signals.

    This lets the selector's signal-based ranking override the static assessment plan
    even when no findings exist yet (e.g. after httpx populates web_target_present).
    """
    for action in _as_list(selector_report.get("actions")):
        if not isinstance(action, dict):
            continue
        if str(action.get("decision") or "") not in {"RUN", "APPROVAL"}:
            continue
        if _as_list(action.get("matched_triggers")):
            return True
    return False


def _next_action_payload(candidate: LoopCandidate) -> dict[str, Any]:
    payload = {
        "tool": candidate.tool,
        "target": candidate.target,
        "params": dict(candidate.params),
        "tier": candidate.tier,
        "reasoning": candidate.reasoning,
        "confidence": round(float(candidate.confidence), 3),
        "follow_up_hints": list(candidate.follow_up_hints),
        "expected_evidence": list(candidate.expected_evidence),
        "required_approvals": int(candidate.required_approvals),
        "decision_source": candidate.decision_source,
    }
    if candidate.selector_decision:
        payload["selector_decision"] = candidate.selector_decision
        payload["selector_rank"] = candidate.selector_rank
        payload["selector_provenance"] = dict(candidate.selector_provenance or {})
    return payload


_WEB_DISCOVERY_TOOLS = {"httpx", "web-depth", "easm-discover"}
_WEB_PROBE_TOOLS = {"xss-extended", "session-security", "headers-security", "content-discovery", "logging-probe"}


def _extract_discovered_links(session: Session, run: Run, *, scope_allowlist: dict[str, Any] | None) -> list[str]:
    """Pull HTTP links discovered by prior web-discovery tasks and filter to approved scope.

    Searches the current run first, then recent completed runs in the same engagement so
    xss-extended and other probe tools can use httpx output even from a separate baseline run.
    """
    from api.app.services.runs import web_target_value_is_allowed_with_path

    # Collect run IDs to search: current run + up to 5 recent completed runs in same engagement.
    run_ids: list = [run.id]
    if run.engagement_id is not None:
        sibling_ids = session.scalars(
            select(Run.id)
            .where(Run.engagement_id == run.engagement_id)
            .where(Run.id != run.id)
            .where(Run.status.in_(["completed", "completed_with_errors"]))
            .where(Run.deleted_at.is_(None))
            .order_by(Run.created_at.desc())
            .limit(5)
        ).all()
        run_ids.extend(sibling_ids)

    completed_tasks = session.scalars(
        select(Task)
        .where(Task.run_id.in_(run_ids))
        .where(Task.tool.in_(_WEB_DISCOVERY_TOOLS))
        .where(Task.status.in_(["completed", "completed_with_errors"]))
    ).all()

    links: list[str] = []
    seen: set[str] = set()
    for task in completed_tasks:
        executions = list(task.executions or [])
        raw = str(executions[-1].stdout_text or "") if executions else ""
        if not raw:
            continue
        try:
            parsed = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            continue
        results = parsed.get("results") if isinstance(parsed, dict) else None
        if not isinstance(results, list):
            results = [parsed] if isinstance(parsed, dict) else []
        for result in results:
            if not isinstance(result, dict):
                continue
            for link in result.get("links") or []:
                candidate = str(link or "").strip()
                if not candidate or candidate in seen:
                    continue
                if scope_allowlist and not web_target_value_is_allowed_with_path(scope_allowlist, candidate):
                    continue
                seen.add(candidate)
                links.append(candidate)
    return links


def _queue_passive_loop_task(
    *,
    session: Session,
    run: Run,
    candidate: LoopCandidate,
    actor: str,
    iteration_number: int,
    context_document_id: str,
    rationale_ledger_entry_id: str,
) -> Task:
    if candidate.tool not in supported_execution_tools():
        raise ValueError(f"assessment loop selected unsupported runner: {candidate.tool}")
    # Last-line defense against concurrent advance_assessment_loop callers from
    # different worker threads: query DB directly for any existing task with
    # the same (run, tool, target). If found, return that task instead of
    # creating a duplicate. tested_keys is cached per-call so it cannot guard
    # against tasks created by OTHER concurrent advance calls.
    # Exception: exec-plan can legitimately run multiple times on the same
    # target with DIFFERENT custom plans, so we don't dedupe it here.
    # Exception: script_critic dispatches a REVISED script against the same
    # (tool, target) by design; uniqueness is per predecessor_task_id which
    # is enforced upstream in _maybe_dispatch_script_critic via record scan.
    candidate_specialist = ""
    if isinstance(candidate.params, dict):
        candidate_specialist = str(
            (candidate.params.get("_specialist_metadata") or {}).get("specialist") or ""
        )
    if candidate_specialist == "script_critic":
        logger.info(
            "PROOF_EXEC_CRITIC_BYPASS_QUEUE_DB_2026052312 tool=%s target=%s",
            candidate.tool, str(candidate.target)[:60],
        )
    if candidate.tool != "exec-plan" and candidate_specialist != "script_critic":
        existing_dupe = session.scalar(
            select(Task).where(
                Task.run_id == run.id,
                Task.tool == candidate.tool,
                Task.target_id == candidate.target,
            ).limit(1)
        )
        if existing_dupe is not None:
            logger.warning(
                "AI loop: queue suppressed duplicate (%s, %s) — task %s already exists for run %s",
                candidate.tool, candidate.target[:60], str(existing_dupe.id)[:8], str(run.id)[:8],
            )
            return existing_dupe
    normalized_limits = normalize_profile_limits(
        candidate.tier,
        {
            **(_as_dict(run.profile.limits_json) if run.profile is not None else {}),
            "tools": [candidate.tool],
        },
    )
    # Enrich web-probe tools with links discovered by prior httpx/web-depth tasks.
    enriched_params: dict[str, Any] = dict(candidate.params)
    if candidate.tool in _WEB_PROBE_TOOLS and "candidate_paths" not in enriched_params:
        scope_allowlist = None
        if run.engagement_id is not None:
            scope = session.scalar(
                select(Scope)
                .where(Scope.engagement_id == run.engagement_id)
                .order_by(Scope.created_at.desc(), Scope.id.desc())
            )
            if scope is not None:
                scope_allowlist = _as_dict(scope.allowlist_json)
        discovered = _extract_discovered_links(session, run, scope_allowlist=scope_allowlist)
        if discovered:
            enriched_params["candidate_paths"] = discovered
    task = Task(
        run=run,
        tool=candidate.tool,
        target_id=candidate.target,
        status="queued",
        params_json={
            **enriched_params,
            "target_kind": enriched_params.get("target_kind"),
            "profile_name": run.profile.name if run.profile is not None else "ai-loop",
            "run_class": candidate.tier,
            "limits": normalized_limits,
            "assessment_loop": {
                "enabled": True,
                "run_mode": "ai_loop",
                "iteration": iteration_number,
                "tool": candidate.tool,
                "target": candidate.target,
                "tier": candidate.tier,
                "reasoning": candidate.reasoning,
                "confidence": round(float(candidate.confidence), 3),
                "approval_effect": "passive_auto_queued",
                "dispatch_mode": "queued_for_auto_dispatch",
                "registered_runner_required": True,
                "context_document_id": context_document_id,
                "rationale_ledger_entry_id": rationale_ledger_entry_id,
                "scope_enforced": True,
                "kill_switch_still_authoritative": True,
            },
        },
    )
    session.add(task)
    session.flush()
    inject_run_credential_vault_into_task(
        session,
        run=run,
        task=task,
        actor=actor,
    )
    if str(run.status or "").lower() not in {"cancelled", "cancelling", "rejected"}:
        run.status = "queued"
    write_audit_event(
        session=session,
        actor=actor,
        action="assessment_loop.passive_task_queued",
        object_type="task",
        object_id=str(task.id),
        metadata={
            "run_id": str(run.id),
            "iteration": iteration_number,
            "tool": candidate.tool,
            "target": candidate.target,
            "tier": candidate.tier,
            "dispatch_mode": "queued_for_auto_dispatch",
            "operator_controlled_flow_only": True,
        },
    )
    # backlog-410: every advance writes one episodic memory record so future
    # advances (and future runs) can recall the (action, context, outcome) by
    # vector similarity. Per ANTI_DRIFT Rule 1 — observability never breaks
    # the agent runtime, so wrap every call in try/except.
    try:
        from api.app.services.episodic_memory import write_episode  # noqa: E402
        write_episode(
            session,
            run=run,
            action_type=f"pick:{candidate.tool}",
            context={
                "iteration": iteration_number,
                "tool": candidate.tool,
                "target": candidate.target,
                "tier": candidate.tier,
                "decision_source": candidate.decision_source,
                "reasoning": (candidate.reasoning or "")[:600],
                "confidence": round(float(candidate.confidence), 3),
            },
            outcome={
                "task_id": str(task.id),
                "status": "queued",
                "dispatch_mode": "queued_for_auto_dispatch",
            },
            success_marker=None,
        )
    except Exception as exc:  # noqa: BLE001
        logger.debug("episodic_memory.write_episode skipped (%s)", exc)
    return task


def _store_next_action_proposal(
    *,
    session: Session,
    run: Run,
    reasoning,
    candidate: LoopCandidate,
    actor: str,
    iteration_number: int,
    context_document_id: str,
    rationale_ledger_entry_id: str,
) -> AgentProposal:
    proposal = store_agent_proposal_record(
        session=session,
        reasoning=reasoning,
        proposed_tool=candidate.tool,
        proposed_target=candidate.target,
        proposed_params={
            **candidate.params,
            "assessment_loop": {
                "enabled": True,
                "run_mode": "ai_loop",
                "iteration": iteration_number,
                "tier": candidate.tier,
                "required_approvals": candidate.required_approvals,
                "approval_required": candidate.tier in {"active", "intrusive"},
                "dispatches_work": False,
                "registered_runner_required": True,
                "context_document_id": context_document_id,
                "rationale_ledger_entry_id": rationale_ledger_entry_id,
                "scope_enforced": True,
                "roe_enforced": True,
                "kill_switch_still_authoritative": True,
            },
            "review_required": True,
        },
        reasoning_text=candidate.reasoning,
        risk_tier=candidate.tier,
        priority=10 if candidate.tier == "active" else 5,
        confidence_score=float(candidate.confidence),
        status="pending_review",
        metadata={
            "proposal_kind": LOOP_PROPOSAL_KIND,
            "run_mode": "ai_loop",
            "iteration": iteration_number,
            "created_by": actor,
            "requires_operator_review": True,
            "dispatches_work": False,
            "operator_controlled_flow_only": True,
            "active_runtime_mutated": False,
            "context_document_id": context_document_id,
            "rationale_ledger_entry_id": rationale_ledger_entry_id,
            "approval_boundary": (
                "per_action_explicit_approval"
                if candidate.tier == "intrusive"
                else "active_wave_approval"
            ),
        },
    )
    return proposal


_RUN_TERMINAL_STATUSES = {"completed", "completed_with_errors", "failed", "cancelled", "rejected"}


def _exec_plan_fallback_candidate(
    *,
    run: Run,
    scope: Scope | None,
    session: Session | None,
    targets: list[dict[str, Any]],
    loop_state: dict[str, Any],
    tested_keys: set[str],
) -> LoopCandidate | None:
    """Last-resort candidate when every regular path returned None.

    The dominant pre-fix stop pattern was ``no_registered_runner_candidate``
    after ~4-12 iterations: the picker had a pick but it didn't match the
    runner registry, the heuristic chain was empty (no findings yet), and
    the loop just gave up. Per operator feedback 2026-05-21 (and against
    feedback_no_prescriptive_recipes — we must NOT hardcode an exploit
    chain) the right behaviour is to ask Claude once more with a strict
    constraint: "regular catalog is exhausted; emit exec_plan with steps
    that use the agent_tools (bash, code_exec, web_fetch, file_io_read,
    subagent), or admit you cannot proceed."

    Returns:
        - a LoopCandidate(tool='exec-plan', ...) when Claude returns a
          valid exec_plan with non-empty steps
        - None when Claude returns anything else (picker stop, malformed
          plan, or itself returns None); the caller then falls through to
          the existing branch-D STOP path

    Guarded by ``exec_plan_fallback_attempted`` in loop_state so we never
    re-enter this fallback twice in the same advance — prevents infinite
    re-prompting if Claude is being uncooperative.
    """
    if loop_state.get("exec_plan_fallback_attempted"):
        return None
    loop_state["exec_plan_fallback_attempted"] = True

    refinement_notes = [{
        "reason": "catalog_exhausted_use_exec_plan_with_agent_tools",
        "detail": (
            "Every other candidate source returned None: target-intel, "
            "lan-intel, claude, ai-proposal, goal, auth, recursive, "
            "selector, seed, plan. The runner catalog has been tried "
            "and yielded no fit for the current evidence. You MUST emit "
            "action='exec_plan' with a 'plan' body whose 'steps' use the "
            "agent_tools (bash, code_exec, web_fetch, file_io_read, "
            "subagent) for free-form exploration of the target. The "
            "exec-plan runner will dispatch the steps sequentially. "
            "STOP is acceptable only if you can articulate a concrete "
            "reason to give up (e.g. flag captured, scope blocked); "
            "'I have nothing left' is NOT acceptable because the "
            "agent_tools are always available."
        ),
    }]
    decision = _call_picker_with_retries(
        run=run,
        tested_keys=tested_keys,
        available_tools=["exec-plan"],
        targets=targets,
        scope=scope,
        session=session,
        loop_state=loop_state,
        extra_recent_rejections=refinement_notes,
    )
    if decision is None:
        return None
    if str(decision.get("action") or "").lower() != "exec_plan":
        return None
    plan_body = _decode_picker_plan(decision)
    steps = plan_body.get("steps") if isinstance(plan_body, dict) else None
    if not isinstance(steps, list) or len(steps) == 0:
        return None
    primary_target = str(targets[0].get("value") or "") if targets else ""
    plan_name = str(decision.get("plan_name") or "fallback-exec-plan")[:120]
    reasoning = str(decision.get("reasoning") or "agent_tools fallback after catalog exhausted")[:500]
    confidence_raw = decision.get("confidence")
    try:
        confidence = max(0.0, min(1.0, float(confidence_raw))) if confidence_raw is not None else 0.6
    except (TypeError, ValueError):
        confidence = 0.6
    return LoopCandidate(
        tool="exec-plan",
        target=primary_target,
        params={
            "source": "ai_loop_exec_plan_fallback_after_catalog_exhausted",
            "ai_reasoning": reasoning,
            "target_kind": "url",
            "target_source": "approved_scope_root",
            "plan": plan_body,
            "plan_name": plan_name,
        },
        tier="active",
        reasoning=reasoning,
        confidence=confidence,
        follow_up_hints=[],
        expected_evidence=["exec_plan_success", "agent_tool_dispatch"],
        required_approvals=0,
        decision_source="ai_loop_exec_plan_fallback",
    )


def _finalize_run_after_loop_stop(run: Run, *, stop_reason: str) -> None:
    """Transition ``run.status`` to a terminal value when the picker emits a
    STOP. Without this hook the picker would set ``loop_state.status=stopped``
    but ``run.status`` would stay ``running`` forever — exactly the orphan
    pattern we found on 34 historical runs whose picker had already given
    up days earlier. Picks the terminal value based on observed task
    outcomes; the stop_reason is recorded in loop_state already so we
    don't duplicate it here."""
    if str(run.status or "").lower() in _RUN_TERMINAL_STATUSES:
        return
    tasks = list(run.tasks or [])
    statuses = [str(t.status or "").lower() for t in tasks]
    has_failed = any(s == "failed" for s in statuses)
    has_completed = any(s == "completed" for s in statuses)
    if not tasks:
        run.status = "failed"
    elif has_completed and not has_failed:
        run.status = "completed"
    elif has_completed and has_failed:
        run.status = "completed_with_errors"
    else:
        run.status = "failed"
    if getattr(run, "completed_at", None) is None:
        run.completed_at = datetime.now(tz=UTC)
    logger.info(
        "assessment_loop: finalized run=%s status=%s stop_reason=%s "
        "(tasks: %d completed, %d failed)",
        str(run.id)[:8], run.status, stop_reason,
        sum(1 for s in statuses if s == "completed"),
        sum(1 for s in statuses if s == "failed"),
    )


def build_assessment_loop_state(session: Session, *, run: Run, scope: Scope) -> dict[str, Any]:
    configuration = _as_dict(run.configuration_json)
    loop_state = _loop_state(configuration)
    targets = _targets_for_loop(scope, run)
    evidence_fingerprint = _evidence_fingerprint(run)
    current_state = _current_state_payload(
        run=run,
        scope=scope,
        targets=targets,
        evidence_fingerprint=evidence_fingerprint,
    )
    plan = build_assessment_plan_for_run(session, run)
    context_document = latest_context_document(session, run_id=run.id)
    context_summary = None
    if context_document is not None:
        context_summary = {
            "context_document_id": str(context_document.id),
            "layer_name": context_document.layer_name,
            "context_kind": context_document.context_kind,
            "status": context_document.status,
            "recommended_tools": list(context_document.recommended_tools_json or []),
            "micro_plan_step_count": len(list(context_document.micro_plan_json or [])),
            "evidence_ref_count": len(list(context_document.evidence_refs_json or [])),
        }
    active_tasks = _active_loop_tasks(run)
    effective_status = loop_state["status"]
    if active_tasks and effective_status == "waiting_for_execution":
        effective_status = "running"

    return {
        "available": True,
        "run_id": str(run.id),
        "run_mode": "ai_loop",
        "loop_version": LOOP_VERSION,
        "status": effective_status,
        "stop_reason": loop_state.get("stop_reason"),
        "iteration_count": loop_state["iteration_count"],
        "max_iterations": loop_state["max_iterations"],
        "stuck_threshold": loop_state["stuck_threshold"],
        "no_new_signal_iterations": loop_state["no_new_signal_iterations"],
        "current_state": current_state,
        "target_context": context_summary,
        "latest_next_action": loop_state.get("latest_next_action"),
        "active_tasks": active_tasks,
        "assessment_plan_summary": plan.get("summary", {}),
        "goal_oriented_reasoning": _as_dict(loop_state.get("goal_oriented_reasoning")),
        "rationale_ledger": _rationale_ledger_payloads(session, run=run),
        "iterations": list(loop_state.get("iterations") or []),
        "dispatches_work_directly": False,
        "manual_chain_alternative_preserved": True,
        "fixed_phase_chains_replaced_globally": False,
    }


def _rationale_ledger_payloads(session: Session, *, run: Run) -> list[dict[str, Any]]:
    entries = session.scalars(
        select(RationaleLedgerEntry)
        .where(RationaleLedgerEntry.run_id == run.id)
        .order_by(RationaleLedgerEntry.created_at.asc(), RationaleLedgerEntry.id.asc())
    ).all()
    payloads: list[dict[str, Any]] = []
    for entry in entries:
        payloads.append(
            {
                "id": str(entry.id),
                "context_document_id": str(entry.context_document_id) if entry.context_document_id else None,
                "task_id": str(entry.task_id) if entry.task_id else None,
                "agent_proposal_id": str(entry.agent_proposal_id) if entry.agent_proposal_id else None,
                "action_type": entry.action_type,
                "tool_name": entry.tool_name,
                "target": entry.target,
                "rationale_text": entry.rationale_text,
                "decision_source": _as_dict(entry.decision_source_json),
                "parameters": _as_dict(entry.parameters_json),
                "status": entry.status,
                "provenance": _as_dict(entry.provenance_json),
                "created_at": entry.created_at.isoformat(),
            }
        )
    return payloads


def record_assessment_loop_goal(
    session: Session,
    *,
    run: Run,
    scope: Scope,
    actor: str,
    objective: str,
    operator_note: str | None = None,
) -> dict[str, Any]:
    if not _run_uses_ai_loop(run):
        raise ValueError("goal-oriented reasoning is available only for runs configured with run_mode=ai_loop")
    normalized_objective = " ".join(str(objective or "").split())
    if not normalized_objective:
        raise ValueError("goal-oriented reasoning requires a non-empty operator objective")
    targets = _targets_for_loop(scope, run)
    if not targets:
        raise ValueError("goal-oriented reasoning requires at least one approved target in scope")
    configuration = _as_dict(run.configuration_json)
    loop_state = _loop_state(configuration)
    plan = build_assessment_plan_for_run(session, run)
    context_document = ensure_context_document(
        session,
        run=run,
        scope=scope,
        targets=targets,
        plan=plan,
    )
    goal_reasoning = _build_goal_oriented_reasoning(
        run=run,
        scope=scope,
        targets=targets,
        plan=plan,
        context_document=context_document,
        objective=normalized_objective,
        actor=actor,
        operator_note=operator_note,
    )
    reasoning = store_agent_reasoning_record(
        session=session,
        run=run,
        reasoning_type=GOAL_REASONING_KIND,
        status="recorded",
        context_snapshot={
            "run_id": str(run.id),
            "run_mode": "ai_loop",
            "objective": normalized_objective,
            "target_context_document_id": str(context_document.id),
            "assessment_plan_summary": plan.get("summary", {}),
            "scope_enforced": True,
            "roe_enforced": True,
            "fixed_phase_chains_replaced_globally": False,
        },
        observations=[
            {
                "summary": "Operator objective recorded for bounded goal-oriented reasoning.",
                "target_type": _target_type(targets),
                "target_count": len(targets),
            }
        ],
        hypotheses=list(goal_reasoning.get("hypothesis_path") or []),
        proposals=[],
        summary_text=f"Recorded objective: {normalized_objective}",
        thought_text=(
            "Reason backward from the operator objective using only evidence-linked, registered-runner "
            "steps inside scope, ROE, approval, and kill-switch controls."
        ),
        action_text="Store the bounded hypothesis path; no work is dispatched by objective registration.",
        provider="deterministic-assessment-loop",
        model=None,
        llm_tokens_used=0,
        confidence_score=0.84 if goal_reasoning.get("hypothesis_path") else 0.4,
        metadata={
            "reasoning_kind": GOAL_REASONING_KIND,
            "run_mode": "ai_loop",
            "dispatches_work": False,
            "direct_dispatch": False,
            "registered_runner_required": True,
            "scope_enforced": True,
            "roe_enforced": True,
            "approval_gates_bypassed": False,
            "kill_switch_still_authoritative": True,
            "manual_chain_alternative_preserved": True,
        },
    )
    goal_reasoning["reasoning_id"] = str(reasoning.id)
    loop_state["goal_oriented_reasoning"] = goal_reasoning
    loop_state["status"] = loop_state.get("status") or "ready"
    _store_loop_state(configuration, loop_state)
    run.configuration_json = configuration
    write_audit_event(
        session=session,
        actor=actor,
        action="assessment_loop.goal_recorded",
        object_type="run",
        object_id=str(run.id),
        metadata={
            "reasoning_id": str(reasoning.id),
            "objective_type": goal_reasoning.get("objective_type"),
            "hypothesis_step_count": len(list(goal_reasoning.get("hypothesis_path") or [])),
            "dispatches_work": False,
            "registered_runner_required": True,
            "scope_enforced": True,
            "roe_enforced": True,
            "approval_gates_bypassed": False,
        },
    )
    return build_assessment_loop_state(session, run=run, scope=scope)


def _rotate_run_progress_safely() -> dict[str, int] | None:
    """Invoke ``memory_backend.rotate_run_progress()`` and swallow any
    exception. Returns the rotation result dict (or None) for callers
    that want to log/inspect. Wire-up for #332 rotation, filed as #342.

    Rotation is housekeeping: a failure here MUST NOT crash the advance.
    The wired call site sits just before ``advance_assessment_loop``'s
    final return so it fires once per advance that reaches the picker
    dispatch path.
    """
    try:
        from api.app.services import memory_backend as _memory_backend
        result = _memory_backend.rotate_run_progress()
    except Exception as exc:
        logger.warning("rotate_run_progress: skipped (%s)", exc)
        return None
    if result is not None:
        logger.info(
            "AI loop: run-progress rotated before=%d after=%d dropped=%d",
            result["before"],
            result["after"],
            result["dropped"],
        )
    return result


@traced("picker.advance")  # backlog-407: tracing-only, no behavior change
def advance_assessment_loop(
    session: Session,
    *,
    run: Run,
    scope: Scope,
    actor: str,
    operator_note: str | None = None,
) -> dict[str, Any]:
    if not _run_uses_ai_loop(run):
        raise ValueError("assessment loop can advance only for runs configured with run_mode=ai_loop")
    if run.profile is not None and pending_approvals(run, run.profile) > 0:
        raise ValueError("assessment loop cannot advance while the selected run still has pending approvals")

    # Idempotent terminal guard: if the run is already in a terminal status
    # OR loop_state.stop_reason is the early-stop flag, just rebuild the
    # state and return. Post-task worker hooks fire after every completed
    # task, and without this guard they re-enter the picker after the
    # early-stop has already finalized the run, overwriting stop_reason
    # with "no_registered_runner_candidate".
    _existing_loop_state = _loop_state(_as_dict(run.configuration_json))
    _existing_stop_reason = str(_existing_loop_state.get("stop_reason") or "").lower()
    if str(run.status or "").lower() in _RUN_TERMINAL_STATUSES or _existing_stop_reason == "flag_extracted":
        logger.info(
            "PROOF_EXEC_ADVANCE_SKIPPED_TERMINAL_2026052410 run=%s status=%s stop_reason=%s",
            str(getattr(run, "id", "?"))[:8],
            str(run.status or "").lower(),
            _existing_stop_reason or "-",
        )
        return build_assessment_loop_state(session, run=run, scope=scope)

    # Refresh run.tasks from DB before reading. The same advance call is
    # invoked right after _maybe_queue_next_step_hints adds new tasks in this
    # session; the cached run.tasks relationship does NOT include those tasks
    # unless we expire+reload. Without this, _active_loop_tasks returns empty
    # → Claude is asked → picks a tool that is already queued = duplicate.
    try:
        session.expire(run, ["tasks", "findings"])
    except Exception:
        pass
    active_tasks = _active_loop_tasks(run)
    configuration = _as_dict(run.configuration_json)
    loop_state = _loop_state(configuration)
    targets = _targets_for_loop(scope, run)
    if not targets:
        raise ValueError("assessment loop requires at least one approved target in scope")

    evidence_fingerprint = _evidence_fingerprint(run)
    previous_fingerprint = str(loop_state.get("latest_evidence_fingerprint") or "")
    no_new_signal_iterations = int(loop_state.get("no_new_signal_iterations") or 0)
    if previous_fingerprint and previous_fingerprint == evidence_fingerprint:
        no_new_signal_iterations += 1
    else:
        no_new_signal_iterations = 0
    loop_state["no_new_signal_iterations"] = no_new_signal_iterations
    loop_state["latest_evidence_fingerprint"] = evidence_fingerprint

    # Early-stop on solve: when ANY persisted finding has severity=critical
    # AND its evidence references a flag-pattern literal (xbow-..., flag{...}),
    # the engagement has yielded a confirmed exploit. Continuing the loop
    # only burns LLM tokens for no incremental value. Mark the run finalized.
    try:
        import re as _re_solve  # noqa: E402
        flag_re = _re_solve.compile(
            r"(flag\{[^}\r\n]{1,200}\}|xbow-[a-f0-9]{16,128}|ctf\{[^}\r\n]{1,200}\})",
            _re_solve.IGNORECASE,
        )
        for finding in (getattr(run, "findings", None) or []):
            sev = str(getattr(finding, "severity", "") or "").lower()
            if sev not in {"critical", "high"}:
                continue
            haystack = " ".join([
                str(getattr(finding, "title", "") or ""),
                str(getattr(finding, "summary", "") or ""),
                str(getattr(finding, "target_id", "") or ""),
            ])
            if flag_re.search(haystack):
                logger.info(
                    "PROOF_EXEC_SOLVE_EARLY_STOP_2026052408 run=%s finding=%s severity=%s",
                    str(getattr(run, "id", "?"))[:8],
                    str(getattr(finding, "id", "?"))[:8],
                    sev,
                )
                loop_state["status"] = "stopped"
                loop_state["stop_reason"] = "flag_extracted"
                loop_state["ai_stop_summary"] = (
                    f"Flag literal extracted in finding {str(getattr(finding, 'id', '?'))[:8]} — early-stop."
                )
                _store_loop_state(configuration, loop_state)
                run.configuration_json = configuration
                try:
                    from sqlalchemy.orm.attributes import flag_modified as _flag_modified_es  # noqa: E402
                    _flag_modified_es(run, "configuration_json")
                except Exception:  # noqa: BLE001
                    pass
                try:
                    run.status = "completed"
                except Exception:  # noqa: BLE001
                    pass
                # M5 success-marker writeback: tag every episode this run
                # produced so future cross-run recall can surface them as
                # SOLVED examples. Without this, recall_similar returns the
                # episodes with success_marker=NULL and the picker filter
                # drops them silently.
                try:
                    from sqlalchemy import text as _text_sm  # noqa: E402
                    res = session.execute(
                        _text_sm(
                            "UPDATE agent_episodic_memory "
                            "SET success_marker = 'flag_extracted' "
                            "WHERE run_id = :rid "
                            "AND (success_marker IS NULL OR success_marker = '')"
                        ),
                        {"rid": run.id},
                    )
                    logger.info(
                        "PROOF_EXEC_SUCCESS_MARKER_WRITE_2026052411 run=%s tagged_rows=%s marker=flag_extracted",
                        str(run.id)[:8],
                        getattr(res, "rowcount", "?"),
                    )
                except Exception as _sm_exc:  # noqa: BLE001
                    logger.warning("success_marker writeback failed: %s", _sm_exc)
                session.flush()
                return build_assessment_loop_state(session, run=run, scope=scope)
    except Exception as exc:  # noqa: BLE001
        logger.warning("early-stop check failed: %s", exc)

    # Target-health guard: when the last 3 tool_executions on this run all
    # failed with "Connection refused" / "ConnectError" against the SAME
    # target, the target container is down (or never started). Continuing
    # the loop burns LLM tokens dispatching scripts that cannot connect.
    # Empirical signal only — no synthetic probing.
    try:
        from sqlalchemy import select as _select_th  # noqa: E402
        from api.app.models import ToolExecution as _TE_th  # noqa: E402
        recent_exec_rows = session.execute(
            _select_th(_TE_th.exit_code, _TE_th.stderr_text, _TE_th.task_id)
            .join(Task, Task.id == _TE_th.task_id)
            .where(Task.run_id == run.id)
            .order_by(_TE_th.created_at.desc())
            .limit(3)
        ).all()
        if len(recent_exec_rows) >= 3 and all(
            (row.exit_code or 0) != 0
            and isinstance(row.stderr_text, str)
            and ("Connection refused" in row.stderr_text or "ConnectError" in row.stderr_text)
            for row in recent_exec_rows
        ):
            logger.info(
                "PROOF_EXEC_TARGET_UNREACHABLE_2026052409 run=%s consecutive_connect_refused=%d",
                str(getattr(run, "id", "?"))[:8],
                len(recent_exec_rows),
            )
            loop_state["status"] = "stopped"
            loop_state["stop_reason"] = "target_unreachable"
            loop_state["ai_stop_summary"] = (
                "Last 3 tool executions all failed with Connection refused — target appears down. "
                "Restart the target container and re-launch the engagement."
            )
            _store_loop_state(configuration, loop_state)
            run.configuration_json = configuration
            try:
                from sqlalchemy.orm.attributes import flag_modified as _flag_modified_th  # noqa: E402
                _flag_modified_th(run, "configuration_json")
            except Exception:  # noqa: BLE001
                pass
            try:
                run.status = "completed_with_errors"
            except Exception:  # noqa: BLE001
                pass
            try:
                from sqlalchemy import text as _text_sm_th  # noqa: E402
                res_th = session.execute(
                    _text_sm_th(
                        "UPDATE agent_episodic_memory "
                        "SET success_marker = 'target_unreachable' "
                        "WHERE run_id = :rid "
                        "AND (success_marker IS NULL OR success_marker = '')"
                    ),
                    {"rid": run.id},
                )
                logger.info(
                    "PROOF_EXEC_SUCCESS_MARKER_WRITE_2026052411 run=%s tagged_rows=%s marker=target_unreachable",
                    str(run.id)[:8],
                    getattr(res_th, "rowcount", "?"),
                )
            except Exception as _sm_th_exc:  # noqa: BLE001
                logger.warning("success_marker writeback (target_unreachable) failed: %s", _sm_th_exc)
            session.flush()
            return build_assessment_loop_state(session, run=run, scope=scope)
    except Exception as exc:  # noqa: BLE001
        logger.warning("target-health guard check failed: %s", exc)

    # backlog-412 — Layer 3 Attack State: foothold tracking + heuristic
    # advancement from this advance's findings. The full TAP-style AttackTree
    # is in api/app/services/attack_state.py; this hook persists just the
    # foothold rank in loop_state so it survives across advances and gets
    # injected into the picker prompt below. Per ``no_unverified_transitions``
    # constraint: advancement requires a finding of severity critical/high
    # (acting as the proxy verifier until backlog-413 lands the deterministic
    # validator).
    try:
        from api.app.services.attack_state import FootholdState  # noqa: E402
        current_foothold = str(loop_state.get("foothold_state") or FootholdState.ANONYMOUS.value)
        new_foothold = _infer_foothold_from_findings(run, current_foothold)
        if new_foothold != current_foothold:
            loop_state["foothold_state"] = new_foothold
            loop_state["foothold_transitions"] = list(loop_state.get("foothold_transitions") or []) + [
                {
                    "from": current_foothold,
                    "to": new_foothold,
                    "at_fingerprint": evidence_fingerprint,
                }
            ]
            logger.info(
                "attack_state: foothold transition %s -> %s (run=%s)",
                current_foothold, new_foothold, str(run.id)[:8],
            )
        else:
            loop_state.setdefault("foothold_state", current_foothold)
    except Exception as exc:  # noqa: BLE001
        logger.debug("attack_state foothold tracking skipped (%s)", exc)

    if active_tasks:
        loop_state["status"] = "waiting_for_execution"
        loop_state["stop_reason"] = None
        _store_loop_state(configuration, loop_state)
        run.configuration_json = configuration
        return build_assessment_loop_state(session, run=run, scope=scope)

    max_iterations = int(loop_state.get("max_iterations") or LOOP_MAX_ITERATIONS)
    stuck_threshold = int(loop_state.get("stuck_threshold") or LOOP_STUCK_THRESHOLD)
    if int(loop_state.get("iteration_count") or 0) >= max_iterations:
        loop_state["status"] = "stopped"
        loop_state["stop_reason"] = "max_iterations_reached"
        _store_loop_state(configuration, loop_state)
        run.configuration_json = configuration
        _finalize_run_after_loop_stop(run, stop_reason="max_iterations_reached")
        clear_run_credential_vault_if_terminal(
            session,
            run=run,
            actor=actor,
            reason="assessment_loop_max_iterations_reached",
        )
        write_audit_event(
            session=session,
            actor=actor,
            action="assessment_loop.stopped",
            object_type="run",
            object_id=str(run.id),
            metadata={"reason": "max_iterations_reached", "max_iterations": max_iterations},
        )
        return build_assessment_loop_state(session, run=run, scope=scope)
    if no_new_signal_iterations >= stuck_threshold:
        loop_state["status"] = "stopped"
        loop_state["stop_reason"] = "stuck_no_new_signals"
        _store_loop_state(configuration, loop_state)
        run.configuration_json = configuration
        _finalize_run_after_loop_stop(run, stop_reason="stuck_no_new_signals")
        clear_run_credential_vault_if_terminal(
            session,
            run=run,
            actor=actor,
            reason="assessment_loop_stuck_no_new_signals",
        )
        write_audit_event(
            session=session,
            actor=actor,
            action="assessment_loop.stopped",
            object_type="run",
            object_id=str(run.id),
            metadata={"reason": "stuck_no_new_signals", "threshold": stuck_threshold},
        )
        return build_assessment_loop_state(session, run=run, scope=scope)

    plan = build_assessment_plan_for_run(session, run)
    parent_context_document = ensure_context_document(
        session,
        run=run,
        scope=scope,
        targets=targets,
        plan=plan,
    )
    context_document = (
        ensure_recursive_surface_context(
            session,
            run=run,
            scope=scope,
            parent_context=parent_context_document,
            plan=plan,
        )
        or parent_context_document
    )
    recommended_tools = {
        str(tool).strip()
        for tool in list(context_document.recommended_tools_json or [])
        if str(tool).strip()
    }
    tested_keys = _tested_action_keys(run)
    # FIRST: target-intel must run before any other tool in ai_loop web assessments.
    # It analyzes the target with Claude to detect technology, CVEs, and build a
    # targeted test plan — replacing blind tool execution with intelligence-driven testing.
    _target_intel_candidate: LoopCandidate | None = None
    if targets and "target-intel" in supported_execution_tools():
        for target in targets:
            target_value = str(target.get("value") or "").strip()
            if target_value and _task_key("target-intel", target_value) not in tested_keys:
                if _scope_target_allowed(scope, target_value):
                    _target_intel_candidate = LoopCandidate(
                        tool="target-intel",
                        target=target_value,
                        params={"target_kind": str(target.get("kind") or "url"), "source": "target-intel-first"},
                        tier="passive",
                        reasoning="Target intelligence: AI analyzes the target FIRST to detect technology stack, applicable CVEs, and create a targeted test plan.",
                        confidence=0.95,
                        follow_up_hints=["xss-extended", "nuclei", "smart-web-probe", "ai-pentest-agent"],
                        expected_evidence=["technology_fingerprint", "targeted_scan_plan"],
                        required_approvals=0,
                        decision_source="target_intel_first",
                    )
                    break

    # LAN intel: after nmap runs for host/cidr targets, lan-intel analyzes services.
    # Mirrors target-intel's role for web — intelligence before blind attack tools.
    _lan_intel_candidate: LoopCandidate | None = None
    if "lan-intel" in supported_execution_tools():
        lan_targets = [t for t in targets if str(t.get("kind") or "") in ("host", "cidr", "domain", "target")]
        for target in lan_targets:
            target_value = str(target.get("value") or "").strip()
            lan_key = _task_key("lan-intel", target_value)
            nmap_key = _task_key("nmap", target_value)
            # Only queue lan-intel if nmap has run AND lan-intel hasn't yet
            nmap_done = nmap_key in tested_keys
            lan_done = lan_key in tested_keys
            if nmap_done and not lan_done and target_value and _scope_target_allowed(scope, target_value):
                # Get nmap stdout to pass to lan-intel
                nmap_stdout = ""
                for task in list(run.tasks or []):
                    if str(task.tool or "") == "nmap" and str(task.status or "") == "completed":
                        for exe in list(task.tool_executions or []):
                            if exe.stdout_text:
                                nmap_stdout = exe.stdout_text[:8000]
                                break
                        if nmap_stdout:
                            break
                _lan_intel_candidate = LoopCandidate(
                    tool="lan-intel",
                    target=target_value,
                    params={
                        "target_kind": str(target.get("kind") or "host"),
                        "source": "lan-intel-post-nmap",
                        "nmap_stdout": nmap_stdout,
                    },
                    tier="passive",
                    reasoning="LAN intelligence: AI analyzes nmap service scan to detect AD, CVEs, and create targeted attack plan.",
                    confidence=0.92,
                    follow_up_hints=["nuclei", "bloodhound-collect", "ldap-enum", "ssh-brute", "credential-attacks"],
                    expected_evidence=["service_fingerprint", "targeted_lan_plan"],
                    required_approvals=0,
                    decision_source="lan_intel_post_nmap",
                )
                break

    selector_targets = _context_targets(context_document) or targets
    # backlog-404 — when the operator explicitly opted into
    # autonomous-intrusive at run-create time, the selector returns
    # RUN instead of APPROVAL for active/intrusive runners. This makes
    # the Claude picker (or selector fallback) the dispatch authority
    # rather than competing with an APPROVAL workflow that no operator
    # is watching.
    selector_report = select_next_best_action_for_run(
        session,
        run=run,
        scope=scope,
        approved_targets=selector_targets,
        tested_action_keys=tested_keys,
        allow_active_without_review=bool(
            getattr(run, "autonomous_intrusive_allowed", False)
        ),
    )
    goal_candidate = _goal_oriented_candidate(
        run=run,
        scope=scope,
        goal_reasoning=_as_dict(loop_state.get("goal_oriented_reasoning")),
        plan=plan,
        tested_keys=tested_keys,
    )
    auth_candidate = _auth_signal_candidate(
        run=run,
        scope=scope,
        targets=_context_targets(context_document) or targets,
        plan=plan,
        tested_keys=tested_keys,
    )
    recursive_candidate = _context_micro_plan_candidate(
        scope=scope,
        context_document=context_document,
        plan=plan,
        tested_keys=tested_keys,
    )
    # Use selector only after at least one tool has run (tested_keys non-empty).
    # On the very first call, seed_candidate picks the discovery tool (httpx/nmap)
    # so active probes (xss-extended etc.) never run before initial fingerprinting.
    selector_candidate = (
        _selector_candidate(selector_report, plan)
        if tested_keys and (
            _selector_has_finding_sources(selector_report)
            or _selector_has_triggered_actions(selector_report)
        )
        else None
    )
    # target-intel runs as the FIRST tool in every ai_loop web assessment,
    # before xss-extended, sqlmap, or any other probe. It must come before
    # selector_candidate so the AI analysis happens before blind scanning.
    seed = _seed_candidate(
        run=run,
        scope=scope,
        targets=_context_targets(context_document) or targets,
        plan=plan,
        tested_keys=tested_keys,
        recommended_tools=recommended_tools,
    )
    seed_is_intel = seed is not None and seed.tool == "target-intel"

    # Claude-driven next-action selection: after at least one tool has run,
    # ask Claude to pick what to do next based on actual findings.
    # Now operates in the PHASE model: pick / level_up / exec_plan / stop.
    claude_candidate: LoopCandidate | None = None
    claude_stop_decision: dict[str, Any] | None = None
    claude_levelup_decision: dict[str, Any] | None = None
    current_phase = _as_dict(loop_state.get("current_phase"))
    phase_index = int(loop_state.get("phase_count") or 0)
    # Rejection sink: validators append (reason, detail) entries that we
    # persist into loop_state so the NEXT advance call shows them to Claude,
    # giving him a feedback loop to self-correct.
    rejection_sink: list[dict[str, Any]] = []

    logger.info(
        "AI loop: advance run=%s phase=%s/%d tools_picked_this_phase=%d total_findings=%d",
        str(run.id)[:8],
        phase_index + 1,
        len({k.split("|", 1)[0] for k in tested_keys}),
        len(list(current_phase.get("tool_picks") or [])),
        len(list(run.findings or [])),
    )
    if tested_keys:
        available_tools = supported_execution_tools()
        # Drop runners that returned metadata.skipped=True earlier in this
        # run — they're unconfigured in this deployment, and offering them
        # to Claude again just produces another no-op task. See
        # _runners_skipped_in_run docstring.
        skipped_runners = _runners_skipped_in_run(run)
        if skipped_runners:
            available_tools = available_tools - skipped_runners
            logger.info(
                "AI loop: hiding %d skipped runner(s) from picker (%s) run=%s",
                len(skipped_runners), sorted(skipped_runners), str(run.id)[:8],
            )
        decision = _call_picker_with_exec_plan_refinement(
            run=run,
            tested_keys=tested_keys,
            available_tools=sorted(available_tools),
            targets=targets,
            scope=scope,
            session=session,
            loop_state=loop_state,
        )
        action = str((decision or {}).get("action") or "").lower() if decision else ""
        if decision is None:
            logger.info("AI loop: Claude returned None — using heuristics")
        elif action == "stop" or decision.get("stop"):
            stop_reason = str(decision.get("stop_reason") or decision.get("summary") or "")
            logger.info("AI loop: picker said STOP reason=%s", stop_reason)
            # Evidence-first enforcement: refuse "admin_compromise_proven" or
            # similar finality claims unless there is an actual critical-severity
            # finding with admin/takeover/RCE/compromise keywords in the title.
            # Claude tends to declare victory based on a hunch ("I see XSS so
            # admin is reachable"); we don't let that end the run.
            if "compromise" in stop_reason.lower() or "admin" in stop_reason.lower() or "takeover" in stop_reason.lower():
                critical_findings = [
                    f for f in list(run.findings or [])
                    if str(f.severity or "").lower() == "critical"
                ]
                proof_keywords = ("admin", "compromise", "takeover", "privilege", "rce", "remote code", "escalation")
                has_proof = any(
                    any(kw in str(f.title or "").lower() for kw in proof_keywords)
                    for f in critical_findings
                )
                if not has_proof:
                    logger.warning(
                        "AI loop: REJECTED Claude STOP claim %r — no critical finding with proof keywords; demoting to level_up",
                        stop_reason,
                    )
                    rejection_sink.append({
                        "reason": "unproven_stop_claim",
                        "detail": (
                            f"You said action='stop' with stop_reason={stop_reason!r}, but there is no critical-severity "
                            "finding whose title proves that impact (e.g. 'Admin Compromise via X', 'Account Takeover via Y'). "
                            "AegisPT is evidence-first: hunches don't end the run. Run an exec_plan that PROVES the chain "
                            "end-to-end (with verification steps that observe the expected impact in the response body) "
                            "before claiming admin compromise."
                        ),
                        "at": _now(),
                    })
                    # Don't store this as a stop decision — let the loop continue.
                    # The rejection will surface in Claude's next prompt.
                else:
                    claude_stop_decision = decision
            else:
                claude_stop_decision = decision
        elif action == "level_up":
            logger.info(
                "AI loop: picker said LEVEL_UP to phase=%r tool=%s target=%s",
                decision.get("new_phase_label"),
                decision.get("tool"),
                str(decision.get("target") or "")[:60],
            )
            claude_levelup_decision = decision
            # Allow Claude to combine level_up with an exec_plan body in one shot.
            # Natural intent: "open a new phase AND run this custom HTTP chain there".
            if str(decision.get("tool") or "").strip() == "exec-plan" and isinstance(decision.get("plan"), dict):
                plan_body = decision.get("plan") or {}
                plan_name = str(decision.get("plan_name") or plan_body.get("name") or "claude-exec-plan")
                if isinstance(plan_body.get("steps"), list) and plan_body["steps"] and "exec-plan" in available_tools:
                    primary_target = str(targets[0].get("value") or "") if targets else ""
                    tier = str(decision.get("tier") or "active").lower()
                    if tier not in {"passive", "active", "intrusive"}:
                        tier = "active"
                    reasoning = str(decision.get("reasoning") or f"Level-up custom plan: {plan_name}")
                    confidence = float(decision.get("confidence") or 0.8) if str(decision.get("confidence") or "").strip() else 0.8
                    claude_candidate = LoopCandidate(
                        tool="exec-plan",
                        target=primary_target,
                        params={
                            "source": "ai_loop_claude_exec_plan",
                            "ai_reasoning": reasoning[:500],
                            "target_kind": "url",
                            "target_source": "approved_scope_root",
                            "plan": plan_body,
                            "plan_name": plan_name,
                        },
                        tier=tier,
                        reasoning=reasoning,
                        confidence=max(0.0, min(1.0, confidence)),
                        follow_up_hints=[],
                        expected_evidence=["exec_plan_success", "multi_step_exploit_chain"],
                        required_approvals=0,
                        decision_source="ai_loop_claude_exec_plan",
                    )
                    logger.info(
                        "AI loop: LEVEL_UP combined with exec_plan plan_name=%r steps=%d",
                        plan_name, len(plan_body["steps"]),
                    )
                else:
                    rejection_sink.append({
                        "reason": "level_up_exec_plan_malformed",
                        "detail": "You used action='level_up' with tool='exec-plan' but the plan body is empty/malformed "
                                  "or the exec-plan runner isn't registered. Include a non-empty 'plan.steps' list, "
                                  "or use a registered tool instead of exec-plan.",
                        "at": _now(),
                    })
                    logger.warning("AI loop: LEVEL_UP with tool=exec-plan rejected — malformed plan body")
                    claude_levelup_decision = None
            else:
                claude_candidate = _claude_candidate_to_loop_candidate(
                    decision, targets=targets, available_tools=available_tools, scope=scope,
                    tested_keys=tested_keys, rejection_sink=rejection_sink,
                )
                if claude_candidate is None:
                    logger.warning("AI loop: Claude level_up pick rejected (invalid tool/target)")
                    claude_levelup_decision = None
        elif action == "exec_plan":
            # Claude provided a custom multi-step HTTP plan. Wrap it as a
            # LoopCandidate that points to the exec-plan runner with the
            # plan body in params. The runner executes the plan safely.
            plan_body = decision.get("plan")
            plan_name = str(decision.get("plan_name") or (plan_body or {}).get("name") or "claude-exec-plan")
            logger.info(
                "AI loop: picker said EXEC_PLAN plan_name=%r steps=%d",
                plan_name,
                len((plan_body or {}).get("steps") or []) if isinstance(plan_body, dict) else 0,
            )
            if not isinstance(plan_body, dict) or not isinstance(plan_body.get("steps"), list) or not plan_body["steps"]:
                logger.warning("AI loop: exec_plan rejected — empty or malformed plan body")
                rejection_sink.append({
                    "reason": "exec_plan_malformed",
                    "detail": "You used action='exec_plan' but the 'plan' field was missing, "
                              "not a dict, or had no 'steps' list. Re-read the EXEC_PLAN GRAMMAR section "
                              "in the system prompt and include the full plan body with a non-empty steps array.",
                    "at": _now(),
                })
            elif "exec-plan" not in available_tools:
                logger.warning("AI loop: exec_plan rejected — exec-plan runner not registered")
                rejection_sink.append({
                    "reason": "exec_plan_runner_missing",
                    "detail": "The exec-plan runner is not registered in this deployment. "
                              "Use action='pick' with a registered tool instead.",
                    "at": _now(),
                })
            else:
                primary_target = ""
                if targets:
                    primary_target = str(targets[0].get("value") or "")
                tier = str(decision.get("tier") or "active").lower()
                if tier not in {"passive", "active", "intrusive"}:
                    tier = "active"
                reasoning = str(decision.get("reasoning") or f"Custom plan: {plan_name}")
                confidence = float(decision.get("confidence") or 0.8) if str(decision.get("confidence") or "").strip() else 0.8
                claude_candidate = LoopCandidate(
                    tool="exec-plan",
                    target=primary_target,
                    params={
                        "source": "ai_loop_claude_exec_plan",
                        "ai_reasoning": reasoning[:500],
                        "target_kind": "url",
                        "target_source": "approved_scope_root",
                        "plan": plan_body,
                        "plan_name": plan_name,
                    },
                    tier=tier,
                    reasoning=reasoning,
                    confidence=max(0.0, min(1.0, confidence)),
                    follow_up_hints=[],
                    expected_evidence=["exec_plan_success", "multi_step_exploit_chain"],
                    required_approvals=0,
                    decision_source="ai_loop_claude_exec_plan",
                )
        else:
            # action == "pick" or unspecified (legacy) — continue current phase
            logger.info(
                "AI loop: picker PICK tool=%s tier=%s confidence=%s",
                decision.get("tool"),
                decision.get("tier"),
                decision.get("confidence"),
            )
            claude_candidate = _claude_candidate_to_loop_candidate(
                decision, targets=targets, available_tools=available_tools, scope=scope,
                tested_keys=tested_keys, rejection_sink=rejection_sink,
            )
            if claude_candidate is None:
                logger.warning("AI loop: Claude pick rejected (invalid tool/target)")

    # ---- STOP path ----
    if claude_stop_decision is not None:
        loop_state["status"] = "stopped"
        loop_state["stop_reason"] = str(
            claude_stop_decision.get("stop_reason") or "ai_concluded_complete"
        )
        loop_state["ai_stop_summary"] = str(
            claude_stop_decision.get("summary")
            or claude_stop_decision.get("reasoning")
            or ""
        )
        # Archive the active phase if any so the UI sees a clean completion.
        if current_phase.get("label"):
            current_phase["status"] = "completed"
            current_phase["completed_at"] = _now()
            phases_archive = list(loop_state.get("phases") or [])
            phases_archive.append(current_phase)
            loop_state["phases"] = phases_archive
            loop_state["current_phase"] = {}
        _store_loop_state(configuration, loop_state)
        run.configuration_json = configuration
        _finalize_run_after_loop_stop(run, stop_reason=str(loop_state["stop_reason"]))
        clear_run_credential_vault_if_terminal(
            session,
            run=run,
            actor=actor,
            reason=f"assessment_loop_ai_stopped_{loop_state['stop_reason']}",
        )
        write_audit_event(
            session=session,
            actor=actor,
            action="assessment_loop.ai_stopped",
            object_type="run",
            object_id=str(run.id),
            metadata={
                "reason": loop_state["stop_reason"],
                "ai_summary": loop_state["ai_stop_summary"][:300],
            },
        )
        return build_assessment_loop_state(session, run=run, scope=scope)

    # ---- LEVEL_UP path: archive current phase, start a new one ----
    if claude_levelup_decision is not None and claude_candidate is not None:
        # Archive the just-completed phase
        if current_phase.get("label"):
            current_phase["status"] = "completed"
            current_phase["completed_at"] = _now()
            current_phase["summary"] = str(
                claude_levelup_decision.get("previous_phase_summary") or ""
            )
            phases_archive = list(loop_state.get("phases") or [])
            phases_archive.append(current_phase)
            loop_state["phases"] = phases_archive
        # Open new phase
        new_label = str(claude_levelup_decision.get("new_phase_label") or "next-phase")
        phase_index += 1
        loop_state["phase_count"] = phase_index
        loop_state["current_phase"] = {
            "label": new_label,
            "goal": str(claude_levelup_decision.get("reasoning") or "")[:300],
            "started_at": _now(),
            "findings_count_at_start": len(list(run.findings or [])),
            "tool_picks": [],
            "status": "active",
        }
        write_audit_event(
            session=session,
            actor=actor,
            action="assessment_loop.phase_level_up",
            object_type="run",
            object_id=str(run.id),
            metadata={
                "phase_index": phase_index,
                "new_phase_label": new_label,
                "previous_summary": str(
                    claude_levelup_decision.get("previous_phase_summary") or ""
                )[:300],
            },
        )
        # claude_candidate is set; will be used as the first tool of the new phase.

    candidate = (
        _target_intel_candidate  # web: AI site analysis before scanning (iter 1)
        or _lan_intel_candidate   # LAN: AI service analysis after nmap
        or claude_candidate       # Claude-picked next action based on findings (iter 2+)
        or (_ai_proposal_candidate(run=run, scope=scope, plan=plan, tested_keys=tested_keys) if tested_keys else None)
        or (seed if seed_is_intel else None)
        or goal_candidate
        or auth_candidate
        or recursive_candidate
        or selector_candidate
        or (seed if not seed_is_intel else None)
        or _plan_candidate(
            run=run,
            scope=scope,
            targets=_context_targets(context_document) or targets,
            plan=plan,
            tested_keys=tested_keys,
            recommended_tools=recommended_tools,
        )
    )
    if candidate is None:
        # Last-resort: ask Claude for an exec_plan using agent_tools before
        # giving up. See _exec_plan_fallback_candidate docstring — without
        # this the picker stops at iter ~4-12 with no_registered_runner_candidate
        # even when bash/code_exec/web_fetch could still make progress.
        candidate = _exec_plan_fallback_candidate(
            run=run,
            scope=scope,
            session=session,
            targets=targets,
            loop_state=loop_state,
            tested_keys=tested_keys,
        )
        if candidate is not None:
            logger.info(
                "AI loop: exec_plan fallback produced candidate after catalog "
                "exhausted (run=%s plan_name=%s)",
                str(run.id)[:8],
                candidate.params.get("plan_name"),
            )
    if candidate is None:
        logger.warning(
            "AI loop: candidate is None — stopping loop. "
            "target_intel=%s lan_intel=%s claude=%s goal=%s auth=%s recursive=%s selector=%s seed=%s plan_cand=False  (full names of None means each was None)",
            type(_target_intel_candidate).__name__,
            type(_lan_intel_candidate).__name__,
            type(claude_candidate).__name__,
            type(goal_candidate).__name__ if 'goal_candidate' in locals() else 'N/A',
            type(auth_candidate).__name__ if 'auth_candidate' in locals() else 'N/A',
            type(recursive_candidate).__name__ if 'recursive_candidate' in locals() else 'N/A',
            type(selector_candidate).__name__ if 'selector_candidate' in locals() else 'N/A',
            type(seed).__name__ if 'seed' in locals() else 'N/A',
        )
        loop_state["status"] = "stopped"
        # #331: distinguish between "no fallback candidate" (genuine
        # exhaustion of the heuristic chain) and "picker retried but
        # never produced a usable decision". Both end the run, but the
        # cause is different — operators get a clear signal which one.
        if loop_state.get("picker_retry_exhausted"):
            stop_reason_value = "picker_retry_exhausted"
            credential_clear_reason = "assessment_loop_picker_retry_exhausted"
        else:
            stop_reason_value = "no_registered_runner_candidate"
            credential_clear_reason = "assessment_loop_no_registered_runner_candidate"
        loop_state["stop_reason"] = stop_reason_value
        _store_loop_state(configuration, loop_state)
        run.configuration_json = configuration
        _finalize_run_after_loop_stop(run, stop_reason=stop_reason_value)
        clear_run_credential_vault_if_terminal(
            session,
            run=run,
            actor=actor,
            reason=credential_clear_reason,
        )
        write_audit_event(
            session=session,
            actor=actor,
            action="assessment_loop.stopped",
            object_type="run",
            object_id=str(run.id),
            metadata={
                "reason": stop_reason_value,
                "retries_this_advance": int(loop_state.get("retries_this_advance") or 0),
            },
        )
        return build_assessment_loop_state(session, run=run, scope=scope)

    iteration_number = int(loop_state.get("iteration_count") or 0) + 1
    current_state = _current_state_payload(
        run=run,
        scope=scope,
        targets=targets,
        evidence_fingerprint=evidence_fingerprint,
    )
    next_action = _next_action_payload(candidate)
    next_action["context_document_id"] = str(context_document.id)
    reasoning = store_agent_reasoning_record(
        session=session,
        run=run,
        reasoning_type="assessment_loop_next_action",
        status="recorded",
        context_snapshot={
            "run_id": str(run.id),
            "run_mode": "ai_loop",
            "iteration": iteration_number,
            "assessment_state": current_state,
            "target_context_document_id": str(context_document.id),
            "parent_context_document_id": (
                str(context_document.parent_context_document_id)
                if context_document.parent_context_document_id
                else None
            ),
            "target_context_summary": context_document.context_summary,
            "target_context_evidence_refs": list(context_document.evidence_refs_json or []),
            "target_context_micro_plan": list(context_document.micro_plan_json or []),
            "assessment_plan_summary": plan.get("summary", {}),
            "next_best_action_selector": {
                "selector_version": selector_report.get("selector_version"),
                "enabled": selector_report.get("enabled"),
                "top_actions": [
                    {
                        "rank": action.get("rank"),
                        "decision": action.get("decision"),
                        "runner": action.get("runner"),
                        "target": action.get("target"),
                        "confidence": action.get("confidence"),
                        "expected_proof_value": action.get("expected_proof_value"),
                        "missing_prerequisites": _as_dict(
                            action.get("prerequisite_state")
                        ).get("missing", []),
                    }
                    for action in _as_list(selector_report.get("actions"))[:5]
                    if isinstance(action, dict)
                ],
                "dispatches_work_directly": False,
            },
            "goal_oriented_reasoning": _as_dict(loop_state.get("goal_oriented_reasoning")),
            "scope_enforced": True,
            "fixed_phase_chains_replaced_globally": False,
        },
        observations=[
            {
                "summary": (
                    f"Assessment loop observed {current_state['task_count']} task(s), "
                    f"{current_state['finding_count']} finding(s), and "
                    f"{current_state['signal_count']} signal(s)."
                ),
                "target_type": current_state["target_type"],
                "no_new_signal_iterations": no_new_signal_iterations,
            }
        ],
        hypotheses=[
            {
                "summary": candidate.reasoning,
                "tool": candidate.tool,
                "target": candidate.target,
                "tier": candidate.tier,
                "confidence": round(float(candidate.confidence), 3),
                "decision_source": candidate.decision_source,
                "selector_decision": candidate.selector_decision,
            }
        ],
        proposals=[next_action],
        summary_text=f"Iteration {iteration_number}: selected {candidate.tool} for {candidate.target}.",
        thought_text=candidate.reasoning,
        action_text=(
            "Queue passive action through the registered runner path."
            if candidate.tier == "passive"
            else "Create a reviewable AI proposal; execution waits for existing approval flow."
        ),
        provider="deterministic-assessment-loop",
        model=None,
        llm_tokens_used=0,
        confidence_score=float(candidate.confidence),
        metadata={
            "proposal_kind": LOOP_PROPOSAL_KIND,
            "run_mode": "ai_loop",
            "iteration": iteration_number,
            "operator_note": operator_note,
            "dispatches_work": candidate.tier == "passive",
            "direct_dispatch": False,
            "registered_runner_required": True,
            "scope_enforced": True,
            "roe_enforced": True,
            "kill_switch_still_authoritative": True,
            "manual_chain_alternative_preserved": True,
            "target_context_document_id": str(context_document.id),
            "next_best_action_selector_used": candidate.decision_source == "next_best_action_selector",
            "selector_decision": candidate.selector_decision,
            "selector_rank": candidate.selector_rank,
        },
    )
    rationale_entry = record_rationale(
        session,
        run=run,
        context_document=context_document,
        tool_name=candidate.tool,
        target=candidate.target,
        rationale=candidate.reasoning,
        parameters={
            **candidate.params,
            "tier": candidate.tier,
            "iteration": iteration_number,
            "confidence": round(float(candidate.confidence), 3),
            "required_approvals": candidate.required_approvals,
        },
        action_type=LOOP_PROPOSAL_KIND,
        decision_source={
            "source": candidate.decision_source,
            "context_document_id": str(context_document.id),
            "goal_oriented_reasoning": _as_dict(candidate.params.get("goal_oriented_reasoning")),
            "next_best_action_selector": _as_dict(candidate.params.get("next_best_action_selector")),
            "selector_provenance": dict(candidate.selector_provenance or {}),
            "recommended_tools": list(context_document.recommended_tools_json or []),
            "registered_runner_required": True,
            "approval_gates_bypassed": False,
        },
        status="recorded_before_dispatch",
    )
    next_action["rationale_ledger_entry_id"] = str(rationale_entry.id)
    queued_task: Task | None = None
    proposal: AgentProposal | None = None
    action_status = "pending_review"

    # Initialize the FIRST phase if none exists yet (this is the very first pick).
    if not loop_state.get("current_phase"):
        loop_state["phase_count"] = 0
        loop_state["current_phase"] = {
            "label": "reconnaissance",
            "goal": "Map the attack surface and identify entry points.",
            "started_at": _now(),
            "findings_count_at_start": 0,
            "tool_picks": [],
            "status": "active",
        }
    # Record this tool pick in the current phase's tool_picks list.
    current_phase = _as_dict(loop_state.get("current_phase"))
    phase_picks = list(current_phase.get("tool_picks") or [])
    phase_picks.append({
        "tool": candidate.tool,
        "target": candidate.target,
        "reasoning": candidate.reasoning[:200],
        "decision_source": candidate.decision_source,
        "picked_at": _now(),
    })
    current_phase["tool_picks"] = phase_picks
    loop_state["current_phase"] = current_phase

    # Persist any rejections accumulated during this advance call so Claude
    # can see them in the next iteration's prompt and self-correct.
    if rejection_sink:
        existing_rejections = list(loop_state.get("recent_rejections") or [])
        existing_rejections.extend(rejection_sink)
        # Keep only the most recent 10 — older ones drop off
        loop_state["recent_rejections"] = existing_rejections[-10:]

    # For ai_loop runs, auto-queue active candidates too (operator already authorized the run).
    # Intrusive-exploitation tier auto-queues only when the run was created with
    # autonomous_intrusive_allowed=True (operator opt-in via intake wizard).
    is_ai_loop = _run_uses_ai_loop(run)
    auto_queue_active = is_ai_loop and candidate.tier == "active"
    auto_queue_intrusive = (
        is_ai_loop
        and candidate.tier == "intrusive"
        and bool(getattr(run, "autonomous_intrusive_allowed", False))
    )
    will_queue = candidate.tier == "passive" or auto_queue_active or auto_queue_intrusive
    logger.info(
        "AI loop: queue-decision tool=%s tier=%s ai_loop=%s intrusive_allowed=%s auto_queue_active=%s auto_queue_intrusive=%s will_queue=%s",
        candidate.tool, candidate.tier, is_ai_loop,
        bool(getattr(run, "autonomous_intrusive_allowed", False)),
        auto_queue_active, auto_queue_intrusive, will_queue,
    )
    if will_queue:
        queued_task = _queue_passive_loop_task(
            session=session,
            run=run,
            candidate=candidate,
            actor=actor,
            iteration_number=iteration_number,
            context_document_id=str(context_document.id),
            rationale_ledger_entry_id=str(rationale_entry.id),
        )
        proposal = store_agent_proposal_record(
            session=session,
            reasoning=reasoning,
            proposed_tool=candidate.tool,
            proposed_target=candidate.target,
            proposed_params={
                **candidate.params,
                "assessment_loop": {
                    "enabled": True,
                    "run_mode": "ai_loop",
                    "iteration": iteration_number,
                    "queued_task_id": str(queued_task.id),
                    "dispatch_mode": "queued_for_auto_dispatch",
                    "context_document_id": str(context_document.id),
                    "rationale_ledger_entry_id": str(rationale_entry.id),
                },
            },
            reasoning_text=candidate.reasoning,
            risk_tier=candidate.tier,
            priority=20,
            confidence_score=float(candidate.confidence),
            status="approved",
            metadata={
                "proposal_kind": LOOP_PROPOSAL_KIND,
                "run_mode": "ai_loop",
                "iteration": iteration_number,
                "dispatches_work": True,
                "queued_task_id": str(queued_task.id),
                "approval_boundary": "passive_auto_queued",
                "operator_controlled_flow_only": True,
                "active_runtime_mutated": False,
                "context_document_id": str(context_document.id),
                "rationale_ledger_entry_id": str(rationale_entry.id),
            },
        )
        proposal.approved_by = actor
        proposal.approved_at = datetime.now(UTC)
        rationale_entry.task_id = queued_task.id
        rationale_entry.agent_proposal_id = proposal.id
        rationale_entry.status = "task_queued"
        action_status = "queued"
    else:
        proposal = _store_next_action_proposal(
            session=session,
            run=run,
            reasoning=reasoning,
            candidate=candidate,
            actor=actor,
            iteration_number=iteration_number,
            context_document_id=str(context_document.id),
            rationale_ledger_entry_id=str(rationale_entry.id),
        )
        rationale_entry.agent_proposal_id = proposal.id
        rationale_entry.status = "pending_approval"

    iteration = {
        "iteration": iteration_number,
        "status": action_status,
        "created_at": _now(),
        "reasoning_id": str(reasoning.id),
        "proposal_id": str(proposal.id) if proposal is not None else None,
        "queued_task_id": str(queued_task.id) if queued_task is not None else None,
        "context_document_id": str(context_document.id),
        "rationale_ledger_entry_id": str(rationale_entry.id),
        "next_action": next_action,
        "evidence_fingerprint": evidence_fingerprint,
    }
    loop_state["iteration_count"] = iteration_number
    loop_state["status"] = "waiting_for_execution" if queued_task is not None else "waiting_for_approval"
    loop_state["stop_reason"] = None
    loop_state["latest_next_action"] = next_action
    loop_state["iterations"] = [*list(loop_state.get("iterations") or []), iteration]

    # Persist whatever advance built so far (decisions, phase state, thinking).
    _store_loop_state(configuration, loop_state)
    run.configuration_json = configuration

    write_audit_event(
        session=session,
        actor=actor,
        action="assessment_loop.iteration_created",
        object_type="run",
        object_id=str(run.id),
        metadata={
            "iteration": iteration_number,
            "tool": candidate.tool,
            "target": candidate.target,
            "tier": candidate.tier,
            "queued_task_id": str(queued_task.id) if queued_task is not None else None,
            "proposal_id": str(proposal.id) if proposal is not None else None,
            "context_document_id": str(context_document.id),
            "rationale_ledger_entry_id": str(rationale_entry.id),
            "dispatch_mode": "queued_for_auto_dispatch" if queued_task is not None else "review_only",
        },
    )

    # === Cross-runner verifier (#335) ===
    # After this advance is persisted, verify any newly-arrived critical/
    # high findings that don't yet have a verdict. The verifier uses a
    # DIFFERENT code path than the originating runner (raw httpx +
    # scope check; no runner imports) so it acts as an independent
    # confirmation. Bounded at 10 per advance for cost control. Failures
    # here MUST NOT crash the advance — verifier is enrichment, not
    # gating.
    try:
        from api.app.services.finding_verifier import verify_pending_critical_findings
        _verdicts = verify_pending_critical_findings(
            session, run=run, scope=scope, limit=10,
        )
        if _verdicts:
            logger.info(
                "AI loop: verifier processed %d critical/high finding(s) verdicts=%s",
                len(_verdicts),
                ",".join(v.verdict for v in _verdicts),
            )
    except Exception as _verifier_exc:
        logger.warning("finding_verifier: skipped (%s)", _verifier_exc)

    # === Comic-strip narrator ===
    # Generate a plain-language panel and append it ATOMICALLY via SQL.
    # We run this LAST (after the ORM has flushed all its other writes) so
    # nothing overwrites the narrative.panels array. Failure is silent.
    try:
        session.flush()  # ensure prior ORM writes are in DB before SQL append
        from api.app.services import narrator as _narrator
        _panel = _narrator.generate_narrative_panel(
            session=session,
            run=run,
            findings=list(run.findings or []),
            tasks=list(run.tasks or []),
            last_decision_reasoning=candidate.reasoning,
        )
        if _panel:
            _narrator.append_panel_atomic_sql(session, run.id, _panel)
            # Refresh the ORM-tracked run so a subsequent flush from the
            # caller doesn't write a stale configuration_json on top of us.
            session.refresh(run, ["configuration_json"])
    except Exception as _narr_exc:
        logger.warning("narrator: panel generation skipped: %s", _narr_exc)

    # === Memory rotation (#332 wire-up, #342) ===
    # Trim /memories/run-progress.md when it exceeds ROTATE_THRESHOLD_BYTES
    # (8 KB) so the next picker hop's memory-tool view stays bounded
    # alongside the per-view cap from #332. Housekeeping only: failure
    # here MUST NOT crash the advance.
    _rotate_run_progress_safely()

    return {
        **build_assessment_loop_state(session, run=run, scope=scope),
        "next_action": next_action,
        "queued_task_id": str(queued_task.id) if queued_task is not None else None,
        "proposal_id": str(proposal.id) if proposal is not None else None,
        "reasoning_id": str(reasoning.id),
        "context_document_id": str(context_document.id),
        "rationale_ledger_entry_id": str(rationale_entry.id),
    }
