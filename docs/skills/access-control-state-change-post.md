# Skill: Access control on state-changing POST routes

Vulnerability class: broken access control / IDOR / BOLA on
state-changing routes that lack per-actor authorization checks.

> **NOT a benchmark recipe.** This skill is class-level technique
> knowledge. It must apply equally to any unknown web app whose
> request graph contains the class signature below. If you find
> yourself wanting to write "for XBEN-XXX" or "the flag is in
> /path", stop — that violates `feedback_no_prescriptive_recipes`.

## Class signature

A route matches this class when ALL of the following hold:

1. **HTTP shape**: `POST`, `PUT`, `PATCH`, or `DELETE` (state-changing).
2. **Path or body carries a per-user identifier**: `user_id`, `account_id`,
   `owner_id`, `customer_id`, etc., either in the URL path segment,
   query string, JSON body, or form-encoded body.
3. **Route name suggests state change**: verb in the name such as
   `archive`, `transfer`, `grant`, `claim`, `set_*`, `update_*`,
   `delete_*`, `revoke`, `assign`, `share`. (These tend to be the
   ones whose authorization check is forgotten.)
4. **Auth is present**: the app has a logged-in session — i.e. the
   class only matters AFTER the picker has authenticated as some
   user. Pre-auth attempts are a different class (auth-bypass).

If any of (1)-(4) is missing this is NOT the right class. Look
elsewhere.

## Why this class wins on web benchmarks

Source-graph analyzers (CPG / Joern) routinely identify state-changing
endpoints, but the **access-check predicate** at the function head is
the part that fails. When the predicate is `is_authenticated(user)`
instead of `is_authenticated(user) AND (user.owns(resource) OR user.is_admin)`,
the route mutates resources outside the caller's authorization scope.
This is the same class of bug that powers most IDOR/BOLA findings on
real-world apps and on the public XBOW set's authorization challenges.

## Distinguishing tests (probe BEFORE committing to exploit)

These cheap probes confirm or rule out the class without committing
to a specific payload chain. Run them in order; stop on first
definitive answer.

1. **Auth-precondition test**: GET an authenticated-only route as the
   picker's session user. If 401 / 302-to-login, the session is dead
   and the class doesn't apply. Print `{auth_precondition: failed}`
   and pivot.

2. **Predicate-side-channel test**: send the same `POST` with a body
   parameter referring to your OWN resource id. Note the success
   response shape (200 with `ok:true` body, 302, etc.).

3. **Cross-tenant probe**: send the same request with the parameter
   changed to a DIFFERENT user's id you can guess or enumerate (1, 2,
   3, ..., or pull from a `/users` list endpoint if exposed).
   Distinguish responses:
   - 200 + same success shape → vulnerable, class confirmed.
   - 403 / 401 / `{error: "forbidden"}` → access check present.
   - 404 / 200 + `{error: "not found"}` → object enumeration may
     leak existence; still a finding but different class.
   - 500 / 422 → schema validator hit; mutate the parameter shape.

## Mutation strategy (when the predicate-test confirms vulnerability)

Once the class is confirmed, the picker should pivot to
`code-exec-attack` or `exploit-developer` with a targeted hypothesis,
not stay on scanners. The mutation tree:

- **Object id sweep**: enumerate the id space (small integer range
  or known-good ids from a list endpoint). Capture the response
  delta per id.
- **Field-level mutation**: when the route accepts a JSON body, set
  fields the requesting user shouldn't be able to set (`is_admin`,
  `role`, `tenant_id`, `permissions`). Check both the route's response
  AND a follow-up GET as the victim user to confirm persistence.
- **State machine pivot**: if the route is multi-step (`archive`
  -> `delete`), exploit the cheapest one whose access predicate
  doesn't validate cross-user ownership.

Stop at the first verified pivot. Do not exhaustively enumerate.

## Stop conditions

- Cross-tenant probe returned 403/401 for every id tested → class
  ruled out. Move to a different vuln class.
- Object enumeration shows your own id is the only one that exists
  (in dev/test fixtures) → not testable; pivot.
- 3 different mutation strategies tried, none changed the cross-tenant
  result → class ruled out OR predicate has unguessable structure.

## What this skill is NOT

- Not a benchmark answer key. If this file ever names XBEN ids,
  flags, or specific URLs, it has degenerated into solution caching
  and must be reverted.
- Not a substitute for source-aware analysis. CPG/Joern's
  control-flow + access predicate output is the primary signal;
  this skill describes what to DO with that signal.

## Provenance and license

Format inspired by transilienceai/communitytools (MIT). Content here
is written from scratch against AegisPT's own architecture — no
verbatim copy of their skill files into this repo's runtime path.
