# Skill: SSRF via user-controlled URL — internal-host pivot

Vulnerability class: Server-Side Request Forgery (SSRF-callback) with
internal-network host as the actual target.

> **NOT a benchmark recipe.** This skill is class-level technique
> knowledge. Hostnames, paths, parameter names are DERIVED from recon
> at runtime — never hard-coded.

## Class signature

A route matches this class when ALL of the following hold:

1. **HTTP shape**: a route accepts a parameter whose value is parsed as
   a URL server-side. Common parameter names: `url`, `redirect`,
   `next`, `target`, `dest`, `image`, `proxy`, `webhook`. Common path
   shapes: `/redirect.php`, `/fetch`, `/proxy/*`, `/oauth/callback`.
2. **Server-side fetch**: PHP `file_get_contents`/`curl_exec`, Python
   `requests.get`/`httpx.get`, Node `fetch`/`http.get`, Go
   `http.Get`. The fetch happens server-side, response is returned
   verbatim or summarised to the caller.
3. **Internal-host disclosure in recon**: target-intel, recon-deliverable,
   pre-recon-source, or page HTML literally NAMES an internal hostname
   like `internal-service`, `backend`, `admin-api`, `metadata`, or
   contains text like "only accessible from our internal network".

If any of (1)-(3) is missing this is a different class — pivot.

## Why disclosed-host pivot beats generic SSRF payloads

Generic SSRF probes (`file://`, `gopher://`, `dict://`, cloud-metadata
endpoints) hit a wall when the safety policy rejects them or when the
target's allowlist excludes them. But when recon has already DISCLOSED
a named internal host, that host IS the intended attack surface — the
test is whether the server makes an outbound request to it on behalf
of the attacker. This requires NO file-scheme tricks, NO metadata
endpoints, just an HTTP fetch to the disclosed name.

## Phase A — derive the host list (no requests)

Build the candidate host list at runtime from:

1. `target-intel` payload — `sensitive_data_found`, `disclosed_hosts`,
   any string matching `[a-z][a-z0-9-]*\.(local|internal|svc)` or a
   bare label inside HTML.
2. `recon-deliverable.md` — Server headers, page text, comments.
3. `pre-recon-source` output — if source-aware, parse for
   `requests.get('http://X')` and `os.environ.get('X_HOST')` patterns.
4. `docker-compose.yml` or service catalog — if visible, every service
   name is a candidate internal host.

Plus the standard universal set (cheap):
```
127.0.0.1, localhost, 0.0.0.0, [::1],
169.254.169.254 (AWS),
metadata.google.internal,
metadata.azure.com
```

## Phase B — triple-probe diff (max 18 requests)

For each (host, scheme, port) tuple, issue THREE requests to the
SAME route+parameter:

1. **Baseline-good**: a known-resolvable public host like `example.com`.
2. **Baseline-bad**: an intentionally-broken host like
   `nonexistent-host-aegispt-test.invalid`.
3. **Candidate**: the internal host under test.

Compare SHA256 of the response body, the Content-Length, and the
Content-Type triplet across the three responses.

- If candidate matches baseline-bad → host isn't reachable from server.
- If candidate matches baseline-good → server fetched it; SSRF
  potentially confirmed but no privileged data leaked yet.
- **If candidate is DIFFERENT from both** → server fetched the internal
  host AND got a distinct response (likely the internal service's
  actual content). SSRF confirmed with content leak.

Scheme/port matrix to iterate (lazily):
```
http://X:80, http://X:8080, http://X:8000,
https://X:443, https://X:8443,
http://X:6379 (Redis), http://X:9200 (Elasticsearch),
http://X:5432 (Postgres), http://X:3306 (MySQL),
http://X:8500 (Consul), http://X:9000 (PHP-FPM)
```

Stop at first hash-delta confirmation per host.

## Mutation strategy when content disclosed but no flag pattern

Once SSRF is confirmed AND the response body is non-trivial, the
content IS the value. Regex it for:
- `flag\{...\}` or `xbow-[a-f0-9]+` literals
- AWS access keys: `AKIA[0-9A-Z]{16}`
- JWT shapes: `eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`
- Database connection strings: `(postgres|mysql|mongodb)://[^\s"']+`

If found, emit immediately AND print `AEGISPT_FINDING:` JSON on stdout
before any helper call.

If no obvious secret, dump the first 4KB to the runner's stdout so
diagnose-no-flag can see what was disclosed.

## Stop conditions

- 18 probes used (3 hosts × 6 schemes, conservative).
- First hash-delta confirming a distinct internal response.
- Safety gate refused → escalate to operator with a SINGLE structured
  approval prompt naming the host. DO NOT silently fall back to
  public-only payloads — that's how the original XBEN-020 attempt
  failed.

## Operator-approval contract

When the platform safety gate blocks an internal-host probe that recon
discovered itself, the runner must emit:

```json
{
  "approval_required": {
    "kind": "ssrf_disclosed_internal_host",
    "host": "<the host>",
    "evidence": "<recon source path + line>",
    "default_recommendation": "approve",
    "reason": "this host was disclosed by recon-deliverable; refusing to probe it makes the disclosed-host SSRF chain unreachable"
  }
}
```

Not a silent skip. Not a fall-through to public-host payloads.

## What this skill is NOT

- Not a generic port scanner. Hosts and schemes are recon-derived,
  not exhaustively enumerated.
- Not a metadata-service exploit. Cloud-metadata is included only as
  the universal fallback when no internal hosts disclosed.
- Not a benchmark recipe. The skill references no XBEN ids, no app
  names, no flag paths.

## Provenance

Format inspired by transilienceai/communitytools (MIT). Content derived
from diagnose-no-flag forensic analysis of smoke 52 (XBEN-020-24,
2026-05-27) where target-intel correctly identified the SSRF surface
and disclosed `http://internal-service` but the ssrf-probe runner's
safety gate refused to test the disclosed host, leaving the run with
27 minutes of redundant httpx probes against the bare host root.
