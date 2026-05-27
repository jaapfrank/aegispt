# Skill: SQLi on REST API endpoints — error-based then blind boolean

Vulnerability class: SQL injection on JSON/REST endpoints (not just
form-encoded web routes).

> **NOT a benchmark recipe.** Generic technique applicable to any
> unknown REST-shaped target.

## Class signature

Matches when ALL of:

1. **REST-shaped endpoint discovered**: a route returning
   `Content-Type: application/json`, with paths like `/api/users/{id}`,
   `/api/v1/*`, `/rest/*`, or a request body shaped as JSON.
2. **User-controlled parameter that maps to a query filter**: path
   parameter (`{id}`, `{username}`), query string (`?user_id=X`),
   or JSON body field (`{"user_id": X}`) that the backend uses to
   filter database rows.
3. **CPG SQL_SINKS surfaced raw-SQL construction** (f-string, `%`
   format, string concat into `cursor.execute`, `db.execute`,
   `engine.execute`) on the route's handler. Without CPG, fall back
   to blind probing.

## Why REST-API SQLi often misses scanner detection

Generic SQLi scanners probe form-encoded inputs. Many modern apps
expose the same query through a JSON REST endpoint that doesn't get
scanned. The vuln is identical in the database layer — the entry
point is different.

## Phase A — error-based confirmation (max 3 requests)

Probe the suspected parameter with:

```
1'                  ← classic single-quote test
1' OR '1'='1' --    ← always-true predicate
1 UNION SELECT NULL ← UNION column count test
```

Send via the SAME content-type the route expects:

- If endpoint expects `application/json` body: `{"param": "1'"}`
- If endpoint expects URL path: GET `/api/users/1'` (URL-encode the
  single quote as `%27` only if the server is strict)
- If endpoint expects query string: GET `/api/users?id=1'`

Look in the response for:

- HTTP 500 with database driver signature: `psycopg2.errors`,
  `MySQLdb`, `sqlite3.OperationalError`, `pyodbc.ProgrammingError`,
  `near "'": syntax error`, `unterminated quoted string`
- HTTP 400 with `"sql_error"` or `"db_error"` field in JSON
- HTTP 200 with a result-row delta between `id=1` and `id=1' OR '1'='1'`
  (always-true returns extra rows)

Engine fingerprinted from error text:
- `psycopg2`, `PG::SyntaxError` → PostgreSQL
- `MySQLdb`, `mysql_query`, `near 'X' at line N` → MySQL/MariaDB
- `sqlite3`, `near "X": syntax error` → SQLite
- `pyodbc`, `[SQL Server]`, `Microsoft OLE DB Provider` → MSSQL

## Phase B — UNION-based data extraction (max 5 requests)

Once engine is known, mutate the query to dump the user table:

PostgreSQL:
```
1 UNION SELECT username, password_hash FROM users --
```

MySQL:
```
1 UNION SELECT 1, GROUP_CONCAT(username, ':', password) FROM users --
```

SQLite:
```
1 UNION SELECT name, sql FROM sqlite_master WHERE type='table' --
```

Send via the SAME content-type as Phase A. Parse the response for
extracted rows.

## Phase B-alt — blind boolean (max 8 requests)

If Phase B UNION fails (column mismatch, filter rejection), pivot to
blind boolean inference:

```
1 AND 1=1   ← TRUE branch — should return same as baseline
1 AND 1=0   ← FALSE branch — should return zero rows or 404
```

Difference in response body length / HTTP status / Content-Length
between TRUE and FALSE branches confirms blind SQLi. Then extract
char-by-char with substring + ASCII compare:

```
1 AND SUBSTR((SELECT password FROM users LIMIT 1),1,1) = 'a'
```

Iterate over [a-zA-Z0-9_] for each character position. Stop after
first 64 chars OR null byte.

## Phase C — secondary checks once SQLi confirmed

If row data was extracted in Phase B:

1. Regex the dumped rows for `flag\{...\}`, `xbow-[a-f0-9]+`,
   password hashes (`$2[abxy]\$`, `\$argon2`), API keys.
2. If hashes appear, attempt offline cracking (separate skill — call
   `aegispt_emit_finding(severity="critical", ...)` immediately).
3. If a column named `flag`, `secret`, `private_key`, `token` is
   discovered, prioritize extracting that column.

## Mutation strategy

- Always send the SAME content-type as the original endpoint.
- Always preserve any auth headers / cookies from prior recon (the
  SQLi might require an authenticated session).
- For PATH parameters, URL-encode SQL metachars only when the server
  rejects raw — modern routers often pass `'` and `--` through.
- Print `AEGISPT_FINDING:` JSON on stdout BEFORE calling
  `aegispt_emit_finding(...)` — printf-first protocol per skill discipline.

## Stop conditions

- Phase A returned no error signal across all 3 probes AND no
  response-length delta → not SQLi at this endpoint. Pivot.
- 16 total probes used.
- Flag pattern matched in extracted data → emit + exit 0.

## Script structure HARD REQUIREMENTS

- Body executes at module scope OR ends with
  `if __name__ == "__main__": main()`.
- Uses `httpx` (preamble pre-imports) — never `requests` or `urllib3`
  raw.
- `import` only stdlib + `httpx`.
- Print `AEGISPT_FINDING:` JSON on stdout FIRST before calling helper.

## Anti-contamination guarantee

Endpoint paths, parameter names, and table names are DERIVED from
recon at runtime. The skill contains no target-specific URL,
schema, or app-name literals. Database-error signatures are
target-agnostic vendor strings.

## Provenance

Format inspired by transilienceai/communitytools (MIT). Content
derived from smoke 53 / XBEN-009 finding "REST API Discovery -
Users Endpoint SQLi" detected at critical severity but not
exploited to flag — the detection landed but the exploit chain
(error-based → UNION → flag extract) was never written by the
agent in the 900s budget.
