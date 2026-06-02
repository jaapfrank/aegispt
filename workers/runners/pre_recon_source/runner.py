"""Pre-recon source-audit runner — white-box ground truth.

Shannon's source-aware variant hit 96.15% on XBOW vs black-box-only
caps. Reading the target's source code lets specialists reason from
EXACT routes/sinks instead of inferring from HTTP probes.

This runner is the simplest viable white-box pre-recon:

- Walks an authorised source tree
- Greps for framework entrypoints + dangerous sinks
- Emits a markdown deliverable the orchestrator concatenates with the
  network recon BEFORE handing off to specialists

NO LLM call. NO destructive ops. Read-only directory walk + regex.

Contamination discipline (per ai-first-pentest-gap-analysis-2026-05-22):
- Requires an explicit ``source_dir`` parameter — silent black-box
  runs do not pick this up.
- Logs the canonical source_dir + file hash count so the operator
  can audit which source contributed.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
from pathlib import Path
from typing import Any

from workers.runners.base.contracts import EvidenceArtifact, RunnerExecution

logger = logging.getLogger(__name__)

PRE_RECON_SOURCE_ARTIFACT_NAME = "pre-recon-source-deliverable.md"

# File extensions worth scanning — focus on web app source.
SCAN_EXTENSIONS = {
    ".py", ".php", ".rb", ".js", ".ts", ".go", ".java", ".kt",
    ".html", ".jinja", ".jinja2", ".erb", ".twig", ".sql",
    ".yml", ".yaml", ".toml", ".json", ".env",
}

# Hard skip: vendored / generated / mass-noise directories.
SKIP_DIRECTORIES = {
    "node_modules", "vendor", ".git", "__pycache__", "venv", ".venv",
    "site-packages", "dist", "build", ".next", ".nuxt", ".cache",
    "static",  # JS bundles like jquery.min.js explode the file count
}

# Per-file content cap so a giant migration doesn't blow up the run.
FILE_READ_CAP_BYTES = 64 * 1024
TOTAL_DELIVERABLE_CAP_BYTES = 256 * 1024

# Framework entry-point patterns.
ROUTE_PATTERNS = [
    # Flask / FastAPI / Bottle
    (re.compile(r"@(?:app|bp|api|router|blueprint)\.(?:route|get|post|put|patch|delete)\s*\(\s*[\"']([^\"']+)[\"']", re.IGNORECASE), "python-decorator"),
    # Django urls.py path()
    (re.compile(r"\bpath\s*\(\s*[\"']([^\"']+)[\"']", re.IGNORECASE), "django-path"),
    # Express / Koa / NestJS
    (re.compile(r"\b(?:app|router|express)\s*\.\s*(?:get|post|put|delete|patch|use)\s*\(\s*[\"']([^\"']+)[\"']", re.IGNORECASE), "node-route"),
    # Rails routes.rb (simplified)
    (re.compile(r"\b(?:get|post|put|patch|delete)\s+[\"']([^\"']+)[\"']", re.IGNORECASE), "rails-route"),
    # Manual dispatch routers (BaseHTTPRequestHandler / do_GET/do_POST and any
    # hand-rolled `if request.path == "/x"` style). 2026-05-28: the lab suite
    # routes this way and its routes (e.g. /tools/webhook-tester) were never
    # surfaced, so the agent kept GUESSING the path (/webhook_tester -> 404).
    # Matches `parsed.path == "/x"`, `self.path == "/x"`, `path.startswith("/x")`.
    (re.compile(r"(?:self\.|parsed\.|request\.|req\.)?path\s*==\s*[\"']([^\"']+)[\"']"), "manual-path-dispatch"),
    (re.compile(r"(?:self\.|parsed\.|request\.|req\.)?path\.startswith\s*\(\s*[\"']([^\"']+)[\"']"), "manual-path-prefix"),
]

# Dangerous sinks — each tuple = (regex, sink_label, severity_hint).
SINK_PATTERNS = [
    (re.compile(r"\beval\s*\("), "eval", "critical"),
    (re.compile(r"\bexec\s*\("), "exec", "critical"),
    (re.compile(r"\bos\.system\s*\("), "os.system", "critical"),
    (re.compile(r"\bsubprocess\.(?:call|run|Popen)\s*\([^)]*shell\s*=\s*True"), "subprocess-shell-true", "critical"),
    (re.compile(r"\bsystem\s*\("), "system()", "critical"),
    (re.compile(r"\bpopen\s*\("), "popen()", "high"),
    (re.compile(r"\bexecute\s*\(\s*[fr]?[\"'].*\{[^}]+\}.*[\"']"), "raw-sql-fstring", "critical"),  # cursor.execute(f"...{x}...")
    (re.compile(r"\bexecute\s*\(\s*[fr]?[\"'][^\"']*%s[^\"']*[\"']\s*%"), "raw-sql-percent", "high"),  # cursor.execute("...%s..." % x)
    (re.compile(r"\brender_template_string\s*\("), "render_template_string", "high"),
    (re.compile(r"\bMarkup\s*\("), "flask-Markup", "medium"),
    (re.compile(r"\b__import__\s*\("), "dynamic-import", "high"),
    (re.compile(r"\bpickle\.loads?\s*\("), "pickle-loads", "critical"),
    (re.compile(r"\byaml\.load\s*\([^)]*Loader\s*=\s*(?:yaml\.Loader|yaml\.UnsafeLoader)?\)"), "yaml-unsafe-load", "high"),
    (re.compile(r"new\s+Function\s*\("), "js-new-Function", "critical"),
    (re.compile(r"\beval\s*\("), "js-eval", "critical"),
    (re.compile(r"\bdocument\.write\s*\("), "js-document-write", "high"),
    (re.compile(r"\bsetTimeout\s*\(\s*[fr]?[\"']"), "js-setTimeout-string", "medium"),
    # Headless-browser-callback indicator: server-side spawn of a
    # JS-executing renderer over user-supplied HTML. Win condition for
    # this class is JS firing inside the headless browser, NOT a
    # server-side state change. vuln_xss specialist's
    # `headless_callback` hypothesis triggers on this finding.
    (re.compile(r"\bphantomjs\b", re.IGNORECASE), "headless-phantomjs", "high"),
    (re.compile(r"\bpuppeteer\b"), "headless-puppeteer", "high"),
    (re.compile(r"\bselenium\b", re.IGNORECASE), "headless-selenium", "high"),
    (re.compile(r"\bplaywright\b", re.IGNORECASE), "headless-playwright", "high"),
    (re.compile(r"\bheadless[\s_-]?chrome\b", re.IGNORECASE), "headless-chrome", "high"),
    (re.compile(r"\bwebdriver\b", re.IGNORECASE), "headless-webdriver", "high"),
    # PHP dangerous sinks. 2026-06-01: the table had NO PHP-specific sinks —
    # pickle.loads covered Python deserialization but `unserialize()` (PHP
    # object injection / insecure deserialization) was absent, plus the PHP
    # command-exec and dynamic-include families. So PHP challenges whose vuln is
    # not a web-probe signature reported sink_count=0 and the loop chased
    # false positives (XBEN-014: `unserialize($_COOKIE['creds'])` was invisible,
    # so smart-web-probe's bogus "SQLi auth bypass" won). These are generic PHP
    # sink CLASSES (function names PHP-exclusive), not challenge-specific. Note
    # eval()/exec()/system()/popen() above already match the PHP forms too.
    (re.compile(r"\bunserialize\s*\("), "php-unserialize", "critical"),
    (re.compile(r"\bshell_exec\s*\("), "php-shell_exec", "critical"),
    (re.compile(r"\bpassthru\s*\("), "php-passthru", "critical"),
    (re.compile(r"\bproc_open\s*\("), "php-proc_open", "critical"),
    (re.compile(r"\bpcntl_exec\s*\("), "php-pcntl_exec", "critical"),
    (re.compile(r"\bcreate_function\s*\("), "php-create_function", "critical"),
    (re.compile(r"\bcall_user_func(?:_array)?\s*\("), "php-call_user_func", "high"),
    (re.compile(r"(?<![.\w])extract\s*\("), "php-extract", "high"),
    # include/require fed a variable => LFI / RFI (string-literal includes are safe)
    (re.compile(r"\b(?:include|require)(?:_once)?\s*(?:\(\s*)?\$"), "php-dynamic-include", "critical"),
    # assert() on a variable behaves like eval() in PHP
    (re.compile(r"\bassert\s*\(\s*\$"), "php-assert-var", "critical"),
    # preg_replace with the /e modifier evaluates the replacement as PHP code
    (re.compile(r"\bpreg_replace\s*\(\s*[\"'][^\"']*/[a-zA-Z]*e[a-zA-Z]*[\"']"), "php-preg-replace-e", "critical"),
]

# Internal listen-port patterns. 2026-05-28: the SSRF self-fetch class needs
# the port the service listens on INSIDE its container — which differs from
# the externally-published port (lab listens on :8080, published as :8088).
# Without surfacing this the agent points server-side fetches at the external
# port and gets fetch_failed/502. Generic across frameworks + Dockerfile.
LISTEN_PORT_PATTERNS = [
    (re.compile(r"""(?:environ\.get|getenv)\s*\(\s*[\"'][^\"']*PORT[^\"']*[\"']\s*,\s*[\"']?(\d{2,5})[\"']?""", re.IGNORECASE), "env-default-port"),
    (re.compile(r"(?:HTTPServer|TCPServer|socketserver\.\w+)\s*\(\s*\([^)]*,\s*(\d{2,5})\s*\)"), "httpserver-bind"),
    (re.compile(r"\.run\s*\([^)]*\bport\s*=\s*(\d{2,5})"), "framework-run-port"),
    (re.compile(r"0\.0\.0\.0:(\d{2,5})"), "bind-literal"),
    (re.compile(r"\.listen\s*\(\s*(\d{2,5})"), "node-listen"),
    (re.compile(r"^\s*EXPOSE\s+(\d{2,5})", re.IGNORECASE), "dockerfile-expose"),
    (re.compile(r"\bENV\s+\w*PORT\w*\s*=?\s*(\d{2,5})", re.IGNORECASE), "dockerfile-env-port"),
]

# Source-defined GATE TOKENS / magic constants. 2026-05-29: the SSRF win
# proved that surfacing a source-derived literal the agent can't guess
# black-box (the internal port) closes solves. A whole class of logic bugs is
# gated by a custom literal token the handler compares user input against:
# a custom header NAME, an interpolation token (${lab:lookup:flag}), a nested
# binder key (profile.class.module.loader.resource), a grammar prefix/substring
# (fn:...|print_flag), or a magic equality value. CVE-canonical black-box
# payloads (jndi, Shellshock, Spring4Shell defaults) will NOT hit these. We
# extract the EXACT literals from source so the exploit LLM submits them
# verbatim. Generic across apps, not challenge-specific.
GATE_TOKEN_PATTERNS = [
    # Custom request headers the app reads (X-* and any headers.get("...")).
    (re.compile(r"""(?:self\.headers|\bheaders|request\.headers|req\.headers)\.get\s*\(\s*[\"']([A-Za-z][\w-]{2,40})[\"']"""), "custom-request-header"),
    # Interpolation / lookup tokens: ${...}, #{...}, %{...}, {{...}} literals.
    (re.compile(r"""[\"'](\$\{[^\"'}]{1,80}\}|\#\{[^\"'}]{1,80}\}|%\{[^\"'}]{1,80}\})[\"']"""), "interpolation-token"),
    # Nested dotted binder keys (>=2 dots) — Spring4Shell-style property paths.
    (re.compile(r"""[\"']([A-Za-z_][\w]*(?:\.[A-Za-z_][\w]*){2,})[\"']"""), "nested-binder-key"),
    # Grammar gates: startswith("prefix:") and substring "needle" used as a gate.
    (re.compile(r"""\.startswith\s*\(\s*[\"']([^\"']{2,40})[\"']"""), "grammar-prefix"),
    (re.compile(r"""[\"']([|][\w:-]{2,40}|[\w:-]{2,40}[|])[\"']\s+in\b"""), "grammar-substring"),
    # Magic equality value compared against a header/param/field.
    (re.compile(r"""(?:headers\.get\([^)]*\)|params?\.get\([^)]*\)|\bfunction_env|\bbackend|\btrust\w*)\s*[!=]=\s*[\"']([^\"']{2,60})[\"']"""), "magic-equality-value"),
]

# Auth + credentials patterns.
AUTH_PATTERNS = [
    (re.compile(r"@login_required\b", re.IGNORECASE), "auth-decorator"),
    (re.compile(r"@admin_required\b", re.IGNORECASE), "admin-decorator"),
    (re.compile(r"@requires_auth\b", re.IGNORECASE), "auth-decorator"),
    (re.compile(r"\bcheck_password_hash\s*\(", re.IGNORECASE), "pw-hash-check"),
    (re.compile(r"\bbcrypt\.checkpw\s*\(", re.IGNORECASE), "bcrypt-check"),
    (re.compile(r"\bsession\[[\"'](user|uid|user_id|is_admin)[\"']", re.IGNORECASE), "session-key"),
    (re.compile(r"\bjwt\.(?:encode|decode)\s*\(", re.IGNORECASE), "jwt-call"),
]

# Default/seed credentials — high-impact when found.
DEFAULT_CRED_PATTERNS = [
    # name/username/user/login + password, with optional quotes around the keys so
    # dict-shaped seeds like {"name": "demo", "password": "demo"} are caught too
    # (XBEN-005 seeded its companies this way and the old `username`-only pattern
    # missed them → cred_count=0).
    (re.compile(r"""[\"']?(?:name|username|user|login)[\"']?\s*[:=]\s*[\"']([\w._-]{2,40})[\"'][,\s]*[\"']?(?:password|pw|passwd)[\"']?\s*[:=]\s*[\"']([^\"']{2,80})[\"']""", re.IGNORECASE), "user/pass-pair"),
    # Bare credential dict: `users = {'john': 'password123'}` — a username->password
    # mapping with NO explicit `password:` key, so the `user/pass-pair` regex (which
    # requires that key) misses it. This was the exact XBEN-032 gap: the XXE sink sits
    # behind `@login_required`, the only account is `users = {'john':'password123'}`,
    # and because recon never surfaced it the interactive-exploit agent burned every
    # step on 401 login guesses and never reached the SOAP/XXE. Scoped to a variable
    # named users/accounts/credentials/logins so a generic `{'a':'b'}` dict is NOT
    # flagged. Captures the FIRST pair (enough to give the exploit a usable login).
    (re.compile(r"""\b(?:users|accounts|credentials|logins|user_db|USERS|ACCOUNTS|CREDENTIALS)\s*=\s*\{\s*[\"']([\w.@-]{2,40})[\"']\s*:\s*[\"']([^\"']{2,80})[\"']"""), "users-dict-seed"),
    (re.compile(r"INSERT\s+INTO\s+users.*?VALUES\s*\(\s*[\"']?(\w+)[\"']?\s*,\s*[\"']([^\"']+)[\"']", re.IGNORECASE), "sql-seed-user"),
    (re.compile(r"create_user\s*\(\s*[\"'](\w+)[\"']\s*,\s*[\"']([^\"']+)[\"']", re.IGNORECASE), "create_user-call"),
    (re.compile(r"<!--\s*.*?(test|admin|dev|demo)\s*[:/=]\s*([^\s\"'>-]{3,30})\s*.*?-->", re.IGNORECASE), "html-comment-leak"),
    # Hardcoded cryptographic secret / token-signing key assigned to a string
    # literal — a JWT-forgery / session-mint enabler. This was the exact XBEN-005
    # gap: `SECRET_KEY = "a very secret key"` let an attacker forge an elevated JWT
    # and read the premium-gated flag, but recon never surfaced it. Generic vuln
    # CLASS (any *_SECRET / *_KEY signing constant), never a per-challenge recipe.
    (re.compile(r"""\b(SECRET_KEY|JWT_SECRET|JWT_KEY|TOKEN_SECRET|SIGNING_KEY|SESSION_SECRET|APP_SECRET|FLASK_SECRET|DJANGO_SECRET_KEY|PRIVATE_KEY|API_KEY|API_SECRET)\b\s*[:=]\s*[\"']([^\"']{4,200})[\"']""", re.IGNORECASE), "hardcoded-secret"),
]


def _iter_files(root: Path) -> list[Path]:
    """DFS over root, skipping noisy directories."""
    out: list[Path] = []
    for entry in root.rglob("*"):
        if not entry.is_file():
            continue
        if any(part in SKIP_DIRECTORIES for part in entry.parts):
            continue
        if entry.suffix.lower() not in SCAN_EXTENSIONS:
            continue
        try:
            if entry.stat().st_size > FILE_READ_CAP_BYTES * 4:  # skip mega-files
                continue
        except OSError:
            continue
        out.append(entry)
    return out


def _read_capped(path: Path) -> str:
    try:
        with path.open("rb") as fh:
            data = fh.read(FILE_READ_CAP_BYTES)
        return data.decode("utf-8", errors="replace")
    except OSError:
        return ""


def _scan_file(path: Path, root: Path) -> dict[str, list[dict[str, Any]]]:
    """Run all pattern groups against one file. Returns categorised hits."""
    text = _read_capped(path)
    if not text:
        return {}
    rel = str(path.relative_to(root)) if path.is_relative_to(root) else str(path)
    hits: dict[str, list[dict[str, Any]]] = {
        "routes": [],
        "sinks": [],
        "auth": [],
        "creds": [],
        "listen_ports": [],
        "gate_tokens": [],
    }
    lines = text.splitlines()
    for lineno, line in enumerate(lines, 1):
        for pattern, kind in LISTEN_PORT_PATTERNS:
            m = pattern.search(line)
            if m:
                hits["listen_ports"].append({"file": rel, "line": lineno, "kind": kind, "port": m.group(1), "snippet": line.strip()[:200]})
        for pattern, kind in GATE_TOKEN_PATTERNS:
            for m in pattern.finditer(line):
                tok = m.group(1)
                # Drop obvious noise: dotted module imports / stdlib paths.
                if kind == "nested-binder-key" and tok.split(".")[0] in {
                    "os", "sys", "urllib", "http", "json", "self", "logging",
                    "datetime", "hashlib", "hmac", "pathlib", "socketserver",
                }:
                    continue
                hits["gate_tokens"].append({"file": rel, "line": lineno, "kind": kind, "token": tok, "snippet": line.strip()[:200]})
        for pattern, kind in ROUTE_PATTERNS:
            m = pattern.search(line)
            if m:
                hits["routes"].append({"file": rel, "line": lineno, "kind": kind, "path": m.group(1), "snippet": line.strip()[:200]})
        for pattern, kind, sev in SINK_PATTERNS:
            if pattern.search(line):
                hits["sinks"].append({"file": rel, "line": lineno, "sink": kind, "severity_hint": sev, "snippet": line.strip()[:200]})
        for pattern, kind in AUTH_PATTERNS:
            if pattern.search(line):
                hits["auth"].append({"file": rel, "line": lineno, "kind": kind, "snippet": line.strip()[:200]})
        for pattern, kind in DEFAULT_CRED_PATTERNS:
            m = pattern.search(line)
            if m:
                hits["creds"].append({
                    "file": rel, "line": lineno, "kind": kind,
                    "user_or_role": (m.group(1) if m.lastindex and m.lastindex >= 1 else None),
                    "cred_or_value": (m.group(2) if m.lastindex and m.lastindex >= 2 else None),
                    "snippet": line.strip()[:200],
                })
    return hits


def _build_markdown(
    *,
    source_dir: str,
    file_count: int,
    hashes_sha256_prefix: list[str],
    routes: list[dict[str, Any]],
    sinks: list[dict[str, Any]],
    auth: list[dict[str, Any]],
    creds: list[dict[str, Any]],
    listen_ports: list[dict[str, Any]] | None = None,
    gate_tokens: list[dict[str, Any]] | None = None,
) -> str:
    listen_ports = listen_ports or []
    gate_tokens = gate_tokens or []
    def _section(title: str, body: str) -> str:
        return f"## {title}\n\n{body.strip()}\n"

    summary = (
        f"Source root: `{source_dir}`. "
        f"Scanned {file_count} file(s). "
        f"Found {len(routes)} route entrypoint(s), {len(sinks)} dangerous sink(s), "
        f"{len(auth)} auth-related call(s), {len(creds)} credential-shaped pattern(s)."
    )

    def _rows(items: list[dict[str, Any]], *cols: str) -> str:
        if not items:
            return "_(none observed)_"
        header = "| " + " | ".join(cols) + " |"
        sep = "|" + "|".join("---" for _ in cols) + "|"
        rows = [header, sep]
        for it in items[:60]:
            rows.append("| " + " | ".join(str(it.get(c, ""))[:120].replace("|", "\\|") for c in cols) + " |")
        if len(items) > 60:
            rows.append(f"| _… {len(items) - 60} more truncated_ |")
        return "\n".join(rows)

    body = (
        "# Pre-Recon Source Audit\n\n"
        + _section("Executive Summary", summary)
        + _section("Provenance", "\n".join(f"- `{h}`" for h in hashes_sha256_prefix[:10]) or "_(no files)_")
        + _section(
            "Service Internal Listen Port(s) — for container-internal / SSRF self-fetch targeting",
            (_rows(listen_ports, "file", "line", "kind", "port", "snippet")
             + "\n\nNOTE: these are the port(s) the service listens on INSIDE its container. "
               "For SSRF / server-side-fetch exploits the server fetches from inside the "
               "container, so target the INTERNAL port here (e.g. `http://127.0.0.1:<port>/...`), "
               "NOT the externally-published port you connect to.")
            if listen_ports else "_(none observed)_",
        )
        + _section(
            "Source-Defined Gate Tokens / Magic Constants (submit these LITERALLY)",
            (_rows(gate_tokens, "file", "line", "kind", "token", "snippet")
             + "\n\nNOTE: these are exact literals the code compares user input against to "
               "gate a sensitive branch — custom header NAMES, interpolation tokens "
               "(`${...}`), nested binder keys, grammar prefixes/substrings, magic equality "
               "values. CVE-canonical payloads (jndi, Shellshock, Spring4Shell defaults) will "
               "NOT match these. To reach the gated branch, submit the EXACT literal verbatim "
               "(e.g. send the custom header with the magic value, POST the exact interpolation "
               "token, use the exact dotted binder key).")
            if gate_tokens else "_(none observed)_",
        )
        + _section("Route Inventory (source-grepped)", _rows(routes, "file", "line", "kind", "path", "snippet"))
        + _section("Dangerous Sinks (CRITICAL = direct RCE candidates)", _rows(sinks, "file", "line", "sink", "severity_hint", "snippet"))
        + _section("Auth / Session Surface (source)", _rows(auth, "file", "line", "kind", "snippet"))
        + _section("Default / Seed Credentials (source-disclosed)", _rows(creds, "file", "line", "kind", "user_or_role", "cred_or_value", "snippet"))
    )

    if len(body.encode("utf-8")) > TOTAL_DELIVERABLE_CAP_BYTES:
        body = body.encode("utf-8")[:TOTAL_DELIVERABLE_CAP_BYTES].decode("utf-8", errors="replace") + "\n\n_(truncated to cap)_"
    return body


def execute_pre_recon_source(
    targets: list[str],
    *,
    source_dir: str | None = None,
    scope_allowlist: dict[str, Any] | None = None,  # noqa: ARG001 — recorded for audit
    timeout_seconds: float = 30.0,  # noqa: ARG001 — file scan is fast; reserved for caller compat
) -> RunnerExecution:
    """Walk `source_dir`, grep for surface + sinks + auth + creds, emit md.

    Refuses to run when source_dir is not provided — black-box runs do
    not silently turn into white-box ones (contamination discipline per
    gap-analysis-2026-05-22).
    """
    if not source_dir:
        return RunnerExecution(
            tool="pre-recon-source",
            exit_code=78,  # EX_CONFIG — runner unavailable: no source path
            stdout="",
            stderr=(
                "pre-recon-source skipped: no source_dir parameter. "
                "This runner is opt-in for source-aware engagements only."
            ),
            artifacts=[],
            metadata={"skipped": True, "skip_reason": "no_source_dir"},
        )

    root = Path(source_dir).resolve()
    if not root.exists() or not root.is_dir():
        return RunnerExecution(
            tool="pre-recon-source",
            exit_code=78,
            stdout="",
            stderr=f"pre-recon-source: source_dir not found or not a directory: {root}",
            artifacts=[],
            metadata={"skipped": True, "skip_reason": "source_dir_invalid"},
        )

    files = _iter_files(root)
    routes: list[dict[str, Any]] = []
    sinks: list[dict[str, Any]] = []
    auth: list[dict[str, Any]] = []
    creds: list[dict[str, Any]] = []
    listen_ports: list[dict[str, Any]] = []
    gate_tokens: list[dict[str, Any]] = []
    hashes_prefix: list[str] = []

    for path in files:
        hits = _scan_file(path, root)
        routes.extend(hits.get("routes", []))
        sinks.extend(hits.get("sinks", []))
        auth.extend(hits.get("auth", []))
        creds.extend(hits.get("creds", []))
        listen_ports.extend(hits.get("listen_ports", []))
        gate_tokens.extend(hits.get("gate_tokens", []))
        try:
            with path.open("rb") as fh:
                digest = hashlib.sha256(fh.read(FILE_READ_CAP_BYTES)).hexdigest()
            hashes_prefix.append(f"{digest[:12]}  {path.relative_to(root)}")
        except OSError:
            continue

    markdown = _build_markdown(
        source_dir=str(root),
        file_count=len(files),
        hashes_sha256_prefix=hashes_prefix,
        routes=routes,
        sinks=sinks,
        auth=auth,
        creds=creds,
        listen_ports=listen_ports,
        gate_tokens=gate_tokens,
    )

    payload = {
        "tool": "pre-recon-source",
        "source_dir": str(root),
        "file_count": len(files),
        "route_count": len(routes),
        "sink_count": len(sinks),
        "auth_count": len(auth),
        "cred_count": len(creds),
        "critical_sinks": sum(1 for s in sinks if s.get("severity_hint") == "critical"),
    }

    artifact = EvidenceArtifact(
        name=PRE_RECON_SOURCE_ARTIFACT_NAME,
        content_type="text/markdown",
        data=markdown.encode("utf-8"),
        kind="pre-recon-source",
    )

    return RunnerExecution(
        tool="pre-recon-source",
        exit_code=0,
        stdout=json.dumps(payload),
        stderr="",
        artifacts=[artifact],
        metadata={
            "tool_version": "pre-recon-source:v1-phase4-2026-05-22",
            "runner_digest": "workers.pre_recon_source.runner:v1",
        },
    )
