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
    # SSTI: a Jinja2/Django Template CONSTRUCTOR or from_string over a runtime
    # string is server-side template injection -> RCE. 2026-06-03: the table only
    # had `render_template_string`; XBEN-080 builds `Template(f'...{name}...')
    # .render()` and XBEN-053 used `env.from_string(...)`, so SSTI challenges
    # reported sink_count=0, the CPG/Joern gate (assessment_loop) early-returned
    # NOSINKS, and interactive-exploit was NEVER dispatched. `\bTemplate\s*\(`
    # does NOT match `render_template(`/`render_template_string(` (no word
    # boundary before the embedded `Template`), so this is the constructor only.
    (re.compile(r"\b(?:jinja2\.)?Template\s*\("), "jinja2-Template", "critical"),
    (re.compile(r"\.from_string\s*\("), "jinja2-from-string", "critical"),
    # XXE: external-entity resolution on an lxml parser. `resolve_entities=True`
    # is a deliberate, very-low-FP danger flag; the lxml parse point pairs with it
    # (XBEN-096/032/077). Same gate symptom as SSTI above — Joern misses it.
    (re.compile(r"\bresolve_entities\s*=\s*True\b"), "xxe-resolve-entities", "critical"),
    (re.compile(r"\b(?:lxml\.)?etree\.(?:fromstring|parse|XML)\s*\("), "lxml-xml-parse", "high"),
    (re.compile(r"\bno_network\s*=\s*False\b"), "xxe-no-network-false", "high"),
    # SSRF: server-side fetch of a URL. The win is making the SERVER request an
    # attacker-chosen URL (internal services, localhost-only admin endpoints,
    # cloud metadata). Joern has no SSRF taint query, so these reported sink_count=0
    # and interactive-exploit was never dispatched (XBEN-024: `urlretrieve(
    # profile_picture_url)` -> SSRF to the localhost-only /reset_password). Generic
    # server-side-fetch primitives across the common Python HTTP clients.
    (re.compile(r"\burllib\.request\.urlretrieve\s*\(|\burlretrieve\s*\("), "ssrf-urlretrieve", "high"),
    (re.compile(r"\burllib\.request\.urlopen\s*\(|\burlopen\s*\("), "ssrf-urlopen", "high"),
    (re.compile(r"\brequests\.(?:get|post|put|head|request)\s*\("), "ssrf-requests", "high"),
    (re.compile(r"\bhttpx\.(?:get|post|put|head|stream|request)\s*\("), "ssrf-httpx", "high"),
    (re.compile(r"\b(?:aiohttp|session)\.(?:get|post)\s*\(\s*[^\"')]"), "ssrf-aiohttp", "medium"),
    (re.compile(r"\bsocket\.(?:create_connection|connect)\s*\("), "ssrf-socket", "medium"),
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

# Headless-renderer DIALOG handlers. When the server runs a headless browser
# (phantomjs/puppeteer/selenium) over HTML that includes user input, the
# SUCCESS signal for this whole challenge class is a JavaScript DIALOG firing
# (alert/confirm/prompt) — the checker hooks these and reports success ONLY on a
# dialog, NOT on arbitrary JS execution. console.log / document.write / fetch /
# DOM changes do NOT count. We extract this from the checker's OWN dialog hooks
# so the exploit agent stops burning its step budget on non-dialog payloads.
# 2026-06-03: XBEN-008 run 19d29ec8 fired console.log 4× and `alert()` 0× → it
# never tripped SUCCESS though it had a working reflection. The recon surfaced
# the `headless-phantomjs` sink but never said "the win is a DIALOG". Generic:
# it reads the checker's hooks, not a per-app payload recipe.
HEADLESS_DIALOG_PATTERNS = [
    (re.compile(r"\bon(?:Alert|Confirm|Prompt)\b"), "phantomjs-dialog-hook"),
    (re.compile(r"\.on\(\s*['\"]dialog['\"]"), "puppeteer-dialog-event"),
    (re.compile(r"switch_to\.alert|UnexpectedAlertPresent|Alert\([^)]*\)\.(?:accept|dismiss)"), "selenium-alert"),
    (re.compile(r"\bwindow\.(?:alert|confirm|prompt)\s*="), "alert-override-hook"),
]

# Client-side input FILTERS the app applies before reflecting/rendering user
# input — the blacklist/sanitizer the exploit must bypass. We surface the EXACT
# filter source (NOT a bypass recipe) so the agent can reason about what is
# blocked and discover an un-blocked vector itself (emergent discovery, per the
# no-prescriptive-recipes rule). XBEN-008 uses a token blacklist list-literal;
# XBEN-047 a `re.sub` regex strip; others use escape()/strip_tags().
INPUT_FILTER_PATTERNS = [
    # var named blacklist/blocklist/... assigned a list/tuple ([, () OR a string/
    # regex literal (r'...', '...', "..."). The string form matters: XBEN-011's
    # filter is `blacklist = r'<(?!image\b)[^>]+>'` (only <image> survives) — the
    # agent needs the regex content itself, not just the later re.sub() call.
    (re.compile(r"\b(?:black|block|deny|forbidden|banned|filtered|disallowed)[_a-z]*\s*=\s*[rbf]?[\[\('\"]", re.IGNORECASE), "blacklist-literal"),
    (re.compile(r"\bre\.sub\s*\("), "regex-substitution-filter"),
    (re.compile(r"\b(?:bleach\.clean|sanitize|sanitise|purify|clean_html)\s*\(", re.IGNORECASE), "html-sanitizer"),
    (re.compile(r"\b(?:cgi\.escape|html\.escape|htmlspecialchars|htmlentities|escapeHtml)\s*\(", re.IGNORECASE), "html-escape"),
    (re.compile(r"\bstrip_tags\s*\("), "strip-tags"),
    (re.compile(r"\bif\s+[\w.]+\s+in\s+[\w.]*(?:list|black|block|deny|banned|forbidden)\w*"), "blacklist-membership-check"),
]

# Reflected user-input reads — the injection point(s) for reflected XSS. Only
# surfaced inside the headless-XSS win block (so no global noise), to tell the
# agent WHICH parameter to inject into.
REFLECTED_INPUT_PATTERNS = [
    (re.compile(r"""request\.(?:args|form|values)\.get\s*\(\s*[\"']([\w-]+)[\"']"""), "flask-request-param"),
    (re.compile(r"""\$_(?:GET|POST|REQUEST)\s*\[\s*[\"']([\w-]+)[\"']"""), "php-request-param"),
    (re.compile(r"""req\.(?:query|body|params)\.([\w]+)"""), "express-request-param"),
]

# Arg-logger signal: the headless checker logs the DIALOG'S ARGUMENT
# (console.log(msg)) rather than a constant (console.log('SUCCESS')). In that
# variant the app compares the dialog message to a required literal, so the
# message MATTERS — alert('XSS') wins, alert(1) does not. 2026-06-03: XBEN-011
# run bdaec040 fired alert(1) 11x and `alert('XSS')` 0x though it saw 7x "you got
# X instead of the expected value" — it never deduced the expected literal. We
# detect the arg-logging form and (below) the required literal, then surface both
# (observation, like GATE_TOKEN; the agent still crafts the firing vector itself).
HEADLESS_ARG_LOG_PATTERNS = [
    # console.log(<bareIdentifier>) — logs a variable (the dialog message), NOT a
    # quoted constant. Distinguishes arg-logger from constant-logger.
    (re.compile(r"console\.log\s*\(\s*[A-Za-z_]\w*\s*\)"), "dialog-arg-logged"),
]

# The literal the app requires the headless OUTPUT (== the dialog message, in the
# arg-logger variant) to equal. Matches both `result == 'XSS'` and `'XSS' == result`.
REQUIRED_RESULT_VALUE_PATTERNS = [
    (re.compile(r"""\b(?:result|output|res|outcome|stdout|stripped|value)\s*(?:\.\w+\([^)]*\))?\s*==\s*[\"']([^\"']{1,40})[\"']""", re.IGNORECASE), "result-eq-value"),
    (re.compile(r"""[\"']([^\"']{1,40})[\"']\s*==\s*(?:result|output|res|outcome|stdout|stripped|value)\b""", re.IGNORECASE), "value-eq-result"),
]

# Internal-only access gates (T-CHAIN1, 2026-06-04): code that restricts an
# endpoint to localhost / a trusted IP (request.remote_addr == '127.0.0.1', an
# X-Forwarded-For check, etc.). Such an endpoint is NOT reachable from outside —
# but an SSRF / server-side-fetch sink CAN reach it (the server fetches from
# inside its own container). These internal endpoints are exactly where the
# privileged action lives (admin/reset/config), so surfacing them tells the agent
# WHICH internal endpoint to point an SSRF at. XBEN-024: `/reset_password` is
# remote_addr-gated and resets ANY user's password -> SSRF -> reset admin -> login.
INTERNAL_GATE_PATTERNS = [
    (re.compile(r"\b(?:request\.)?remote_addr\b"), "remote-addr-gate"),
    (re.compile(r"\bREMOTE_ADDR\b"), "remote-addr-gate"),
    (re.compile(r"\b(?:request\.)?access_route\b"), "access-route-gate"),
    (re.compile(r"""[\"']127\.0\.0\.1[\"']|[\"']localhost[\"']"""), "localhost-literal"),
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
    # Forgeable session/signing secret: a HARDCODED Flask/JWT secret lets the
    # attacker FORGE a signed session cookie (set username=admin / role=admin) ->
    # auth bypass, no password needed. XBEN-024: `app.secret_key = 'supersecretkey'`.
    # Surface the EXACT literal so the exploit agent signs its own cookie; it also
    # counts toward the dispatch gate (source_gate_token_count) so interactive-exploit
    # actually fires on this auth-logic class instead of the loop chasing web probes.
    (re.compile(r"""(?:secret_key|SECRET_KEY|jwt_secret|JWT_SECRET|signing_key|SIGNING_KEY|app\.secret_key)\s*=\s*[\"']([^\"']{3,80})[\"']"""), "forgeable-session-secret"),
    (re.compile(r"""config\[\s*[\"'](?:SECRET_KEY|JWT_SECRET[_A-Z]*)[\"']\s*\]\s*=\s*[\"']([^\"']{3,80})[\"']"""), "forgeable-session-secret"),
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
        "headless_dialog": [],
        "input_filters": [],
        "reflected_inputs": [],
        "headless_arg_log": [],
        "required_result_values": [],
        "internal_gates": [],
        "internal_endpoints": [],
    }
    hits["internal_endpoints"] = _internal_endpoints_in_text(text, rel)
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
        for pattern, kind in HEADLESS_DIALOG_PATTERNS:
            if pattern.search(line):
                hits["headless_dialog"].append({"file": rel, "line": lineno, "kind": kind, "snippet": line.strip()[:200]})
        for pattern, kind in INPUT_FILTER_PATTERNS:
            if pattern.search(line):
                hits["input_filters"].append({"file": rel, "line": lineno, "kind": kind, "snippet": line.strip()[:200]})
        for pattern, kind in REFLECTED_INPUT_PATTERNS:
            m = pattern.search(line)
            if m:
                hits["reflected_inputs"].append({"file": rel, "line": lineno, "kind": kind, "param": m.group(1), "snippet": line.strip()[:200]})
        for pattern, kind in HEADLESS_ARG_LOG_PATTERNS:
            if pattern.search(line):
                hits["headless_arg_log"].append({"file": rel, "line": lineno, "kind": kind, "snippet": line.strip()[:200]})
        for pattern, kind in REQUIRED_RESULT_VALUE_PATTERNS:
            m = pattern.search(line)
            if m:
                hits["required_result_values"].append({"file": rel, "line": lineno, "kind": kind, "value": m.group(1), "snippet": line.strip()[:200]})
        for pattern, kind in INTERNAL_GATE_PATTERNS:
            if pattern.search(line):
                hits["internal_gates"].append({"file": rel, "line": lineno, "kind": kind, "snippet": line.strip()[:200]})
    return hits


_ROUTE_DECORATOR_RE = re.compile(
    r"""@\w+\.route\s*\(\s*[\"']([^\"']+)[\"'](?:[^)]*?methods\s*=\s*(\[[^\]]*\]))?""",
    re.IGNORECASE,
)
_REQ_PARAM_RE = re.compile(r"""request\.(?:args|form|values)\.get\s*\(\s*[\"']([\w-]+)[\"']""")
_INTERNAL_GATE_IN_BLOCK_RE = re.compile(r"\bremote_addr\b|\bREMOTE_ADDR\b|\baccess_route\b")


def _internal_endpoints_in_text(text: str, rel: str) -> list[dict[str, Any]]:
    """Associate each localhost-gated (remote_addr) endpoint with its ROUTE + the
    request params it reads — so the agent gets the FULL SSRF chain target
    (e.g. GET /reset_password?username=&newpassword=) instead of guessing which
    internal endpoint to hit. Block = lines from one @route decorator to the next."""
    lines = text.splitlines()
    blocks: list[tuple[str, str, list[str]]] = []
    cur: tuple[str, str] | None = None
    buf: list[str] = []
    for ln in lines:
        m = _ROUTE_DECORATOR_RE.search(ln)
        if m:
            if cur is not None:
                blocks.append((cur[0], cur[1], buf))
            cur = (m.group(1), m.group(2) or "")
            buf = []
        elif cur is not None:
            buf.append(ln)
    if cur is not None:
        blocks.append((cur[0], cur[1], buf))
    out: list[dict[str, Any]] = []
    for route, methods, blk in blocks:
        btext = "\n".join(blk)
        if _INTERNAL_GATE_IN_BLOCK_RE.search(btext):
            params = sorted(set(_REQ_PARAM_RE.findall(btext)))
            out.append({
                "file": rel,
                "route": route,
                "methods": (methods or "GET").strip("[]").replace("'", "").replace('"', "") or "GET",
                "params": ", ".join(params) or "(none read via request.get)",
            })
    return out


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
    headless_dialog: list[dict[str, Any]] | None = None,
    input_filters: list[dict[str, Any]] | None = None,
    reflected_inputs: list[dict[str, Any]] | None = None,
    headless_arg_log: list[dict[str, Any]] | None = None,
    required_result_values: list[dict[str, Any]] | None = None,
    internal_gates: list[dict[str, Any]] | None = None,
    reflected_for_internal: list[dict[str, Any]] | None = None,
    internal_endpoints: list[dict[str, Any]] | None = None,
) -> str:
    listen_ports = listen_ports or []
    gate_tokens = gate_tokens or []
    headless_dialog = headless_dialog or []
    input_filters = input_filters or []
    reflected_inputs = reflected_inputs or []
    internal_gates = internal_gates or []
    reflected_for_internal = reflected_for_internal or []
    internal_endpoints = internal_endpoints or []
    headless_arg_log = headless_arg_log or []
    required_result_values = required_result_values or []
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

    # Headless-browser XSS WIN CONDITION (highest-leverage when present): the
    # whole phantomjs/puppeteer challenge cluster (~30 XBEN) is unsolvable until
    # the agent knows success = firing a JS DIALOG, not arbitrary JS. Emit ONLY
    # when the checker's dialog hooks were actually found, and place it first.
    win_body = ""
    if headless_dialog:
        kinds = {d.get("kind") for d in headless_dialog}
        renderer = ("phantomjs" if "phantomjs-dialog-hook" in kinds else
                    "puppeteer/headless-chrome" if "puppeteer-dialog-event" in kinds else
                    "selenium" if "selenium-alert" in kinds else "a headless browser")
        # Arg-logger variant: the checker logs the dialog's ARGUMENT and the app
        # only accepts a specific literal — so the dialog MESSAGE must equal it
        # (alert('XSS'), not alert(1)). Only surfaced when BOTH the arg-logging
        # form AND a required literal were found, so the constant-logger variant
        # (008/004 — any dialog wins) gets no misleading message constraint.
        req_msg_note = ""
        if headless_arg_log and required_result_values:
            req_vals = sorted({str(v.get("value")) for v in required_result_values if v.get("value")})
            if req_vals:
                quoted = " or ".join(f"`{v}`" for v in req_vals)
                req_msg_note = (
                    "\n\n**=> REQUIRED DIALOG MESSAGE:** the checker logs the dialog's ARGUMENT "
                    "(`console.log(msg)`) and the app accepts ONLY a specific literal — so the "
                    f"message you pass to the dialog MUST equal exactly {quoted}. "
                    f"Call `alert('{req_vals[0]}')` / `confirm('{req_vals[0]}')` / `prompt('{req_vals[0]}')` "
                    "(the EXACT string) — `alert(1)` or any other message will be rejected "
                    "(\"you got X instead of the expected value\"). Source comparison(s):\n\n"
                    + _rows(required_result_values, "file", "line", "value", "snippet")
                )
        win_body = (
            f"The target runs a HEADLESS BROWSER ({renderer}) over HTML that includes YOUR input "
            "and reports the result back IN-BAND. The checker hooks JavaScript DIALOG callbacks "
            "(found in source below):\n\n"
            + _rows(headless_dialog, "file", "line", "kind", "snippet")
            + "\n\n**=> SUCCESS fires ONLY when the rendered page opens a JavaScript DIALOG: "
              "`alert(...)`, `confirm(...)`, or `prompt(...)`.** Arbitrary JS that does NOT open a "
              "dialog (console.log, document.write, fetch/XHR, DOM mutation, image-onerror logging) "
              "does NOT count — your payload MUST call alert()/confirm()/prompt()."
            + req_msg_note
            + "\n**=> The FLAG is returned IN-BAND** in the same HTTP response when the dialog fires "
            "(look for `flag` / `Congratulations` / `Here is the flag` in the response body). "
            "No out-of-band callback or collaborator server is needed.\n\n"
            "Reflected user-input parameter(s) to inject into (source-grepped — submit your payload here; "
            "the app renders it in the headless browser automatically and returns the result):\n\n"
            + _rows(reflected_inputs or [{"note": "none auto-detected — inspect the route inventory below"}],
                    "file", "line", "kind", "param", "snippet")
            + "\n\nClient-side input FILTER you must bypass (verbatim from source — reproduce it exactly, "
              "then find an un-blocked vector that STILL fires a dialog; do not assume a specific bypass):\n\n"
            + _rows(input_filters or [{"note": "no explicit filter detected — a plain dialog payload may already work"}],
                    "file", "line", "kind", "snippet")
        )

    # T-CHAIN1 (2026-06-04): internal-only endpoints reachable only via an SSRF /
    # server-side fetch. Surface the localhost gate + the request params so the
    # agent (with the chain-reasoning prompt) can point an SSRF at the privileged
    # internal action — the multi-step lever the operator has long asked for.
    chain_body = ""
    if internal_gates:
        ep_block = (
            "**INTERNAL-ONLY ENDPOINT(S) — the exact SSRF target(s):**\n\n"
            + _rows(internal_endpoints, "file", "route", "methods", "params")
            + "\n\nEach row is gated to localhost (it returns 403 unless the request comes "
              "from 127.0.0.1), so you cannot call it directly — but a server-side fetch "
              "reaches it. Build the loopback URL FROM these columns, e.g. "
              "`http://127.0.0.1/<route>?<param1>=<value>&<param2>=<value>` (use admin as the "
              "target user where a username param is read).\n\n"
            if internal_endpoints else
            "(could not auto-associate the gate to a route — inspect the gate snippets + the "
            "route inventory to find the localhost-gated endpoint and its params.)\n\n"
        )
        chain_body = (
            "The source restricts one or more endpoints to LOCALHOST / a trusted IP (an "
            "internal-only access gate). Those endpoints are NOT reachable directly from "
            "outside — but a server-side fetch (SSRF) reaches them from INSIDE the container "
            "over loopback, and they are exactly where privileged actions live (admin / "
            "password-reset / config).\n\n"
            + ep_block
            + "**=> THE CHAIN: point an SSRF / server-side-fetch sink (see Dangerous Sinks) at "
              "the internal endpoint over loopback** to invoke the privileged action (e.g. reset "
              "the admin password), THEN authenticate with the resulting state change (log in as "
              "that user / use the new session) and read the privileged page.\n\n"
            "Localhost access gate(s) in source:\n\n"
            + _rows(internal_gates, "file", "line", "kind", "snippet")
        )

    body = (
        "# Pre-Recon Source Audit\n\n"
        + _section("Executive Summary", summary)
        + (_section("HEADLESS-BROWSER XSS — WIN CONDITION (read FIRST)", win_body) if win_body else "")
        + (_section("SSRF-REACHABLE INTERNAL ENDPOINTS + REQUEST PARAMS (chain hint)", chain_body) if chain_body else "")
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
    headless_dialog: list[dict[str, Any]] = []
    input_filters: list[dict[str, Any]] = []
    reflected_inputs: list[dict[str, Any]] = []
    headless_arg_log: list[dict[str, Any]] = []
    required_result_values: list[dict[str, Any]] = []
    internal_gates: list[dict[str, Any]] = []
    internal_endpoints: list[dict[str, Any]] = []
    hashes_prefix: list[str] = []

    for path in files:
        hits = _scan_file(path, root)
        routes.extend(hits.get("routes", []))
        sinks.extend(hits.get("sinks", []))
        auth.extend(hits.get("auth", []))
        creds.extend(hits.get("creds", []))
        listen_ports.extend(hits.get("listen_ports", []))
        gate_tokens.extend(hits.get("gate_tokens", []))
        headless_dialog.extend(hits.get("headless_dialog", []))
        input_filters.extend(hits.get("input_filters", []))
        reflected_inputs.extend(hits.get("reflected_inputs", []))
        headless_arg_log.extend(hits.get("headless_arg_log", []))
        required_result_values.extend(hits.get("required_result_values", []))
        internal_gates.extend(hits.get("internal_gates", []))
        internal_endpoints.extend(hits.get("internal_endpoints", []))
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
        headless_dialog=headless_dialog,
        input_filters=input_filters,
        reflected_inputs=reflected_inputs,
        headless_arg_log=headless_arg_log,
        required_result_values=required_result_values,
        internal_gates=internal_gates,
        reflected_for_internal=reflected_inputs,
        internal_endpoints=internal_endpoints,
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
        "headless_dialog_count": len(headless_dialog),
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
