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
    (re.compile(r"(?:username|user|login)\s*[:=]\s*[\"']([\w._-]{2,40})[\"'][,\s]*(?:password|pw|passwd)\s*[:=]\s*[\"']([^\"']{2,80})[\"']", re.IGNORECASE), "user/pass-pair"),
    (re.compile(r"INSERT\s+INTO\s+users.*?VALUES\s*\(\s*[\"']?(\w+)[\"']?\s*,\s*[\"']([^\"']+)[\"']", re.IGNORECASE), "sql-seed-user"),
    (re.compile(r"create_user\s*\(\s*[\"'](\w+)[\"']\s*,\s*[\"']([^\"']+)[\"']", re.IGNORECASE), "create_user-call"),
    (re.compile(r"<!--\s*.*?(test|admin|dev|demo)\s*[:/=]\s*([^\s\"'>-]{3,30})\s*.*?-->", re.IGNORECASE), "html-comment-leak"),
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
    }
    lines = text.splitlines()
    for lineno, line in enumerate(lines, 1):
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
) -> str:
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
        f"# Pre-Recon Source Audit\n\n"
        + _section("Executive Summary", summary)
        + _section("Provenance", "\n".join(f"- `{h}`" for h in hashes_sha256_prefix[:10]) or "_(no files)_")
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
    hashes_prefix: list[str] = []

    for path in files:
        hits = _scan_file(path, root)
        routes.extend(hits.get("routes", []))
        sinks.extend(hits.get("sinks", []))
        auth.extend(hits.get("auth", []))
        creds.extend(hits.get("creds", []))
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
