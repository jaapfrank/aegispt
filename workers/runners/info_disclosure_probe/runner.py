"""info-disclosure-probe — probe a target for debug/admin endpoints that
leak sensitive data (passwords, secrets, internal state).

Covers gaps left by content-discovery: that runner uses generic wordlists
and produces "Hidden Endpoint Discovered" findings without checking the
*content*. This runner checks each candidate path for content-disclosure
signals (cleartext passwords, dump-like payloads, config secrets) and
flags HIGH-severity info-disclosure findings only when content confirms.

Target gaps explicitly addressed:
- Google Gruyere `/dump.gtl` (R20 — cleartext password dump)
- `.env`, `.git/config`, `phpinfo.php` style misconfigs
- Java/Spring Actuator endpoints
- Generic admin/debug pages that return JSON of records
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx as httpx_client

from api.app.services.runs import web_target_value_is_allowed_with_path
from workers.runners.base.contracts import EvidenceArtifact, RunnerExecution

logger = logging.getLogger(__name__)

RUNNER_NAME = "info-disclosure-probe"
RESULTS_ARTIFACT_NAME = "info-disclosure-results.json"
DEFAULT_TIMEOUT = 8.0
MAX_BODY_BYTES = 32_768
MAX_PROBES_PER_TARGET = 60

# Paths grouped by what they typically reveal.
PROBE_PATHS: tuple[tuple[str, str], ...] = (
    # --- generic debug dumps ---
    ("/dump", "debug-dump"),
    ("/dump.gtl", "debug-dump"),  # Google Gruyere R20
    ("/dump.json", "debug-dump"),
    ("/dump.txt", "debug-dump"),
    ("/_dump", "debug-dump"),
    ("/__dump__", "debug-dump"),
    ("/debug", "debug-dump"),
    ("/_debug", "debug-dump"),
    ("/debug.gtl", "debug-dump"),
    ("/debug/vars", "debug-dump"),
    ("/debug/pprof", "debug-dump"),
    ("/console", "debug-console"),
    ("/__console__", "debug-console"),
    # --- VCS / dotfile leaks ---
    ("/.env", "dotfile-leak"),
    ("/.env.local", "dotfile-leak"),
    ("/.env.production", "dotfile-leak"),
    ("/.git/config", "dotfile-leak"),
    ("/.git/HEAD", "dotfile-leak"),
    ("/.svn/entries", "dotfile-leak"),
    ("/.htaccess", "dotfile-leak"),
    ("/.htpasswd", "dotfile-leak"),
    ("/.DS_Store", "dotfile-leak"),
    # --- backup / swap ---
    ("/backup", "backup-leak"),
    ("/backup.tar.gz", "backup-leak"),
    ("/backup.sql", "backup-leak"),
    ("/database.sql", "backup-leak"),
    ("/db.sqlite", "backup-leak"),
    ("/index.bak", "backup-leak"),
    ("/index.old", "backup-leak"),
    # --- info disclosure endpoints ---
    ("/phpinfo.php", "phpinfo"),
    ("/info.php", "phpinfo"),
    ("/server-status", "server-status"),
    ("/server-info", "server-status"),
    ("/status", "status"),
    ("/metrics", "metrics"),
    # --- spring actuator family ---
    ("/actuator", "actuator"),
    ("/actuator/env", "actuator"),
    ("/actuator/heapdump", "actuator"),
    ("/actuator/configprops", "actuator"),
    ("/actuator/mappings", "actuator"),
    # --- admin / management ---
    ("/admin/users", "admin-data"),
    ("/admin/dump", "admin-data"),
    ("/admin/export", "admin-data"),
    ("/api/users", "admin-data"),
    ("/api/admin", "admin-data"),
    ("/api/dump", "admin-data"),
    ("/users.json", "admin-data"),
    ("/users.xml", "admin-data"),
    # --- common discovery quirks ---
    ("/swagger.json", "swagger"),
    ("/swagger/v1/swagger.json", "swagger"),
    ("/openapi.json", "swagger"),
    ("/robots.txt", "robots"),
    ("/sitemap.xml", "sitemap"),
)

# Content patterns that strongly suggest sensitive data leaking.
# Key/value forms covered: `pw: secret`, `'pw': 'secret'`, `"pw"="secret"`,
# `pw = secret`, JSON, Python-repr dicts, and YAML.
_SENSITIVE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("password_leak", re.compile(
        r"(?i)(?:^|[\s,{\[(])['\"]?(?:password|passwd|pw|pwd)['\"]?\s*[:=]\s*['\"][^'\"\s,;<>]{2,}['\"]",
        re.MULTILINE,
    )),
    ("api_key_leak", re.compile(
        r"(?i)(?:^|[\s,{\[(])['\"]?(?:api[_\- ]?key|secret[_\- ]?key|access[_\- ]?token)['\"]?\s*[:=]\s*['\"][a-z0-9_\-]{12,}['\"]",
        re.MULTILINE,
    )),
    ("private_key_leak", re.compile(r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |)PRIVATE KEY-----")),
    ("aws_secret", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("etc_passwd", re.compile(r"^(?:root|nobody|daemon|bin):[^\n]*:[0-9]+:[0-9]+", re.MULTILINE)),
    ("user_dump", re.compile(
        r"(?i)['\"](?:password|hashed_password|password_hash|pw|secret_word)['\"]\s*:\s*['\"][^'\"]+['\"]",
    )),
    ("admin_flag_dump", re.compile(
        r"(?i)['\"](?:is_admin|is_superuser|is_staff|is_root|admin)['\"]\s*:\s*(?:true|['\"]?true['\"]?)",
    )),
    ("stack_trace", re.compile(
        r"(?i)(?:traceback \(most recent call last\)|java\.lang\.[a-z]+exception|django\.core|werkzeug|^\s+at\s)",
        re.MULTILINE,
    )),
    ("git_config", re.compile(r"\[remote ['\"][a-zA-Z0-9_-]+['\"]\][\s\S]+url\s*=")),
    ("env_secret", re.compile(
        r"(?im)^(?:DATABASE_URL|DJANGO_SECRET_KEY|SECRET_KEY|JWT_SECRET|ADMIN_PASSWORD|MYSQL_PASSWORD|POSTGRES_PASSWORD)\s*=\s*\S+",
    )),
    ("phpinfo", re.compile(r"<h1[^>]*>PHP Version", re.IGNORECASE)),
    ("spring_env", re.compile(r"\"(?:propertySources|activeProfiles|server\.port)\"\s*:")),
    ("debug_dump_title", re.compile(r"<title>(?:Debug Dump|App State|Internal State|Server State)</title>", re.IGNORECASE)),
)


def _artifact(payload: dict[str, Any]) -> EvidenceArtifact:
    return EvidenceArtifact(
        name=RESULTS_ARTIFACT_NAME,
        content_type="application/json",
        data=(json.dumps(payload, sort_keys=True) + "\n").encode("utf-8"),
        kind="runner-results",
    )


def _root_for(target: str) -> str:
    """Strip path/query/fragment so we can build sibling probe URLs."""
    parsed = urlparse(target)
    if not parsed.scheme or not parsed.netloc:
        return target
    return f"{parsed.scheme}://{parsed.netloc}"


def _probe_urls(target_url: str) -> list[tuple[str, str]]:
    """Build (url, category) tuples for a target.

    Strategy: probe relative to BOTH the host root and the path root of the
    target, so `/dump.gtl` is tested under both `https://host/dump.gtl` AND
    `https://host/{instance}/dump.gtl`. The latter is what apps like Gruyere
    actually expose.
    """
    out: list[tuple[str, str]] = []
    base = _root_for(target_url)
    parsed = urlparse(target_url)
    # Path prefix from the target (drop trailing filename so we can compose)
    path = parsed.path or "/"
    if not path.endswith("/"):
        # Strip filename, keep directory.
        path = path.rsplit("/", 1)[0] + "/"
    seen: set[str] = set()
    for rel, cat in PROBE_PATHS:
        for prefix in ("", path.rstrip("/")):
            full = urljoin(base + "/", prefix + rel)
            if full in seen:
                continue
            seen.add(full)
            out.append((full, cat))
            if len(out) >= MAX_PROBES_PER_TARGET:
                return out
    return out


def _detect_sensitive(text: str) -> list[tuple[str, str]]:
    hits: list[tuple[str, str]] = []
    truncated = text[:MAX_BODY_BYTES]
    for label, pattern in _SENSITIVE_PATTERNS:
        m = pattern.search(truncated)
        if m:
            hits.append((label, m.group(0)[:120]))
    return hits


def execute_info_disclosure_probe(
    targets: list[str] | list[dict[str, Any]],
    *,
    scope_allowlist: dict[str, Any] | None = None,
    timeout_seconds: float = DEFAULT_TIMEOUT,
) -> RunnerExecution:
    findings_payload: list[dict[str, Any]] = []
    raw_results: list[dict[str, Any]] = []
    stderr_lines: list[str] = []
    exit_code = 0

    # Accept BOTH a list of URL strings (orchestrator-style) and a list of
    # {"kind":"url","value":"..."} dicts (smoke-test style).
    web_targets: list[str] = []
    for t in targets:
        if isinstance(t, str):
            if t.strip().lower().startswith(("http://", "https://")):
                web_targets.append(t.strip())
        elif isinstance(t, dict):
            kind = str(t.get("kind") or "").lower()
            value = str(t.get("value") or "").strip()
            if kind == "url" and value:
                web_targets.append(value)
    if not web_targets:
        stderr_lines.append("no web targets supplied")
        return RunnerExecution(
            tool=RUNNER_NAME, exit_code=2, stdout=json.dumps({"probes": []}),
            stderr="\n".join(stderr_lines), metadata={"status": "skip"},
            artifacts=[_artifact({"probes": []})], protected_outputs=[],
        )

    with httpx_client.Client(timeout=timeout_seconds, follow_redirects=False) as client:
        for target in web_targets:
            for url, category in _probe_urls(target):
                if scope_allowlist and not web_target_value_is_allowed_with_path(scope_allowlist, url):
                    continue
                try:
                    resp = client.get(url, headers={"User-Agent": "AegisPT/info-disclosure-probe"})
                except httpx_client.RequestError as exc:
                    raw_results.append({"url": url, "category": category, "error": str(exc)[:160]})
                    continue
                status = resp.status_code
                body = resp.text or ""
                raw_results.append({
                    "url": url,
                    "category": category,
                    "status": status,
                    "content_type": resp.headers.get("content-type", ""),
                    "body_len": len(body),
                })
                if status not in (200, 401, 403):
                    continue
                hits = _detect_sensitive(body) if status == 200 else []
                if status == 200 and hits:
                    severity = "critical" if any(label in {"password_leak", "etc_passwd", "user_dump", "private_key_leak", "aws_secret", "env_secret"} for label, _ in hits) else "high"
                    findings_payload.append({
                        "title": f"Info Disclosure — {category} — {hits[0][0]}",
                        "severity": severity,
                        "category": "info-disclosure",
                        "target_id": url,
                        "evidence": {
                            "url": url,
                            "status": status,
                            "category": category,
                            "leak_patterns": [{"type": l, "sample": s} for l, s in hits[:5]],
                            "body_excerpt": body[:600],
                        },
                    })

    result = {"probes": raw_results, "findings": findings_payload, "probe_count": len(raw_results)}
    if findings_payload:
        stderr_lines.append(f"flagged {len(findings_payload)} info-disclosure leak(s)")
    return RunnerExecution(
        tool=RUNNER_NAME,
        exit_code=exit_code,
        stdout=json.dumps(result),
        stderr="\n".join(stderr_lines),
        metadata={"status": "ok", "tool_version": f"{RUNNER_NAME}:v1", "findings_count": len(findings_payload)},
        artifacts=[_artifact(result)],
        protected_outputs=[],
    )
