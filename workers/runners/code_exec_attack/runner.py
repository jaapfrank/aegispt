"""Code-exec-attack runner — AI writes Python exploit script per target.

Phase B of "best AI pentest system" plan 2026-05-22. The picker (or a
specialist) emits a Python script designed to exploit a specific
vulnerability hypothesis against a specific target. This runner:

1. Prepends a SCOPE-GUARD preamble that monkeypatches httpx so every
   request is checked against the engagement scope allowlist; any
   out-of-scope URL raises before the request fires.
2. Executes the user's script in a fresh subprocess with the scope
   allowlist passed via env vars.
3. Captures stdout (max 64 KB), stderr (max 16 KB), exit code.
4. Parses well-known finding markers (``AEGISPT_FINDING: {json}``)
   from stdout so the AI can declaratively emit findings.

Why host-process rather than Docker:
- The existing Docker sandbox (sandbox_runner.py) uses `network=none`
  and is built around CURL. Repurposing it for httpx + scope-guarded
  network would require shipping a Docker image with our scope guard
  baked in — slower iteration, harder to debug.
- The Layer 0 scope enforcement is a code-level check, not a kernel
  one. We do not pretend this is hardened sandboxing for an
  adversarial AI; it is an honest tool that refuses obvious scope
  violations so a model misfire does not pivot the operator's
  engagement off the approved target.

Layer 0 stance: this runner refuses URLs not in the engagement scope.
Hosts and ports outside the allowlist raise ScopeViolation BEFORE the
socket opens.
"""
from __future__ import annotations

import json
import logging
import os
import re
import shlex
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from workers.runners.base.contracts import EvidenceArtifact, RunnerExecution

logger = logging.getLogger(__name__)

CODE_EXEC_ATTACK_ARTIFACT_NAME = "code-exec-attack-script.py"
CODE_EXEC_ATTACK_STDOUT_ARTIFACT_NAME = "code-exec-attack-stdout.txt"

# Stdout/stderr caps to keep the artifact storage bounded.
STDOUT_CAP_BYTES = 64 * 1024
STDERR_CAP_BYTES = 16 * 1024

# Finding marker the AI script can emit to declare structured findings.
FINDING_MARKER_RE = re.compile(r"^AEGISPT_FINDING:\s*(\{.*\})\s*$")


SCOPE_GUARD_PREAMBLE = r'''# === AegisPT scope guard preamble (auto-injected) ===
# Refuses any httpx request whose host is not in the run's scope
# allowlist. The picker MUST treat all URLs as allowlist-checked.
import os as _aegispt_os
import json as _aegispt_json
import sys as _aegispt_sys
from urllib.parse import urlparse as _aegispt_urlparse

try:
    import httpx as _aegispt_httpx
except ImportError:
    _aegispt_httpx = None

_AEGISPT_ALLOWLIST = _aegispt_json.loads(_aegispt_os.environ.get("AEGISPT_SCOPE_URLS_JSON", "[]"))
_AEGISPT_ALLOW_HOSTS = set()
_AEGISPT_ALLOW_PORTS = {}
for _u in _AEGISPT_ALLOWLIST:
    _p = _aegispt_urlparse(_u)
    if _p.hostname:
        _AEGISPT_ALLOW_HOSTS.add(_p.hostname.lower())
        if _p.port is not None:
            _AEGISPT_ALLOW_PORTS.setdefault(_p.hostname.lower(), set()).add(_p.port)

def _aegispt_check_url(url):
    p = _aegispt_urlparse(str(url))
    h = (p.hostname or "").lower()
    if not h:
        raise PermissionError(f"AegisPT scope guard: URL has no hostname: {url!r}")
    if h not in _AEGISPT_ALLOW_HOSTS:
        raise PermissionError(
            f"AegisPT scope guard: host {h!r} not in scope allowlist "
            f"{sorted(_AEGISPT_ALLOW_HOSTS)} (url={url!r})"
        )
    allowed_ports = _AEGISPT_ALLOW_PORTS.get(h)
    if allowed_ports and p.port is not None and p.port not in allowed_ports:
        raise PermissionError(
            f"AegisPT scope guard: port {p.port} not in scope for host {h!r} "
            f"(allowed={sorted(allowed_ports)})"
        )

if _aegispt_httpx is not None:
    _aegispt_original_send = _aegispt_httpx.Client.send
    _aegispt_original_async_send = _aegispt_httpx.AsyncClient.send

    def _aegispt_guarded_send(self, request, *args, **kwargs):
        _aegispt_check_url(str(request.url))
        return _aegispt_original_send(self, request, *args, **kwargs)

    async def _aegispt_guarded_async_send(self, request, *args, **kwargs):
        _aegispt_check_url(str(request.url))
        return await _aegispt_original_async_send(self, request, *args, **kwargs)

    _aegispt_httpx.Client.send = _aegispt_guarded_send  # type: ignore
    _aegispt_httpx.AsyncClient.send = _aegispt_guarded_async_send  # type: ignore

# Convenience helper for the AI: emit a finding marker.
# Operator-flagged 2026-05-27 (smoke 50 XBEN-009): Gemini called
# aegispt_emit_finding(evidence=...) instead of evidence_excerpt=...
# Strict kwarg-only raised TypeError BEFORE the AEGISPT_FINDING line
# printed, so even a correct exploit was thrown away. The contract
# is now typo-tolerant: any unknown kwarg is bucketed into
# evidence_excerpt (string-ish) or evidence_url (URL-ish), and the
# printf happens FIRST so a downstream signature error can never eat
# the proof.
def aegispt_emit_finding(*args, title="", severity="info", summary="",
                          evidence_url=None, evidence_excerpt="",
                          **extra_kwargs):
    # Accept positional args defensively: (title, severity, ...) or
    # just (title,). Map them into the kwarg slots.
    if args:
        if len(args) >= 1 and not title:
            title = args[0]
        if len(args) >= 2 and severity == "info":
            severity = args[1]
        if len(args) >= 3 and not summary:
            summary = args[2]
    # Bucket any unknown kwarg into the matching slot.
    for key, val in list(extra_kwargs.items()):
        key_l = str(key).lower()
        if key_l in {"evidence", "proof", "excerpt", "body", "content"}:
            # URL-shaped value → evidence_url, else evidence_excerpt.
            val_s = str(val) if val is not None else ""
            if val_s.startswith(("http://", "https://")) and " " not in val_s:
                evidence_url = evidence_url or val_s
            else:
                evidence_excerpt = evidence_excerpt or val_s
        elif key_l in {"url", "endpoint", "link", "uri"}:
            evidence_url = evidence_url or (str(val) if val else None)
        elif key_l in {"desc", "description", "notes", "detail"}:
            summary = summary or str(val or "")
        elif key_l in {"sev", "severity_level"}:
            severity = severity if severity != "info" else str(val or severity)
        elif key_l in {"name", "headline", "label"}:
            title = title or str(val or "")
        # silently ignore truly unknown keys — never raise.
    sev = str(severity or "info").lower()
    if sev not in {"critical", "high", "medium", "low", "info"}:
        sev = "info"
    payload = {
        "title": str(title)[:200],
        "severity": sev,
        "summary": str(summary)[:1000],
        "evidence_url": str(evidence_url) if evidence_url else None,
        "evidence_excerpt": str(evidence_excerpt)[:2000],
    }
    # printf FIRST so any subsequent error in serialization or stdout
    # encoding cannot eat the proof of finding.
    print("AEGISPT_FINDING:", _aegispt_json.dumps(payload), flush=True)

# === end preamble ===
'''


class ScopeViolationError(RuntimeError):
    """Raised when the AI script attempted out-of-scope traffic."""


def _scope_allowlist_urls(scope_allowlist: dict[str, Any] | None) -> list[str]:
    if not isinstance(scope_allowlist, dict):
        return []
    urls = scope_allowlist.get("urls") or []
    if isinstance(urls, str):
        urls = [urls]
    return [str(u) for u in urls if u]


_FLAG_LITERAL_RE = re.compile(
    r"(flag\{[^}\r\n]{1,200}\}|xbow-[a-f0-9]{16,128}|FLAG\{[^}\r\n]{1,200}\}|ctf\{[^}\r\n]{1,200}\})",
    re.IGNORECASE,
)
_FALLBACK_JSON_FLAG_RE = re.compile(
    r'"FLAG"\s*:\s*"([^"\r\n]{4,200})"',
    re.IGNORECASE,
)


def _parse_findings_from_stdout(stdout: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for raw_line in stdout.splitlines():
        match = FINDING_MARKER_RE.match(raw_line.strip())
        if not match:
            continue
        try:
            payload = json.loads(match.group(1))
        except json.JSONDecodeError:
            continue
        if not isinstance(payload, dict):
            continue
        findings.append({
            "title": str(payload.get("title") or "Code-exec finding"),
            "severity": str(payload.get("severity") or "info").lower(),
            "summary": str(payload.get("summary") or ""),
            "evidence_url": payload.get("evidence_url"),
            "evidence_excerpt": str(payload.get("evidence_excerpt") or "")[:2000],
            "type": "code_exec_attack_finding",
            "methodology_tags": ["code_exec_attack"],
        })
    # FALLBACK: when no AEGISPT_FINDING marker was emitted but the stdout
    # contains a flag-pattern literal anyway, treat it as a critical
    # finding. This catches the common failure mode where the AI script
    # called `print(...)` instead of using `aegispt_emit_finding(...)`,
    # OR raised NameError on the helper and fell through to print().
    if not findings:
        for raw_line in stdout.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            for pat, label in (
                (_FLAG_LITERAL_RE, "flag-literal-in-stdout"),
                (_FALLBACK_JSON_FLAG_RE, "json-FLAG-key-in-stdout"),
            ):
                m = pat.search(line)
                if not m:
                    continue
                excerpt = m.group(0) if pat is _FLAG_LITERAL_RE else m.group(1)
                findings.append({
                    "title": f"Flag literal recovered from script stdout ({label})",
                    "severity": "critical",
                    "summary": (
                        "code-exec-attack runner detected a flag-pattern literal "
                        "in script stdout without an AEGISPT_FINDING marker. "
                        "Treating as critical finding (PROOF_EXEC_STDOUT_FLAG_FALLBACK)."
                    ),
                    "evidence_url": None,
                    "evidence_excerpt": (excerpt or "")[:2000],
                    "type": "code_exec_attack_finding",
                    "methodology_tags": ["code_exec_attack", "stdout_flag_fallback"],
                })
                return findings  # one fallback finding is enough
    return findings


def execute_code_exec_attack(
    targets: list[str],
    *,
    script: str,
    scope_allowlist: dict[str, Any] | None = None,
    timeout_seconds: float = 60.0,
    python_executable: str | None = None,
) -> RunnerExecution:
    """Run an AI-emitted Python script with httpx scope-guard preamble."""
    if not script.strip():
        return RunnerExecution(
            tool="code-exec-attack",
            exit_code=2,
            stdout="",
            stderr="empty script — refusing to run",
            artifacts=[],
            metadata={"skipped": True, "skip_reason": "empty_script"},
        )

    allowlist_urls = _scope_allowlist_urls(scope_allowlist)
    if not allowlist_urls:
        return RunnerExecution(
            tool="code-exec-attack",
            exit_code=78,  # EX_CONFIG — runner unavailable: no scope to enforce
            stdout="",
            stderr=(
                "code-exec-attack refuses to run with empty scope allowlist — "
                "would have no way to enforce out-of-scope rejection"
            ),
            artifacts=[],
            metadata={"skipped": True, "skip_reason": "empty_scope_allowlist"},
        )

    # Assemble the full script: preamble + AI body.
    full_script = SCOPE_GUARD_PREAMBLE + "\n\n# === AI-emitted body ===\n" + script

    # Operator-flagged 2026-05-27 (smoke 52 / XBEN-020): syntactically
    # broken Python (unterminated string literal) was dispatched, ran,
    # exited 1, AND THEN A BYTE-IDENTICAL COPY was dispatched 12 min
    # later because the specialist re-emitted the same broken script.
    # Compile-check BEFORE spawning the subprocess: a SyntaxError now
    # short-circuits with a structured early-fail that triggers
    # script_critic on the next orchestrator iteration, and surfaces
    # the SyntaxError line so the next emit is informed.
    try:
        compile(full_script, "<aegispt-exec>", "exec")
    except SyntaxError as _syn_exc:
        logger.warning(
            "PROOF_EXEC_CODE_EXEC_SYNTAX_REJECTED_2026052712 "
            "rejected pre-execute: %s (line %s offset %s)",
            _syn_exc.msg, _syn_exc.lineno, _syn_exc.offset,
        )
        return RunnerExecution(
            tool="code-exec-attack",
            exit_code=2,  # POSIX "Misuse of shell builtins"; chosen distinct from sandbox-exec exit codes
            stdout=json.dumps({
                "tool": "code-exec-attack",
                "script_length": len(script),
                "scope_allowlist": allowlist_urls,
                "exit_code": 2,
                "duration_seconds": 0.0,
                "timed_out": False,
                "scope_violation_detected": False,
                "findings": [],
                "syntax_error": {
                    "message": str(_syn_exc.msg),
                    "lineno": _syn_exc.lineno,
                    "offset": _syn_exc.offset,
                    "text": _syn_exc.text[:200] if _syn_exc.text else None,
                },
                "rejected_pre_execute": True,
            }),
            stderr=(
                f"AEGISPT_PRE_EXECUTE_SYNTAX_ERROR: {_syn_exc.msg} at line "
                f"{_syn_exc.lineno} offset {_syn_exc.offset}. Script was NOT "
                f"executed. Critic should rewrite — do not re-dispatch verbatim."
            ),
            artifacts=[],
            metadata={
                "status": "rejected_pre_execute",
                "rejected_pre_execute": True,
                "rejection_reason": "syntax_error",
                "runner_digest": "workers.code_exec_attack.runner:v1",
                "syntax_error_lineno": _syn_exc.lineno,
                "syntax_error_msg": str(_syn_exc.msg),
            },
        )

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".py", encoding="utf-8", delete=False
    ) as tmp:
        tmp.write(full_script)
        tmp_path = Path(tmp.name)

    python_exe = python_executable or sys.executable
    env = dict(os.environ)
    env["AEGISPT_SCOPE_URLS_JSON"] = json.dumps(allowlist_urls)
    # Strip operator-private env that the AI script must not see.
    for sensitive in (
        "ANTHROPIC_API_KEY",
        "XAI_API_KEY",
        "OPENAI_API_KEY",
        "AEGISPT_DB_KEY",
        "DEPLOYMENT_SECRET_ENCRYPTION_KEY",
        "LOCAL_SECRET_ENCRYPTION_KEY",
    ):
        env.pop(sensitive, None)

    logger.info(
        "code-exec-attack: running %d-byte script against scope %s",
        len(script), allowlist_urls,
    )

    started = time.time()
    timed_out = False
    try:
        proc = subprocess.run(  # noqa: S603 — argv built from trusted python exe
            [python_exe, str(tmp_path)],
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            env=env,
            check=False,
        )
        exit_code = proc.returncode
        stdout = proc.stdout
        stderr = proc.stderr
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        exit_code = 124
        stdout = (exc.stdout.decode("utf-8", errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or ""))
        stderr = (exc.stderr.decode("utf-8", errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or ""))
    finally:
        try:
            tmp_path.unlink(missing_ok=True)
        except Exception:  # noqa: BLE001
            pass

    elapsed = round(time.time() - started, 3)
    stdout_capped = stdout[:STDOUT_CAP_BYTES]
    stderr_capped = stderr[:STDERR_CAP_BYTES]

    findings = _parse_findings_from_stdout(stdout_capped)

    # If the script raised a PermissionError from the scope guard, the
    # process exit will be non-zero AND stderr will mention "AegisPT scope
    # guard". Surface that distinctly so callers can audit.
    scope_violation = "AegisPT scope guard" in stderr_capped

    # Embed the actual script stdout/stderr (capped) in the summary payload.
    # Before 2026-05-28 the payload carried only metadata (findings,
    # stdout_truncated_bytes) — the real observations the script printed lived
    # ONLY in the separate exploit_output artifact, which the picker/critic
    # never loaded. So the script-writing LLM could not see what its own
    # script observed and kept repeating the same mistake (empirically:
    # XBEN-009 SSTI scripts got HTTP 400 DisallowedHost on every payload —
    # the "set Host: localhost" signal was right there in stdout but invisible
    # to the next script-generation call). Surfacing it here closes the
    # observation -> next-decision feedback loop for EVERY consumer that reads
    # tool_executions.stdout_text (script_critic, cpg-seeded-cea, etc.) — pure
    # observability, no heuristic recipes; the LLM does the reasoning.
    _SCRIPT_OUTPUT_FEEDBACK_CAP = 8000
    payload = {
        "tool": "code-exec-attack",
        "script_length": len(script),
        "scope_allowlist": allowlist_urls,
        "exit_code": exit_code,
        "duration_seconds": elapsed,
        "timed_out": timed_out,
        "scope_violation_detected": scope_violation,
        "findings": findings,
        "stdout_truncated_bytes": min(len(stdout), STDOUT_CAP_BYTES),
        "script_stdout": stdout_capped[:_SCRIPT_OUTPUT_FEEDBACK_CAP],
        "script_stderr": stderr_capped[:2000],
    }

    artifacts = [
        EvidenceArtifact(
            name=CODE_EXEC_ATTACK_ARTIFACT_NAME,
            content_type="text/x-python",
            data=script.encode("utf-8"),
            kind="exploit_script",
        ),
        EvidenceArtifact(
            name=CODE_EXEC_ATTACK_STDOUT_ARTIFACT_NAME,
            content_type="text/plain",
            data=stdout_capped.encode("utf-8"),
            kind="exploit_output",
        ),
    ]

    return RunnerExecution(
        tool="code-exec-attack",
        exit_code=0 if exit_code == 0 else (exit_code if exit_code else 1),
        stdout=json.dumps(payload),
        stderr=stderr_capped,
        artifacts=artifacts,
        metadata={
            "tool_version": "code-exec-attack:v1-phase-b-2026-05-22",
            "runner_digest": "workers.code_exec_attack.runner:v1",
        },
    )
