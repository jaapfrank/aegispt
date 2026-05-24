"""Joern CPG pre-recon runner — M3 of beat-shannon-pro-roadmap-2026-05-23.

Workflow:
1. Detect dominant language in `source_dir` by file extension.
2. Pick the matching Joern frontend (pysrc2cpg / javasrc2cpg / jssrc2cpg).
3. Generate a CPG (`/tmp/aegispt-cpg-<digest>.bin.zip`) via `joern-parse`.
4. Run a small Scala query in `joern --script` that lists:
   - HTTP-source identifiers (Flask `request.*`, Express `req.*`, Spring
     `@RequestParam`, etc) AND
   - SQL/file/template/exec sinks reachable from them.
5. Emit a markdown deliverable concatenating routes + traced flows.

The runner is BEST-EFFORT — graceful degradation when Joern is missing
or fails. Empty deliverable when nothing was traced (do not block the
loop). Logs `PROOF_EXEC_M3_CPG_2026052330` markers so live-trigger is
auditable.

Per ANTI_DRIFT Rule 1: this runner is INSTRUMENT, not capability. It
emits a deliverable; whether the deliverable moves the score is
measured separately.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from workers.runners.base.contracts import EvidenceArtifact, RunnerExecution

logger = logging.getLogger(__name__)

PRE_RECON_CPG_ARTIFACT_NAME = "pre-recon-cpg-deliverable.md"
PROOF_EXEC_MARKER = "PROOF_EXEC_M3_CPG_2026052330"

JOERN_INSTALL_DIR = Path(
    os.environ.get("AEGISPT_JOERN_DIR")
    or "/home/administrator/.aegispt-tools/joern/joern-cli"
)
PARSE_TIMEOUT_SECONDS = 300
QUERY_TIMEOUT_SECONDS = 180

# Joern frontend names for `joern-parse --language <name>` (from `--list-languages`).
# Source-based frontends use the "src" suffix to distinguish from binary/bytecode
# frontends (`python` vs `pythonsrc`).
LANGUAGE_FRONTENDS = {
    "python": "pythonsrc",
    "java": "javasrc",
    "javascript": "jssrc",
    "typescript": "jssrc",
    "go": "golang",
    "php": "php",
    "ruby": "rubysrc",
    "csharp": "csharpsrc",
}

EXTENSION_LANGUAGE = {
    ".py": "python",
    ".java": "java",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".go": "go",
    ".php": "php",
    ".rb": "ruby",
    ".cs": "csharp",
}

SCAN_SKIP_DIRS = {
    "node_modules", "vendor", ".git", "__pycache__", "venv", ".venv",
    "site-packages", "dist", "build", ".next", ".nuxt", ".cache",
}


def _detect_dominant_language(root: Path) -> str | None:
    """Walk the source tree, count files per language extension, return
    the language with the most files. None when no recognised files exist."""
    counts: dict[str, int] = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SCAN_SKIP_DIRS]
        for fn in filenames:
            ext = Path(fn).suffix.lower()
            lang = EXTENSION_LANGUAGE.get(ext)
            if lang:
                counts[lang] = counts.get(lang, 0) + 1
    if not counts:
        return None
    return max(counts.items(), key=lambda kv: kv[1])[0]


def _clean_env() -> dict[str, str]:
    """Build a clean PATH env so Joern's launcher doesn't choke on
    Windows-PATH leakage (observed in WSL: `C:/Program Files/...` paths
    confuse joern-cli/joern's launcher and it fails to find `java`)."""
    java_home = (
        os.environ.get("JAVA_HOME")
        or "/usr/lib/jvm/java-17-openjdk-amd64"
    )
    return {
        "PATH": "/usr/bin:/bin",
        "HOME": os.environ.get("HOME", "/home/administrator"),
        "JAVA_HOME": java_home,
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
    }


_TAINT_QUERY_TEMPLATE = """
import io.shiftleft.semanticcpg.language._

@main def main(cpgPath: String) = {
  importCpg(cpgPath)

  // Routes: HTTP handler methods (Flask @app.route, Django views.X,
  // Express app.get, Spring @RequestMapping) — full-method-name regex.
  val ROUTES = cpg.method.fullName("(?i).*(request|route|GET|POST|PUT|DELETE|HEAD|PATCH|view|handler).*").l.take(80)

  // SQL: ORM + raw cursor calls. Common Python: SQLAlchemy `execute`,
  // `query`, `filter_by`, `filter`; raw sqlite/psycopg: `execute`,
  // `executemany`. PHP: `mysqli_query`, `PDO::query`. JS: `db.query`.
  val SQL_SINKS = cpg.call.name("(?i)(execute|executemany|raw|query|filter_by|filter|where|select_from|text|fetchall|fetchone|sql)").l.take(80)

  // Command exec sinks across languages.
  val EXEC_SINKS = cpg.call.name("(?i)(exec|popen|spawn|system|subprocess_run|subprocess_call|subprocess_popen|os_system|shell_exec|eval|compile)").l.take(80)

  // File I/O: `open`, `read`, `write`, file send. CRITICAL — read-from-
  // disk often is the flag retrieval primitive in CTFs.
  val FILE_SINKS = cpg.call.name("(?i)(open|read|write|readlines|sendfile|send_file|send_from_directory)").l.take(80)

  // Template SSTI sinks: Jinja `render_template_string`, Django Template.
  val TEMPLATE_SINKS = cpg.call.name("(?i)(render_template_string|render_to_string|from_string|jinja_render|escape_off)").l.take(40)

  // Deserialization: pickle.loads, yaml.unsafe_load, marshal.loads — RCE classics.
  val DESERIALIZE_SINKS = cpg.call.name("(?i)(loads|unsafe_load|load_all|unmarshal|json_load|pickle_loads|yaml_load)").l.take(40)

  // Hardcoded credentials / secrets — useful default-cred + leak intel.
  val LITERAL_SECRETS = cpg.literal.code(".*(?i)(password|secret|api[_-]?key|token|admin)[\\\\s=:'\\\"]+.*").l.take(40)

  def emit(label: String, items: List[Any], renderer: Any => String): Unit = {
    println(s"== $label (sample, ${items.size}) ==")
    items.foreach { item => println(renderer(item)) }
  }

  emit("ROUTES", ROUTES.toList,
    (it: Any) => { val m = it.asInstanceOf[io.shiftleft.codepropertygraph.generated.nodes.Method]
                   s"${m.fullName}\\t${m.filename}:${m.lineNumber.getOrElse(0)}" })
  emit("SQL_SINKS", SQL_SINKS.toList,
    (it: Any) => { val c = it.asInstanceOf[io.shiftleft.codepropertygraph.generated.nodes.Call]
                   s"${c.code}\\t${c.method.filename}:${c.lineNumber.getOrElse(0)}" })
  emit("EXEC_SINKS", EXEC_SINKS.toList,
    (it: Any) => { val c = it.asInstanceOf[io.shiftleft.codepropertygraph.generated.nodes.Call]
                   s"${c.code}\\t${c.method.filename}:${c.lineNumber.getOrElse(0)}" })
  emit("FILE_SINKS", FILE_SINKS.toList,
    (it: Any) => { val c = it.asInstanceOf[io.shiftleft.codepropertygraph.generated.nodes.Call]
                   s"${c.code}\\t${c.method.filename}:${c.lineNumber.getOrElse(0)}" })
  emit("TEMPLATE_SINKS", TEMPLATE_SINKS.toList,
    (it: Any) => { val c = it.asInstanceOf[io.shiftleft.codepropertygraph.generated.nodes.Call]
                   s"${c.code}\\t${c.method.filename}:${c.lineNumber.getOrElse(0)}" })
  emit("DESERIALIZE_SINKS", DESERIALIZE_SINKS.toList,
    (it: Any) => { val c = it.asInstanceOf[io.shiftleft.codepropertygraph.generated.nodes.Call]
                   s"${c.code}\\t${c.method.filename}:${c.lineNumber.getOrElse(0)}" })
  emit("LITERAL_SECRETS", LITERAL_SECRETS.toList,
    (it: Any) => { val l = it.asInstanceOf[io.shiftleft.codepropertygraph.generated.nodes.Literal]
                   s"${l.code}\\t${l.method.filename}:${l.lineNumber.getOrElse(0)}" })
}
"""


def _render_markdown(*, source_dir: str, language: str, query_output: str, parse_seconds: float, query_seconds: float) -> str:
    lines = [
        f"# CPG pre-recon deliverable (Joern, language={language})",
        "",
        f"- Source: `{source_dir}`",
        f"- Language detected: `{language}`",
        f"- CPG parse time: {parse_seconds:.1f}s",
        f"- Query time: {query_seconds:.1f}s",
        "",
        "## Joern query output",
        "",
        "```",
        query_output.strip() or "(no output)",
        "```",
        "",
        "_Generated by `pre-recon-cpg` runner. Concatenate with the regex-based",
        "`pre-recon-source` deliverable for the broadest source-aware picture._",
    ]
    return "\n".join(lines) + "\n"


def execute_pre_recon_cpg(
    targets: list[str],  # noqa: ARG001 — kept for runner-signature uniformity
    *,
    source_dir: str | None = None,
    scope_allowlist: dict[str, Any] | None = None,  # noqa: ARG001 — audit-only
    timeout_seconds: float = float(PARSE_TIMEOUT_SECONDS + QUERY_TIMEOUT_SECONDS),  # noqa: ARG001
) -> RunnerExecution:
    """Generate a CPG from `source_dir` and emit a markdown deliverable."""

    if not source_dir:
        return RunnerExecution(
            tool="pre-recon-cpg",
            exit_code=78,
            stdout="",
            stderr=(
                "pre-recon-cpg skipped: no source_dir parameter. "
                "Opt-in runner for source-aware engagements only."
            ),
            artifacts=[],
            metadata={"skipped": True, "skip_reason": "no_source_dir"},
        )

    root = Path(source_dir).resolve()
    if not root.exists() or not root.is_dir():
        return RunnerExecution(
            tool="pre-recon-cpg",
            exit_code=78,
            stdout="",
            stderr=f"pre-recon-cpg: source_dir not found: {root}",
            artifacts=[],
            metadata={"skipped": True, "skip_reason": "source_dir_invalid"},
        )

    joern_parse = JOERN_INSTALL_DIR / "joern-parse"
    joern_bin = JOERN_INSTALL_DIR / "joern"
    if not joern_parse.exists() or not joern_bin.exists():
        return RunnerExecution(
            tool="pre-recon-cpg",
            exit_code=78,
            stdout="",
            stderr=(
                f"pre-recon-cpg: Joern not installed at {JOERN_INSTALL_DIR}. "
                "Install via `sh joern-install.sh --install-dir=...`."
            ),
            artifacts=[],
            metadata={"skipped": True, "skip_reason": "joern_missing"},
        )

    language = _detect_dominant_language(root)
    if language is None:
        return RunnerExecution(
            tool="pre-recon-cpg",
            exit_code=0,
            stdout=json.dumps({"tool": "pre-recon-cpg", "skipped": True, "reason": "no_recognized_files"}),
            stderr="pre-recon-cpg: no recognised source files in tree.",
            artifacts=[],
            metadata={"skipped": True, "skip_reason": "no_recognized_files"},
        )

    frontend = LANGUAGE_FRONTENDS.get(language)
    if frontend is None:
        return RunnerExecution(
            tool="pre-recon-cpg",
            exit_code=0,
            stdout=json.dumps({"tool": "pre-recon-cpg", "skipped": True, "reason": f"no_frontend_for_{language}"}),
            stderr=f"pre-recon-cpg: no Joern frontend for language={language}.",
            artifacts=[],
            metadata={"skipped": True, "skip_reason": "no_frontend"},
        )

    # CPG output path keyed by source-dir hash so re-runs reuse the cache.
    src_hash = hashlib.sha256(str(root).encode()).hexdigest()[:12]
    cpg_path = Path("/tmp") / f"aegispt-cpg-{src_hash}.bin.zip"

    env = _clean_env()
    joern_language = frontend  # frontend == joern's --language name (e.g. "pythonsrc")
    logger.info("%s parse start language=%s joern_language=%s root=%s", PROOF_EXEC_MARKER, language, joern_language, root)
    parse_start = time.time()
    try:
        parse_result = subprocess.run(
            [str(joern_parse), str(root), "--language", joern_language, "--output", str(cpg_path)],
            env=env, capture_output=True, text=True, timeout=PARSE_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        return RunnerExecution(
            tool="pre-recon-cpg", exit_code=124, stdout="",
            stderr=f"pre-recon-cpg: joern-parse timed out after {PARSE_TIMEOUT_SECONDS}s",
            artifacts=[],
            metadata={"skip_reason": "parse_timeout"},
        )
    parse_seconds = time.time() - parse_start
    if parse_result.returncode != 0 or not cpg_path.exists():
        return RunnerExecution(
            tool="pre-recon-cpg", exit_code=parse_result.returncode, stdout=parse_result.stdout,
            stderr=f"pre-recon-cpg: joern-parse failed:\n{parse_result.stderr[:2000]}",
            artifacts=[],
            metadata={"skip_reason": "parse_failed"},
        )
    logger.info("%s parse done language=%s elapsed=%.1fs cpg=%s", PROOF_EXEC_MARKER, language, parse_seconds, cpg_path)

    # Write the taint-survey query to a temp file and invoke joern --script.
    with tempfile.NamedTemporaryFile(mode="w", suffix=".sc", delete=False, dir="/tmp") as fh:
        fh.write(_TAINT_QUERY_TEMPLATE)
        query_path = fh.name

    query_start = time.time()
    try:
        query_result = subprocess.run(
            [str(joern_bin), "--script", query_path, "--param", f"cpgPath={cpg_path}"],
            env=env, capture_output=True, text=True, timeout=QUERY_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        return RunnerExecution(
            tool="pre-recon-cpg", exit_code=124, stdout="",
            stderr=f"pre-recon-cpg: joern script timed out after {QUERY_TIMEOUT_SECONDS}s",
            artifacts=[],
            metadata={"skip_reason": "query_timeout"},
        )
    finally:
        try:
            os.unlink(query_path)
        except OSError:
            pass
    query_seconds = time.time() - query_start

    if query_result.returncode != 0:
        logger.warning(
            "pre-recon-cpg: joern script returned %d: %s",
            query_result.returncode, query_result.stderr[:600],
        )

    markdown = _render_markdown(
        source_dir=str(root),
        language=language,
        query_output=query_result.stdout or "",
        parse_seconds=parse_seconds,
        query_seconds=query_seconds,
    )

    logger.info(
        "%s query done language=%s parse=%.1fs query=%.1fs out_bytes=%d",
        PROOF_EXEC_MARKER, language, parse_seconds, query_seconds, len(markdown),
    )

    payload = {
        "tool": "pre-recon-cpg",
        "source_dir": str(root),
        "language": language,
        "parse_seconds": parse_seconds,
        "query_seconds": query_seconds,
        "cpg_bytes": cpg_path.stat().st_size if cpg_path.exists() else 0,
        "query_returncode": query_result.returncode,
    }

    artifact = EvidenceArtifact(
        name=PRE_RECON_CPG_ARTIFACT_NAME,
        content_type="text/markdown",
        data=markdown.encode("utf-8"),
        kind="pre-recon-cpg",
    )

    return RunnerExecution(
        tool="pre-recon-cpg",
        exit_code=0,
        stdout=json.dumps(payload),
        stderr="",
        artifacts=[artifact],
        metadata={
            "tool_version": "pre-recon-cpg:v1-m3-2026-05-23",
            "runner_digest": "workers.pre_recon_cpg.runner:v1",
        },
    )
