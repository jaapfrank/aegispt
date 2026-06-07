"""Source-backed XBEN triage for unknown rows in the D6 backlog.

The output intentionally avoids source snippets. It records rule IDs, relative
file paths, and line numbers so labels are evidence-linked without copying
benchmark canaries or challenge code into training artifacts.
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_BACKLOG = (
    REPO_ROOT
    / "codex"
    / "results"
    / "training"
    / "xben-triage-backlog-20260607"
    / "aegispt_xben_triage_backlog_iter10.jsonl"
)
DEFAULT_SOURCE_ROOT = Path("/home/administrator/xbow-validation-benchmarks/benchmarks")
DEFAULT_OUT_DIR = REPO_ROOT / "codex" / "results" / "training" / "xben-source-triage-20260607"
DEFAULT_PREFIX = "aegispt_xben_source_triage_iter10"
DEFAULT_EXISTING_TRIAGE = DEFAULT_OUT_DIR / f"{DEFAULT_PREFIX}.jsonl"

TEXT_SUFFIXES = {
    ".conf",
    ".go",
    ".html",
    ".java",
    ".js",
    ".json",
    ".jsp",
    ".php",
    ".py",
    ".rb",
    ".sql",
    ".ts",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
}
SKIP_DIRS = {"__pycache__", ".git", "node_modules", "vendor"}


@dataclass(frozen=True)
class Rule:
    rule_id: str
    vuln_class: str
    chain_depth: int
    coverage_bucket: str
    patterns: tuple[str, ...]
    min_hits: int = 1
    priority: int = 50
    file_suffixes: tuple[str, ...] = ()


RULES = (
    Rule(
        "headless_browser_bot",
        "headless_xss_ssrf",
        4,
        "headless_xss_ssrf",
        ("phantomjs", "puppeteer", "selenium", "webpage.create", "check.js"),
        priority=100,
    ),
    Rule(
        "php_sql_string_interpolation",
        "auth_gated_injection",
        3,
        "auth_logic_session_forgery",
        (
            r"re:select\s+.+\$_(post|get|request)",
            r"re:where\s+.+\$_(post|get|request)",
            r"re:mysqli?_query\s*\(",
        ),
        min_hits=2,
        priority=92,
        file_suffixes=(".php",),
    ),
    Rule(
        "python_sql_string_interpolation",
        "auth_gated_injection",
        3,
        "auth_logic_session_forgery",
        (
            r"re:select\s+.+(request\.|args|get_json|form)",
            r"re:execute\s*\([^)]*%",
            r"re:execute\s*\([^)]*format",
        ),
        min_hits=2,
        priority=90,
        file_suffixes=(".py",),
    ),
    Rule(
        "template_render_user_input",
        "ssti",
        1,
        "ssti_template_context_pivot",
        ("render_template_string", "jinja2.template", "template(", "twig", "nunjucks", "ejs.render"),
        priority=88,
        file_suffixes=(".js", ".jsp", ".php", ".py", ".rb", ".ts"),
    ),
    Rule(
        "xxe_parser_unsafe_entities",
        "xxe",
        2,
        "xxe_document_parser_pivot",
        ("resolve_entities=true", "noent", "load_dtd=true", "documentbuilderfactory", "external-general-entities"),
        priority=88,
        file_suffixes=(".java", ".jsp", ".php", ".py", ".xml"),
    ),
    Rule(
        "server_side_fetch_user_url",
        "ssrf",
        2,
        "ssrf_internal_endpoint_recovery",
        ("requests.get", "requests.post", "urlopen", "curl_exec", "http.get", "axios.get"),
        priority=82,
        file_suffixes=(".go", ".java", ".js", ".php", ".py", ".ts"),
    ),
    Rule(
        "command_exec_sink",
        "command_injection",
        1,
        "command_injection",
        ("os.system", "subprocess.", "shell_exec", "passthru", "child_process.exec", "popen("),
        priority=78,
        file_suffixes=(".go", ".java", ".js", ".php", ".py", ".ts"),
    ),
    Rule(
        "unsafe_deserialization",
        "unsafe_deserialization",
        1,
        "unsafe_deserialization",
        ("pickle.loads", "yaml.load", "unserialize", "objectinputstream", "readobject"),
        priority=78,
        file_suffixes=(".java", ".jsp", ".php", ".py", ".rb"),
    ),
    Rule(
        "jwt_or_session_secret",
        "jwt_or_file_read_auth_logic",
        2,
        "auth_logic_session_forgery",
        ("jwt.decode", "secret_key", "session_secret", "app.secret_key", "flask_session"),
        priority=72,
        file_suffixes=(".js", ".php", ".py", ".ts"),
    ),
    Rule(
        "path_traversal_file_read",
        "path_traversal_file_read",
        2,
        "path_traversal_file_read",
        (
            r"re:send_file\s*\([^)]*(request|args|form|get_json|\$_)",
            r"re:send_from_directory\s*\([^)]*(request|args|form|get_json|\$_)",
            r"re:readfile\s*\([^)]*\$_(get|post|request)",
            r"re:include\s*\([^)]*\$_(get|post|request)",
            r"re:file_get_contents\s*\([^)]*\$_(get|post|request)",
            "open(request",
            "open(os.path.join",
        ),
        priority=70,
        file_suffixes=(".js", ".php", ".py", ".ts"),
    ),
    Rule(
        "nosql_query_object",
        "nosql_filter_bypass_chain",
        3,
        "nosql_filter_bypass_chain",
        (
            "find_one(request",
            "findone(req",
            "findone(request",
            "req.body",
            "request.json",
            "get_json",
            "$where",
        ),
        min_hits=2,
        priority=68,
        file_suffixes=(".js", ".py", ".ts"),
    ),
)


def read_backlog(path: Path = DEFAULT_BACKLOG) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def source_triage_ids(backlog_rows: list[dict[str, Any]]) -> list[str]:
    return [
        str(row["xben_id"])
        for row in backlog_rows
        if row.get("lane") == "source_triage_required"
    ]


def existing_triage_ids(path: Path) -> list[str]:
    if not path.exists():
        return []
    ids: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        xben_id = row.get("xben_id")
        if xben_id:
            ids.append(str(xben_id))
    return ids


def ids_to_triage(
    backlog_rows: list[dict[str, Any]],
    *,
    backlog_path: Path,
    existing_triage_path: Path | None,
) -> list[str]:
    ids = set(source_triage_ids(backlog_rows))
    if existing_triage_path is None and backlog_path == DEFAULT_BACKLOG:
        existing_triage_path = DEFAULT_EXISTING_TRIAGE
    if existing_triage_path is not None:
        ids.update(existing_triage_ids(existing_triage_path))
    return sorted(ids)


def challenge_dir(source_root: Path, xben_id: str) -> Path:
    return source_root / f"{xben_id}-24"


def iter_text_files(root: Path) -> list[Path]:
    if not root.exists():
        return []
    files: list[Path] = []
    for path in root.rglob("*"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if not path.is_file():
            continue
        if path.suffix.lower() not in TEXT_SUFFIXES and path.name not in {"Dockerfile", "Makefile"}:
            continue
        if path.name.endswith(".min.js") or path.name in {"package-lock.json", "yarn.lock"}:
            continue
        if path.name == "benchmark.json":
            continue
        files.append(path)
    return sorted(files)


def pattern_matches(pattern: str, lowered_line: str) -> bool:
    if pattern.startswith("re:"):
        return re.search(pattern[3:], lowered_line, flags=re.IGNORECASE) is not None
    return pattern.lower() in lowered_line


def scan_file(path: Path, root: Path) -> list[dict[str, Any]]:
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return []
    matches: list[dict[str, Any]] = []
    for line_no, line in enumerate(lines, start=1):
        lowered = line.lower()
        for rule in RULES:
            if rule.file_suffixes and path.suffix.lower() not in rule.file_suffixes:
                continue
            for pattern in rule.patterns:
                if pattern_matches(pattern, lowered):
                    matches.append(
                        {
                            "coverage_bucket": rule.coverage_bucket,
                            "file": str(path.relative_to(root)),
                            "line": line_no,
                            "rule_id": rule.rule_id,
                            "vuln_class": rule.vuln_class,
                        }
                    )
                    break
    return matches


def classify(matches: list[dict[str, Any]]) -> dict[str, Any]:
    by_rule = Counter(match["rule_id"] for match in matches)
    candidates: list[tuple[int, Rule]] = []
    for rule in RULES:
        if by_rule.get(rule.rule_id, 0) >= rule.min_hits:
            candidates.append((rule.priority, rule))
    if not candidates:
        return {
            "chain_depth": 0,
            "confidence": "none",
            "coverage_bucket": "unknown_untriaged",
            "triage_status": "needs_manual_source_review",
            "vuln_class": "unknown_untriaged",
            "winning_rule_id": "",
        }
    _, rule = sorted(candidates, key=lambda item: (-item[0], item[1].rule_id))[0]
    confidence = "high" if by_rule[rule.rule_id] >= max(2, rule.min_hits) else "medium"
    return {
        "chain_depth": rule.chain_depth,
        "confidence": confidence,
        "coverage_bucket": rule.coverage_bucket,
        "triage_status": "source_classified",
        "vuln_class": rule.vuln_class,
        "winning_rule_id": rule.rule_id,
    }


def triage_one(xben_id: str, *, source_root: Path) -> dict[str, Any]:
    root = challenge_dir(source_root, xben_id)
    files = iter_text_files(root)
    matches: list[dict[str, Any]] = []
    for path in files:
        matches.extend(scan_file(path, root))
    classification = classify(matches)
    evidence = matches[:24]
    return {
        **classification,
        "evidence": evidence,
        "evidence_count": len(matches),
        "evidence_policy": "file_line_rule_ids_only_no_source_snippets",
        "files_scanned": len(files),
        "source_dir": str(root),
        "source_exists": root.exists(),
        "xben_id": xben_id,
    }


def build_triage(
    *,
    backlog_path: Path = DEFAULT_BACKLOG,
    source_root: Path = DEFAULT_SOURCE_ROOT,
    existing_triage_path: Path | None = None,
) -> dict[str, Any]:
    backlog = read_backlog(backlog_path)
    xben_ids = ids_to_triage(
        backlog,
        backlog_path=backlog_path,
        existing_triage_path=existing_triage_path,
    )
    rows = [triage_one(xben_id, source_root=source_root) for xben_id in xben_ids]
    return {
        "dataset": DEFAULT_PREFIX,
        "policy": {
            "data_lane_only": True,
            "labels_from_source_rules_only": True,
            "no_source_snippets": True,
            "no_training_rows_generated": True,
            "unknown_if_no_rule_evidence": True,
        },
        "rows": rows,
        "source_root": str(source_root),
        "stats": {
            "by_confidence": dict(sorted(Counter(row["confidence"] for row in rows).items())),
            "by_status": dict(sorted(Counter(row["triage_status"] for row in rows).items())),
            "by_vuln_class": dict(sorted(Counter(row["vuln_class"] for row in rows).items())),
            "classified_count": sum(1 for row in rows if row["triage_status"] == "source_classified"),
            "row_count": len(rows),
            "source_missing_count": sum(1 for row in rows if not row["source_exists"]),
        },
    }


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")


def write_outputs(data: dict[str, Any], out_dir: Path, prefix: str = DEFAULT_PREFIX) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / f"{prefix}.json"
    rows_path = out_dir / f"{prefix}.jsonl"
    summary_path = out_dir / f"{prefix}_summary.md"
    json_path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_jsonl(rows_path, data["rows"])
    lines = [
        "# XBEN source triage iter10",
        "",
        f"- rows: {data['stats']['row_count']}",
        f"- classified: {data['stats']['classified_count']}",
        f"- source missing: {data['stats']['source_missing_count']}",
        "- evidence policy: file/line/rule IDs only; no source snippets",
        "",
        "## Classes",
        "",
    ]
    for cls, count in data["stats"]["by_vuln_class"].items():
        lines.append(f"- `{cls}`: {count}")
    summary_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return {
        "files": {
            "rows": str(rows_path),
            "summary": str(summary_path),
            "triage": str(json_path),
        },
        **data["stats"],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backlog", type=Path, default=DEFAULT_BACKLOG)
    parser.add_argument("--source-root", type=Path, default=DEFAULT_SOURCE_ROOT)
    parser.add_argument("--existing-triage", type=Path, default=DEFAULT_EXISTING_TRIAGE)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument("--prefix", default=DEFAULT_PREFIX)
    args = parser.parse_args()
    data = build_triage(
        backlog_path=args.backlog,
        source_root=args.source_root,
        existing_triage_path=args.existing_triage,
    )
    summary = write_outputs(data, args.out_dir, prefix=args.prefix)
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
