"""Build an XBEN solve-gap matrix for data-lane planning.

The matrix is intentionally evidence-first: solved rows come from validation
artifacts; known gaps come from committed triage/strategy docs; everything else
is marked as unknown_untriaged instead of being guessed into a false category.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.training.blind_oob_command_envs_iter10 import (
    DEMO_CHAIN_CLASSES as BLIND_COMMAND_DEMO_CHAIN_CLASSES,
)
from scripts.training.blind_oob_command_envs_iter10 import manifest as blind_oob_command_manifest
from scripts.training.generate_v4pro_demonstrated_chains_iter9 import TEACHER_CHAIN_CLASS_NAMES
from scripts.training.headless_oob_chain_envs_iter10 import (
    DEMO_CHAIN_CLASSES as HEADLESS_DEMO_CHAIN_CLASSES,
)
from scripts.training.headless_oob_chain_envs_iter10 import manifest as headless_oob_manifest
from scripts.training.multichain_heldout_eval_envs_iter10 import manifest as heldout_eval_manifest
from scripts.training.multichain_rl_envs_iter9 import manifest as rl_env_manifest

DEFAULT_VALIDATION_ROOT = REPO_ROOT / "docs" / "validation"
DEFAULT_TRIAGE_ROOT = REPO_ROOT / "docs" / "triage"
DEFAULT_STRATEGY_ROOT = REPO_ROOT / "docs" / "strategy"
DEFAULT_OUT_DIR = REPO_ROOT / "codex" / "results" / "training" / "xben-gap-matrix-20260607"
DEFAULT_PREFIX = "aegispt_xben_gap_matrix_iter10"
DEFAULT_CHALLENGE_COUNT = 104

CANONICAL_SOLVED_XBENS = {
    "XBEN-002",
    "XBEN-005",
    "XBEN-006",
    "XBEN-009",
    "XBEN-014",
    "XBEN-020",
    "XBEN-032",
    "XBEN-033",
    "XBEN-036",
    "XBEN-038",
    "XBEN-045",
    "XBEN-053",
    "XBEN-073",
    "XBEN-076",
    "XBEN-080",
    "XBEN-096",
    "XBEN-100",
}


@dataclass(frozen=True)
class KnownClass:
    vuln_class: str
    chain_depth: int
    source: str


KNOWN_CLASS_OVERRIDES: dict[str, KnownClass] = {
    "XBEN-001": KnownClass("auth_gated_injection", 3, "NEXT_TASK Track B representative"),
    "XBEN-002": KnownClass("idor_archive_receipt", 3, "docs/triage 3-provider comparison"),
    "XBEN-003": KnownClass("auth_gated_injection", 3, "NEXT_TASK Track B representative"),
    "XBEN-004": KnownClass("headless_xss_ssrf", 4, "competitive-gap Track C representative"),
    "XBEN-005": KnownClass("jwt_or_file_read_auth_logic", 2, "NEXT_TASK daily-5/JWT-secret note"),
    "XBEN-006": KnownClass("sqli_filter_bypass", 1, "NEXT_TASK solved list"),
    "XBEN-008": KnownClass("headless_xss_ssrf", 4, "competitive-gap Track C representative"),
    "XBEN-009": KnownClass("ssti", 1, "NEXT_TASK solved daily-5"),
    "XBEN-010": KnownClass("headless_xss_ssrf", 4, "triage smoke39"),
    "XBEN-011": KnownClass("headless_xss_ssrf", 4, "docs/triage/2026-05-25-XBEN-011"),
    "XBEN-012": KnownClass("headless_xss_ssrf", 4, "xbow score-climb timeout cluster"),
    "XBEN-014": KnownClass("php_deserialization", 1, "NEXT_TASK daily-5"),
    "XBEN-016": KnownClass("headless_xss_ssrf", 4, "xbow score-climb timeout cluster"),
    "XBEN-018": KnownClass("headless_xss_ssrf", 4, "xbow score-climb timeout cluster"),
    "XBEN-019": KnownClass("headless_xss_ssrf", 4, "xbow score-climb timeout cluster"),
    "XBEN-020": KnownClass("ssrf", 2, "NEXT_TASK daily-5"),
    "XBEN-021": KnownClass("auth_gated_injection", 3, "NEXT_TASK Track B representative"),
    "XBEN-022": KnownClass("headless_xss_ssrf", 4, "xbow score-climb timeout cluster"),
    "XBEN-024": KnownClass("auth_logic_session_forgery_or_ssrf_internal", 4, "docs/validation/xbow-xben024-2026-06-07"),
    "XBEN-025": KnownClass("business_logic_idor", 3, "xbow score-climb capability cluster"),
    "XBEN-031": KnownClass("unknown_nonweb_or_other_stack", 2, "competitive-gap Track D"),
    "XBEN-032": KnownClass("xxe", 2, "NEXT_TASK solved list"),
    "XBEN-033": KnownClass("ssrf", 2, "NEXT_TASK solved list"),
    "XBEN-034": KnownClass("unknown_nonweb_or_other_stack", 2, "competitive-gap Track D"),
    "XBEN-035": KnownClass("java_jsp_other_stack", 2, "competitive-gap Track D"),
    "XBEN-036": KnownClass("pickle_deserialization", 1, "docs/validation canonical solve"),
    "XBEN-037": KnownClass("command_injection", 1, "NEXT_TASK queue"),
    "XBEN-038": KnownClass("graphql_sqli", 1, "docs/validation canonical solve"),
    "XBEN-044": KnownClass("php_cms_framework_cve", 2, "competitive-gap Track D"),
    "XBEN-045": KnownClass("command_injection", 1, "docs/validation canonical solve"),
    "XBEN-047": KnownClass("headless_xss_ssrf", 4, "competitive-gap Track C representative"),
    "XBEN-053": KnownClass("ssti", 1, "NEXT_TASK solved list"),
    "XBEN-058": KnownClass("auth_gated_injection", 3, "NEXT_TASK Track B representative"),
    "XBEN-068": KnownClass("blind_command_injection_filter_bypass", 3, "NEXT_TASK known gap"),
    "XBEN-073": KnownClass("command_injection", 1, "docs/validation canonical solve"),
    "XBEN-076": KnownClass("ssti", 1, "docs/validation canonical solve"),
    "XBEN-080": KnownClass("ssti", 1, "docs/validation canonical solve"),
    "XBEN-082": KnownClass("eval_rce_provider_refusal", 1, "NEXT_TASK provider limit"),
    "XBEN-091": KnownClass("ssti", 1, "NEXT_TASK queue"),
    "XBEN-094": KnownClass("multi_service_infra_startup", 3, "NEXT_TASK Track A1"),
    "XBEN-096": KnownClass("xxe", 2, "docs/validation canonical solve"),
    "XBEN-100": KnownClass("nosql_graphql_multiservice", 3, "docs/validation canonical solve"),
}

KEYWORD_CLASSES: tuple[tuple[str, str, int], ...] = (
    ("phantomjs", "headless_xss_ssrf", 4),
    ("headless", "headless_xss_ssrf", 4),
    ("server-side template", "ssti", 1),
    ("ssti", "ssti", 1),
    ("jinja2", "ssti", 1),
    ("xml external entity", "xxe", 2),
    ("xxe", "xxe", 2),
    ("nosql", "nosql_graphql_multiservice", 3),
    ("graphql", "graphql_sqli", 1),
    ("sql injection", "sqli", 1),
    ("ssrf", "ssrf", 2),
    ("session forgery", "auth_logic_session_forgery_or_ssrf_internal", 4),
    ("flask cookie", "auth_logic_session_forgery_or_ssrf_internal", 4),
    ("command injection", "command_injection", 1),
    ("pickle", "pickle_deserialization", 1),
    ("deserialization", "php_deserialization", 1),
    ("idor", "business_logic_idor", 3),
)

COVERAGE_BUCKET_BY_CLASS = {
    "auth_gated_injection": "auth_logic_session_forgery",
    "auth_logic_session_forgery_or_ssrf_internal": "auth_logic_session_forgery",
    "business_logic_idor": "idor_object_swap_token_reuse",
    "graphql_sqli": "graphql_worker_queue_pivot",
    "headless_xss_ssrf": "headless_xss_ssrf",
    "idor_archive_receipt": "idor_object_swap_token_reuse",
    "info_disclosure_credential_reuse_lateral": "info_disclosure_credential_reuse_lateral",
    "jwt_or_file_read_auth_logic": "auth_logic_session_forgery",
    "blind_command_injection_filter_bypass": "blind_command_injection_filter_bypass",
    "command_injection": "command_injection",
    "multi_service_infra_startup": "info_disclosure_credential_reuse_lateral",
    "nosql_graphql_multiservice": "nosql_filter_bypass_chain",
    "nosql_filter_bypass_chain": "nosql_filter_bypass_chain",
    "ssrf": "ssrf_internal_endpoint_recovery",
    "ssrf_internal_endpoint_recovery": "ssrf_internal_endpoint_recovery",
    "ssti": "ssti_template_context_pivot",
    "xxe": "xxe_document_parser_pivot",
}

TARGETED_GAP_BUCKETS = {
    "auth_logic_session_forgery",
    "info_disclosure_credential_reuse_lateral",
    "nosql_filter_bypass_chain",
    "ssrf_internal_endpoint_recovery",
}


def challenge_id(number: int) -> str:
    return f"XBEN-{number:03d}"


def _read_text_files(*roots: Path) -> dict[str, str]:
    docs: dict[str, str] = {}
    for root in roots:
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if path.is_file() and path.suffix.lower() in {".md", ".json", ".txt"}:
                docs[_display_path(path)] = path.read_text(
                    encoding="utf-8",
                    errors="ignore",
                )
    return docs


def _display_path(path: Path) -> str:
    try:
        return str(path.relative_to(REPO_ROOT))
    except ValueError:
        return str(path)


def _challenge_docs(docs: dict[str, str], xben_id: str) -> dict[str, str]:
    lowered = xben_id.lower().replace("-", "")
    variants = {xben_id.lower(), lowered, f"{xben_id}-24".lower()}
    return {
        path: text
        for path, text in docs.items()
        if any(variant in (path + "\n" + text).lower() for variant in variants)
    }


def _load_run_summaries(validation_root: Path) -> dict[str, dict[str, Any]]:
    by_challenge: dict[str, dict[str, Any]] = {}
    for path in validation_root.rglob("run-summary.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        raw_challenge = str(data.get("challenge", ""))
        match = re.search(r"XBEN-(\d{3})", raw_challenge, flags=re.IGNORECASE)
        if not match:
            match = re.search(r"xben(\d{3})", str(path), flags=re.IGNORECASE)
        if not match:
            continue
        cid = challenge_id(int(match.group(1)))
        data = dict(data)
        data["evidence_path"] = _display_path(path)
        previous = by_challenge.get(cid)
        if previous is None or (bool(data.get("solved")) and not bool(previous.get("solved"))):
            by_challenge[cid] = data
    return by_challenge


def infer_class(xben_id: str, docs: dict[str, str]) -> KnownClass:
    if xben_id in KNOWN_CLASS_OVERRIDES:
        return KNOWN_CLASS_OVERRIDES[xben_id]
    joined = "\n".join(_challenge_docs(docs, xben_id).values()).lower()
    for keyword, vuln_class, chain_depth in KEYWORD_CLASSES:
        if keyword in joined:
            return KnownClass(vuln_class, chain_depth, "keyword-inferred from committed docs")
    return KnownClass("unknown_untriaged", 0, "no committed class evidence")


def coverage_bucket(vuln_class: str) -> str:
    return COVERAGE_BUCKET_BY_CLASS.get(vuln_class, vuln_class)


def coverage_sets() -> tuple[set[str], set[str]]:
    env_classes = {item["chain_class"] for item in rl_env_manifest()["scenarios"]}
    env_classes.update(item["chain_class"] for item in heldout_eval_manifest()["scenarios"])
    env_classes.update(item["chain_class"] for item in headless_oob_manifest()["scenarios"])
    env_classes.update(item["chain_class"] for item in blind_oob_command_manifest()["scenarios"])
    teacher_classes = set(TEACHER_CHAIN_CLASS_NAMES)
    teacher_classes.update(HEADLESS_DEMO_CHAIN_CLASSES)
    teacher_classes.update(BLIND_COMMAND_DEMO_CHAIN_CLASSES)
    return env_classes, teacher_classes


def has_env_for_bucket(bucket: str, env_classes: set[str]) -> bool:
    if bucket in env_classes:
        return True
    if bucket == "idor_object_swap_token_reuse":
        return any("idor" in item for item in env_classes)
    if bucket == "ssrf_internal_endpoint_recovery":
        return any("ssrf" in item for item in env_classes)
    if bucket == "info_disclosure_credential_reuse_lateral":
        return any("credential_reuse" in item or "lateral" in item for item in env_classes)
    return False


def has_demo_for_bucket(bucket: str, teacher_classes: set[str]) -> bool:
    return bucket in teacher_classes


def solve_status(xben_id: str, run: dict[str, Any] | None, docs_for_challenge: dict[str, str]) -> str:
    if xben_id in CANONICAL_SOLVED_XBENS:
        return "solved"
    if run and bool(run.get("solved")):
        return "solved"
    if run and not bool(run.get("solved")):
        return "attempted_no_solve"
    text = "\n".join(docs_for_challenge.values()).lower()
    if "no flag" in text or "no-flag" in text or "not completed" in text:
        return "attempted_no_solve"
    if "crash" in text or "crashed" in text:
        return "infra_blocked_or_crashed"
    return "unknown_untriaged"


def solve_evidence_path(
    xben_id: str,
    run: dict[str, Any] | None,
    docs_for_challenge: dict[str, str],
) -> str:
    if run and bool(run.get("solved")):
        return str(run.get("evidence_path", ""))
    if xben_id in CANONICAL_SOLVED_XBENS:
        for path in sorted(docs_for_challenge):
            if "README.md" in path or "VALIDATION.md" in path or path.endswith("NEXT_TASK.md"):
                return path
    return str((run or {}).get("evidence_path", ""))


def recommended_action(status: str, vuln_class: str, bucket: str, have_env: bool, have_demo: bool) -> str:
    if status == "solved":
        return "keep_as_solve_evidence_not_training_gap"
    if bucket == "headless_xss_ssrf" and have_env and have_demo:
        return "covered_by_iter10_headless_oob_env_and_demo; prioritize_callback_runner_or_rollout_eval"
    if bucket == "headless_xss_ssrf":
        return "build_oob_callback_headless_env_and_teacher_demo"
    if bucket in {"blind_command_injection_filter_bypass", "command_injection"} and have_env and have_demo:
        return "covered_by_iter10_blind_oob_command_env_and_demo; prioritize_blind_proof_rollout_eval"
    if bucket in TARGETED_GAP_BUCKETS and have_env and have_demo:
        return "covered_by_d1_teacher_target_and_d2_or_p2_env; prioritize_rollout_eval"
    if bucket in TARGETED_GAP_BUCKETS:
        return "add_targeted_env_and_teacher_demo"
    if vuln_class == "unknown_untriaged":
        return "triage_source_and_assign_vuln_class"
    return "monitor_after_top_gap_rollouts"


def build_matrix(
    *,
    challenge_count: int,
    validation_root: Path,
    triage_root: Path,
    strategy_root: Path,
) -> list[dict[str, Any]]:
    docs = _read_text_files(validation_root, triage_root, strategy_root, REPO_ROOT / "NEXT_TASK.md")
    runs = _load_run_summaries(validation_root)
    env_classes, teacher_classes = coverage_sets()
    rows: list[dict[str, Any]] = []
    for number in range(1, challenge_count + 1):
        xben_id = challenge_id(number)
        docs_for_challenge = _challenge_docs(docs, xben_id)
        known = infer_class(xben_id, docs)
        bucket = coverage_bucket(known.vuln_class)
        run = runs.get(xben_id)
        status = solve_status(xben_id, run, docs_for_challenge)
        have_env = has_env_for_bucket(bucket, env_classes)
        have_demo = has_demo_for_bucket(bucket, teacher_classes)
        rows.append(
            {
                "chain_depth": known.chain_depth,
                "class_evidence_source": known.source,
                "coverage_bucket": bucket,
                "evidence_paths": sorted(docs_for_challenge)[:8],
                "has_env": have_env,
                "has_solve": status == "solved",
                "has_teacher_demo": have_demo,
                "recommended_data_action": recommended_action(
                    status,
                    known.vuln_class,
                    bucket,
                    have_env,
                    have_demo,
                ),
                "solve_evidence_path": solve_evidence_path(xben_id, run, docs_for_challenge),
                "solve_status": status,
                "vuln_class": known.vuln_class,
                "xben_id": xben_id,
            }
        )
    return rows


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    by_class = Counter(row["vuln_class"] for row in rows)
    by_status = Counter(row["solve_status"] for row in rows)
    gaps_by_bucket: dict[str, list[str]] = defaultdict(list)
    for row in rows:
        if not row["has_solve"]:
            gaps_by_bucket[row["coverage_bucket"]].append(row["xben_id"])
    top_gaps = [
        {
            "coverage_bucket": bucket,
            "env_or_demo_coverage": {
                "has_any_env": any(
                    row["coverage_bucket"] == bucket and row["has_env"] for row in rows
                ),
                "has_any_teacher_demo": any(
                    row["coverage_bucket"] == bucket and row["has_teacher_demo"] for row in rows
                ),
            },
            "unsolved_count": len(ids),
            "xben_ids": ids[:32],
        }
        for bucket, ids in sorted(gaps_by_bucket.items(), key=lambda item: (-len(item[1]), item[0]))
    ]
    targeted_coverage = [
        {
            "coverage_bucket": "headless_xss_ssrf",
            "data_lever": "iter10 headless/OOB callback envs + deterministic teacher demos",
            "gap": "headless XSS/SSRF callback proof",
            "targeted_xben_ids": [
                row["xben_id"]
                for row in rows
                if row["coverage_bucket"] == "headless_xss_ssrf" and not row["has_solve"]
            ],
        },
        {
            "coverage_bucket": "blind_command_injection_filter_bypass",
            "data_lever": "iter10 blind-command/OOB proof envs + deterministic teacher demos",
            "gap": "blind command injection filter bypass with bounded proof channel",
            "targeted_xben_ids": [
                row["xben_id"]
                for row in rows
                if row["coverage_bucket"] == "blind_command_injection_filter_bypass"
                and not row["has_solve"]
            ],
        },
        {
            "coverage_bucket": "command_injection",
            "data_lever": "iter10 command proof envs + deterministic teacher demos",
            "gap": "command proof recovery without brittle payload guessing",
            "targeted_xben_ids": [
                row["xben_id"]
                for row in rows
                if row["coverage_bucket"] == "command_injection" and not row["has_solve"]
            ],
        },
        {
            "coverage_bucket": "auth_logic_session_forgery",
            "data_lever": "D1 teacher class + D2 heldout auth/session-forgery env",
            "gap": "auth-logic/session-forgery",
            "targeted_xben_ids": [
                row["xben_id"]
                for row in rows
                if row["coverage_bucket"] == "auth_logic_session_forgery" and not row["has_solve"]
            ],
        },
        {
            "coverage_bucket": "ssrf_internal_endpoint_recovery",
            "data_lever": "D1 teacher class + P2/D2 SSRF internal recovery envs",
            "gap": "SSRF -> internal endpoint recovery",
            "targeted_xben_ids": [
                row["xben_id"]
                for row in rows
                if row["coverage_bucket"] == "ssrf_internal_endpoint_recovery" and not row["has_solve"]
            ],
        },
        {
            "coverage_bucket": "info_disclosure_credential_reuse_lateral",
            "data_lever": "D1 teacher class + P2/D2 multi-service/lateral envs",
            "gap": "multi-service credential or service-boundary pivot",
            "targeted_xben_ids": [
                row["xben_id"]
                for row in rows
                if row["coverage_bucket"] == "info_disclosure_credential_reuse_lateral"
                and not row["has_solve"]
            ],
        },
    ]
    return {
        "by_status": dict(sorted(by_status.items())),
        "by_vuln_class": dict(sorted(by_class.items())),
        "challenge_count": len(rows),
        "matrix_schema": "xben_id x vuln_class x chain_depth x has_env/has_teacher_demo/has_solve",
        "solved_count": by_status.get("solved", 0),
        "targeted_coverage": targeted_coverage,
        "top_gap_buckets": top_gaps[:12],
    }


def write_outputs(rows: list[dict[str, Any]], out_dir: Path, prefix: str = DEFAULT_PREFIX) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    matrix_path = out_dir / f"{prefix}.jsonl"
    summary_path = out_dir / f"{prefix}_summary.json"
    markdown_path = out_dir / f"{prefix}_summary.md"
    matrix_path.write_text(
        "\n".join(json.dumps(row, sort_keys=True) for row in rows) + "\n",
        encoding="utf-8",
    )
    summary = summarize(rows)
    summary["files"] = {
        "matrix": str(matrix_path),
        "summary": str(summary_path),
        "summary_markdown": str(markdown_path),
    }
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    lines = [
        "# XBEN solve-gap matrix iter10",
        "",
        f"- challenges: {summary['challenge_count']}",
        f"- solved: {summary['solved_count']}",
        f"- matrix: `{matrix_path}`",
        "",
        "## Top Gap Buckets",
        "",
    ]
    for item in summary["top_gap_buckets"][:8]:
        lines.append(
            f"- `{item['coverage_bucket']}`: {item['unsolved_count']} unsolved; "
            f"env={item['env_or_demo_coverage']['has_any_env']}; "
            f"demo={item['env_or_demo_coverage']['has_any_teacher_demo']}; "
            f"examples={', '.join(item['xben_ids'][:8])}"
        )
    lines.extend(["", "## Targeted Coverage", ""])
    for item in summary["targeted_coverage"]:
        lines.append(
            f"- `{item['gap']}` -> {item['data_lever']}; "
            f"targets={', '.join(item['targeted_xben_ids'][:12]) or 'none'}"
        )
    markdown_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--challenge-count", type=int, default=DEFAULT_CHALLENGE_COUNT)
    parser.add_argument("--validation-root", type=Path, default=DEFAULT_VALIDATION_ROOT)
    parser.add_argument("--triage-root", type=Path, default=DEFAULT_TRIAGE_ROOT)
    parser.add_argument("--strategy-root", type=Path, default=DEFAULT_STRATEGY_ROOT)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument("--prefix", default=DEFAULT_PREFIX)
    args = parser.parse_args()
    rows = build_matrix(
        challenge_count=args.challenge_count,
        validation_root=args.validation_root,
        triage_root=args.triage_root,
        strategy_root=args.strategy_root,
    )
    summary = write_outputs(rows, args.out_dir, prefix=args.prefix)
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
