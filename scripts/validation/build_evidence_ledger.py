#!/usr/bin/env python3
"""Build the canonical Rework 4 evidence ledger.

The ledger is intentionally generated from committed evidence artifacts instead
of narrative score claims. It produces one current status row per XBEN target and
enriches solved rows with the strongest validation artifact available.

Optional held-out transfer matrices can be included as separate
``heldout_transfer_eval`` rows. They are canonical eval evidence, but they do
not change the XBOW target score.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from statistics import mean
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from api.app.services.finding_evidence_gate import PASSIVE, PROVEN, UNPROVEN

DEFAULT_VALIDATION_ROOT = REPO_ROOT / "docs" / "validation"
DEFAULT_GAP_MATRIX = (
    REPO_ROOT
    / "codex"
    / "results"
    / "training"
    / "xben-gap-matrix-20260607"
    / "aegispt_xben_gap_matrix_iter10.jsonl"
)
DEFAULT_LEDGER_JSONL = DEFAULT_VALIDATION_ROOT / "evidence_ledger.jsonl"
DEFAULT_LEDGER_MD = DEFAULT_VALIDATION_ROOT / "EVIDENCE_LEDGER.md"

SUMMARY_START = "<!-- evidence-ledger-summary:start -->"
SUMMARY_END = "<!-- evidence-ledger-summary:end -->"

ALLOWED_OUTCOMES = {
    "solved",
    "admin",
    "finding",
    "attempted_no_solve",
    "no_finding",
    "infra_blocked",
    "scaffold_error",
    "unknown",
    "known_clean",
    "known_vulnerable",
    "live_no_oracle",
}

SOLVE_STATUS_TO_OUTCOME = {
    "solved": "solved",
    "attempted_no_solve": "attempted_no_solve",
    "infra_blocked_or_crashed": "infra_blocked",
    "unknown_untriaged": "unknown",
}

XBEN_RE = re.compile(r"\bXBEN-(\d{3})(?:-24)?\b", re.IGNORECASE)
DATE_RE = re.compile(r"(20\d{2}-\d{2}-\d{2})")
DATE_COMPACT_RE = re.compile(r"(20\d{2})(\d{2})(\d{2})")
RUN_ID_RE = re.compile(r"\brun_id\s*`?([0-9a-f]{8,}-[0-9a-f-]{8,})`?", re.IGNORECASE)
FLAG_RE = re.compile(r"\bxbow-[0-9a-f]{16,}\b", re.IGNORECASE)


@dataclass(frozen=True)
class ArtifactEvidence:
    xben_id: str
    evidence_ref: str
    evidence_level: str
    proof_status: str
    run_id: str
    provider: str
    observed_date: str
    quality: int
    flag_sha256: str
    flag_found_in: tuple[str, ...]
    invariant_pass: bool
    notes: str


def repo_rel(path: Path) -> str:
    try:
        return path.resolve().relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def normalize_xben(value: str | None) -> str:
    if not value:
        return ""
    match = XBEN_RE.search(value)
    if not match:
        return ""
    return f"XBEN-{match.group(1)}"


def xben_target(xben_id: str) -> str:
    return f"{xben_id}-24"


def artifact_date(path: Path) -> str:
    for part in (path.name, *path.parts[::-1]):
        match = DATE_RE.search(part)
        if match:
            return match.group(1)
        compact_match = DATE_COMPACT_RE.search(part)
        if compact_match:
            return "-".join(compact_match.groups())
    return "1970-01-01"


def stable_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def load_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def load_gap_rows(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
    return rows


def iter_result_summaries(path: Path) -> list[dict[str, Any]]:
    data = load_json(path)
    if not isinstance(data, dict):
        return []
    if isinstance(data.get("results"), list):
        return [item for item in data["results"] if isinstance(item, dict)]
    if data.get("challenge") or data.get("challenge_id"):
        return [data]
    return []


def flag_hash(flag: str | None) -> str:
    return stable_hash(flag or "") if flag else ""


def scan_run_summary(path: Path) -> list[ArtifactEvidence]:
    evidence: list[ArtifactEvidence] = []
    try:
        results = iter_result_summaries(path)
    except (json.JSONDecodeError, OSError):
        return evidence

    invariant_path = path.parent / "invariant.txt"
    invariant_pass = False
    if invariant_path.exists():
        invariant_pass = "[PASS]" in invariant_path.read_text(encoding="utf-8", errors="ignore")

    for result in results:
        xben_id = normalize_xben(str(result.get("challenge") or result.get("challenge_id") or ""))
        if not xben_id or result.get("solved") is not True:
            continue
        flag_found_in = tuple(str(item) for item in result.get("flag_found_in") or [])
        flag = str(result.get("flag_injected") or "")
        if not flag_found_in or not flag:
            continue
        has_finding = "findings" in flag_found_in
        evidence_level = "flag_capture_persisted_finding" if has_finding else "flag_capture"
        proof_status = "flag_capture_persisted" if has_finding else "flag_capture_no_persisted_finding"
        quality = 100 + (10 if invariant_pass else 0) + (5 if has_finding else 0)
        evidence.append(
            ArtifactEvidence(
                xben_id=xben_id,
                evidence_ref=repo_rel(path),
                evidence_level=evidence_level,
                proof_status=proof_status,
                run_id=str(result.get("run_id") or ""),
                provider=str(result.get("provider") or ""),
                observed_date=artifact_date(path.parent),
                quality=quality,
                flag_sha256=flag_hash(flag),
                flag_found_in=flag_found_in,
                invariant_pass=invariant_pass,
                notes=str(result.get("note") or ""),
            )
        )
    return evidence


def scan_readme(path: Path) -> list[ArtifactEvidence]:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    title = next((line.strip("# ").strip() for line in text.splitlines() if line.startswith("#")), "")
    title_lower = title.lower()
    if "solve" not in title_lower:
        return []
    xben_id = normalize_xben(title) or normalize_xben(text)
    if not xben_id:
        return []
    if "byte-equal" not in text.lower() and "grader solve" not in title_lower:
        return []
    flag_match = FLAG_RE.search(text)
    flag = flag_match.group(0) if flag_match else ""
    run_match = RUN_ID_RE.search(text)
    persisted_gap = "not canonical-finding-persisted" in text.lower()
    proof_status = (
        "grader_solved_not_finding_persisted"
        if persisted_gap
        else "readme_canonical_solve"
    )
    evidence_level = (
        "byte_equal_tool_capture_no_persisted_finding"
        if persisted_gap
        else "readme_byte_equal_solve"
    )
    return [
        ArtifactEvidence(
            xben_id=xben_id,
            evidence_ref=repo_rel(path),
            evidence_level=evidence_level,
            proof_status=proof_status,
            run_id=run_match.group(1) if run_match else "",
            provider="chatgpt_oauth" if "chatgpt_oauth" in text else "",
            observed_date=artifact_date(path.parent),
            quality=90 if not persisted_gap else 80,
            flag_sha256=flag_hash(flag),
            flag_found_in=("readme",),
            invariant_pass="[PASS]" in text,
            notes=title,
        )
    ]


def scan_status_outcome(path: Path) -> ArtifactEvidence | None:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None
    xben_id = normalize_xben(path.name) or normalize_xben(text)
    if not xben_id:
        return None
    lowered = text.lower()
    if "no flag" not in lowered and "not done" not in lowered:
        return None
    return ArtifactEvidence(
        xben_id=xben_id,
        evidence_ref=repo_rel(path),
        evidence_level="no_flag_outcome_note",
        proof_status="attempted_no_solve",
        run_id="",
        provider="",
        observed_date=artifact_date(path.parent),
        quality=50,
        flag_sha256="",
        flag_found_in=(),
        invariant_pass=False,
        notes="NO FLAG outcome note",
    )


def scan_validation_artifacts(validation_root: Path) -> dict[str, list[ArtifactEvidence]]:
    by_xben: dict[str, list[ArtifactEvidence]] = {}
    for run_summary in validation_root.glob("xbow-*/run-summary.json"):
        for item in scan_run_summary(run_summary):
            by_xben.setdefault(item.xben_id, []).append(item)
    for readme in validation_root.glob("xbow-*/README.md"):
        for item in scan_readme(readme):
            by_xben.setdefault(item.xben_id, []).append(item)
    for outcome in validation_root.glob("xbow-*/OUTCOME.md"):
        item = scan_status_outcome(outcome)
        if item:
            by_xben.setdefault(item.xben_id, []).append(item)
    return by_xben


def best_artifact(items: list[ArtifactEvidence], solved: bool) -> ArtifactEvidence | None:
    if not items:
        return None
    candidates = [
        item
        for item in items
        if solved
        or item.proof_status in {"attempted_no_solve"}
    ]
    if not candidates:
        return None
    return sorted(candidates, key=lambda item: (item.quality, item.observed_date, item.evidence_ref))[
        -1
    ]


def path_mentions_xben(path_text: str, xben_id: str, repo_root: Path = REPO_ROOT) -> bool:
    path = repo_root / path_text
    if xben_id.lower() in path_text.lower():
        return True
    if path.exists() and path.is_file():
        try:
            return xben_id in path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return False
    return False


def row_from_gap(
    gap_row: dict[str, Any],
    artifacts: dict[str, list[ArtifactEvidence]],
    matrix_path: Path,
) -> dict[str, Any]:
    xben_id = str(gap_row["xben_id"])
    solve_status = str(gap_row.get("solve_status") or "unknown_untriaged")
    outcome = SOLVE_STATUS_TO_OUTCOME.get(solve_status, "unknown")
    if outcome not in ALLOWED_OUTCOMES:
        raise ValueError(f"unsupported outcome for {xben_id}: {outcome}")

    artifact = best_artifact(artifacts.get(xben_id, []), solved=outcome == "solved")
    matrix_evidence_path = str(gap_row.get("solve_evidence_path") or "")
    review_flags: list[str] = []

    if matrix_evidence_path and not path_mentions_xben(matrix_evidence_path, xben_id):
        review_flags.append("matrix_solve_evidence_path_target_mismatch")

    if outcome == "solved" and not artifact:
        review_flags.append("solved_without_structured_artifact")

    evidence_ref = artifact.evidence_ref if artifact else matrix_evidence_path or repo_rel(matrix_path)
    status_source = "validation_artifact" if artifact else "xben_gap_matrix_iter10"
    observed_date = artifact.observed_date if artifact else artifact_date(matrix_path)
    evidence_level = artifact.evidence_level if artifact else "matrix_status"
    proof_status = artifact.proof_status if artifact else solve_status
    reportability_class = derive_reportability_class(
        outcome=outcome,
        evidence_level=evidence_level,
        proof_status=proof_status,
    )

    row_material = f"{xben_id}|{outcome}|{evidence_ref}|{status_source}"
    return {
        "schema_version": "aegispt.evidence-ledger.v1",
        "row_id": stable_hash(row_material)[:24],
        "row_type": "target_status",
        "ts": f"{observed_date}T00:00:00Z",
        "benchmark": "XBOW",
        "target": xben_target(xben_id),
        "xben_id": xben_id,
        "outcome": outcome,
        "source_status": solve_status,
        "vuln_class": gap_row.get("vuln_class", ""),
        "coverage_bucket": gap_row.get("coverage_bucket", ""),
        "chain_depth": gap_row.get("chain_depth", 0),
        "run_id": artifact.run_id if artifact else "",
        "brain": artifact.provider if artifact else "",
        "evidence_ref": evidence_ref,
        "evidence_level": evidence_level,
        "proof_status": proof_status,
        "reportability_class": reportability_class,
        "reportable_under_no_exploit_no_report": reportability_class == PROVEN,
        "flag_sha256": artifact.flag_sha256 if artifact else "",
        "flag_found_in": list(artifact.flag_found_in) if artifact else [],
        "finding_persistence_invariant": "pass" if artifact and artifact.invariant_pass else "",
        "status_source": status_source,
        "source_artifacts": [repo_rel(matrix_path), *gap_row.get("evidence_paths", [])],
        "matrix_solve_evidence_path": matrix_evidence_path,
        "review_flags": review_flags,
        "needs_review": bool(review_flags),
        "notes": artifact.notes if artifact else gap_row.get("recommended_data_action", ""),
    }


def row_from_transfer_result(matrix_path: Path, result: dict[str, Any]) -> dict[str, Any]:
    scenario_id = str(result.get("scenario_id") or "")
    run_label = str(result.get("run_label") or "")
    result_path = str(result.get("result_path") or "")
    reward = int(result.get("reward") or 0)
    flag = bool(result.get("flag"))
    pivot = bool(result.get("pivot") or result.get("idor"))
    recovered = bool(result.get("recovered_after_block"))
    evidence_level = (
        "heldout_transfer_flag"
        if flag
        else "heldout_transfer_partial"
        if reward > 0
        else "heldout_transfer_no_signal"
    )
    proof_status = (
        "heldout_flag_recovered"
        if flag and recovered
        else "heldout_flag"
        if flag
        else "heldout_partial_progress"
        if reward > 0
        else "heldout_no_signal"
    )
    outcome = "solved" if flag else "attempted_no_solve"
    reportability_class = derive_reportability_class(
        outcome=outcome,
        evidence_level=evidence_level,
        proof_status=proof_status,
    )
    review_flags: list[str] = []
    if not scenario_id:
        review_flags.append("heldout_transfer_missing_scenario_id")
    if not run_label:
        review_flags.append("heldout_transfer_missing_run_label")

    evidence_ref = result_path or repo_rel(matrix_path)
    row_material = f"heldout_transfer_eval|{run_label}|{scenario_id}|{evidence_ref}|{reward}|{flag}"
    return {
        "schema_version": "aegispt.evidence-ledger.v1",
        "row_id": stable_hash(row_material)[:24],
        "row_type": "heldout_transfer_eval",
        "ts": f"{artifact_date(matrix_path)}T00:00:00Z",
        "benchmark": "AegisPT-D2-heldout",
        "target": scenario_id,
        "xben_id": "",
        "outcome": outcome,
        "source_status": proof_status,
        "vuln_class": str(result.get("chain_class") or ""),
        "coverage_bucket": str(result.get("domain") or ""),
        "chain_depth": int(result.get("steps") or 0),
        "run_id": "",
        "brain": run_label,
        "evidence_ref": evidence_ref,
        "evidence_level": evidence_level,
        "proof_status": proof_status,
        "reportability_class": reportability_class,
        "reportable_under_no_exploit_no_report": reportability_class == PROVEN,
        "flag_sha256": "",
        "flag_found_in": ["heldout_env"] if flag else [],
        "finding_persistence_invariant": "",
        "status_source": "heldout_transfer_matrix",
        "source_artifacts": [repo_rel(matrix_path), *([result_path] if result_path else [])],
        "matrix_solve_evidence_path": "",
        "review_flags": review_flags,
        "needs_review": bool(review_flags),
        "notes": (
            f"reward={reward}; steps={int(result.get('steps') or 0)}; "
            f"pivot={pivot}; "
            f"recovered_after_block={recovered}; "
            f"used_revealed_value={bool(result.get('used_revealed_value'))}"
        ),
        "scenario_hash": str(result.get("scenario_hash") or ""),
        "scenario_id": scenario_id,
        "run_label": run_label,
        "transfer_reward": reward,
        "transfer_flag": flag,
        "transfer_pivot": pivot,
        "transfer_recovered_after_block": recovered,
        "transfer_used_revealed_value": bool(result.get("used_revealed_value")),
        "transfer_steps": int(result.get("steps") or 0),
        "lab_truth": str(result.get("lab_truth") or ""),
        "dataset_family": str(result.get("dataset_family") or ""),
    }


def load_transfer_rows(matrix_path: Path) -> list[dict[str, Any]]:
    try:
        matrix = load_json(matrix_path)
    except (json.JSONDecodeError, OSError):
        return []
    raw_rows = matrix.get("rows") if isinstance(matrix, dict) else None
    if not isinstance(raw_rows, list):
        return []
    return [
        row_from_transfer_result(matrix_path, item)
        for item in raw_rows
        if isinstance(item, dict)
    ]


def build_ledger(
    gap_matrix_path: Path,
    validation_root: Path,
    transfer_matrix_paths: list[Path] | None = None,
) -> list[dict[str, Any]]:
    gap_rows = load_gap_rows(gap_matrix_path)
    artifacts = scan_validation_artifacts(validation_root)
    rows = [row_from_gap(row, artifacts, gap_matrix_path) for row in gap_rows]
    for transfer_matrix_path in transfer_matrix_paths or []:
        rows.extend(load_transfer_rows(transfer_matrix_path))
    rows.sort(key=lambda row: (row["row_type"], row["target"]))
    return rows


def derive_reportability_class(*, outcome: str, evidence_level: str, proof_status: str) -> str:
    """Map ledger status rows into the No-Exploit-No-Report taxonomy.

    The target-status ledger only stores one current row per target, so it currently
    expresses exploit-proven versus not-yet-proven status. Passive observations may appear
    in future adapter-fed rows; the category remains part of the schema now so the shared
    contract is stable across lanes.
    """
    if proof_status == PASSIVE or evidence_level == PASSIVE:
        return PASSIVE
    if outcome in {"solved", "admin", "finding"} and evidence_level != "matrix_status":
        return PROVEN
    return UNPROVEN


def summarize_transfer_group(rows: list[dict[str, Any]]) -> dict[str, Any]:
    attempts = len(rows)
    flags = sum(1 for row in rows if row["transfer_flag"])
    pivot = sum(1 for row in rows if row["transfer_pivot"])
    recovered = sum(1 for row in rows if row["transfer_recovered_after_block"])
    revealed = sum(1 for row in rows if row["transfer_used_revealed_value"])
    milestone = sum(
        1
        for row in rows
        if row["transfer_flag"]
        or row["transfer_pivot"]
        or row["transfer_recovered_after_block"]
        or row["transfer_used_revealed_value"]
    )
    rewards = [int(row["transfer_reward"]) for row in rows]
    return {
        "attempts": attempts,
        "avg_reward": round(mean(rewards), 3) if rewards else 0.0,
        "flag": flags,
        "flag_rate": round(flags / attempts, 3) if attempts else 0.0,
        "max_reward": max(rewards) if rewards else 0,
        "milestone": milestone,
        "milestone_rate": round(milestone / attempts, 3) if attempts else 0.0,
        "pivot": pivot,
        "pivot_rate": round(pivot / attempts, 3) if attempts else 0.0,
        "recovered_after_block": recovered,
        "recovered_after_block_rate": round(recovered / attempts, 3) if attempts else 0.0,
        "solved": flags,
        "solve_rate": round(flags / attempts, 3) if attempts else 0.0,
        "used_revealed_value": revealed,
        "used_revealed_value_rate": round(revealed / attempts, 3) if attempts else 0.0,
    }


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    target_rows = [row for row in rows if row["row_type"] == "target_status"]
    transfer_rows = [row for row in rows if row["row_type"] == "heldout_transfer_eval"]
    outcomes = Counter(row["outcome"] for row in target_rows)
    reportability_counts = Counter(row["reportability_class"] for row in target_rows)
    review_flags = Counter(flag for row in rows for flag in row["review_flags"])
    transfer_by_run: dict[str, dict[str, Any]] = {}
    for run_label in sorted({row["run_label"] for row in transfer_rows}):
        run_rows = [row for row in transfer_rows if row["run_label"] == run_label]
        transfer_by_run[run_label] = summarize_transfer_group(run_rows)
    transfer_by_run_class: dict[str, dict[str, Any]] = {}
    for run_label, chain_class in sorted(
        {(row["run_label"], row["vuln_class"]) for row in transfer_rows}
    ):
        group_rows = [
            row
            for row in transfer_rows
            if row["run_label"] == run_label and row["vuln_class"] == chain_class
        ]
        transfer_by_run_class[f"{run_label}::{chain_class}"] = {
            "chain_class": chain_class,
            "run_label": run_label,
            **summarize_transfer_group(group_rows),
        }
    return {
        "schema_version": "aegispt.evidence-ledger-summary.v1",
        "row_count": len(rows),
        "target_count": len(target_rows),
        "outcomes": dict(sorted(outcomes.items())),
        "reportability_counts": {
            PROVEN: reportability_counts.get(PROVEN, 0),
            PASSIVE: reportability_counts.get(PASSIVE, 0),
            UNPROVEN: reportability_counts.get(UNPROVEN, 0),
        },
        "heldout_transfer": {
            "by_run": transfer_by_run,
            "by_run_class": transfer_by_run_class,
            "row_count": len(transfer_rows),
            "run_count": len(transfer_by_run),
        },
        "solved_count": outcomes.get("solved", 0),
        "needs_review_count": sum(1 for row in rows if row["needs_review"]),
        "review_flags": dict(sorted(review_flags.items())),
        "canonical_score": f"{outcomes.get('solved', 0)}/{len(target_rows)}",
    }


def write_jsonl(rows: list[dict[str, Any]], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")


def render_summary_block(summary: dict[str, Any], jsonl_path: Path, matrix_path: Path) -> str:
    outcome_lines = "\n".join(
        f"- `{name}`: {count}" for name, count in sorted(summary["outcomes"].items())
    )
    reportability_lines = "\n".join(
        f"- `{name}`: {count}" for name, count in summary["reportability_counts"].items()
    )
    review_lines = "\n".join(
        f"- `{name}`: {count}" for name, count in sorted(summary["review_flags"].items())
    )
    if not review_lines:
        review_lines = "- none"
    heldout_lines: list[str] = []
    if summary["heldout_transfer"]["row_count"]:
        heldout_lines = [
            "",
            "Held-out transfer eval:",
            "",
            f"- rows: `{summary['heldout_transfer']['row_count']}`",
            f"- runs: `{summary['heldout_transfer']['run_count']}`",
        ]
        for run_label, item in summary["heldout_transfer"]["by_run"].items():
            heldout_lines.append(
                f"- `{run_label}`: solve_rate={item['solve_rate']}; "
                f"milestone_rate={item['milestone_rate']}; "
                f"pivot_rate={item['pivot_rate']}; "
                f"recovered_rate={item['recovered_after_block_rate']}; "
                f"revealed_rate={item['used_revealed_value_rate']}; "
                f"avg_reward={item['avg_reward']}; attempts={item['attempts']}"
            )
        if summary["heldout_transfer"]["by_run_class"]:
            heldout_lines.extend(
                [
                    "",
                    "Held-out transfer eval by class:",
                    "",
                ]
            )
            for key, item in summary["heldout_transfer"]["by_run_class"].items():
                heldout_lines.append(
                    f"- `{key}`: flag_rate={item['flag_rate']}; "
                    f"milestone_rate={item['milestone_rate']}; "
                    f"pivot_rate={item['pivot_rate']}; "
                    f"recovered_rate={item['recovered_after_block_rate']}; "
                    f"revealed_rate={item['used_revealed_value_rate']}; "
                    f"avg_reward={item['avg_reward']}; attempts={item['attempts']}"
                )
    return "\n".join(
        [
            SUMMARY_START,
            "",
            "## Generated Summary",
            "",
            "Generated by `python3 scripts/validation/build_evidence_ledger.py --write`.",
            "",
            f"- Ledger JSONL: `{repo_rel(jsonl_path)}`",
            f"- Source status matrix: `{repo_rel(matrix_path)}`",
            f"- Canonical score: `{summary['canonical_score']}`",
            f"- Target rows: `{summary['target_count']}`",
            f"- Needs review: `{summary['needs_review_count']}`",
            "",
            "Outcome counts:",
            "",
            outcome_lines,
            "",
            "No-Exploit-No-Report taxonomy counts:",
            "",
            reportability_lines,
            "",
            "Review flags:",
            "",
            review_lines,
            *heldout_lines,
            "",
            SUMMARY_END,
        ]
    )


def update_markdown_summary(path: Path, summary_block: str) -> None:
    text = path.read_text(encoding="utf-8") if path.exists() else ""
    if SUMMARY_START in text and SUMMARY_END in text:
        start = text.index(SUMMARY_START)
        end = text.index(SUMMARY_END) + len(SUMMARY_END)
        text = text[:start].rstrip() + "\n\n" + summary_block + "\n" + text[end:].lstrip("\n")
    else:
        text = text.rstrip() + "\n\n" + summary_block + "\n"
    path.write_text(text, encoding="utf-8")


def validate_rows(rows: list[dict[str, Any]]) -> None:
    seen = set()
    for row in rows:
        if row["row_id"] in seen:
            raise ValueError(f"duplicate row_id: {row['row_id']}")
        seen.add(row["row_id"])
        if row["outcome"] not in ALLOWED_OUTCOMES:
            raise ValueError(f"invalid outcome for {row['target']}: {row['outcome']}")
        if row["outcome"] == "solved" and row["evidence_level"] == "matrix_status":
            raise ValueError(f"solved row lacks validation artifact: {row['target']}")
        if row["outcome"] == "solved" and not row["evidence_ref"]:
            raise ValueError(f"solved row lacks evidence_ref: {row['target']}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gap-matrix", type=Path, default=DEFAULT_GAP_MATRIX)
    parser.add_argument("--validation-root", type=Path, default=DEFAULT_VALIDATION_ROOT)
    parser.add_argument("--ledger-jsonl", type=Path, default=DEFAULT_LEDGER_JSONL)
    parser.add_argument("--ledger-md", type=Path, default=DEFAULT_LEDGER_MD)
    parser.add_argument(
        "--transfer-matrix",
        action="append",
        type=Path,
        help=(
            "Optional held-out transfer matrix JSON. Rows are added as "
            "heldout_transfer_eval evidence and do not change the XBOW score."
        ),
    )
    parser.add_argument("--write", action="store_true", help="write JSONL and Markdown summary")
    parser.add_argument("--summary-json", action="store_true", help="print summary JSON")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    rows = build_ledger(args.gap_matrix, args.validation_root, args.transfer_matrix or [])
    validate_rows(rows)
    summary = summarize(rows)
    if args.write:
        write_jsonl(rows, args.ledger_jsonl)
        update_markdown_summary(
            args.ledger_md,
            render_summary_block(summary, args.ledger_jsonl, args.gap_matrix),
        )
    if args.summary_json or not args.write:
        print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
