#!/usr/bin/env python3
"""Score-climb orchestrator — backlog-423.

End-to-end iteration cycle:

    1. Read the most recent XBOW baseline JSON.
    2. Cluster failure modes via failure_analysis.cluster_failures.
    3. Emit one versioned prompt proposal per cluster via
       proposal_generator.generate_proposals (all `approve: false`).
    4. Write a delta-report markdown that lists every proposal + the
       operator's next-action checklist.

Per backlog-423 ``no_runtime_self_modification``: proposals NEVER land
in ``prompts/active/`` automatically. The operator reviews, flips
``approve: true``, and runs ``scripts/aegispt_promote_proposal.py`` —
which is the only entry into :func:`api.app.agents.coordinator.approve_prompt_change`.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from api.app.services.failure_analysis import cluster_failures, summarize_patterns  # noqa: E402
from api.app.services.proposal_generator import generate_proposals, proposal_summary  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="XBOW score-climb iteration orchestrator")
    parser.add_argument(
        "--baseline",
        type=Path,
        default=REPO_ROOT / "docs/validation/xbow-2026-05-21-baseline.json",
        help="Path to an XBOW baseline JSON emitted by scripts/xbow_benchmark.py",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=REPO_ROOT / "prompts/proposals",
        help="Where to write generated proposal Markdown files.",
    )
    parser.add_argument(
        "--report-out",
        type=Path,
        default=REPO_ROOT / "docs/validation",
        help="Where to write the delta-report.",
    )
    args = parser.parse_args(argv)

    patterns = cluster_failures(args.baseline)
    written = generate_proposals(patterns, output_dir=args.output_dir)

    today = datetime.now(UTC).strftime("%Y-%m-%d")
    report_path = args.report_out / f"xbow-score-climb-{today}.md"
    report_path.parent.mkdir(parents=True, exist_ok=True)

    summary = summarize_patterns(patterns)
    files_summary = proposal_summary(patterns, written)

    lines: list[str] = [
        f"# XBOW score-climb iteration — {today}",
        "",
        f"**Baseline source:** `{args.baseline}`",
        f"**Total failed challenges:** {summary['total_failed']}",
        f"**Cluster count:** {summary['cluster_count']}",
        f"**Proposals generated:** {files_summary['proposals_generated']}",
        "",
        "## Failure clusters",
        "",
        "| cluster | mode | change kind | affected | target component |",
        "|---|---|---|---|---|",
    ]
    for p in patterns:
        lines.append(
            f"| {p.cluster_name} | `{p.failure_mode}` | {p.change_kind} | "
            f"{len(p.affected_challenges)} | {p.proposed_target_component[:60]} |"
        )

    lines.extend([
        "",
        "## Proposals (review + approve + promote)",
        "",
    ])
    for f in written:
        try:
            display = f.relative_to(REPO_ROOT).as_posix()
        except ValueError:
            # Output dir lives outside the repo (operator-chosen path) —
            # fall back to the absolute path for the report.
            display = str(f)
        lines.append(f"- `{display}`")

    lines.extend([
        "",
        "## Next-action checklist (operator)",
        "",
        "1. Open each proposal file under `prompts/proposals/`.",
        "2. Review the failure pattern + proposed change.",
        "3. If correct, flip `approve: false` → `approve: true` in the file.",
        "4. Run `python3 scripts/aegispt_promote_proposal.py <file> --approver <handle>`.",
        "5. Re-run `scripts/xbow_benchmark.py` to measure the delta.",
        "6. Compare to baseline; if score climbed, commit. If not, iterate.",
        "",
        "## Raw cluster summary (JSON)",
        "",
        "```json",
        json.dumps(summary, indent=2, default=str),
        "```",
        "",
    ])

    report_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"score-climb iteration written: {report_path}")
    print(f"{files_summary['proposals_generated']} proposals under {args.output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
