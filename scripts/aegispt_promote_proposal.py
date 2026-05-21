#!/usr/bin/env python3
"""CLI wrapper around api.app.agents.coordinator.approve_prompt_change.

Per backlog-423 / backlog-415: agents NEVER overwrite their own prompts at
runtime. This CLI is the operator-facing path that promotes a proposal
under ``prompts/proposals/`` into ``prompts/active/<role>.md``. The
proposal MUST contain an ``approve: true`` header line — opening the file
in an editor and flipping the value is the explicit operator action.

Usage::

    python3 scripts/aegispt_promote_proposal.py \\
        prompts/proposals/2026-05-21-recon-rev1.md \\
        --approver jaap
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from api.app.agents.coordinator import approve_prompt_change  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Promote a versioned prompt proposal into prompts/active/")
    parser.add_argument("proposal_file", type=Path, help="Path to the proposal Markdown.")
    parser.add_argument("--approver", required=True, help="Operator identity (recorded in audit log).")
    parser.add_argument(
        "--role",
        default=None,
        help="Specialist role override (inferred from filename when omitted).",
    )
    args = parser.parse_args(argv)

    try:
        dest = approve_prompt_change(
            args.proposal_file,
            approver=args.approver,
            role=args.role,  # type: ignore[arg-type]  # SpecialistRole | None at runtime
        )
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 3
    print(f"promoted to {dest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
