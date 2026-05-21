"""Score-climb iteration step 2 — generate versioned prompt proposals.

Per backlog-423: after :func:`api.app.services.failure_analysis.cluster_failures`
groups failures, this module turns each pattern into a Markdown file under
``prompts/proposals/{YYYY-MM-DD}-{component}-rev{N}.md``.

Per ``no_runtime_self_modification`` (backlog-415): every generated
proposal starts with ``approve: false`` — the operator MUST flip that to
``approve: true`` and run ``aegispt promote-proposal`` before the change
goes live. The proposal generator never writes into ``prompts/active/``.
"""
from __future__ import annotations

import logging
import os
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from api.app.services.failure_analysis import FailurePattern

logger = logging.getLogger(__name__)


PROMPTS_ROOT_ENV = "AEGISPT_PROMPTS_ROOT"


def _prompts_root() -> Path:
    env = os.environ.get(PROMPTS_ROOT_ENV, "").strip()
    if env:
        return Path(env).expanduser().resolve()
    here = Path(__file__).resolve()
    # api/app/services/proposal_generator.py → up 3 → repo root → prompts/
    return (here.parents[3] / "prompts").resolve()


def _slug_component(target_component: str) -> str:
    """Turn a free-form target name into a filename-safe slug."""
    s = target_component.strip().lower()
    s = re.sub(r"[^a-z0-9]+", "-", s).strip("-")
    return s[:60] or "general"


def _next_rev(proposals_dir: Path, today: str, slug: str) -> int:
    pattern = re.compile(rf"^{re.escape(today)}-{re.escape(slug)}-rev(\d+)\.md$")
    existing = []
    if proposals_dir.is_dir():
        for entry in proposals_dir.iterdir():
            m = pattern.match(entry.name)
            if m:
                existing.append(int(m.group(1)))
    return (max(existing) + 1) if existing else 1


def render_proposal(pattern: FailurePattern, *, today: str | None = None) -> str:
    """Compose the Markdown body for one proposal file (header + sections)."""
    today = today or datetime.now(UTC).strftime("%Y-%m-%d")
    body_lines: list[str] = [
        "approve: false",
        f"title: {pattern.cluster_name}",
        f"change_kind: {pattern.change_kind}",
        f"target_component: {pattern.proposed_target_component}",
        f"generated_at: {today}",
        f"affected_challenge_count: {len(pattern.affected_challenges)}",
        "",
        "## Failure pattern",
        "",
        f"**Mode:** `{pattern.failure_mode}`",
        f"**Affected challenges:** {', '.join(pattern.affected_challenges[:25])}"
        + (" …" if len(pattern.affected_challenges) > 25 else ""),
        "",
        "**Representative error:**",
        "",
        "```",
        pattern.representative_error or "(none captured)",
        "```",
        "",
        "## Root-cause hypothesis",
        "",
        pattern.root_cause_hypothesis or "(operator to fill in)",
        "",
        "## Proposed change",
        "",
        pattern.proposed_change_summary or "(operator to fill in)",
        "",
        "## Operator approval checklist",
        "",
        "- [ ] Read the affected challenges list above; the pattern is real, not a one-off.",
        "- [ ] The proposed change does not violate any ANTI_DRIFT rule (review).",
        "- [ ] Change is reversible OR has a clear rollback path.",
        "- [ ] Flip `approve: false` → `approve: true` only when all 3 boxes are checked.",
        "",
        "After approval, run:",
        "",
        "```",
        "python3 scripts/aegispt_promote_proposal.py <this-file> --approver <your-handle>",
        "```",
        "",
    ]
    return "\n".join(body_lines)


def generate_proposals(
    patterns: list[FailurePattern],
    *,
    output_dir: Path | None = None,
    today: str | None = None,
) -> list[Path]:
    """Write one proposal Markdown per pattern. Returns the list of paths."""
    out_dir = (output_dir or (_prompts_root() / "proposals")).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    today = today or datetime.now(UTC).strftime("%Y-%m-%d")
    written: list[Path] = []
    for pattern in patterns:
        slug = _slug_component(pattern.cluster_name)
        rev = _next_rev(out_dir, today, slug)
        path = out_dir / f"{today}-{slug}-rev{rev}.md"
        body = render_proposal(pattern, today=today)
        path.write_text(body, encoding="utf-8")
        written.append(path)
        logger.info("proposal_generator: wrote %s", path.name)
    return written


def proposal_summary(patterns: list[FailurePattern], written: list[Path]) -> dict[str, Any]:
    return {
        "proposals_generated": len(written),
        "patterns_clustered": len(patterns),
        "files": [str(p) for p in written],
        "next_step": "review each file, set `approve: true`, then run scripts/aegispt_promote_proposal.py",
    }


__all__ = [
    "PROMPTS_ROOT_ENV",
    "generate_proposals",
    "proposal_summary",
    "render_proposal",
]
