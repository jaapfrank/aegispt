"""Internal helpers extracted from assessment_loop.py during the O4 split.

This package is the new home for code that used to live as private helpers
inside the 6680-line assessment_loop module. The split is incremental:
each commit moves one logical block (helpers, then guards, then recall,
then candidate cascade, ...) without changing behaviour. The legacy
``assessment_loop.py`` keeps the public surface (advance_assessment_loop,
build_assessment_loop_state, record_assessment_loop_goal) and re-imports
from here so existing callers do not move.

See docs/plans/session-followups-2026-05-24.md (O4) for the full target
module layout.
"""
