"""Top-level loop-state constants used across the assessment-loop code.

Extracted from assessment_loop.py (O4 step 8). All public CAPS-named
constants that drive loop policy decisions live here. The legacy file
re-imports them under the same names so call sites do not move.
"""
from __future__ import annotations

LOOP_VERSION = "2026-05-07.1"
LOOP_CONFIG_KEY = "ai_assessment_loop"
GOAL_REASONING_KIND = "assessment_loop_goal_oriented_reasoning"
LOOP_MAX_ITERATIONS = 35
LOOP_STUCK_THRESHOLD = 3
LOOP_ACTIVE_TASK_STATUSES = {"queued", "pending", "running", "dispatching", "in_progress", "started"}
LOOP_TERMINAL_STATUSES = {"completed", "failed", "cancelled", "skipped"}
LOOP_PROPOSAL_KIND = "assessment_loop_next_action"
LOOP_SEED_TOOLS_BY_TARGET_KIND = {
    # target-intel runs FIRST for web targets in ai_loop mode.
    # It analyzes the site with Claude before any scanning tool runs,
    # detects the technology stack, identifies applicable CVEs, and
    # creates a targeted scan plan. httpx is the fallback for non-ai_loop runs.
    "url": "target-intel",
    "host": "nmap",
    "cidr": "nmap",
    "domain": "easm-discover",
    "target": "target-intel",
}
LOOP_LOW_IMPACT_AUTO_TOOLS = {"httpx", "target-intel"}

# Depth levels — each level represents a strategic decision point
# Level 1: Discovery (surface mapping, no findings yet)
# Level 2: Probing (attack surface identified, testing for weaknesses)
# Level 3: Confirmation (vulnerability confirmed, exploiting)
# Level 4: Post-exploitation (session/credential material obtained)
DEPTH_LEVEL_LABELS = {
    1: "Verkenning",
    2: "Kwetsbaarheidstests",
    3: "Bevestiging & Exploitatie",
    4: "Escalatie",
}
