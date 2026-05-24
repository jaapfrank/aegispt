"""Joern-based CPG pre-recon runner (M3 of beat-shannon-pro-roadmap-2026-05-23).

Generates a Code Property Graph from authorised source via Joern's
language-specific frontends, runs a small taint query to surface
HTTP-source -> dangerous-sink flows, and emits a markdown deliverable
the orchestrator concatenates with the regex-based pre-recon-source
audit.

NOT a replacement for `pre_recon_source` — additive. Where the regex
audit produces a quick route/sink list from grep, this runner produces
ACTUAL dataflow paths (source -> sink with intermediate nodes).
"""

from .runner import (  # noqa: F401
    PRE_RECON_CPG_ARTIFACT_NAME,
    execute_pre_recon_cpg,
)
