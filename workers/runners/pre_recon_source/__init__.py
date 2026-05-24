"""Pre-recon source-audit runner (Phase 4 of landscape-plan 2026-05-22).

Shannon-style white-box pre-reconnaissance: read the target's source code
(when available — XBOW source-aware mode, or an authorised pentest with
read access to the repo) and extract:

- Framework routes (Flask/Django/FastAPI/Rails entrypoints)
- Dangerous sinks (eval/exec/os.system/subprocess shell=True/raw SQL)
- Auth decorators + cred handling
- Default/seed credentials in migrations
- Template renders that pass user input unsanitised

Output is a `pre-recon-source-deliverable.md` artifact that the
specialist orchestrator reads BEFORE the network recon, giving the AI
ground-truth attack surface instead of best-effort HTTP probes.

Contamination guard: this runner refuses to run unless an explicit
``source_dir`` parameter is passed. The harness must wire it; runs
against a black-box target keep doing network-only recon.
"""
from .runner import (
    PRE_RECON_SOURCE_ARTIFACT_NAME,
    execute_pre_recon_source,
)

__all__ = ["PRE_RECON_SOURCE_ARTIFACT_NAME", "execute_pre_recon_source"]
