"""Recon deliverable runner (Phase 2 of landscape-plan 2026-05-22).

Produces the Shannon-style 9-section attack-surface map that the 5
specialist agents consume. Without this, specialists return empty
hypothesis lists because they have no evidence to reason from.
"""
from .runner import RECON_DELIVERABLE_ARTIFACT_NAME, execute_recon_deliverable

__all__ = ["RECON_DELIVERABLE_ARTIFACT_NAME", "execute_recon_deliverable"]
