"""Track 0 (recon→action): discovered endpoints become an explicit pursue-backlog."""
from __future__ import annotations

from api.app.services.attack_surface import (
    discovered_attack_surface,
    render_attack_surface_block,
)

# Shaped like the real Gruyere findings: title + target_id (path in the URL).
GRUYERE_FINDINGS = [
    {"title": "Hidden Endpoint Discovered", "target_id": "https://x/123/admin"},
    {"title": "Hidden Endpoint Discovered", "target_id": "https://x/123/upload.gtl"},
    {"title": "Hidden Endpoint Discovered", "target_id": "https://x/123/saveprofile"},
    {"title": "Hidden Endpoint Discovered", "target_id": "https://x/123/feed.gtl"},
    {"title": "Session Cookie Theft via XSS", "target_id": "https://x/123/"},  # not an endpoint finding
]


def test_extracts_discovered_endpoints_only():
    surface = discovered_attack_surface(GRUYERE_FINDINGS)
    eps = {it["endpoint"] for it in surface}
    assert "https://x/123/admin" in eps
    assert "https://x/123/upload.gtl" in eps
    # the XSS finding is NOT an endpoint discovery → excluded
    assert "https://x/123/" not in eps
    assert len(surface) == 4


def test_high_value_endpoints_ranked_first():
    surface = discovered_attack_surface(GRUYERE_FINDINGS)
    # /admin, /upload, /saveprofile carry a specific focus and sort before the generic /feed
    foci = {it["endpoint"]: it["focus"] for it in surface}
    assert "access-control" in foci["https://x/123/admin"]
    assert "upload" in foci["https://x/123/upload.gtl"].lower()
    # generic endpoint gets the generic probe focus and is ordered last
    assert surface[-1]["endpoint"] == "https://x/123/feed.gtl"
    assert surface[-1]["focus"].startswith("probe:")


def test_dedup_and_empty():
    dup = GRUYERE_FINDINGS + [{"title": "Hidden Endpoint Discovered", "target_id": "https://x/123/admin"}]
    assert len(discovered_attack_surface(dup)) == 4  # /admin deduped
    assert discovered_attack_surface([]) == []


def test_render_block_lists_endpoints_and_is_empty_when_none():
    block = render_attack_surface_block(GRUYERE_FINDINGS)
    assert "PENDING ATTACK SURFACE" in block
    assert "do NOT stop while any remain" in block
    assert "/admin" in block and "/upload.gtl" in block
    # no discoveries yet -> no block (no noise on a fresh run)
    assert render_attack_surface_block([{"title": "Session Cookie Theft via XSS", "target_id": "https://x/"}]) == ""


def test_specialist_context_includes_attack_surface_block():
    # Track 0: the backlog must reach the SPECIALISTS (black-box exploitation path),
    # not only the source-aware CPG-CEA context.
    from api.app.services.picker_specialists.orchestrator import (
        _build_user_content_for_specialist,
    )
    block = render_attack_surface_block(GRUYERE_FINDINGS)
    uc = _build_user_content_for_specialist(
        recon_deliverable="r", available_tools=["x"],
        prior_findings_summary="f", attack_surface_block=block,
    )
    assert "PENDING ATTACK SURFACE" in uc
    assert "/admin" in uc
    # no block passed -> no section (default empty, no noise)
    uc0 = _build_user_content_for_specialist(
        recon_deliverable="r", available_tools=["x"], prior_findings_summary="f",
    )
    assert "PENDING ATTACK SURFACE" not in uc0
