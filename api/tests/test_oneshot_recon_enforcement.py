"""Enforce the picker prompt's stated ONE-SHOT-per-run recon hard rule (2026-06-12).

The prompt says "Recon tools (httpx, target-intel, content-discovery, smart-web-probe,
nuclei, ...) are ONE-SHOT per run ... the system enforces these in code" — but it did NOT,
so weaker models re-picked httpx 30+ times on sub-paths (action-light churn). These tests
lock the menu-level enforcement: a recon tool that has already run is hidden from the picker.
"""
from __future__ import annotations

from api.app.services.assessment_loop import _ONE_SHOT_RECON_TOOLS, _oneshot_recon_to_hide


def test_nothing_run_hides_nothing():
    assert _oneshot_recon_to_hide(set()) == set()


def test_dispatched_recon_tool_is_hidden():
    assert _oneshot_recon_to_hide({"httpx|http://t/"}) == {"httpx"}


def test_multiple_recon_tools_hidden():
    keys = {"httpx|http://t/", "content-discovery|http://t/", "target-intel|http://t/"}
    assert _oneshot_recon_to_hide(keys) == {"httpx", "content-discovery", "target-intel"}


def test_exploit_tools_are_never_hidden():
    # ssti-probe / interactive-exploit / idor-bac are exploitation, not one-shot recon.
    keys = {"ssti-probe|http://t/", "interactive-exploit|http://t/", "idor-bac|http://t/"}
    assert _oneshot_recon_to_hide(keys) == set()


def test_recon_on_subpath_still_hides_the_root_tool():
    # httpx on the root AND a sub-path both map to the tool key -> hidden either way.
    assert _oneshot_recon_to_hide({"httpx|http://t/admin"}) == {"httpx"}


def test_exploit_tools_not_in_the_oneshot_set():
    for exploit in ("interactive-exploit", "exec-plan", "ssti-probe", "sqlmap", "idor-bac"):
        assert exploit not in _ONE_SHOT_RECON_TOOLS
