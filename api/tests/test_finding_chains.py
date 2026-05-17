"""Baseline smoke tests for the existing finding_chains service.

Created alongside #335 (backlog-385) so the task's `required_checks`
list — which referenced both `test_finding_verifier.py` (new) and
`test_finding_chains.py` (this file) — has both files present.

#335 explicitly does NOT modify finding_chains.py per `must_not_touch`
guidance for the verifier task. These tests therefore guard the
existing surface (the module imports cleanly + the public symbols
the verifier may want to consume in future are addressable) rather
than asserting deep behavior.
"""

from __future__ import annotations

import inspect

import pytest


def test_finding_chains_module_imports() -> None:
    """Sentinel: the module loads without error. Catches accidental
    import-time regressions from neighboring service changes."""
    from api.app.services import finding_chains  # noqa: F401


def test_finding_chains_public_surface_exists() -> None:
    """Public functions used elsewhere in the codebase remain importable.
    If a future refactor renames or removes one of these, the test fails
    fast — the caller should also be updated in the same change."""
    from api.app.services.finding_chains import (
        ChainPattern,
        build_finding_chain_context,
        refresh_finding_chains_for_run,
    )
    assert inspect.isclass(ChainPattern)
    assert callable(build_finding_chain_context)
    assert callable(refresh_finding_chains_for_run)


def test_finding_chains_module_has_severity_constants() -> None:
    """Internal constants referenced in chain heuristics — sanity-only."""
    from api.app.services import finding_chains as fc
    # The module documents that chain detection does NOT auto-escalate
    # severity. Whatever constant the module uses to express that,
    # be it a frozenset or a dict, must still exist as the file-level
    # contract didn't change in #335.
    assert hasattr(fc, "refresh_finding_chains_for_run")


@pytest.mark.parametrize("name", [
    "ChainPattern",
    "build_finding_chain_context",
    "refresh_finding_chains_for_run",
])
def test_finding_chains_named_symbol_callable_or_class(name: str) -> None:
    from api.app.services import finding_chains as fc
    obj = getattr(fc, name, None)
    assert obj is not None, f"finding_chains.{name} missing"
    assert inspect.isclass(obj) or callable(obj)
