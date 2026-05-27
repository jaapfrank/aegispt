from __future__ import annotations

from datetime import datetime, timedelta, UTC
from types import SimpleNamespace
from uuid import uuid4

import pytest

from api.app.services.assessment_loop import (
    _DEFAULT_WALL_CLOCK_BUDGET_SECONDS,
    _run_budget_exhausted,
)


def _make_run(*, started_minutes_ago: float, budget_seconds: float | None = None):
    cfg = {}
    if budget_seconds is not None:
        cfg["wall_clock_budget_seconds"] = budget_seconds
    return SimpleNamespace(
        id=uuid4(),
        configuration_json=cfg,
        started_at=datetime.now(UTC) - timedelta(minutes=started_minutes_ago),
    )


def test_run_within_default_budget_is_not_exhausted() -> None:
    run = _make_run(started_minutes_ago=5)
    assert _run_budget_exhausted(run) is False


def test_run_past_default_budget_is_exhausted(caplog) -> None:
    # Default budget is 1800s = 30min. 35min ago -> exhausted.
    run = _make_run(started_minutes_ago=35)
    with caplog.at_level("WARNING"):
        assert _run_budget_exhausted(run) is True
    assert any("PROOF_EXEC_RUN_BUDGET_EXHAUSTED_2026052712" in m for m in caplog.messages)


def test_explicit_short_budget_fires_early() -> None:
    # Budget=60s, run started 5min ago -> exhausted.
    run = _make_run(started_minutes_ago=5, budget_seconds=60.0)
    assert _run_budget_exhausted(run) is True


def test_explicit_long_budget_holds() -> None:
    # Budget=2 hours, run started 30min ago -> NOT exhausted.
    run = _make_run(started_minutes_ago=30, budget_seconds=7200.0)
    assert _run_budget_exhausted(run) is False


def test_missing_started_at_returns_false() -> None:
    run = SimpleNamespace(id=uuid4(), configuration_json={}, started_at=None)
    assert _run_budget_exhausted(run) is False


def test_iso_string_started_at_parsed() -> None:
    iso = (datetime.now(UTC) - timedelta(hours=2)).isoformat().replace("+00:00", "Z")
    run = SimpleNamespace(id=uuid4(), configuration_json={"wall_clock_budget_seconds": 60.0}, started_at=iso)
    assert _run_budget_exhausted(run) is True


def test_default_budget_constant() -> None:
    assert _DEFAULT_WALL_CLOCK_BUDGET_SECONDS == 1800.0


def test_env_override_when_config_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AEGISPT_RUN_BUDGET_SECONDS", "60")
    run = SimpleNamespace(
        id=uuid4(),
        configuration_json={},
        started_at=datetime.now(UTC) - timedelta(minutes=5),
    )
    assert _run_budget_exhausted(run) is True
