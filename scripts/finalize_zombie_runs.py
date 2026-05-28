"""Finalize zombie runs — running/queued with NO activity for >10 min.

2026-05-28: predicate changed from ``started_at < NOW() - 5min`` to
``updated_at < NOW() - 10min`` to match the in-process zombie-sweeper fix
in api/app/services/scheduled_runs.py. The old started_at-based check
killed healthy long-running challenge runs (900s wall-clock budget) at
5 minutes. ``updated_at`` (onupdate=func.now()) is the correct
last-activity signal; only genuinely-hung runs trip the 10-min window.
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from sqlalchemy import create_engine, text
from api.app.config import get_settings

eng = create_engine(get_settings().database_url)
with eng.begin() as cx:
    rows = cx.execute(text(
        "UPDATE runs SET status='completed_with_errors', updated_at=NOW() "
        "WHERE status IN ('running','queued') "
        "AND updated_at < NOW() - INTERVAL '10 minutes' "
        "RETURNING id, status"
    )).fetchall()
    print(f"finalized {len(rows)} zombie runs (no activity >10min)")
    for r in rows[:20]:
        print(" -", r[0])
