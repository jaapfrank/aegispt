"""Finalize zombie runs (status=running/queued, older than 5 min)."""
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
        "AND started_at < NOW() - INTERVAL '5 minutes' "
        "RETURNING id, status"
    )).fetchall()
    print(f"finalized {len(rows)} zombie runs")
    for r in rows[:20]:
        print(" -", r[0])
