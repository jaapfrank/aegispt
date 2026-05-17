"""Tests for memory_backend view-truncation + run-progress rotation (#332)."""

from __future__ import annotations

from pathlib import Path

import pytest

from api.app.services import memory_backend
from api.app.services.memory_backend import (
    ROTATE_KEEP_BYTES,
    ROTATE_THRESHOLD_BYTES,
    RUN_PROGRESS_LOGICAL_PATH,
    VIEW_MAX_BYTES,
    _truncate_for_view,
    rotate_run_progress,
)


@pytest.fixture(autouse=True)
def isolated_memory_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "memories"
    root.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("AEGISPT_MEMORY_ROOT", str(root))
    return root


# ---------------------------------------------------------------------------
# _truncate_for_view (pure helper)
# ---------------------------------------------------------------------------


def test_truncate_passthrough_when_under_cap() -> None:
    """Payloads under VIEW_MAX_BYTES are returned unchanged."""
    small = "x" * 100
    assert _truncate_for_view(small) == small


def test_truncate_caps_oversized_payload_with_marker() -> None:
    """Oversized payloads get a [...truncated, N more bytes] marker."""
    big = "x" * (VIEW_MAX_BYTES * 3)
    result = _truncate_for_view(big)
    assert len(result.encode("utf-8")) <= VIEW_MAX_BYTES + 256  # marker tail
    assert "[...truncated," in result
    assert "more bytes" in result


def test_truncate_marker_reports_dropped_byte_count() -> None:
    big = "y" * (VIEW_MAX_BYTES + 500)
    result = _truncate_for_view(big)
    # 500 bytes were dropped.
    assert "500 more bytes" in result


def test_truncate_includes_logical_path_hint() -> None:
    big = "z" * (VIEW_MAX_BYTES * 2)
    result = _truncate_for_view(big, logical_path="/memories/big.md")
    assert "/memories/big.md" in result
    assert "view_range" in result


def test_truncate_handles_none_payload() -> None:
    assert _truncate_for_view(None) == ""  # type: ignore[arg-type]


def test_truncate_handles_utf8_boundary() -> None:
    """Truncating mid-multi-byte-codepoint should not raise."""
    # Build a string that has a multi-byte char straddling the cap.
    multi = "é" * (VIEW_MAX_BYTES * 2)  # "é" = 2 UTF-8 bytes
    result = _truncate_for_view(multi)
    # Must be decodable.
    result.encode("utf-8").decode("utf-8")  # no exception
    assert "[...truncated," in result


# ---------------------------------------------------------------------------
# view command — integration with execute()
# ---------------------------------------------------------------------------


def test_view_command_caps_large_file(isolated_memory_root: Path) -> None:
    """Writing a 10 KB file then viewing it returns a capped response."""
    huge = "abcdefghij" * 2000  # 20 KB
    memory_backend.execute("create", path="/memories/huge.md", file_text=huge)
    resp = memory_backend.execute("view", path="/memories/huge.md")
    assert len(resp.encode("utf-8")) <= VIEW_MAX_BYTES + 256
    assert "[...truncated," in resp


def test_view_command_preserves_small_files(isolated_memory_root: Path) -> None:
    """Files under the cap pass through with no marker."""
    small = "line one\nline two\n"
    memory_backend.execute("create", path="/memories/small.md", file_text=small)
    resp = memory_backend.execute("view", path="/memories/small.md")
    assert "[...truncated," not in resp
    assert "line one" in resp


def test_view_command_writes_are_uncapped(isolated_memory_root: Path) -> None:
    """Per task constraint preserve_writes: writes are NOT capped, only
    reads. The on-disk file must equal what was written."""
    huge = "abcdefghij" * 2000  # 20 KB
    memory_backend.execute("create", path="/memories/huge2.md", file_text=huge)
    on_disk = (isolated_memory_root / "huge2.md").read_text(encoding="utf-8")
    assert on_disk == huge  # full content preserved


def test_view_directory_listing_capped(isolated_memory_root: Path) -> None:
    """A directory with many files yields a long listing — must be
    capped too."""
    for i in range(500):
        memory_backend.execute(
            "create",
            path=f"/memories/many/file_{i:04d}.md",
            file_text="x",
        )
    resp = memory_backend.execute("view", path="/memories/many")
    assert len(resp.encode("utf-8")) <= VIEW_MAX_BYTES + 256
    assert "[...truncated," in resp


# ---------------------------------------------------------------------------
# rotate_run_progress
# ---------------------------------------------------------------------------


def test_rotate_noop_when_file_missing(isolated_memory_root: Path) -> None:
    assert rotate_run_progress() is None


def test_rotate_noop_when_under_threshold(isolated_memory_root: Path) -> None:
    memory_backend.execute(
        "create",
        path=RUN_PROGRESS_LOGICAL_PATH,
        file_text="small log\n" * 10,
    )
    assert rotate_run_progress() is None
    # File unchanged.
    rel = RUN_PROGRESS_LOGICAL_PATH.removeprefix("/memories/")
    assert (isolated_memory_root / rel).stat().st_size < ROTATE_THRESHOLD_BYTES


def test_rotate_trims_oversized_file(isolated_memory_root: Path) -> None:
    """Writing a 20 KB run-progress.md then rotating should shrink it
    to ≤ keep_bytes + header overhead."""
    big = "log line padded for size\n" * 1000  # ~25 KB
    memory_backend.execute(
        "create", path=RUN_PROGRESS_LOGICAL_PATH, file_text=big,
    )
    result = rotate_run_progress()
    assert result is not None
    assert result["before"] > ROTATE_THRESHOLD_BYTES
    # Allow some headroom for the rotation header
    assert result["after"] <= ROTATE_KEEP_BYTES + 512
    assert result["dropped"] == result["before"] - result["after"]


def test_rotate_preserves_recent_tail(isolated_memory_root: Path) -> None:
    """The tail (most recent content) must survive rotation."""
    # Head needs to be large enough that head + tail > threshold AND
    # the head ends up outside the keep window.
    head = "ANCIENT_HEADER_DROP_ME\n" + "filler line padded for size\n" * 1000
    tail_marker = "FRESH_TAIL_KEEP_ME_PLEASE\n"
    payload = head + tail_marker
    memory_backend.execute(
        "create", path=RUN_PROGRESS_LOGICAL_PATH, file_text=payload,
    )
    result = rotate_run_progress()
    assert result is not None, "expected rotation to fire on oversized file"
    rel = RUN_PROGRESS_LOGICAL_PATH.removeprefix("/memories/")
    after = (isolated_memory_root / rel).read_text(encoding="utf-8")
    assert tail_marker.strip() in after
    assert "ANCIENT_HEADER_DROP_ME" not in after


def test_rotate_includes_header_marker(isolated_memory_root: Path) -> None:
    """Rotated file should have a small comment header so future
    Claude reads see it was rotated, not silently truncated."""
    big = "filler\n" * 2000
    memory_backend.execute(
        "create", path=RUN_PROGRESS_LOGICAL_PATH, file_text=big,
    )
    rotate_run_progress()
    rel = RUN_PROGRESS_LOGICAL_PATH.removeprefix("/memories/")
    after = (isolated_memory_root / rel).read_text(encoding="utf-8")
    assert "Rotated by memory_backend.rotate_run_progress" in after
    assert "Original size:" in after


def test_rotate_idempotent_when_already_small(isolated_memory_root: Path) -> None:
    """Calling rotate twice on an already-small file is safe."""
    memory_backend.execute(
        "create", path=RUN_PROGRESS_LOGICAL_PATH, file_text="x" * 100,
    )
    assert rotate_run_progress() is None
    assert rotate_run_progress() is None


def test_rotate_respects_custom_thresholds(isolated_memory_root: Path) -> None:
    """Callers can override threshold + keep for tests / different
    use cases."""
    memory_backend.execute(
        "create",
        path=RUN_PROGRESS_LOGICAL_PATH,
        file_text="line\n" * 500,  # ~2500 bytes
    )
    # Use a tight threshold so rotation fires on a smaller file.
    result = rotate_run_progress(threshold_bytes=1024, keep_bytes=512)
    assert result is not None
    assert result["after"] <= 512 + 256


# ---------------------------------------------------------------------------
# Constants are sensible
# ---------------------------------------------------------------------------


def test_constants_match_task_contract() -> None:
    """The task package fixes these numbers; sentinel against silent
    drift."""
    assert VIEW_MAX_BYTES == 2048
    assert ROTATE_THRESHOLD_BYTES == 8192
    assert ROTATE_KEEP_BYTES == 6144
    assert RUN_PROGRESS_LOGICAL_PATH == "/memories/run-progress.md"
    assert ROTATE_KEEP_BYTES < ROTATE_THRESHOLD_BYTES  # rotation must shrink
