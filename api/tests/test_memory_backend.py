"""Baseline regression tests for memory_backend.execute (created
alongside #332). Covers view / create / str_replace / insert / delete
/ rename + the security guard rails. The truncation behavior is tested
in test_memory_backend_truncation.py.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from api.app.services import memory_backend


@pytest.fixture(autouse=True)
def isolated_memory_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "memories"
    root.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("AEGISPT_MEMORY_ROOT", str(root))
    return root


# ---------------------------------------------------------------------------
# create + view
# ---------------------------------------------------------------------------


def test_create_then_view_round_trip(isolated_memory_root: Path) -> None:
    create_resp = memory_backend.execute(
        "create",
        path="/memories/notes/hello.md",
        file_text="line one\nline two\n",
    )
    assert "File created successfully" in create_resp
    view_resp = memory_backend.execute("view", path="/memories/notes/hello.md")
    assert "line one" in view_resp
    assert "line two" in view_resp


def test_create_refuses_overwrite(isolated_memory_root: Path) -> None:
    memory_backend.execute("create", path="/memories/x.md", file_text="a")
    second = memory_backend.execute("create", path="/memories/x.md", file_text="b")
    assert "Error: File" in second and "already exists" in second


def test_view_directory_lists_files(isolated_memory_root: Path) -> None:
    memory_backend.execute("create", path="/memories/a.md", file_text="a")
    memory_backend.execute("create", path="/memories/b.md", file_text="b")
    resp = memory_backend.execute("view", path="/memories")
    assert "/memories/a.md" in resp
    assert "/memories/b.md" in resp


def test_view_missing_path_returns_clear_error(isolated_memory_root: Path) -> None:
    resp = memory_backend.execute("view", path="/memories/does-not-exist.md")
    assert "does not exist" in resp


# ---------------------------------------------------------------------------
# str_replace
# ---------------------------------------------------------------------------


def test_str_replace_happy_path(isolated_memory_root: Path) -> None:
    memory_backend.execute("create", path="/memories/r.md", file_text="hello world")
    resp = memory_backend.execute(
        "str_replace", path="/memories/r.md", old_str="world", new_str="ZIE-DAAR",
    )
    assert "memory file has been edited" in resp
    view = memory_backend.execute("view", path="/memories/r.md")
    assert "hello ZIE-DAAR" in view


def test_str_replace_zero_occurrences(isolated_memory_root: Path) -> None:
    memory_backend.execute("create", path="/memories/r.md", file_text="hello")
    resp = memory_backend.execute(
        "str_replace", path="/memories/r.md", old_str="absent", new_str="x",
    )
    assert "No replacement was performed" in resp


def test_str_replace_multiple_occurrences_rejected(isolated_memory_root: Path) -> None:
    memory_backend.execute("create", path="/memories/r.md", file_text="x\nx\nx\n")
    resp = memory_backend.execute(
        "str_replace", path="/memories/r.md", old_str="x", new_str="y",
    )
    assert "Multiple occurrences" in resp


# ---------------------------------------------------------------------------
# insert
# ---------------------------------------------------------------------------


def test_insert_at_zero_prepends(isolated_memory_root: Path) -> None:
    memory_backend.execute("create", path="/memories/i.md", file_text="b\nc\n")
    resp = memory_backend.execute(
        "insert", path="/memories/i.md", insert_line=0, insert_text="a",
    )
    assert "has been edited" in resp
    view = memory_backend.execute("view", path="/memories/i.md")
    # First content line (after the header) is "a".
    assert "\n     1\ta" in view


def test_insert_invalid_line_returns_error(isolated_memory_root: Path) -> None:
    memory_backend.execute("create", path="/memories/i.md", file_text="x")
    resp = memory_backend.execute(
        "insert", path="/memories/i.md", insert_line=999, insert_text="y",
    )
    assert "Invalid `insert_line`" in resp


# ---------------------------------------------------------------------------
# delete + rename
# ---------------------------------------------------------------------------


def test_delete_file(isolated_memory_root: Path) -> None:
    memory_backend.execute("create", path="/memories/d.md", file_text="x")
    resp = memory_backend.execute("delete", path="/memories/d.md")
    assert "Successfully deleted" in resp
    follow = memory_backend.execute("view", path="/memories/d.md")
    assert "does not exist" in follow


def test_delete_root_refused(isolated_memory_root: Path) -> None:
    resp = memory_backend.execute("delete", path="/memories")
    assert "refusing to delete the memories root" in resp


def test_rename_round_trip(isolated_memory_root: Path) -> None:
    memory_backend.execute("create", path="/memories/old.md", file_text="x")
    resp = memory_backend.execute(
        "rename", old_path="/memories/old.md", new_path="/memories/new.md",
    )
    assert "Successfully renamed" in resp
    assert "x" in memory_backend.execute("view", path="/memories/new.md")


# ---------------------------------------------------------------------------
# Security
# ---------------------------------------------------------------------------


def test_traversal_rejected(isolated_memory_root: Path) -> None:
    resp = memory_backend.execute("view", path="/memories/../../../etc/passwd")
    assert resp.startswith("Error:")


def test_unknown_command_returns_error_not_raise(isolated_memory_root: Path) -> None:
    resp = memory_backend.execute("does_not_exist_cmd", path="/memories/x")
    assert resp.startswith("Error: unknown memory command")
