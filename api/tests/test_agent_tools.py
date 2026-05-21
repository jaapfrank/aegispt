"""Unit tests for backlog-422 picker agent tools."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from uuid import UUID

import pytest

from api.app.agents.agent_tools import (
    ALL_TOOL_SCHEMAS,
    BashTool,
    CodeExecTool,
    FileReadTool,
    FileWriteTool,
    SubagentSpawnTool,
    ToolResult,
    WebFetchTool,
    WebSearchTool,
    execute_tool_call,
    resolve_tool,
)

# --- Fake run + session (mirrors test_governance_control_plane patterns) ---


@dataclass
class _FakeEngagement:
    id: str = "eng-1"
    roe_ref: str = "ROE-AGENT-TOOLS-2026"
    authorization_confirmed_at: Any = None


@dataclass
class _FakeProfile:
    name: str = "autonomous-web"
    run_class: str = "passive"
    limits_json: dict = field(default_factory=lambda: {"max_rps": 5, "max_concurrency": 3})


@dataclass
class _FakeScope:
    allowlist_json: dict = field(default_factory=dict)
    denylist_json: dict = field(default_factory=dict)


@dataclass
class _FakeRun:
    id: UUID = UUID("00000000-0000-0000-0000-000000000a22")
    engagement_id: str = "eng-1"
    engagement: Any = None
    profile: Any = None
    status: str = "running"
    autonomous_intrusive_allowed: bool = True
    approvals: list = field(default_factory=list)


class _SessionStub:
    def __init__(self, scope: _FakeScope | None) -> None:
        self._scope = scope

    def scalar(self, _q: Any) -> Any:
        return self._scope


@pytest.fixture()
def run_and_session() -> tuple[_FakeRun, _SessionStub]:
    eng = _FakeEngagement()
    scope = _FakeScope(allowlist_json={"urls": ["http://127.0.0.1:8080"]})
    run = _FakeRun(engagement=eng, profile=_FakeProfile())
    return run, _SessionStub(scope)


# --- Registry ----------------------------------------------------------


def test_all_seven_tools_registered() -> None:
    names = {s["name"] for s in ALL_TOOL_SCHEMAS}
    assert names == {
        "bash", "code_exec", "file_read", "file_write",
        "subagent_spawn", "web_search", "web_fetch",
    }


def test_resolve_tool_returns_instance_or_none() -> None:
    assert resolve_tool("bash").name == "bash"
    assert resolve_tool("hallucinated") is None


def test_each_schema_has_input_schema_with_required() -> None:
    for s in ALL_TOOL_SCHEMAS:
        assert "input_schema" in s
        assert s["input_schema"].get("type") == "object"
        assert "properties" in s["input_schema"]


def test_execute_tool_call_unknown_returns_error() -> None:
    result = execute_tool_call("hallucinated", {}, run=None, session=None)
    assert not result.ok
    assert "unknown tool" in result.content


# --- Layer 0 enforcement ---------------------------------------------


def test_bash_denied_when_session_missing(run_and_session) -> None:
    run, _ = run_and_session
    result = BashTool().execute({"command": "echo hi", "target_url": "http://127.0.0.1:8080"}, run=run, session=None)
    assert not result.ok
    assert "Layer 0" in result.content


def test_bash_blocks_destructive_token() -> None:
    result = BashTool().execute(
        {"command": "rm -rf / && echo done", "target_url": "http://127.0.0.1:8080"},
        run=_FakeRun(), session=None,
    )
    assert not result.ok
    assert "forbidden token" in (result.deny_reason or "")


def test_web_fetch_denied_when_target_out_of_scope(run_and_session) -> None:
    run, session = run_and_session
    result = WebFetchTool().execute(
        {"url": "http://attacker.com/exfil"}, run=run, session=session,
    )
    assert not result.ok
    assert "outside" in (result.deny_reason or "").lower() or "scope" in (result.deny_reason or "").lower()


def test_web_fetch_method_allowlist(run_and_session) -> None:
    run, session = run_and_session
    result = WebFetchTool().execute(
        {"url": "http://127.0.0.1:8080/", "method": "DELETE"},
        run=run, session=session,
    )
    assert not result.ok
    assert "not allowed" in (result.deny_reason or "")


def test_code_exec_caps_script_size(run_and_session) -> None:
    run, session = run_and_session
    big = "print('x')\n" * 2000  # > 16 KB cap
    result = CodeExecTool().execute(
        {"script": big, "target_url": "http://127.0.0.1:8080"},
        run=run, session=session,
    )
    assert not result.ok
    assert "16 KB cap" in (result.deny_reason or "")


# --- FileIO scope boundary ------------------------------------------


def test_file_read_rejects_traversal(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("AEGISPT_MEMORY_ROOT", str(tmp_path))
    result = FileReadTool().execute({"path": "../../etc/passwd"}, run=_FakeRun(), session=None)
    assert not result.ok
    assert "traversal" in (result.deny_reason or "")


def test_file_write_caps_payload(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("AEGISPT_MEMORY_ROOT", str(tmp_path))
    big = "x" * 70_000
    result = FileWriteTool().execute({"path": "out.txt", "content": big}, run=_FakeRun(), session=None)
    assert not result.ok
    assert "64 KB cap" in (result.deny_reason or "")


def test_file_write_then_read_round_trip(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("AEGISPT_MEMORY_ROOT", str(tmp_path))
    w = FileWriteTool().execute({"path": "notes/a.txt", "content": "hello"}, run=_FakeRun(), session=None)
    assert w.ok
    r = FileReadTool().execute({"path": "notes/a.txt"}, run=_FakeRun(), session=None)
    assert r.ok
    assert "hello" in r.content


def test_file_read_lists_directories(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("AEGISPT_MEMORY_ROOT", str(tmp_path))
    (tmp_path / "notes").mkdir()
    (tmp_path / "notes" / "a.txt").write_text("a", encoding="utf-8")
    (tmp_path / "notes" / "b.txt").write_text("b", encoding="utf-8")
    r = FileReadTool().execute({"path": "notes"}, run=_FakeRun(), session=None)
    assert r.ok, r.content
    assert "a.txt" in r.content
    assert "b.txt" in r.content


# --- Subagent delegation ------------------------------------------


def test_subagent_low_conf_delegates_to_specialist() -> None:
    run = _FakeRun()
    result = SubagentSpawnTool().execute(
        {"intent": "need_multi_step_exploit", "coordinator_confidence": 0.3},
        run=run, session=None,
    )
    assert result.ok
    assert result.metadata["delegated"] is True
    assert result.metadata["specialist"] == "exploit_dev"


def test_subagent_high_conf_handles_directly() -> None:
    run = _FakeRun()
    result = SubagentSpawnTool().execute(
        {"intent": "need_recon", "coordinator_confidence": 0.9},
        run=run, session=None,
    )
    assert result.ok
    assert result.metadata["delegated"] is False
    assert "handles directly" in result.content


# --- Web search (mocked external_knowledge) -----------------------


def test_web_search_returns_marker_wrapped_envelopes(monkeypatch) -> None:
    from datetime import UTC, datetime

    from api.app.services.external_knowledge import ExternalKnowledgeHint

    def fake_lookup(*, cve_id=None, product=None, version=None):  # noqa: ARG001
        return [
            ExternalKnowledgeHint(
                source="cisa_kev",
                source_url="https://x",
                title="Test CVE",
                fetched_at=datetime.now(UTC),
                applicability_score=0.9,
                cve_id=cve_id,
            )
        ]

    monkeypatch.setattr("api.app.services.external_knowledge.lookup_exploits", fake_lookup)
    result = WebSearchTool().execute({"cve_id": "CVE-2024-12345"}, run=_FakeRun(), session=None)
    assert result.ok
    assert "cisa_kev" in result.content
    assert "Test CVE" in result.content


# --- ToolResult helpers ------------------------------------------


def test_tool_result_factory_helpers() -> None:
    assert ToolResult.success("x").ok is True
    assert ToolResult.denied("nope").ok is False
    assert ToolResult.error("boom").ok is False
    denied = ToolResult.denied("scope reject")
    assert denied.deny_reason == "scope reject"
