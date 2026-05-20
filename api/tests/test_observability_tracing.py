"""Unit tests for backlog-407 — OpenTelemetry tracing module.

Verifies the ``@traced`` decorator + graceful-degradation contract +
attribute extraction. Per ANTI_DRIFT.md Rule 1: this task is observational
(not capability); live verification of trace coverage happens via the
backlog-408 XBOW harness with API restart.
"""
from __future__ import annotations

from dataclasses import dataclass

import pytest

from api.app.observability import traced


@pytest.fixture(autouse=True)
def reset_tracer_module():
    """Reset module-level state so each test starts cleanly."""
    from api.app.observability import tracing as tracing_module

    tracing_module._TRACER = None
    tracing_module._INITIALIZED = False
    yield
    tracing_module._TRACER = None
    tracing_module._INITIALIZED = False


def test_traced_decorator_returns_callable():
    """@traced returns a function-wrapping decorator that preserves behavior."""

    @traced("test.span")
    def add(a: int, b: int) -> int:
        return a + b

    assert add(2, 3) == 5
    assert callable(add)


def test_traced_decorator_propagates_exceptions():
    """Exceptions raised inside the wrapped function MUST propagate to caller."""

    @traced("test.error")
    def boom():
        raise ValueError("boom")

    with pytest.raises(ValueError, match="boom"):
        boom()


def test_traced_decorator_preserves_function_metadata():
    """functools.wraps preserves __name__ and docstring."""

    @traced("test.meta")
    def documented_fn():
        """Docstring stays intact."""
        return 42

    assert documented_fn.__name__ == "documented_fn"
    assert "Docstring stays intact" in (documented_fn.__doc__ or "")


def test_traced_passes_through_kwargs():
    """Kwargs are forwarded correctly through the wrapper."""

    @traced("test.kwargs")
    def fn(*, a, b, c=3):
        return a + b + c

    assert fn(a=1, b=2) == 6
    assert fn(a=10, b=20, c=30) == 60


def test_attr_extraction_handles_run_with_id_and_engagement_id():
    """Best-effort extraction pulls run_id + engagement_id off kwargs['run']."""
    from api.app.observability.tracing import _extract_aegispt_attrs

    @dataclass
    class FakeSpan:
        attrs: dict[str, str] = None

        def __post_init__(self):
            if self.attrs is None:
                self.attrs = {}

        def set_attribute(self, k, v):
            self.attrs[k] = v

    @dataclass
    class FakeRun:
        id: str = "run-uuid-123"
        engagement_id: str = "eng-uuid-456"

    span = FakeSpan()
    _extract_aegispt_attrs(span, args=(), kwargs={"run": FakeRun()})

    assert span.attrs["aegispt.run_id"] == "run-uuid-123"
    assert span.attrs["aegispt.engagement_id"] == "eng-uuid-456"


def test_attr_extraction_handles_request_with_tool():
    """RunnerRequest-like object exposes tool name as span attribute."""
    from api.app.observability.tracing import _extract_aegispt_attrs

    @dataclass
    class FakeSpan:
        attrs: dict[str, str] = None

        def __post_init__(self):
            if self.attrs is None:
                self.attrs = {}

        def set_attribute(self, k, v):
            self.attrs[k] = v

    @dataclass
    class FakeRequest:
        tool: str = "exec-plan"
        initiated_by: str = "operator"

    span = FakeSpan()
    _extract_aegispt_attrs(span, args=(), kwargs={"request": FakeRequest()})

    assert span.attrs["aegispt.tool"] == "exec-plan"
    assert span.attrs["aegispt.initiated_by"] == "operator"


def test_attr_extraction_swallows_errors():
    """Per ANTI_DRIFT Rule 1: attribute extraction MUST NOT break agent runtime."""
    from api.app.observability.tracing import _extract_aegispt_attrs

    class ExplodingSpan:
        def set_attribute(self, k, v):
            raise RuntimeError("intentional")

    class ExplodingRun:
        @property
        def id(self):
            raise RuntimeError("intentional")

    span = ExplodingSpan()
    # Should NOT raise — extractor catches everything internally
    _extract_aegispt_attrs(span, args=(), kwargs={"run": ExplodingRun()})


def test_graceful_degradation_when_otel_uninstalled(monkeypatch):
    """Per backlog-407 graceful_degradation: when OTEL SDK is unavailable,
    decorator becomes silent no-op and wrapped function runs normally."""
    from api.app.observability import tracing as tracing_module

    # Force ImportError path
    real_import = __builtins__["__import__"] if isinstance(__builtins__, dict) else __builtins__.__import__

    def fake_import(name, *args, **kwargs):
        if name.startswith("opentelemetry"):
            raise ImportError("simulated missing otel")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr("builtins.__import__", fake_import)
    tracing_module._INITIALIZED = False
    tracing_module._TRACER = None

    @traced("test.degraded")
    def calc():
        return "ok"

    # Must run normally without tracing
    assert calc() == "ok"
    assert tracing_module._TRACER is None


def test_decorator_invoked_in_assessment_loop_advance():
    """Source-grep sentinel: backlog-407 must wire @traced on advance_assessment_loop."""
    from inspect import getsource

    from api.app.services import assessment_loop

    src = getsource(assessment_loop.advance_assessment_loop)
    assert "@traced" in getsource(assessment_loop) or src.startswith("def "), (
        "advance_assessment_loop must be decorated with @traced('picker.advance') — "
        "search assessment_loop module source for the decorator + function pair."
    )
    # Direct check: the wrapper attribute betrays decoration via functools.wraps
    assert hasattr(assessment_loop.advance_assessment_loop, "__wrapped__"), (
        "advance_assessment_loop is not wrapped — @traced decorator missing"
    )


def test_decorator_invoked_in_dispatch_runner():
    """Source-grep sentinel: backlog-407 must wire @traced on dispatch_runner."""
    from workers.orchestration import tasks

    assert hasattr(tasks.dispatch_runner, "__wrapped__"), (
        "dispatch_runner is not wrapped — @traced decorator missing"
    )


def test_decorator_invoked_in_memory_backend():
    """Source-grep sentinel: backlog-407 must wire @traced on memory_backend functions."""
    from api.app.services import memory_backend

    assert hasattr(memory_backend.execute, "__wrapped__"), (
        "memory_backend.execute is not wrapped — @traced decorator missing"
    )
    assert hasattr(memory_backend.rotate_run_progress, "__wrapped__"), (
        "memory_backend.rotate_run_progress is not wrapped — @traced decorator missing"
    )


def test_decorator_invoked_in_claude_select_next_action():
    """Source-grep sentinel: backlog-407 must wire @traced on Claude picker call."""
    from api.app.services import assessment_loop

    assert hasattr(assessment_loop._claude_select_next_action, "__wrapped__"), (
        "_claude_select_next_action is not wrapped — @traced decorator missing"
    )


def test_secrets_not_in_extract_aegispt_attrs():
    """Per backlog-407 no_secrets_in_traces: kwargs with sensitive names
    (password, token, etc.) MUST NOT be passed as span attributes by the
    auto-extractor."""
    from api.app.observability.tracing import _extract_aegispt_attrs

    class FakeSpan:
        def __init__(self):
            self.attrs = {}

        def set_attribute(self, k, v):
            self.attrs[k] = v

    span = FakeSpan()
    _extract_aegispt_attrs(
        span,
        args=(),
        kwargs={"password": "supersecret", "api_key": "sk-XXX", "token": "abc123"},
    )

    # Extractor only looks at run/task/request — not raw credential kwargs
    for _k, v in span.attrs.items():
        assert "supersecret" not in str(v)
        assert "sk-XXX" not in str(v)
        assert "abc123" not in str(v)


def test_init_tracer_idempotent():
    """Calling _init_tracer multiple times returns the same instance."""
    from api.app.observability.tracing import _init_tracer

    t1 = _init_tracer()
    t2 = _init_tracer()
    t3 = _init_tracer()
    assert t1 is t2 is t3
