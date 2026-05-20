"""OpenTelemetry tracing integration with Langfuse OTLP exporter + console fallback.

Per backlog-407 (sprint mythos-exploitation-foundation, task 1/15) + Codex
refinement: TRACING ONLY, no agent logic changes. Pure additive instrumentation
at function boundaries via the :func:`traced` decorator.

Graceful degradation contract:
- Langfuse env vars unset OR Langfuse unreachable → falls back to console exporter
- OpenTelemetry packages not installed → decorator becomes no-op (function runs normally)
- Span attribute extraction failure → swallowed (no impact on agent runtime)

Span attribute conventions (best-effort auto-extraction from args/kwargs):
- ``aegispt.run_id`` — from ``kwargs['run'].id`` or first positional arg with ``.run_id``
- ``aegispt.task_id`` — from ``kwargs['task'].id`` or first positional arg with ``.task_id``
- ``aegispt.engagement_id`` — from ``kwargs['run'].engagement_id``
- ``aegispt.tool`` — from ``kwargs['request'].tool`` when RunnerRequest

Per ANTI_DRIFT.md Rule 4: this module is observability infrastructure; live
verification = trace tree visible in Langfuse UI or console output during
real picker advance.
"""
from __future__ import annotations

import functools
import logging
import os
from collections.abc import Callable
from typing import Any

logger = logging.getLogger(__name__)

_TRACER: Any | None = None
_INITIALIZED: bool = False


def _init_tracer() -> Any | None:
    """Initialize OTEL TracerProvider once per process.

    Picks Langfuse OTLP exporter when LANGFUSE_HOST + LANGFUSE_PUBLIC_KEY +
    LANGFUSE_SECRET_KEY env vars are set. Always adds console exporter as a
    visible fallback / dev aid. Returns the global tracer or None when OTEL
    SDK is not installed.

    Idempotent — safe to call from every decorator invocation.
    """
    global _TRACER, _INITIALIZED
    if _INITIALIZED:
        return _TRACER
    try:
        from opentelemetry import trace
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import (
            BatchSpanProcessor,
            ConsoleSpanExporter,
        )
    except ImportError as exc:
        # OTEL SDK not installed — tracing fully disabled, app continues normally.
        logger.debug("OTEL: opentelemetry SDK not installed (%s); tracing disabled", exc)
        _INITIALIZED = True
        _TRACER = None
        return None

    # Build provider with service.name = aegispt so traces are grouped in Langfuse UI.
    resource = Resource.create({"service.name": "aegispt", "service.namespace": "pentest"})
    provider = TracerProvider(resource=resource)

    langfuse_host = os.environ.get("LANGFUSE_HOST", "").strip()
    langfuse_pub = os.environ.get("LANGFUSE_PUBLIC_KEY", "").strip()
    langfuse_sec = os.environ.get("LANGFUSE_SECRET_KEY", "").strip()

    if langfuse_host and langfuse_pub and langfuse_sec:
        try:
            import base64

            from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
                OTLPSpanExporter,
            )

            auth = base64.b64encode(f"{langfuse_pub}:{langfuse_sec}".encode()).decode()
            otlp = OTLPSpanExporter(
                endpoint=f"{langfuse_host.rstrip('/')}/api/public/otel/v1/traces",
                headers={"Authorization": f"Basic {auth}"},
            )
            provider.add_span_processor(BatchSpanProcessor(otlp))
            logger.info("OTEL: Langfuse OTLP exporter configured at %s", langfuse_host)
        except Exception as exc:  # noqa: BLE001
            # Graceful degradation: Langfuse setup failed, console still works.
            logger.warning(
                "OTEL: Langfuse exporter setup failed (%s) — using console fallback only",
                exc,
            )

    # Always add console exporter as visible local dev aid and graceful fallback.
    provider.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))

    trace.set_tracer_provider(provider)
    _TRACER = trace.get_tracer("aegispt")
    _INITIALIZED = True
    return _TRACER


# Span attribute keys that may contain sensitive data → never set on spans.
# Per backlog-407 no_secrets_in_traces constraint.
_REDACTED_PARAM_NAMES = frozenset(
    {
        "password",
        "secret",
        "token",
        "api_key",
        "credential",
        "credentials",
        "auth",
        "authorization",
        "cookie",
    }
)


def _extract_aegispt_attrs(span: Any, args: tuple[Any, ...], kwargs: dict[str, Any]) -> None:
    """Best-effort extraction of run_id/task_id/engagement_id/tool onto the span.

    Looks at common locations: kwargs['run'], kwargs['task'], kwargs['request'],
    and the first 2 positional args (in case decorator is used on methods or
    direct-arg functions). Any extraction error is swallowed — tracing must
    never break the agent runtime.
    """
    try:
        _extract_aegispt_attrs_inner(span, args, kwargs)
    except Exception:  # noqa: BLE001
        # Defense in depth: even if a property raises a non-AttributeError
        # (e.g. RuntimeError, NetworkError during repr), the agent must
        # continue. Per ANTI_DRIFT.md Rule 1: observability never breaks
        # agent runtime.
        pass


def _extract_aegispt_attrs_inner(span: Any, args: tuple[Any, ...], kwargs: dict[str, Any]) -> None:
    """Inner implementation; wrapped by ``_extract_aegispt_attrs`` for total
    defense in depth. Per-attribute ``_safe_set`` adds another layer."""
    def _safe_set(key: str, getter: Callable[[], Any]) -> None:
        """Defense-in-depth: any individual attribute lookup that throws
        (property raise, network access during repr, etc.) is swallowed
        per-attribute. Tracing MUST NEVER break the agent runtime."""
        try:
            value = getter()
            if value is None:
                return
            span.set_attribute(key, str(value))
        except Exception:  # noqa: BLE001
            pass

    # Direct kwargs
    run = kwargs.get("run")
    task = kwargs.get("task")
    request = kwargs.get("request")

    # Also check first 2 positional args (RunnerRequest, Run, etc.)
    for arg in args[:2]:
        if hasattr(arg, "run_id") and not isinstance(arg, (str, bytes, int)):
            _safe_set("aegispt.run_id", lambda a=arg: getattr(a, "run_id", ""))
        if hasattr(arg, "task_id") and not isinstance(arg, (str, bytes, int)):
            _safe_set("aegispt.task_id", lambda a=arg: getattr(a, "task_id", ""))
        if hasattr(arg, "tool"):
            _safe_set("aegispt.tool", lambda a=arg: getattr(a, "tool", ""))

    if run is not None:
        if hasattr(run, "id"):
            _safe_set("aegispt.run_id", lambda: run.id)
        if hasattr(run, "engagement_id"):
            _safe_set("aegispt.engagement_id", lambda: run.engagement_id)
    if task is not None and hasattr(task, "id"):
        _safe_set("aegispt.task_id", lambda: task.id)
    if request is not None:
        if hasattr(request, "tool"):
            _safe_set("aegispt.tool", lambda: getattr(request, "tool", ""))
        if hasattr(request, "initiated_by"):
            # actor identity is fine on traces; not a secret
            _safe_set("aegispt.initiated_by", lambda: getattr(request, "initiated_by", ""))


def traced(span_name: str) -> Callable[[Callable], Callable]:
    """Decorator that wraps a function in an OTEL span.

    Usage::

        @traced("picker.advance")
        def advance_assessment_loop(*, session, run, scope, ...):
            ...

    Span attributes auto-collected via :func:`_extract_aegispt_attrs`.
    Function executes inside the span context; exceptions are recorded on the
    span and re-raised. When OTEL SDK is not installed, the decorator becomes
    a transparent no-op.

    Per backlog-407 ``no_secrets_in_traces`` constraint: function arguments
    matching :data:`_REDACTED_PARAM_NAMES` are NEVER added as span attributes
    (only structural ids: run_id / task_id / engagement_id / tool).
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            tracer = _init_tracer()
            if tracer is None:
                # OTEL SDK not installed — silent no-op
                return func(*args, **kwargs)
            with tracer.start_as_current_span(span_name) as span:
                try:
                    _extract_aegispt_attrs(span, args, kwargs)
                except Exception:  # noqa: BLE001
                    # Attribute extraction MUST NOT break the agent runtime.
                    pass
                try:
                    result = func(*args, **kwargs)
                    return result
                except Exception as exc:
                    try:
                        from opentelemetry import trace as _trace

                        span.set_status(_trace.Status(_trace.StatusCode.ERROR, str(exc)[:200]))
                        span.record_exception(exc)
                    except Exception:  # noqa: BLE001
                        pass
                    raise

        return wrapper

    return decorator


__all__ = ["traced"]
