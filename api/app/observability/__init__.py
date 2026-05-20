"""AegisPT observability package — OpenTelemetry tracing + Langfuse integration.

Per backlog-407 (sprint mythos-exploitation-foundation, task 1/15):
TRACING ONLY — zero changes to agent logic, dispatch, or runner behavior.
Pure additive instrumentation at function boundaries via the ``traced``
decorator from :mod:`api.app.observability.tracing`.

Public API:
    traced(span_name) — decorator that wraps a function in an OTEL span
"""
from api.app.observability.tracing import traced

__all__ = ["traced"]
