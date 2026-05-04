from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any, Iterator
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app.config import Settings
from api.app.models import AgentReasoning, Finding, Run, Task
from api.app.services.ai_enrichment import store_agent_reasoning_record
from api.app.services.chatgpt_oauth import (
    CHATGPT_OAUTH_PROVIDER,
    ChatGPTOAuthError,
    chatgpt_oauth_status,
    effective_ai_provider_name,
    stream_chatgpt_backend_text_request,
)
from api.app.services.settings import effective_runtime_settings_for_run

LIVE_AI_SIGNAL_KIND = "live_ai_signal"
DETERMINISTIC_PROVIDER = "deterministic"
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def latest_completed_ai_signal_task(run: Run, task_id: UUID | None = None) -> Task | None:
    tasks = [task for task in list(run.tasks or []) if str(task.status or "").lower() == "completed"]
    if task_id is not None:
        return next((task for task in tasks if task.id == task_id), None)
    return sorted(
        tasks,
        key=lambda task: task.updated_at or task.created_at or datetime.min.replace(tzinfo=UTC),
        reverse=True,
    )[0] if tasks else None


def stream_run_ai_signal(
    *,
    session: Session,
    run: Run,
    settings: Settings,
    task_id: UUID | None = None,
) -> Iterator[dict[str, Any]]:
    effective_settings = effective_runtime_settings_for_run(session, run=run, settings=settings)
    task = latest_completed_ai_signal_task(run, task_id=task_id)
    provider = _provider_status(session=session, run=run, settings=effective_settings)
    yield {"event": "status", "data": provider | {"run_id": str(run.id), "task_id": str(task.id) if task else None}}

    if task is None:
        yield {
            "event": "complete",
            "data": {
                "run_id": str(run.id),
                "task_id": None,
                "provider": provider,
                "text": "AI Signal is waiting for the first completed task before analysing this run.",
                "stored": False,
            },
        }
        return

    stored = _stored_live_signal(session=session, run_id=run.id, task_id=task.id)
    if stored is not None:
        text = _analysis_text(stored)
        if text:
            yield {"event": "token", "data": {"text": text}}
        yield {
            "event": "complete",
            "data": {
                "run_id": str(run.id),
                "task_id": str(task.id),
                "provider": provider,
                "text": text,
                "reasoning_id": str(stored.id),
                "stored": True,
                "replay": True,
            },
        }
        return

    context = _signal_context(run=run, task=task)
    chunks: list[str] = []
    try:
        if provider["mode"] == CHATGPT_OAUTH_PROVIDER and provider["connected"]:
            chunk_iter = _chatgpt_signal_chunks(
                session=session,
                engagement_id=run.engagement_id,
                settings=effective_settings,
                context=context,
            )
        else:
            chunk_iter = _deterministic_signal_chunks(context=context, provider=provider)
        for chunk in chunk_iter:
            chunks.append(chunk)
            yield {"event": "token", "data": {"text": chunk}}
        text = "".join(chunks).strip()
        if not text:
            text = "AI Signal did not return text for this task; deterministic guidance remains available."
        reasoning = store_agent_reasoning_record(
            session=session,
            run=run,
            task=task,
            reasoning_type=LIVE_AI_SIGNAL_KIND,
            status="succeeded",
            context_snapshot=context,
            observations=[{"summary": text, "type": LIVE_AI_SIGNAL_KIND, "source": "stream"}],
            provider=provider["mode"],
            model=provider.get("model"),
            metadata={
                "signal_kind": LIVE_AI_SIGNAL_KIND,
                "analysis_text": text,
                "provider_status": provider,
                "dispatches_work": False,
                "executes_tools": False,
                "streamed_at": datetime.now(tz=UTC).isoformat(),
            },
        )
        session.commit()
        yield {
            "event": "complete",
            "data": {
                "run_id": str(run.id),
                "task_id": str(task.id),
                "provider": provider,
                "text": text,
                "reasoning_id": str(reasoning.id),
                "stored": True,
            },
        }
    except Exception as exc:
        session.rollback()
        fallback_text = "AI Signal could not stream from ChatGPT, so deterministic guidance remains active for this run."
        reasoning = store_agent_reasoning_record(
            session=session,
            run=run,
            task=task,
            reasoning_type=LIVE_AI_SIGNAL_KIND,
            status="failed",
            context_snapshot=context,
            provider=provider["mode"] or "unknown",
            model=provider.get("model"),
            failure_reason=str(exc),
            metadata={
                "signal_kind": LIVE_AI_SIGNAL_KIND,
                "dispatches_work": False,
                "executes_tools": False,
                "error_type": exc.__class__.__name__,
                "provider_status": provider,
            },
        )
        session.commit()
        yield {"event": "error", "data": {"message": fallback_text, "detail": str(exc), "reasoning_id": str(reasoning.id)}}


def _provider_status(*, session: Session, run: Run, settings: Settings) -> dict[str, Any]:
    effective = effective_ai_provider_name(settings, settings.ai_agent_post_task_analysis_provider)
    model = str(settings.ai_agent_post_task_analysis_model or "aegispt-post-task-analysis")
    if not settings.ai_agent_post_task_analysis_enabled:
        return {
            "mode": DETERMINISTIC_PROVIDER,
            "label": "Deterministic mode",
            "status": "disabled",
            "connected": False,
            "model": model,
        }
    if effective == CHATGPT_OAUTH_PROVIDER:
        try:
            status = chatgpt_oauth_status(session=session, engagement_id=run.engagement_id, settings=settings)
        except ChatGPTOAuthError:
            status = None
        connected = bool(status and status.connected)
        return {
            "mode": CHATGPT_OAUTH_PROVIDER if connected else DETERMINISTIC_PROVIDER,
            "label": "ChatGPT connected" if connected else "Deterministic mode",
            "status": "connected" if connected else "not_connected",
            "connected": connected,
            "model": str(settings.chatgpt_oauth_model or settings.ai_agent_post_task_analysis_model or "gpt-5.4"),
            "account_id": status.account_id if status else None,
        }
    return {
        "mode": DETERMINISTIC_PROVIDER,
        "label": "Deterministic mode",
        "status": effective or "disabled",
        "connected": False,
        "model": model,
    }


def _chatgpt_signal_chunks(
    *,
    session: Session,
    engagement_id: UUID,
    settings: Settings,
    context: dict[str, Any],
) -> Iterator[str]:
    return stream_chatgpt_backend_text_request(
        session=session,
        engagement_id=engagement_id,
        settings=settings,
        model=str(settings.chatgpt_oauth_model or settings.ai_agent_post_task_analysis_model or "gpt-5.4"),
        instructions=(
            "You are AegisPT AI Signal. Provide exactly three concise sentences for the operator. "
            "Ground the analysis in the completed task, the inventory summary, and the top findings. "
            "Do not execute tools, mutate findings, grant approvals, expand scope, or suggest unsafe live actions."
        ),
        input_items=[
            {
                "role": "user",
                "content": [{"type": "input_text", "text": json.dumps({"task_context": context}, sort_keys=True)}],
            }
        ],
    )


def _deterministic_signal_chunks(*, context: dict[str, Any], provider: dict[str, Any]) -> Iterator[str]:
    task = context["task"]
    findings = context.get("top_findings") or []
    inventory = context.get("inventory_summary") or {}
    finding_text = (
        f"{len(findings)} prioritized finding{'s' if len(findings) != 1 else ''} are already attached"
        if findings
        else "no stored findings are attached yet"
    )
    host_count = inventory.get("host_count")
    inventory_text = f"{host_count} inventoried host{'s' if host_count != 1 else ''}" if host_count is not None else "the current inventory snapshot"
    text = (
        f"{task['tool']} completed on {task['target_id']} and {finding_text}. "
        f"AI Signal is running in {provider['label']}, so this guidance is deterministic and review-only. "
        f"Use {inventory_text} plus the selected task output to decide the next approved operator step."
    )
    for part in _word_chunks(text):
        yield part


def _stored_live_signal(*, session: Session, run_id: UUID, task_id: UUID) -> AgentReasoning | None:
    records = session.scalars(
        select(AgentReasoning)
        .where(
            AgentReasoning.run_id == run_id,
            AgentReasoning.task_id == task_id,
            AgentReasoning.reasoning_type == LIVE_AI_SIGNAL_KIND,
        )
        .order_by(AgentReasoning.updated_at.desc(), AgentReasoning.created_at.desc(), AgentReasoning.id.desc())
    ).all()
    return next(
        (
            record
            for record in records
            if isinstance(record.metadata_json, dict)
            and record.metadata_json.get("signal_kind") == LIVE_AI_SIGNAL_KIND
            and record.status == "succeeded"
        ),
        None,
    )


def _analysis_text(record: AgentReasoning) -> str:
    metadata = record.metadata_json if isinstance(record.metadata_json, dict) else {}
    text = str(metadata.get("analysis_text") or "").strip()
    if text:
        return text
    observations = record.observations_json if isinstance(record.observations_json, list) else []
    return " ".join(str(item.get("summary") or "").strip() for item in observations if isinstance(item, dict)).strip()


def _signal_context(*, run: Run, task: Task) -> dict[str, Any]:
    return {
        "run": {
            "id": str(run.id),
            "engagement_id": str(run.engagement_id),
            "status": run.status,
            "profile": run.profile.name if run.profile is not None else None,
        },
        "task": {
            "id": str(task.id),
            "tool": task.tool,
            "target_id": task.target_id,
            "status": task.status,
            "params_json": _safe_object(task.params_json),
            "latest_stdout_tail": _latest_stdout_tail(task),
        },
        "top_findings": [_finding_payload(finding) for finding in _top_findings(run)],
        "inventory_summary": _inventory_summary(run),
        "guardrails": {
            "dispatches_work": False,
            "executes_tools": False,
            "scope_expansion_allowed": False,
            "operator_review_required": True,
        },
    }


def _top_findings(run: Run) -> list[Finding]:
    return sorted(
        list(run.findings or []),
        key=lambda finding: (
            SEVERITY_ORDER.get(str(finding.severity or "").lower(), 99),
            finding.updated_at or finding.created_at or datetime.min.replace(tzinfo=UTC),
        ),
    )[:3]


def _finding_payload(finding: Finding) -> dict[str, Any]:
    return {
        "id": str(finding.id),
        "title": finding.title,
        "severity": finding.severity,
        "target_id": finding.target_id,
        "status": finding.status,
        "summary": finding.summary,
        "evidence_ref": finding.evidence_ref,
    }


def _inventory_summary(run: Run) -> dict[str, Any]:
    snapshot = run.source_inventory_snapshot
    if snapshot is None:
        return {}
    summary = _safe_object(snapshot.summary_json)
    normalized = _safe_object(snapshot.normalized_inventory_json)
    hosts = normalized.get("hosts")
    services = normalized.get("services")
    return {
        "snapshot_id": str(snapshot.id),
        "status": snapshot.status,
        "host_count": len(hosts) if isinstance(hosts, list) else summary.get("host_count"),
        "service_count": len(services) if isinstance(services, list) else summary.get("service_count"),
        "summary": summary,
    }


def _latest_stdout_tail(task: Task) -> str:
    executions = sorted(
        list(task.executions or []),
        key=lambda execution: execution.created_at or datetime.min.replace(tzinfo=UTC),
        reverse=True,
    )
    if not executions:
        return ""
    lines = str(executions[0].stdout_text or "").splitlines()
    return "\n".join(lines[-20:])


def _safe_object(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def _word_chunks(text: str) -> Iterator[str]:
    words = str(text or "").split(" ")
    for index, word in enumerate(words):
        yield word if index == 0 else f" {word}"
