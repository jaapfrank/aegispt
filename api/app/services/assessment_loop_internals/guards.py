"""Advance-loop early-exit guards extracted from assessment_loop.py.

Three guards, all called at the top of ``advance_assessment_loop`` before
any picker work happens:

1. ``check_terminal_idempotent`` — short-circuit when the run is already
   finalized (post-task worker hooks otherwise re-enter the picker and
   overwrite the stop_reason a previous advance just set).
2. ``check_early_stop_on_flag`` — when a persisted critical/high finding
   contains a flag literal (xbow-..., flag{...}, ctf{...}), mark the run
   completed + write success_marker on all episodes of the run.
3. ``check_target_unreachable`` — when the last 3 tool_executions on the
   run all failed with Connection refused / ConnectError, mark the run
   completed_with_errors + write success_marker=target_unreachable.

Each function returns ``True`` when it short-circuited (caller must return
the build-state to client) or ``False`` when the loop should continue.

Behaviour is byte-identical to the inline guards from the pre-O4-step-2
assessment_loop.py. Same PROOF_EXEC markers, same loop_state mutations,
same SQLAlchemy flag_modified handling, same exception envelope.
"""
from __future__ import annotations

import logging
import re as _re
from typing import Any

from sqlalchemy import select as _select, text as _text
from sqlalchemy.orm import Session

from api.app.models import Run, Scope, Task, ToolExecution
from api.app.services.assessment_loop_internals.helpers import as_dict

logger = logging.getLogger("api.app.services.assessment_loop")

_RUN_TERMINAL_STATUSES = {"completed", "completed_with_errors", "failed", "cancelled", "rejected"}

_FLAG_RE = _re.compile(
    r"(flag\{[^}\r\n]{1,200}\}|xbow-[a-f0-9]{16,128}|ctf\{[^}\r\n]{1,200}\})",
    _re.IGNORECASE,
)


def check_terminal_idempotent(
    *,
    run: Run,
    loop_state_reader,
    build_state,
    session: Session,
    scope: Scope,
) -> Any | None:
    """If the run is already terminal OR the loop is already flagged as
    flag_extracted, return the build-state dict immediately.

    ``loop_state_reader`` is a callable () -> dict that reads the current
    loop_state from run.configuration_json. ``build_state`` is the
    build_assessment_loop_state(session=, run=, scope=) callable.

    Returns the build-state dict (caller must return it) or None.
    """
    existing_loop_state = loop_state_reader()
    existing_stop_reason = str(existing_loop_state.get("stop_reason") or "").lower()
    if str(run.status or "").lower() in _RUN_TERMINAL_STATUSES or existing_stop_reason == "flag_extracted":
        logger.info(
            "PROOF_EXEC_ADVANCE_SKIPPED_TERMINAL_2026052410 run=%s status=%s stop_reason=%s",
            str(getattr(run, "id", "?"))[:8],
            str(run.status or "").lower(),
            existing_stop_reason or "-",
        )
        return build_state(session, run=run, scope=scope)
    return None


def check_early_stop_on_flag(
    *,
    run: Run,
    loop_state: dict[str, Any],
    configuration: dict[str, Any],
    store_loop_state,
    build_state,
    session: Session,
    scope: Scope,
) -> Any | None:
    """Scan run.findings for a flag literal. Returns build-state dict to
    return-immediately if found, else None.

    ``store_loop_state(configuration, loop_state)`` writes the loop state
    back into configuration[LOOP_CONFIG_KEY].
    """
    # Measurement-only bypass (default OFF -> unchanged product behaviour): when
    # running a FULL focused-assessment baseline we want every objective to run,
    # not stop the whole run on the first flag. Gated by an explicit env flag.
    import os as _os_es
    if str(_os_es.environ.get("AEGISPT_DISABLE_SOLVE_EARLY_STOP", "") or "").strip().lower() in {"1", "true", "yes", "on"}:
        return None
    try:
        for finding in (getattr(run, "findings", None) or []):
            sev = str(getattr(finding, "severity", "") or "").lower()
            if sev not in {"critical", "high"}:
                continue
            haystack = " ".join([
                str(getattr(finding, "title", "") or ""),
                str(getattr(finding, "summary", "") or ""),
                str(getattr(finding, "target_id", "") or ""),
            ])
            if _FLAG_RE.search(haystack):
                logger.info(
                    "PROOF_EXEC_SOLVE_EARLY_STOP_2026052408 run=%s finding=%s severity=%s",
                    str(getattr(run, "id", "?"))[:8],
                    str(getattr(finding, "id", "?"))[:8],
                    sev,
                )
                loop_state["status"] = "stopped"
                loop_state["stop_reason"] = "flag_extracted"
                loop_state["ai_stop_summary"] = (
                    f"Flag literal extracted in finding {str(getattr(finding, 'id', '?'))[:8]} — early-stop."
                )
                store_loop_state(configuration, loop_state)
                run.configuration_json = configuration
                try:
                    from sqlalchemy.orm.attributes import flag_modified  # noqa: E402
                    flag_modified(run, "configuration_json")
                except Exception:  # noqa: BLE001
                    pass
                try:
                    run.status = "completed"
                except Exception:  # noqa: BLE001
                    pass
                try:
                    res = session.execute(
                        _text(
                            "UPDATE agent_episodic_memory "
                            "SET success_marker = 'flag_extracted' "
                            "WHERE run_id = :rid "
                            "AND (success_marker IS NULL OR success_marker = '')"
                        ),
                        {"rid": run.id},
                    )
                    logger.info(
                        "PROOF_EXEC_SUCCESS_MARKER_WRITE_2026052411 run=%s tagged_rows=%s marker=flag_extracted",
                        str(run.id)[:8],
                        getattr(res, "rowcount", "?"),
                    )
                except Exception as exc:  # noqa: BLE001
                    logger.warning("success_marker writeback failed: %s", exc)
                session.flush()
                return build_state(session, run=run, scope=scope)
    except Exception as exc:  # noqa: BLE001
        logger.warning("early-stop check failed: %s", exc)
    return None


def check_target_unreachable(
    *,
    run: Run,
    loop_state: dict[str, Any],
    configuration: dict[str, Any],
    store_loop_state,
    build_state,
    session: Session,
    scope: Scope,
) -> Any | None:
    """If the last 3 tool_executions all failed with Connection refused,
    mark the run completed_with_errors and write success_marker. Returns
    build-state to return-immediately, or None.
    """
    try:
        recent_exec_rows = session.execute(
            _select(ToolExecution.exit_code, ToolExecution.stderr_text, ToolExecution.task_id)
            .join(Task, Task.id == ToolExecution.task_id)
            .where(Task.run_id == run.id)
            .order_by(ToolExecution.created_at.desc())
            .limit(3)
        ).all()
        if len(recent_exec_rows) >= 3 and all(
            (row.exit_code or 0) != 0
            and isinstance(row.stderr_text, str)
            and ("Connection refused" in row.stderr_text or "ConnectError" in row.stderr_text)
            for row in recent_exec_rows
        ):
            logger.info(
                "PROOF_EXEC_TARGET_UNREACHABLE_2026052409 run=%s consecutive_connect_refused=%d",
                str(getattr(run, "id", "?"))[:8],
                len(recent_exec_rows),
            )
            loop_state["status"] = "stopped"
            loop_state["stop_reason"] = "target_unreachable"
            loop_state["ai_stop_summary"] = (
                "Last 3 tool executions all failed with Connection refused — target appears down. "
                "Restart the target container and re-launch the engagement."
            )
            store_loop_state(configuration, loop_state)
            run.configuration_json = configuration
            try:
                from sqlalchemy.orm.attributes import flag_modified  # noqa: E402
                flag_modified(run, "configuration_json")
            except Exception:  # noqa: BLE001
                pass
            try:
                run.status = "completed_with_errors"
            except Exception:  # noqa: BLE001
                pass
            try:
                res_th = session.execute(
                    _text(
                        "UPDATE agent_episodic_memory "
                        "SET success_marker = 'target_unreachable' "
                        "WHERE run_id = :rid "
                        "AND (success_marker IS NULL OR success_marker = '')"
                    ),
                    {"rid": run.id},
                )
                logger.info(
                    "PROOF_EXEC_SUCCESS_MARKER_WRITE_2026052411 run=%s tagged_rows=%s marker=target_unreachable",
                    str(run.id)[:8],
                    getattr(res_th, "rowcount", "?"),
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning("success_marker writeback (target_unreachable) failed: %s", exc)
            session.flush()
            return build_state(session, run=run, scope=scope)
    except Exception as exc:  # noqa: BLE001
        logger.warning("target-health guard check failed: %s", exc)
    return None


# Compatibility alias — assessment_loop.py used the underscore-prefixed
# value as a module-level constant. Re-export here so callers that still
# read it via assessment_loop._RUN_TERMINAL_STATUSES keep working.
__all__ = [
    "check_terminal_idempotent",
    "check_early_stop_on_flag",
    "check_target_unreachable",
    "_RUN_TERMINAL_STATUSES",
]
