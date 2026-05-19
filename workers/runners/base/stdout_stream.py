from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from threading import Lock
from uuid import UUID

from api.app.services.redaction import redact_text

MAX_STDOUT_STREAM_LINES = 120
MAX_STDOUT_STREAM_LINE_CHARS = 4000


@dataclass(slots=True)
class StdoutStreamLine:
    sequence: int
    timestamp: str
    stream: str
    text: str


@dataclass(slots=True)
class StdoutStreamRecord:
    task_id: str
    status: str = "unavailable"
    source: str = "runner-buffer"
    reason: str | None = None
    lines: list[StdoutStreamLine] = field(default_factory=list)
    next_sequence: int = 1
    truncated: bool = False
    updated_at: str = field(default_factory=lambda: _now_iso())


_STREAMS: dict[str, StdoutStreamRecord] = {}
_STREAM_LOCK = Lock()


def _now_iso() -> str:
    return datetime.now(tz=UTC).isoformat()


def _normalize_task_id(task_id: UUID | str) -> str:
    return str(task_id)


def _bounded_line(value: str) -> tuple[str, bool]:
    if len(value) <= MAX_STDOUT_STREAM_LINE_CHARS:
        return value, False
    return (
        value[:MAX_STDOUT_STREAM_LINE_CHARS] + "... [truncated]",
        True,
    )


def _redacted_lines(value: str | None) -> tuple[list[str], bool]:
    redacted = redact_text(value).text or ""
    lines = redacted.splitlines()
    bounded_lines: list[str] = []
    truncated = False
    for line in lines:
        bounded, line_truncated = _bounded_line(line)
        bounded_lines.append(bounded)
        truncated = truncated or line_truncated
    return bounded_lines, truncated


def reset_task_stdout_stream(
    task_id: UUID | str,
    *,
    status: str = "streaming",
    reason: str | None = None,
) -> None:
    normalized_task_id = _normalize_task_id(task_id)
    with _STREAM_LOCK:
        _STREAMS[normalized_task_id] = StdoutStreamRecord(
            task_id=normalized_task_id,
            status=status,
            reason=reason,
            updated_at=_now_iso(),
        )


def append_task_stdout(
    task_id: UUID | str,
    stdout: str | None,
    *,
    stream: str = "stdout",
) -> None:
    normalized_task_id = _normalize_task_id(task_id)
    lines, truncated = _redacted_lines(stdout)
    with _STREAM_LOCK:
        record = _STREAMS.setdefault(
            normalized_task_id,
            StdoutStreamRecord(task_id=normalized_task_id, status="streaming"),
        )
        now = _now_iso()
        for line in lines:
            record.lines.append(
                StdoutStreamLine(
                    sequence=record.next_sequence,
                    timestamp=now,
                    stream=stream,
                    text=line,
                )
            )
            record.next_sequence += 1
        overflow = max(0, len(record.lines) - MAX_STDOUT_STREAM_LINES)
        if overflow:
            record.lines = record.lines[overflow:]
            record.truncated = True
        record.truncated = record.truncated or truncated
        record.status = "streaming"
        record.reason = None
        record.updated_at = now


def mark_task_stdout_completed(
    task_id: UUID | str,
    *,
    reason: str | None = None,
) -> None:
    normalized_task_id = _normalize_task_id(task_id)
    with _STREAM_LOCK:
        record = _STREAMS.setdefault(
            normalized_task_id,
            StdoutStreamRecord(task_id=normalized_task_id),
        )
        record.status = "completed" if record.lines else "unavailable"
        record.reason = reason if not record.lines else None
        record.updated_at = _now_iso()


def mark_task_stdout_unavailable(task_id: UUID | str, reason: str) -> None:
    normalized_task_id = _normalize_task_id(task_id)
    with _STREAM_LOCK:
        _STREAMS[normalized_task_id] = StdoutStreamRecord(
            task_id=normalized_task_id,
            status="unavailable",
            reason=reason,
            updated_at=_now_iso(),
        )


def snapshot_task_stdout(task_id: UUID | str) -> dict | None:
    normalized_task_id = _normalize_task_id(task_id)
    with _STREAM_LOCK:
        record = _STREAMS.get(normalized_task_id)
        if record is None:
            return None
        return _snapshot_from_record(record)


def snapshot_task_stdout_from_text(
    task_id: UUID | str,
    stdout: str | None,
    *,
    status: str,
    source: str,
    reason: str | None = None,
) -> dict:
    normalized_task_id = _normalize_task_id(task_id)
    lines, truncated = _redacted_lines(stdout)
    now = _now_iso()
    record = StdoutStreamRecord(
        task_id=normalized_task_id,
        status=status if lines else "unavailable",
        source=source,
        reason=None if lines else reason,
        truncated=truncated,
        updated_at=now,
    )
    for line in lines[-MAX_STDOUT_STREAM_LINES:]:
        record.lines.append(
            StdoutStreamLine(
                sequence=record.next_sequence,
                timestamp=now,
                stream="stdout",
                text=line,
            )
        )
        record.next_sequence += 1
    if len(lines) > MAX_STDOUT_STREAM_LINES:
        record.truncated = True
    return _snapshot_from_record(record)


def empty_task_stdout_snapshot(
    task_id: UUID | str,
    *,
    status: str,
    source: str,
    reason: str,
) -> dict:
    record = StdoutStreamRecord(
        task_id=_normalize_task_id(task_id),
        status=status,
        source=source,
        reason=reason,
        updated_at=_now_iso(),
    )
    return _snapshot_from_record(record)


def _snapshot_from_record(record: StdoutStreamRecord) -> dict:
    return {
        "task_id": record.task_id,
        "status": record.status,
        "source": record.source,
        "reason": record.reason,
        "available": bool(record.lines),
        "line_count": len(record.lines),
        "max_lines": MAX_STDOUT_STREAM_LINES,
        "truncated": record.truncated,
        "updated_at": record.updated_at,
        "lines": [
            {
                "sequence": line.sequence,
                "timestamp": line.timestamp,
                "stream": line.stream,
                "text": line.text,
            }
            for line in record.lines
        ],
    }
