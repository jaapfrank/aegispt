#!/usr/bin/env python3
"""TRUE live CLI for AegisPT — fans in real-time streams from journalctl
(line-buffered API service stdout/stderr) plus SSE event endpoints, prints
each event the instant it arrives, no refresh, no polled snapshot.

Sources (each runs in its own thread, items merged via a shared queue):

1. ``journalctl --user -u aegispt-api -f -o cat`` — character/line stream
   of the API service. This is the truly-live signal: picker decisions
   ("AI loop: Claude said STOP …"), tool dispatches ("Claude picked …"),
   warnings, tracebacks — emitted as soon as the API logger flushes.

2. ``journalctl --user -u xbow-relive -f -o cat`` (optional, when the
   benchmark harness is also running) — gives you the harness's view:
   which challenge it's on, normalization output, the per-challenge
   HTTP POST chain that creates engagement → run → dispatch.

3. SSE from ``/api/v1/runs/{run_id}/events`` — server-pushed run state
   changes (task added, task status changed, run terminal). Reuses the
   API endpoint introduced at routers/runs.py:2037.

4. SSE from ``/api/v1/tasks/{task_id}/stdout/events`` for the currently-
   running task — server pushes each new stdout/stderr chunk as the
   runner writes it. Reuses routers/tasks.py:134.

The CLI auto-discovers the active run on startup (most-recently-started
``running``/``queued``/``dispatched`` run) and re-discovers when the
current run terminates. Each printed line is tagged + colored by event
class so you can see at a glance: picker decision, runner dispatch,
agent_tool call, finding, error.

This is *not* a refreshing dashboard. There is no clear-screen, no
polling loop driving the display. Output is append-only, ordered by
arrival time. To stop, Ctrl-C.

Usage::

    # Auto-detect active run, stream everything
    python3 scripts/aegispt_live.py

    # Pin to a specific run (skip auto-detect)
    python3 scripts/aegispt_live.py --run-id <uuid>

    # Skip the API service tail (just SSE — useful from a remote host)
    python3 scripts/aegispt_live.py --no-journal

    # Skip the harness tail (only watching the API)
    python3 scripts/aegispt_live.py --no-harness

    # Suppress per-task stdout overlay (run+API only)
    python3 scripts/aegispt_live.py --no-task-stdout
"""
from __future__ import annotations

import argparse
import json
import os
import queue
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable

import httpx


# ──────────────────────── ANSI colors ────────────────────────

_USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def _c(text: str, code: str) -> str:
    if not _USE_COLOR:
        return text
    return f"\033[{code}m{text}\033[0m"


COLOR = {
    "dim":      lambda s: _c(s, "2"),
    "bold":     lambda s: _c(s, "1"),
    "red":      lambda s: _c(s, "31"),
    "green":    lambda s: _c(s, "32"),
    "yellow":   lambda s: _c(s, "33"),
    "blue":     lambda s: _c(s, "34"),
    "magenta":  lambda s: _c(s, "35"),
    "cyan":     lambda s: _c(s, "36"),
    "white":    lambda s: _c(s, "97"),
    "br_red":   lambda s: _c(s, "91"),
    "br_green": lambda s: _c(s, "92"),
    "br_yellow":lambda s: _c(s, "93"),
    "br_cyan":  lambda s: _c(s, "96"),
}


# ─────────────────── Event taxonomy + classifier ───────────────────

# Pattern → (tag, color) ordered most-specific first. The classifier runs
# left-to-right so HTTP-200 noise gets eaten by the http_quiet bucket
# before the generic info classifier matches it.

@dataclass
class TaggedLine:
    """A single line ready for the console.  ``arrived`` is the local wall
    clock at the moment we read the line off the source stream (NOT the
    journalctl timestamp from the line itself — this is what gives the
    operator a real sense of latency between event in the system and
    event on their screen)."""
    source: str
    tag: str
    color: str
    text: str
    arrived: float


_CLASSIFIERS: list[tuple[re.Pattern[str], str, str]] = [
    # ---- noise we collapse into one quiet bucket ----------
    (re.compile(r"HTTP/1\.1\" 200 OK"), "http", "dim"),
    (re.compile(r"HTTP Request: GET .*/runs/[0-9a-f-]+\""), "http", "dim"),
    # ---- the events the operator actually wants ----------
    (re.compile(r"AI loop:.*Claude said STOP", re.IGNORECASE), "STOP", "br_yellow"),
    (re.compile(r"AI loop:.*picked.*tool", re.IGNORECASE), "PICK", "br_cyan"),
    (re.compile(r"AI loop:.*level[_ -]up", re.IGNORECASE), "LEVEL_UP", "magenta"),
    (re.compile(r"AI loop:.*exec[_ -]plan", re.IGNORECASE), "EXEC_PLAN", "magenta"),
    (re.compile(r"AI loop:.*picker", re.IGNORECASE), "PICKER", "cyan"),
    (re.compile(r"AI loop:", re.IGNORECASE), "AI_LOOP", "cyan"),
    (re.compile(r"\btool_use\b|execute_tool_call|agent_tool", re.IGNORECASE), "AGENT_TOOL", "br_cyan"),
    (re.compile(r"dispatch", re.IGNORECASE), "DISPATCH", "blue"),
    (re.compile(r"runner|capability", re.IGNORECASE), "RUNNER", "blue"),
    (re.compile(r"\bfinding\b|finding\.created", re.IGNORECASE), "FINDING", "br_green"),
    (re.compile(r"validator|validate_exploit", re.IGNORECASE), "VALIDATOR", "green"),
    (re.compile(r"narrator|comic", re.IGNORECASE), "NARRATOR", "magenta"),
    (re.compile(r"score-?climb|proposal_generator|failure_analysis"), "SCORE_CLIMB", "yellow"),
    (re.compile(r"xbow_benchmark"), "XBOW", "yellow"),
    (re.compile(r"^\s*Traceback|^\s*File \"[^\"]+\", line "), "TRACE", "br_red"),
    (re.compile(r"\bERROR\b|ERROR:|Exception"), "ERROR", "br_red"),
    (re.compile(r"\bWARNING\b|WARN:"), "WARN", "yellow"),
    (re.compile(r"HTTP/1\.1\" 4\d\d"), "HTTP4", "yellow"),
    (re.compile(r"HTTP/1\.1\" 5\d\d"), "HTTP5", "br_red"),
    (re.compile(r"HTTP/1\.1\" \d{3}"), "http", "dim"),
    (re.compile(r"systemd"), "SYSTEMD", "dim"),
    (re.compile(r"INFO httpx"), "http", "dim"),
]


def classify(line: str) -> tuple[str, str]:
    for pat, tag, color in _CLASSIFIERS:
        if pat.search(line):
            return tag, color
    return "log", "white"


_HTTP_QUIET_TAGS = {"http"}


def should_emit(tag: str, quiet_http: bool) -> bool:
    if quiet_http and tag in _HTTP_QUIET_TAGS:
        return False
    return True


# ─────────────────────── stream printers ───────────────────────

def _now_short() -> str:
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]


def emit(out: queue.Queue[TaggedLine | None], source: str, line: str) -> None:
    text = line.rstrip("\r\n")
    if not text:
        return
    tag, color = classify(text)
    out.put(TaggedLine(source=source, tag=tag, color=color, text=text, arrived=time.time()))


# ─────────────────────── source threads ───────────────────────

def _journal_tail_thread(
    unit: str,
    out: queue.Queue[TaggedLine | None],
    stop_event: threading.Event,
    sudo: bool,
) -> None:
    """``journalctl --user -u <unit> -f -o cat`` line-tailed in a background
    thread.  ``-o cat`` strips the systemd preamble (timestamp + host +
    pid) so the line is just the application's own log text — much
    easier to classify and color.

    The thread re-spawns journalctl if it dies (e.g. unit hasn't started
    yet, or the journal rotates), with a small backoff so we don't spin
    a CPU when nothing is wrong.
    """
    base_cmd = ["journalctl", "--user", "-u", unit, "-f", "-o", "cat", "--lines=0"]
    if sudo:
        base_cmd = ["sudo", "-n", *base_cmd]
    while not stop_event.is_set():
        try:
            proc = subprocess.Popen(
                base_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=1,
                text=True,
            )
        except (FileNotFoundError, OSError) as exc:
            emit(out, source=unit, line=f"(journalctl spawn failed: {exc})")
            return
        try:
            assert proc.stdout is not None
            for raw in proc.stdout:
                if stop_event.is_set():
                    break
                emit(out, source=unit, line=raw)
        finally:
            try:
                proc.terminate()
                proc.wait(timeout=2)
            except (subprocess.TimeoutExpired, ProcessLookupError):
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
        if not stop_event.is_set():
            time.sleep(1.0)


def _run_sse_thread(
    base_url: str,
    actor: str,
    run_id_box: dict[str, str | None],
    out: queue.Queue[TaggedLine | None],
    stop_event: threading.Event,
) -> None:
    """Stream ``/api/v1/runs/{run_id}/events`` for the active run, re-
    binding when ``run_id_box['run_id']`` changes (i.e. the harness
    started a new challenge).  Pushes one ``RUN`` line per delta so the
    operator can see status transitions inline with everything else."""
    headers = {"X-Actor": actor}
    last_status: dict[str, str] = {}
    last_task_status: dict[str, dict[str, str]] = {}
    while not stop_event.is_set():
        rid = run_id_box.get("run_id")
        if not rid:
            time.sleep(2.0)
            continue
        try:
            with httpx.Client(base_url=base_url, headers=headers, timeout=None) as client:
                url = f"/api/v1/runs/{rid}/events"
                with client.stream("GET", url) as resp:
                    if resp.status_code != 200:
                        emit(out, source="sse", line=f"(SSE {url} returned {resp.status_code})")
                        time.sleep(2.0)
                        continue
                    event_name = ""
                    for raw in resp.iter_lines():
                        if stop_event.is_set():
                            break
                        if run_id_box.get("run_id") != rid:
                            break
                        if not raw:
                            continue
                        if raw.startswith("event:"):
                            event_name = raw[6:].strip()
                            continue
                        if raw.startswith("data:"):
                            payload_text = raw[5:].strip()
                            try:
                                payload = json.loads(payload_text)
                            except json.JSONDecodeError:
                                continue
                            status = str(payload.get("status") or "")
                            if last_status.get(rid) != status:
                                last_status[rid] = status
                                emit(out, source="run", line=f"RUN {rid[:8]} status={status}")
                            tasks_state = last_task_status.setdefault(rid, {})
                            for task in payload.get("tasks") or []:
                                if not isinstance(task, dict):
                                    continue
                                tid = str(task.get("id") or "")
                                tstatus = str(task.get("status") or "")
                                if not tid or not tstatus:
                                    continue
                                prev = tasks_state.get(tid)
                                if prev != tstatus:
                                    tasks_state[tid] = tstatus
                                    tool = task.get("tool") or "?"
                                    target = task.get("target_id") or "?"
                                    emit(
                                        out,
                                        source="run",
                                        line=f"TASK {tid[:8]} {tool} -> {target} :: {tstatus}",
                                    )
                            if event_name == "finding.enriched":
                                emit(
                                    out,
                                    source="run",
                                    line=(
                                        "finding "
                                        + str(payload.get("finding_title") or "")
                                        + f" [{payload.get('severity')}] -> {payload.get('status')}"
                                    ),
                                )
        except httpx.HTTPError as exc:
            emit(out, source="sse", line=f"(SSE error: {exc})")
            time.sleep(2.0)


def _task_stdout_sse_thread(
    base_url: str,
    actor: str,
    run_id_box: dict[str, str | None],
    out: queue.Queue[TaggedLine | None],
    stop_event: threading.Event,
) -> None:
    """Streams stdout of the currently-running task. Re-targets when the
    picker moves on. Uses the API's ``/api/v1/runs/{id}`` to find the
    active task, then pins to its SSE stdout endpoint until the task
    goes terminal; then loops to find the next one."""
    headers = {"X-Actor": actor}
    seen_task: str = ""
    while not stop_event.is_set():
        rid = run_id_box.get("run_id")
        if not rid:
            time.sleep(2.0)
            continue
        try:
            with httpx.Client(base_url=base_url, headers=headers, timeout=10.0) as client:
                run_resp = client.get(f"/api/v1/runs/{rid}")
                if run_resp.status_code != 200:
                    time.sleep(2.0)
                    continue
                tasks = (run_resp.json() or {}).get("tasks") or []
                active = next(
                    (t for t in tasks if str(t.get("status") or "").lower() == "running"),
                    None,
                )
                if active is None:
                    # Fall back to most-recently-queued so we don't miss the
                    # first stdout chunk of a fresh task.
                    pending = [
                        t for t in tasks
                        if str(t.get("status") or "").lower() in {"queued", "dispatched", "pending"}
                    ]
                    if pending:
                        pending.sort(key=lambda t: str(t.get("created_at") or ""), reverse=True)
                        active = pending[0]
                if active is None:
                    time.sleep(2.0)
                    continue
                tid = str(active.get("id") or "")
                if not tid or tid == seen_task:
                    time.sleep(1.0)
                    continue
                seen_task = tid
                tool = active.get("tool") or "?"
                emit(out, source="task", line=f"╭── stdout follow task {tid[:8]} ({tool}) ──")
                last_count = 0
                event_name = ""
                with httpx.Client(base_url=base_url, headers=headers, timeout=None) as stream_client:
                    with stream_client.stream("GET", f"/api/v1/tasks/{tid}/stdout/events") as resp:
                        if resp.status_code != 200:
                            emit(out, source="task", line=f"(task stdout SSE returned {resp.status_code})")
                            continue
                        for raw in resp.iter_lines():
                            if stop_event.is_set():
                                break
                            if run_id_box.get("run_id") != rid:
                                break
                            if not raw:
                                continue
                            if raw.startswith("event:"):
                                event_name = raw[6:].strip()
                                continue
                            if raw.startswith("data:"):
                                try:
                                    payload = json.loads(raw[5:].strip())
                                except json.JSONDecodeError:
                                    continue
                                lines = payload.get("lines") or []
                                for entry in lines[last_count:]:
                                    if not isinstance(entry, dict):
                                        continue
                                    text = str(entry.get("text") or "").rstrip()
                                    if not text:
                                        continue
                                    stream = str(entry.get("stream") or "").lower()
                                    prefix = (
                                        "$ " if stream == "command"
                                        else "! " if stream in {"stderr", "error"}
                                        else "  "
                                    )
                                    emit(out, source=f"task:{tid[:8]}", line=prefix + text)
                                last_count = len(lines)
                                if event_name == "task.stdout.missing" or payload.get("stream_terminal"):
                                    emit(out, source="task", line=f"╰── stdout end task {tid[:8]}")
                                    break
        except httpx.HTTPError as exc:
            emit(out, source="task", line=f"(task SSE error: {exc})")
            time.sleep(2.0)


# ───────────────────── active-run discovery ─────────────────────

def _discover_active_run(client: httpx.Client) -> str | None:
    """Find the most-recently-started run that's still alive."""
    try:
        engs = client.get("/api/v1/engagements?limit=10").json()
    except httpx.HTTPError:
        return None
    if not isinstance(engs, list):
        engs = engs.get("items") if isinstance(engs, dict) else []
    engs = engs or []
    engs.sort(key=lambda e: str(e.get("created_at") or ""), reverse=True)
    best: dict[str, Any] | None = None
    best_key = ""
    for eng in engs[:10]:
        eid = eng.get("id")
        if not eid:
            continue
        try:
            runs = client.get(f"/api/v1/engagements/{eid}/runs?limit=5").json()
        except httpx.HTTPError:
            continue
        if not isinstance(runs, list):
            runs = runs.get("items") if isinstance(runs, dict) else []
        for r in runs or []:
            status = str(r.get("status") or "").lower()
            # Prefer running > queued > terminal, then newest.
            rank = "0" if status == "running" else ("1" if status in {"queued", "dispatched", "pending"} else "2")
            key = rank + str(r.get("started_at") or r.get("created_at") or "")
            if best is None or key < best_key:
                best = r
                best_key = key
    return str(best.get("id")) if best else None


def _run_discovery_thread(
    base_url: str,
    actor: str,
    run_id_box: dict[str, str | None],
    out: queue.Queue[TaggedLine | None],
    stop_event: threading.Event,
    pinned: bool,
) -> None:
    """Re-evaluate the active run every few seconds.  If pinned (operator
    passed ``--run-id``), this thread is a no-op."""
    if pinned:
        return
    headers = {"X-Actor": actor}
    with httpx.Client(base_url=base_url, headers=headers, timeout=10.0) as client:
        while not stop_event.is_set():
            rid = _discover_active_run(client)
            current = run_id_box.get("run_id")
            if rid and rid != current:
                run_id_box["run_id"] = rid
                emit(out, source="discover", line=f"active run -> {rid[:8]}")
            time.sleep(5.0)


# ────────────────────── render loop ──────────────────────

def _render_loop(
    out: queue.Queue[TaggedLine | None],
    stop_event: threading.Event,
    quiet_http: bool,
    show_source: bool,
) -> None:
    while not stop_event.is_set():
        try:
            item = out.get(timeout=0.25)
        except queue.Empty:
            continue
        if item is None:
            return
        if not should_emit(item.tag, quiet_http):
            continue
        # The colored tag is the visual anchor; we right-pad the tag so
        # the message column lines up across event classes.
        tag_str = COLOR[item.color](f"{item.tag:<10}")
        ts = COLOR["dim"](_now_short())
        src = ""
        if show_source:
            src = COLOR["dim"](f"[{item.source:<10}]")
        # Body color picks up the same hue as the tag for severe events
        # (ERROR/STOP/TRACE) so they pop visually.
        body = item.text
        if item.color in {"br_red", "red"}:
            body = COLOR[item.color](body)
        elif item.color == "br_green":
            body = COLOR["br_green"](body)
        elif item.color == "br_yellow":
            body = COLOR["yellow"](body)
        elif item.color == "dim":
            body = COLOR["dim"](body)
        sys.stdout.write(f"{ts} {tag_str} {src} {body}\n")
        sys.stdout.flush()


# ────────────────────── main ──────────────────────

def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="True live CLI for AegisPT")
    p.add_argument("--base-url", default=os.environ.get("AEGISPT_BASE_URL", "http://127.0.0.1:8000"))
    p.add_argument("--actor", default="aegispt-live")
    p.add_argument("--run-id", default=None, help="Pin to a specific run id; skip auto-detect.")
    p.add_argument("--no-journal", action="store_true", help="Skip the aegispt-api journalctl tail.")
    p.add_argument("--no-harness", action="store_true", help="Skip the xbow-relive journalctl tail.")
    p.add_argument("--no-task-stdout", action="store_true", help="Skip per-task stdout SSE overlay.")
    p.add_argument("--api-unit", default="aegispt-api", help="systemd --user unit name for the API.")
    p.add_argument("--harness-unit", default="xbow-relive", help="systemd --user unit name for the running benchmark/harness (if any).")
    p.add_argument("--show-source", action="store_true", help="Prefix every line with its source thread.")
    p.add_argument("--no-quiet-http", action="store_true", help="Don't suppress HTTP 200 noise.")
    p.add_argument("--sudo-journal", action="store_true", help="Wrap journalctl in 'sudo -n' (use when running this script as a different user than the unit).")
    args = p.parse_args(argv)

    base_url = args.base_url.rstrip("/")
    out: queue.Queue[TaggedLine | None] = queue.Queue()
    stop_event = threading.Event()
    run_id_box: dict[str, str | None] = {"run_id": args.run_id}

    def _signal_handler(_sig, _frame):
        stop_event.set()
        out.put(None)

    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    threads: list[threading.Thread] = []

    if shutil.which("journalctl") is None:
        emit(out, source="discover", line="(journalctl not on PATH — falling back to SSE-only mode)")
    else:
        if not args.no_journal:
            threads.append(threading.Thread(
                target=_journal_tail_thread,
                args=(args.api_unit, out, stop_event, args.sudo_journal),
                daemon=True,
                name="journal-api",
            ))
        if not args.no_harness:
            threads.append(threading.Thread(
                target=_journal_tail_thread,
                args=(args.harness_unit, out, stop_event, args.sudo_journal),
                daemon=True,
                name="journal-harness",
            ))

    threads.append(threading.Thread(
        target=_run_discovery_thread,
        args=(base_url, args.actor, run_id_box, out, stop_event, args.run_id is not None),
        daemon=True,
        name="discover",
    ))

    threads.append(threading.Thread(
        target=_run_sse_thread,
        args=(base_url, args.actor, run_id_box, out, stop_event),
        daemon=True,
        name="run-sse",
    ))

    if not args.no_task_stdout:
        threads.append(threading.Thread(
            target=_task_stdout_sse_thread,
            args=(base_url, args.actor, run_id_box, out, stop_event),
            daemon=True,
            name="task-stdout-sse",
        ))

    for t in threads:
        t.start()

    banner = COLOR["bold"]("aegispt-live") + COLOR["dim"](
        f"  base={base_url}  run={run_id_box['run_id'] or 'auto-detect'}"
        f"  journal={'off' if args.no_journal else args.api_unit}"
        f"  harness={'off' if args.no_harness else args.harness_unit}"
        f"  task-stdout={'off' if args.no_task_stdout else 'on'}"
    )
    sys.stdout.write(banner + "\n")
    sys.stdout.write(COLOR["dim"]("Ctrl-C to exit. Each line printed AS IT ARRIVES — no refresh, no poll.\n"))
    sys.stdout.flush()

    _render_loop(out, stop_event, quiet_http=(not args.no_quiet_http), show_source=args.show_source)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        sys.exit(130)
