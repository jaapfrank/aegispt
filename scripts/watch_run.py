#!/usr/bin/env python3
"""Live drill-down companion to Mission Control — shows what the agent is
ACTUALLY doing under the surface (CLI command, runner stdout, picker
reasoning, findings) instead of the executive-summary view.

Three modes:

1. **Dashboard** (default) — refreshing snapshot of the run: counts,
   picker rationale, last N tasks with FULL stdout/stderr (no
   truncation), last N findings. Like ``top`` for a pentest run.

2. **Follow-running** (``--follow-running``) — continuously identifies
   the most-recently-started task and tails its stdout via the
   SSE endpoint, automatically switching to the next task when one
   starts. Gives a live "tail -f" of whatever the agent is doing right
   now.

3. **Single-task** (``--task TASK_ID``) — pins to one task and streams
   its stdout via ``/api/v1/tasks/{id}/stdout/events`` until terminal.
   Useful for inspecting one runner's full output.

Examples::

    # See everything for the freshest in-flight run
    python3 scripts/watch_run.py

    # Live-tail whatever runner is active right now (best for "what is it doing?")
    python3 scripts/watch_run.py --follow-running

    # Drill into one specific task
    python3 scripts/watch_run.py --task 8a1c4b22-...

    # CI / scripting one-shot
    python3 scripts/watch_run.py --once
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from typing import Any

import httpx


def _fmt_time(value: str | None) -> str:
    if not value:
        return "         "
    try:
        ts = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return ts.astimezone(timezone.utc).strftime("%H:%M:%S")
    except (ValueError, TypeError):
        return value[:9] if isinstance(value, str) else "         "


def _pick_run(client: httpx.Client) -> dict[str, Any] | None:
    eng_resp = client.get("/api/v1/engagements?limit=20")
    if eng_resp.status_code != 200:
        return None
    eng_list = eng_resp.json()
    engagements = eng_list if isinstance(eng_list, list) else eng_list.get("items") or []
    engagements.sort(key=lambda e: str(e.get("created_at") or ""), reverse=True)
    best: dict[str, Any] | None = None
    best_key = ""
    for eng in engagements[:20]:
        eid = eng.get("id")
        if not eid:
            continue
        try:
            runs_resp = client.get(f"/api/v1/engagements/{eid}/runs?limit=5")
        except httpx.HTTPError:
            continue
        if runs_resp.status_code != 200:
            continue
        runs_payload = runs_resp.json()
        runs_list = runs_payload if isinstance(runs_payload, list) else runs_payload.get("items") or []
        for r in runs_list:
            status = str(r.get("status") or "").lower()
            key = ("0" if status in {"running", "queued", "dispatched"} else "1") + str(
                r.get("started_at") or r.get("created_at") or ""
            )
            if best is None or key < best_key:
                best = r
                best_key = key
    return best


def _short(s: Any, n: int = 220) -> str:
    text = str(s or "").replace("\r", "").rstrip()
    return text if len(text) <= n else text[: n - 1] + "…"


def _indent(text: str, prefix: str = "      ") -> str:
    return "\n".join(prefix + line for line in str(text or "").splitlines())


def _command_preview_from_stdout(stdout: str) -> str:
    """The orchestrator writes a ``$ tool --flag value …`` line as the first
    stdout chunk before the runner starts. Pull it out so the dashboard can
    show the full CLI without truncation."""
    for line in str(stdout or "").splitlines():
        s = line.strip()
        if s.startswith("$ "):
            return s
    return ""


def _fetch_task_detail(client: httpx.Client, task_id: str) -> dict[str, Any] | None:
    """GET /api/v1/tasks/{id} — full payload with executions + stdout snapshot.

    The /runs/{id} response only returns shallow task summaries (no executions
    field), so we have to fetch each displayed task individually to surface its
    stdout / stderr / exit_code. Bounded to the dashboard's tail size so the
    extra calls stay predictable.
    """
    try:
        resp = client.get(f"/api/v1/tasks/{task_id}")
    except httpx.HTTPError:
        return None
    if resp.status_code != 200:
        return None
    return resp.json()


def _render_dashboard(
    run: dict[str, Any],
    tasks: list[dict[str, Any]],
    findings_payload: Any,
    *,
    tail: int,
    full_stdout: bool,
    client: httpx.Client,
) -> str:
    findings = findings_payload if isinstance(findings_payload, list) else findings_payload.get("items") or []
    lines: list[str] = []
    lines.append("=" * 100)
    lines.append(
        f"RUN {str(run.get('id') or '?')[:8]} status={run.get('status')}  "
        f"started={_fmt_time(run.get('started_at'))}  "
        f"target={_short((run.get('configuration_json') or {}).get('target_url'), 50)}"
    )
    lines.append(
        f"  tasks: {len(tasks)} total  |  findings: {len(findings)}  |  "
        f"loop: {(run.get('configuration_json') or {}).get('_assessment_loop', {}).get('status', '?')}"
    )

    loop_state = (run.get("configuration_json") or {}).get("_assessment_loop", {}) or {}
    last_reason = (
        loop_state.get("last_next_step_reason")
        or loop_state.get("last_action_reason")
        or loop_state.get("last_rationale")
    )
    if last_reason:
        lines.append("")
        lines.append("PICKER (most recent decision):")
        lines.append(_indent(str(last_reason), "  "))
    stop_reason = loop_state.get("stop_reason")
    if stop_reason:
        lines.append(f"  STOPPED: {stop_reason}")

    lines.append("")
    lines.append(f"TASKS (last {tail}, newest first):")
    sorted_tasks = sorted(
        tasks,
        key=lambda t: str(t.get("updated_at") or t.get("created_at") or ""),
        reverse=True,
    )[:tail]
    for t in sorted_tasks:
        tool = str(t.get("tool") or "?")
        status = str(t.get("status") or "?")
        target = _short(t.get("target_id"), 60)
        when = _fmt_time(t.get("updated_at") or t.get("created_at"))
        task_id = str(t.get("id") or "")
        task_id_short = task_id[:8]
        lines.append(f"  [{when}] {task_id_short}  {tool:18s} {status:10s} -> {target}")
        # The run-list endpoint omits executions; fetch the per-task detail to
        # get stdout / stderr / command preview.
        detail = _fetch_task_detail(client, task_id) if task_id else None
        snapshot = (detail or {}).get("stdout_snapshot") or {}
        snapshot_lines = snapshot.get("lines") or []
        # Reassemble the stdout text from the snapshot (each entry has .text + .stream).
        command_line = ""
        body_lines: list[str] = []
        stderr_lines: list[str] = []
        for entry in snapshot_lines:
            if not isinstance(entry, dict):
                continue
            text = str(entry.get("text") or "").rstrip()
            if not text:
                continue
            stream = str(entry.get("stream") or "").lower()
            if stream == "command" and not command_line:
                command_line = text
            elif stream in {"stderr", "error"}:
                stderr_lines.append(text)
            else:
                body_lines.append(text)
        execs = (detail or {}).get("executions") or []
        exit_code = execs[0].get("exit_code") if execs else None
        if not command_line and execs:
            command_line = _command_preview_from_stdout(str(execs[0].get("stdout_text") or ""))
        if command_line:
            lines.append(f"      {command_line}")
        if body_lines:
            if full_stdout:
                lines.append(_indent("\n".join(body_lines), "      | "))
            else:
                lines.append(_indent("\n".join(body_lines[-6:]), "      | "))
        if stderr_lines:
            lines.append(_indent("\n".join(stderr_lines[-4:]), "      ! "))
        if exit_code is not None and exit_code != 0:
            lines.append(f"      exit_code: {exit_code}")

    if findings:
        lines.append("")
        lines.append(f"FINDINGS (last {tail}):")
        sorted_findings = sorted(
            findings,
            key=lambda f: str(f.get("created_at") or ""),
            reverse=True,
        )[:tail]
        for f in sorted_findings:
            sev = str(f.get("severity") or "?").upper()[:4]
            title = _short(f.get("title"), 100)
            when = _fmt_time(f.get("created_at"))
            lines.append(f"  [{when}] [{sev:4s}] {title}")

    return "\n".join(lines)


def _identify_running_task(tasks: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Pick the task most likely 'doing something right now'.

    Order of preference: ``running`` > newest ``queued``/``dispatched`` > newest
    ``completed``/``failed`` task in the last 30s (so the operator sees a fresh
    completion before the next pick). Returns None if nothing recent.
    """
    now = time.time()
    active = [t for t in tasks if str(t.get("status") or "").lower() == "running"]
    if active:
        active.sort(key=lambda t: str(t.get("updated_at") or ""), reverse=True)
        return active[0]
    pending = [
        t for t in tasks
        if str(t.get("status") or "").lower() in {"queued", "dispatched", "pending"}
    ]
    if pending:
        pending.sort(key=lambda t: str(t.get("created_at") or ""), reverse=True)
        return pending[0]
    recent = []
    for t in tasks:
        ts = t.get("updated_at") or t.get("created_at")
        try:
            then = datetime.fromisoformat(str(ts).replace("Z", "+00:00")).timestamp()
        except (ValueError, TypeError):
            continue
        if now - then < 30:
            recent.append((then, t))
    if recent:
        recent.sort(reverse=True)
        return recent[0][1]
    return None


def _stream_task_stdout(client: httpx.Client, task_id: str, *, until_terminal: bool, max_seconds: float | None) -> None:
    """Tail a single task's stdout via the API's SSE endpoint, printing each
    new line as it arrives. Exits when the task is terminal."""
    url = f"/api/v1/tasks/{task_id}/stdout/events"
    print(f"--- tail -f task {task_id[:8]} (Ctrl-C to detach) ---")
    last_count = 0
    start = time.time()
    try:
        with client.stream("GET", url, timeout=None) as resp:
            if resp.status_code != 200:
                print(f"(SSE error {resp.status_code}: {resp.text[:200]})", file=sys.stderr)
                return
            event_name = ""
            for raw_line in resp.iter_lines():
                if max_seconds is not None and (time.time() - start) > max_seconds:
                    break
                if not raw_line:
                    continue
                if raw_line.startswith("event:"):
                    event_name = raw_line[6:].strip()
                    continue
                if raw_line.startswith("data:"):
                    payload_text = raw_line[5:].strip()
                    try:
                        payload = json.loads(payload_text)
                    except json.JSONDecodeError:
                        continue
                    new_lines = payload.get("lines") or []
                    for entry in new_lines[last_count:]:
                        if isinstance(entry, dict):
                            text = str(entry.get("text") or "").rstrip()
                            stream = str(entry.get("stream") or "").lower()
                            prefix = "$ " if stream == "command" else (
                                "! " if stream in {"stderr", "error"} else ""
                            )
                            if text:
                                print(prefix + text)
                    last_count = len(new_lines)
                    if event_name == "task.stdout.missing":
                        print("(task missing)", file=sys.stderr)
                        return
                    if until_terminal and payload.get("stream_terminal"):
                        return
    except (KeyboardInterrupt, httpx.HTTPError):
        return


def _resolve_run_id(client: httpx.Client, run_id_arg: str | None) -> str | None:
    if run_id_arg:
        return run_id_arg
    picked = _pick_run(client)
    return str(picked.get("id")) if picked else None


def _follow_running_mode(client: httpx.Client, run_id: str, max_seconds: float | None) -> None:
    """Continuously identify the active task and tail it. Auto-switch when
    the active task changes (next pick fires)."""
    seen_task_id = ""
    start = time.time()
    while True:
        if max_seconds is not None and (time.time() - start) > max_seconds:
            return
        try:
            run_resp = client.get(f"/api/v1/runs/{run_id}")
            if run_resp.status_code != 200:
                time.sleep(2.0)
                continue
            tasks = run_resp.json().get("tasks") or []
        except httpx.HTTPError:
            time.sleep(2.0)
            continue
        task = _identify_running_task(tasks)
        if task is None:
            sys.stdout.write("\r(idle — waiting for next task) ")
            sys.stdout.flush()
            time.sleep(2.0)
            continue
        task_id = str(task.get("id") or "")
        if task_id and task_id != seen_task_id:
            sys.stdout.write("\n")
            seen_task_id = task_id
            tool = task.get("tool")
            target = task.get("target_id")
            print(f"\n===== FOLLOWING task {task_id[:8]}  tool={tool}  target={target} =====")
            _stream_task_stdout(client, task_id, until_terminal=True, max_seconds=None)
        else:
            time.sleep(2.0)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Live drill-down for an AegisPT run")
    p.add_argument("--base-url", default="http://127.0.0.1:8000")
    p.add_argument("--actor", default="watch-run")
    p.add_argument("--run-id", default=None, help="Pin to a specific run id; default = most recent running.")
    p.add_argument("--task", default=None, help="Single-task mode: stream this task id's stdout via SSE until terminal.")
    p.add_argument("--follow-running", action="store_true", help="Auto-follow the currently-active task; switch when the next one starts.")
    p.add_argument("--interval", type=float, default=4.0, help="Dashboard refresh interval seconds (default 4).")
    p.add_argument("--tail", type=int, default=8, help="How many recent tasks/findings to show (default 8).")
    p.add_argument("--full-stdout", action="store_true", help="Print full stdout per task (no 6-line tail cap).")
    p.add_argument("--once", action="store_true", help="Dashboard mode: print one snapshot and exit.")
    p.add_argument("--max-seconds", type=float, default=None, help="Cap total runtime (useful for CI).")
    args = p.parse_args(argv)

    headers = {"X-Actor": args.actor}
    with httpx.Client(base_url=args.base_url.rstrip("/"), timeout=30.0, headers=headers) as client:
        # Mode 1: single-task stream
        if args.task:
            _stream_task_stdout(client, args.task, until_terminal=True, max_seconds=args.max_seconds)
            return 0

        run_id = _resolve_run_id(client, args.run_id)
        if run_id is None:
            print("(no runs available)", file=sys.stderr)
            return 1

        # Mode 2: follow-running (auto-switch between tasks)
        if args.follow_running:
            _follow_running_mode(client, run_id, max_seconds=args.max_seconds)
            return 0

        # Mode 3: dashboard (default)
        start = time.time()
        while True:
            try:
                run_resp = client.get(f"/api/v1/runs/{run_id}")
                if run_resp.status_code == 404:
                    print(f"run {run_id} not found — re-picking", file=sys.stderr)
                    run_id = _resolve_run_id(client, None)
                    if run_id is None:
                        return 1
                    continue
                run_resp.raise_for_status()
                run = run_resp.json()
                tasks = run.get("tasks") or []
                findings_resp = client.get(f"/api/v1/runs/{run_id}/findings")
                findings_payload = findings_resp.json() if findings_resp.status_code == 200 else []
            except httpx.HTTPError as exc:
                print(f"watch_run: API error: {exc}", file=sys.stderr)
                if args.once:
                    return 1
                time.sleep(args.interval)
                continue
            sys.stdout.write("\033[H\033[J")
            sys.stdout.write(_render_dashboard(run, tasks, findings_payload, tail=args.tail, full_stdout=args.full_stdout, client=client))
            sys.stdout.write("\n")
            sys.stdout.flush()
            if args.once:
                return 0
            if args.max_seconds is not None and (time.time() - start) > args.max_seconds:
                return 0
            time.sleep(args.interval)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        sys.exit(130)
