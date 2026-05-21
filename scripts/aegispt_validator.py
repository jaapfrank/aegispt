#!/usr/bin/env python3
"""Continuous validator service for AegisPT — tails the live API log and
maintains a one-shot status file with the current health of the system.

The point of this service is to give the operator (and me, in next
sessions) a single file to ``cat`` that says "what is the system actually
doing RIGHT NOW + last few hours" — without running 8 different
diagnostic scripts each time.

Three sources of truth get folded into ``validation-status.md``:

1. **Live API log tail** (``/tmp/aegispt-api.log``, line-buffered) for
   real-time events: picker stop reasons, finalizer fires, foothold
   transitions, agent_tool calls, tracebacks.

2. **Database snapshot** (every 30s) for the slowly-changing facts:
   active runs, terminal-status distribution, stuck-run pile-up.

3. **Anomaly detection** — when a never-before-seen stop_reason or
   exception class shows up, push it into an "anomalies" section
   that the operator should read first.

The output file is rewritten atomically every time something changes,
so reading it is always consistent.

Usage::

    python3 scripts/aegispt_validator.py               # foreground
    python3 scripts/aegispt_validator.py --out PATH    # custom output
    python3 scripts/aegispt_validator.py --once        # one-shot snapshot

Wrapped in ``systemd --user`` as ``aegispt-validator.service`` for
continuous operation. ``validation-status.md`` lives at the repo root
so it's the first thing both the operator and a new session see.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import signal
import sys
import threading
import time
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LOG = Path("/tmp/aegispt-api.log")
DEFAULT_OUT = REPO_ROOT / "validation-status.md"
DEFAULT_BASE = "http://127.0.0.1:8000"


# ─────────────────────── event categorisation ───────────────────────

# Patterns the tailer extracts from each log line. Each pattern bumps a
# counter and optionally feeds into the "recent N" deque so the status
# file can show the freshest examples.

_FINALIZER_RE = re.compile(
    r"assessment_loop: finalized run=([a-f0-9]+) status=(\S+) stop_reason=(\S+) "
    r"\(tasks: (\d+) completed, (\d+) failed\)"
)
_PICKER_PICK_RE = re.compile(r"AI loop: Claude (?:said|picked) (\S+)")
_FOOTHOLD_RE = re.compile(r"attack_state: foothold transition (\w+) -> (\w+)")
_AGENT_TOOL_RE = re.compile(r"(?:execute_tool_call|agent_tool|tool_use).*?(\bbash\b|\bcode_exec\b|\bweb_fetch\b|\bweb_search\b|\bfile_io\b|\bsubagent\b)")
_VALIDATOR_RE = re.compile(r"finding_verifier:.*verdict=(\w+)")
_EXPLOIT_DEV_RE = re.compile(r"exploit_developer|compose_exploit_recipe")
_HARNESS_FINALIZE_RE = re.compile(r"harness-finalized via /cancel")
_TRACEBACK_RE = re.compile(r"^\s*Traceback \(most recent call last\)")
_ERROR_RE = re.compile(r"\bERROR\b|ERROR:|Exception:|raised:")


@dataclass
class TailState:
    """Mutable shared state between the tailer thread and the snapshot
    writer thread. Everything is plain JSON-serialisable so the writer
    doesn't have to know anything about thread-locks beyond grabbing
    the global lock once."""

    started_at: float = field(default_factory=time.time)
    lines_seen: int = 0
    finalizer_events: deque = field(default_factory=lambda: deque(maxlen=20))
    stop_reason_counter: Counter = field(default_factory=Counter)
    picker_pick_counter: Counter = field(default_factory=Counter)
    foothold_transitions: deque = field(default_factory=lambda: deque(maxlen=10))
    agent_tool_fires: Counter = field(default_factory=Counter)
    agent_tool_recent: deque = field(default_factory=lambda: deque(maxlen=15))
    validator_verdicts: Counter = field(default_factory=Counter)
    exploit_dev_fires: int = 0
    harness_finalizes: int = 0
    tracebacks: deque = field(default_factory=lambda: deque(maxlen=5))
    errors_recent: deque = field(default_factory=lambda: deque(maxlen=10))
    known_stop_reasons: set = field(default_factory=set)
    anomalies: deque = field(default_factory=lambda: deque(maxlen=20))


# ─────────────────────── file tail ───────────────────────


def _tail_log(path: Path, state: TailState, stop_event: threading.Event, lock: threading.Lock) -> None:
    """``tail -f`` semantics: open the file, seek to end, follow growth,
    survive log rotation (the systemd unit uses ``append:`` so rotation
    is rare but we handle it anyway). Each line classifies into one or
    more buckets via the regexes above. The lock is grabbed only when
    state needs to be mutated, so reads from the writer thread are not
    serialised against tailing."""
    if not path.exists():
        with lock:
            state.anomalies.append(f"{_now_iso()}  log file {path} missing at startup")
        return
    inode_at_open = path.stat().st_ino
    pending_traceback: list[str] = []

    with path.open("r", encoding="utf-8", errors="replace") as fh:
        fh.seek(0, 2)  # end-of-file
        while not stop_event.is_set():
            line = fh.readline()
            if not line:
                # Check log rotation: if the file's inode has changed,
                # reopen. Otherwise just wait for more bytes.
                try:
                    if path.stat().st_ino != inode_at_open:
                        return _tail_log(path, state, stop_event, lock)
                except FileNotFoundError:
                    pass
                time.sleep(0.25)
                continue
            line = line.rstrip("\n")
            _classify_line(line, state, lock, pending_traceback)


def _classify_line(
    line: str,
    state: TailState,
    lock: threading.Lock,
    pending_traceback: list[str],
) -> None:
    """Single-line classifier — bumps the appropriate counters/deques.
    Multiline tracebacks are accumulated across lines until a non-traceback
    line shows up, then flushed as one entry."""
    if pending_traceback:
        # Keep gathering until a clean non-indent line shows up.
        if line.startswith((" ", "\t")) or "Error" in line or "Exception" in line:
            pending_traceback.append(line)
            return
        with lock:
            state.tracebacks.append(_now_iso() + "  " + " | ".join(pending_traceback[:6]))
        pending_traceback.clear()
        # fall through to classify the current line normally

    with lock:
        state.lines_seen += 1

    if _TRACEBACK_RE.search(line):
        pending_traceback.append(line)
        return

    m = _FINALIZER_RE.search(line)
    if m:
        run_id, status, reason, completed, failed = m.groups()
        with lock:
            state.finalizer_events.append({
                "at": _now_iso(),
                "run": run_id,
                "status": status,
                "stop_reason": reason,
                "completed": int(completed),
                "failed": int(failed),
            })
            state.stop_reason_counter[reason] += 1
            if reason not in state.known_stop_reasons:
                state.known_stop_reasons.add(reason)
                state.anomalies.append(f"{_now_iso()}  NEW stop_reason: {reason} (run={run_id[:8]})")
        return

    m = _FOOTHOLD_RE.search(line)
    if m:
        before, after = m.groups()
        with lock:
            state.foothold_transitions.append({"at": _now_iso(), "from": before, "to": after})
        return

    m = _AGENT_TOOL_RE.search(line)
    if m:
        tool = m.group(1)
        with lock:
            state.agent_tool_fires[tool] += 1
            state.agent_tool_recent.append({"at": _now_iso(), "tool": tool, "line": line[:180]})
        return

    m = _VALIDATOR_RE.search(line)
    if m:
        verdict = m.group(1)
        with lock:
            state.validator_verdicts[verdict] += 1
        return

    if _EXPLOIT_DEV_RE.search(line):
        with lock:
            state.exploit_dev_fires += 1
        return

    if _HARNESS_FINALIZE_RE.search(line):
        with lock:
            state.harness_finalizes += 1
        return

    if _ERROR_RE.search(line) and "PROOF-EXEC" not in line:
        with lock:
            state.errors_recent.append(_now_iso() + "  " + line[:200])
        return


# ─────────────────────── DB / API snapshot ───────────────────────


def _snapshot_runs(base_url: str, state: TailState, lock: threading.Lock) -> None:
    """Pull the active-run list from the API. Cheap: one engagements list
    + per-engagement runs."""
    try:
        client = httpx.Client(base_url=base_url, headers={"X-Actor": "aegispt-validator"}, timeout=10)
    except Exception:
        return
    try:
        try:
            engs = client.get("/api/v1/engagements?limit=20").json()
        except httpx.HTTPError as exc:
            with lock:
                state.errors_recent.append(_now_iso() + f"  validator: API unreachable: {exc}")
            return
        if isinstance(engs, dict):
            engs = engs.get("items", [])
        active: list[dict[str, Any]] = []
        status_dist: Counter = Counter()
        for e in engs[:20]:
            eid = e.get("id")
            if not eid:
                continue
            try:
                runs = client.get(f"/api/v1/engagements/{eid}/runs?limit=5").json()
            except httpx.HTTPError:
                continue
            if isinstance(runs, dict):
                runs = runs.get("items", [])
            for r in runs:
                status = str(r.get("status") or "").lower()
                status_dist[status] += 1
                if status in {"running", "queued", "dispatched"}:
                    cfg = r.get("configuration_json") or {}
                    loop = cfg.get("ai_assessment_loop") or {}
                    active.append({
                        "id": r["id"][:8],
                        "eng": (e.get("name") or "")[:35],
                        "status": status,
                        "updated": (r.get("updated_at") or "")[:19],
                        "loop_status": loop.get("status"),
                        "loop_iter": loop.get("iteration_count"),
                        "stop_reason": loop.get("stop_reason"),
                    })
        with lock:
            state.active_runs = active  # type: ignore[attr-defined]
            state.run_status_distribution = status_dist  # type: ignore[attr-defined]
    finally:
        client.close()


# ─────────────────────── snapshot writer ───────────────────────


def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


def _fmt_counter(c: Counter, *, max_items: int = 8) -> str:
    if not c:
        return "  *(none)*"
    total = sum(c.values())
    rows = [f"  - **{k}**: {v}  ({100*v/total:.0f}%)" for k, v in c.most_common(max_items)]
    return "\n".join(rows)


def _render_status(state: TailState, *, log_path: Path) -> str:
    uptime = time.time() - state.started_at
    active = getattr(state, "active_runs", [])
    status_dist = getattr(state, "run_status_distribution", Counter())

    lines: list[str] = [
        "# AegisPT validator status",
        "",
        f"*Generated {_now_iso()}Z — validator uptime {uptime/60:.1f} min — log lines processed: {state.lines_seen}*",
        f"*Source: tailing `{log_path}` + polling `{DEFAULT_BASE}/api/v1/engagements`*",
        "",
    ]

    # 1. Anomalies (operator reads this first)
    if state.anomalies:
        lines += ["## ⚠ Anomalies (read first)", ""]
        for a in list(state.anomalies)[-10:]:
            lines.append(f"- {a}")
        lines.append("")

    # 2. Active runs
    lines += ["## Active runs (non-terminal)", ""]
    if not active:
        lines.append("*(none — system idle)*")
    else:
        lines.append("| run | engagement | status | loop | iter | stop_reason | updated |")
        lines.append("|---|---|---|---|---|---|---|")
        for r in active:
            lines.append(
                f"| `{r['id']}` | {r['eng']} | {r['status']} | "
                f"{r.get('loop_status') or '-'} | {r.get('loop_iter') or '-'} | "
                f"{r.get('stop_reason') or '-'} | {r['updated']} |"
            )
    lines.append("")

    # 3. Recent finalizer events (the key "did the picker stop" signal)
    lines += ["## Recent finalizer events", ""]
    if not state.finalizer_events:
        lines.append("*(none observed since validator start)*")
    else:
        lines.append("| at | run | status | stop_reason | tasks (✓/✗) |")
        lines.append("|---|---|---|---|---|")
        for ev in list(state.finalizer_events)[-12:]:
            lines.append(
                f"| {ev['at']} | `{ev['run'][:8]}` | {ev['status']} | "
                f"{ev['stop_reason']} | {ev['completed']}/{ev['failed']} |"
            )
    lines.append("")

    # 4. Stop_reason histogram (this session)
    lines += ["## Stop_reason histogram (since validator started)", ""]
    lines.append(_fmt_counter(state.stop_reason_counter))
    lines.append("")

    # 5. Run status distribution from DB
    if status_dist:
        lines += ["## Run status distribution (current DB)", ""]
        lines.append(_fmt_counter(status_dist))
        lines.append("")

    # 6. Agent tool firings — this is the canary for the backlog-422
    # wire-in. If bash/code_exec/web_fetch never fire, the agent tools
    # are dead code.
    lines += ["## Agent tool fires (backlog-422 canary)", ""]
    if not state.agent_tool_fires:
        lines.append("*(none observed — agent tools never fired since validator start)*")
    else:
        lines.append(_fmt_counter(state.agent_tool_fires))
        lines.append("")
        lines.append("Recent:")
        for ev in list(state.agent_tool_recent)[-5:]:
            lines.append(f"  - {ev['at']} `{ev['tool']}` — {ev['line'][:120]}")
    lines.append("")

    # 7. Foothold transitions (backlog-412)
    lines += ["## Foothold transitions (backlog-412 canary)", ""]
    if not state.foothold_transitions:
        lines.append("*(none — foothold tracker never advanced)*")
    else:
        for ft in state.foothold_transitions:
            lines.append(f"  - {ft['at']}  {ft['from']} → **{ft['to']}**")
    lines.append("")

    # 8. Validator verdicts (backlog-413)
    lines += ["## Validator verdicts (backlog-413 canary)", ""]
    if not state.validator_verdicts:
        lines.append("*(none — finding_verifier never ran)*")
    else:
        lines.append(_fmt_counter(state.validator_verdicts))
    lines.append("")

    # 9. Exploit developer (backlog-414)
    lines += [
        "## Exploit developer (backlog-414 canary)",
        "",
        f"Lines mentioning exploit_developer / compose_exploit_recipe: **{state.exploit_dev_fires}**",
        "",
    ]

    # 10. Harness finalize fallback fires
    lines += [
        "## Harness /cancel fallback (xbow_benchmark.py finalizer fix)",
        "",
        f"Times harness had to /cancel a non-terminal run: **{state.harness_finalizes}** "
        "(should be 0 in steady state — every fire means auto-finalizer didn't catch it)",
        "",
    ]

    # 11. Recent tracebacks + errors
    if state.tracebacks or state.errors_recent:
        lines += ["## Recent errors / tracebacks", ""]
        for tb in list(state.tracebacks)[-3:]:
            lines.append(f"  - {tb}")
        for er in list(state.errors_recent)[-5:]:
            lines.append(f"  - {er}")
        lines.append("")

    return "\n".join(lines) + "\n"


def _atomic_write(target: Path, text: str) -> None:
    tmp = target.with_suffix(target.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(target)


# ─────────────────────── main ───────────────────────


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Continuous validator for AegisPT")
    p.add_argument("--log", type=Path, default=DEFAULT_LOG)
    p.add_argument("--out", type=Path, default=DEFAULT_OUT)
    p.add_argument("--base-url", default=DEFAULT_BASE)
    p.add_argument("--interval", type=float, default=15.0, help="Snapshot write + DB poll interval seconds")
    p.add_argument("--once", action="store_true", help="Render one snapshot and exit (CI mode)")
    args = p.parse_args(argv)

    state = TailState()
    state.active_runs = []  # type: ignore[attr-defined]
    state.run_status_distribution = Counter()  # type: ignore[attr-defined]
    stop_event = threading.Event()
    lock = threading.Lock()

    def _handle_sig(*_):
        stop_event.set()

    signal.signal(signal.SIGINT, _handle_sig)
    signal.signal(signal.SIGTERM, _handle_sig)

    if args.once:
        _snapshot_runs(args.base_url, state, lock)
        _atomic_write(args.out, _render_status(state, log_path=args.log))
        print(f"validator: one-shot snapshot -> {args.out}")
        return 0

    tail_thread = threading.Thread(
        target=_tail_log, args=(args.log, state, stop_event, lock), daemon=True, name="tailer",
    )
    tail_thread.start()

    last_db_snapshot = 0.0
    print(f"validator: tailing {args.log} -> writing {args.out} every {args.interval}s", flush=True)
    while not stop_event.is_set():
        now = time.time()
        if now - last_db_snapshot >= args.interval:
            _snapshot_runs(args.base_url, state, lock)
            last_db_snapshot = now
        try:
            _atomic_write(args.out, _render_status(state, log_path=args.log))
        except OSError as exc:
            print(f"validator: write to {args.out} failed: {exc}", flush=True)
        stop_event.wait(args.interval)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        sys.exit(130)
