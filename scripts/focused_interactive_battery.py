#!/usr/bin/env python3
"""Parallel FOCUSED interactive battery (2026-05-29).

Codex's #1 next step after the interactive architecture landed: stop drowning a
single agent in 50 challenges / 96 routes / 52 gate tokens. Instead run many
small, ISOLATED interactive sessions — ONE challenge per agent run, seeded with
ONLY that challenge's facts (entrypoints + notes + family + internal port) — at
controlled concurrency, and let SCORE/EVIDENCE be the truth, not UI findings.

Each run is graded against the lab /grade endpoint. Output is JSONL with the
fields codex asked for: challenge_id, family, provider, model, steps, elapsed,
solved, flag, stop_reason, first_flag_step, failure_reason. The final report
gives solves overall + per family, p50 time-to-flag, and failure clusters.

This is provider-agnostic: it drives the SAME generic interactive loop
(workers.runners.interactive_exploit) for gemini / gpt-5.4 / claude, so model
lift is measured on an identical harness (Gemini-first for cheap, reproducible
proof; Claude/gpt-5.4 as calibration).

Usage:
  python scripts/focused_interactive_battery.py \
      --provider gemini-3.1-pro-preview --budget 120 --max-steps 16 \
      --concurrency 4 --limit 8 --out /tmp/battery.jsonl
  # focus a family or explicit ids:
  --focus ssrf            (family)
  --focus ssrf-loopback-metadata,cache-key-header-confusion
  # gpt-5.4 needs an engagement with an OAuth token:
  --provider gpt-5.4 --engagement-id <uuid>
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

LAB = REPO / "labs" / "aegispt_lab_suite"
DEFAULT_TARGET = "http://127.0.0.155:8088"
DEFAULT_SCOPE = "http://127.0.0.155"

_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _internal_ports() -> list[int]:
    """Scan the lab app once for internal listen ports (global fact)."""
    try:
        from workers.runners.pre_recon_source.runner import _scan_file

        ports: set[int] = set()
        for f in LAB.glob("*.py"):
            for p in _scan_file(f, LAB).get("listen_ports", []):
                try:
                    ports.add(int(p["port"]))
                except Exception:  # noqa: BLE001
                    pass
        return sorted(ports) or [8080]
    except Exception:  # noqa: BLE001
        return [8080]


_APP_SRC: str | None = None


def _app_source() -> str:
    global _APP_SRC
    if _APP_SRC is None:
        try:
            _APP_SRC = (LAB / "app.py").read_text()
        except Exception:  # noqa: BLE001
            _APP_SRC = ""
    return _APP_SRC


def _source_facts_for_challenge(cid: str, entrypoints: list[str] | None = None) -> str:
    """Per-challenge gate-token recon, attributed via expected_flag("<id>").

    This is the SAME fact class `pre_recon_source` extracts on a real target
    (custom headers, magic constants, interpolation tokens, gated params), just
    scoped to THIS challenge's handler instead of dumping all 52 across the app.
    It surfaces what the endpoint INSPECTS — the operator still reasons how to
    satisfy the gate. NOT a hand-written exploit recipe.
    """
    src = _app_source()
    if not src:
        return ""
    import re

    lines = src.splitlines()

    def _region_from_idx(idx: int) -> list[str]:
        start = idx
        while start > 0 and not re.match(r"\s*def ", lines[start]):
            start -= 1
        base = len(lines[start]) - len(lines[start].lstrip())
        end = idx
        for j in range(idx + 1, min(len(lines), idx + 60)):
            if lines[j].strip().startswith("def ") and (len(lines[j]) - len(lines[j].lstrip())) <= base:
                break
            end = j
        return lines[start:end + 1]

    # Anchor regions: (a) the handler that emits THIS challenge's flag, and
    # (b) the handler(s) bound to each of the challenge's entrypoint routes —
    # multi-step challenges set the gate in a DIFFERENT handler than the flag.
    region_lines: list[str] = []
    for i, ln in enumerate(lines):
        if f'expected_flag("{cid}")' in ln or f"expected_flag('{cid}')" in ln:
            region_lines.extend(_region_from_idx(i))
    # route -> handler dispatch map (path on one line, self._handle_X() next)
    handler_of = dict(re.findall(r'parsed\.path == ["\']([^"\']+)["\'][^\n]*\n\s*self\.(_handle_\w+)\(', src))
    for ep in entrypoints or []:
        route = ep.split(" ", 1)[-1].strip() if " " in ep else ep.strip()
        hname = handler_of.get(route)
        if hname:
            for i, ln in enumerate(lines):
                if re.match(rf"\s*def {re.escape(hname)}\(", ln):
                    region_lines.extend(_region_from_idx(i))
                    break
    if not region_lines:
        return ""
    region = "\n".join(region_lines)
    headers = sorted(set(re.findall(r'self\.headers\.get\(\s*["\']([^"\']+)["\']', region)))
    # Equality gates (x == "v") AND substring/membership gates ("v" in x) — the
    # latter is how several challenges gate (e.g. "roadmap" in query).
    magic = sorted(set(
        re.findall(r'==\s*["\']([^"\']{1,48})["\']', region)
        + re.findall(r'["\']([^"\']{1,48})["\']\s+in\s+\w', region)
    ))
    interp = sorted(set(re.findall(r'(\$\{[^}]{1,48}\})', region)))
    params = sorted(set(re.findall(r'params\.get\(\s*["\']([^"\']+)["\']', region)))
    bodyk = sorted(set(re.findall(r'payload\.get\(\s*["\']([^"\']+)["\']', region)))
    facts = []
    if headers:
        facts.append(f"request headers this endpoint inspects: {headers}")
    if interp:
        facts.append(f"interpolation tokens it expands in input: {interp}")
    if magic:
        facts.append(f"exact string values it compares input against: {magic}")
    if params:
        facts.append(f"query params it reads: {params}")
    if bodyk:
        facts.append(f"JSON body fields it reads: {bodyk}")
    if not facts:
        return ""
    return ("SOURCE-DERIVED ENDPOINT FACTS (from source review; reason out how to "
            "satisfy the gate yourself):\n  " + "\n  ".join(facts))


def _focused_recon(ch: dict, ports: list[int]) -> str:
    eps = ", ".join(ch.get("entrypoints", []) or [])
    facts = _source_facts_for_challenge(ch["id"], ch.get("entrypoints"))
    return (
        f"CHALLENGE: {ch['id']} (family={ch.get('family', '?')})\n"
        f"ENTRYPOINTS: {eps or '(discover them)'}\n"
        f"NOTES: {ch.get('notes', '')}\n"
        f"INTERNAL LISTEN PORT(S): {ports} — for server-side-fetch/SSRF the server "
        f"fetches from INSIDE its container; use http://127.0.0.1:<port>/...\n"
        + (facts + "\n" if facts else "")
        + f"GOAL: capture the flag aegispt{{{ch['id']}:...}} this challenge emits when its bug fires."
    )


def _reset_lab(target: str) -> bool:
    """Reset the lab's in-memory STATE so cross-run leakage cannot inflate
    solves (cache entries, search_index_public, channel state persist otherwise)."""
    req = urllib.request.Request(f"{target}/__lab/reset", data=b"", method="POST")
    try:
        return json.loads(_OPENER.open(req, timeout=5).read()).get("status") == "reset"
    except Exception:  # noqa: BLE001
        return False


def _grade(challenge_id: str, flag: str, target: str) -> bool:
    body = json.dumps({"challenge_id": challenge_id, "flag": flag}).encode()
    req = urllib.request.Request(f"{target}/grade", data=body,
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        return bool(json.loads(_OPENER.open(req, timeout=5).read()).get("match"))
    except Exception:  # noqa: BLE001
        return False


def _run_one(ch: dict, *, target: str, scope: str, model: str, budget: float,
             max_steps: int, ports: list[int], engagement_id: str | None,
             reset_each: bool = False) -> dict:
    from workers.runners.interactive_exploit.runner import execute_interactive_exploit

    if reset_each:
        _reset_lab(target)
    t0 = time.time()
    res = execute_interactive_exploit(
        [target], scope_allowlist={"urls": [scope]},
        recon_context=_focused_recon(ch, ports), timeout_seconds=budget,
        model=model, max_steps=max_steps, engagement_id=engagement_id,
        stop_on_first_flag=True,  # focused single-challenge: stop on proof
        allow_loopback=True,  # local lab driver: scope is loopback by design
    )
    summary = json.loads(res.stdout) if res.stdout else {}
    flags = summary.get("captured_flags", []) or []
    # Grade ONLY a flag whose id matches this challenge (no cross-challenge credit).
    solved_flag = None
    for fl in flags:
        try:
            cid = fl.split("{", 1)[1].split(":", 1)[0]
        except Exception:  # noqa: BLE001
            continue
        if cid == ch["id"] and _grade(cid, fl, target):
            solved_flag = fl
            break
    solved = solved_flag is not None
    stop = summary.get("stop_reason")
    if solved:
        failure = None
    elif flags and not solved_flag:
        failure = "captured_but_grader_reject_or_wrong_challenge"
    else:
        failure = stop or "no_flag"
    return {
        "challenge_id": ch["id"],
        "family": ch.get("family", "?"),
        "provider": summary.get("provider"),
        "model": summary.get("model", model),
        "steps": summary.get("steps"),
        "elapsed": round(time.time() - t0, 1),
        "solved": solved,
        "flag": solved_flag,
        "stop_reason": stop,
        "first_flag_step": summary.get("first_flag_step"),
        "first_flag_elapsed": summary.get("first_flag_elapsed"),
        "failure_reason": failure,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--provider", "--model", dest="model", default="gemini-3.1-pro-preview")
    ap.add_argument("--target", default=DEFAULT_TARGET)
    ap.add_argument("--scope", default=DEFAULT_SCOPE)
    ap.add_argument("--budget", type=float, default=120.0, help="per-challenge seconds")
    ap.add_argument("--max-steps", type=int, default=16)
    ap.add_argument("--concurrency", type=int, default=4)
    ap.add_argument("--limit", type=int, default=0, help="0 = all")
    ap.add_argument("--focus", default="", help="family name OR comma-separated challenge ids")
    ap.add_argument("--engagement-id", default="", help="required for gpt-5.4/chatgpt-oauth")
    ap.add_argument("--reset-each", action="store_true",
                    help="reset lab STATE before each challenge (forces sequential; clean measurement)")
    ap.add_argument("--out", default="/tmp/focused_battery.jsonl")
    args = ap.parse_args()
    if args.reset_each:
        args.concurrency = 1  # isolation requires sequential runs

    manifest = json.loads((LAB / "suite_manifest.json").read_text())
    challenges = manifest["challenges"]
    if args.focus:
        sel = {s.strip() for s in args.focus.split(",") if s.strip()}
        challenges = [c for c in challenges
                      if c["id"] in sel or c.get("family") in sel]
    if args.limit:
        challenges = challenges[:args.limit]
    ports = _internal_ports()
    eng = args.engagement_id or None

    print(f"FOCUSED BATTERY model={args.model} challenges={len(challenges)} "
          f"budget={args.budget}s max_steps={args.max_steps} concurrency={args.concurrency} ports={ports}")
    rows: list[dict] = []
    out = Path(args.out)
    t0 = time.time()
    with out.open("w") as fh, ThreadPoolExecutor(max_workers=args.concurrency) as ex:
        futs = {ex.submit(_run_one, c, target=args.target, scope=args.scope, model=args.model,
                          budget=args.budget, max_steps=args.max_steps, ports=ports,
                          engagement_id=eng, reset_each=args.reset_each): c for c in challenges}
        for fut in as_completed(futs):
            try:
                row = fut.result()
            except Exception as exc:  # noqa: BLE001
                c = futs[fut]
                row = {"challenge_id": c["id"], "family": c.get("family"), "solved": False,
                       "failure_reason": f"harness_error:{str(exc)[:120]}"}
            rows.append(row)
            fh.write(json.dumps(row) + "\n")
            fh.flush()
            mark = "OK " if row.get("solved") else "...."
            print(f"  [{mark}] {row['challenge_id']:<34} steps={row.get('steps')} "
                  f"ttf={row.get('first_flag_elapsed')}s stop={row.get('stop_reason')} "
                  f"fail={row.get('failure_reason')}")

    solved = [r for r in rows if r.get("solved")]
    ttf = [r["first_flag_elapsed"] for r in solved if r.get("first_flag_elapsed") is not None]
    by_family: dict[str, list[dict]] = {}
    for r in rows:
        by_family.setdefault(r.get("family", "?"), []).append(r)
    fail_clusters: dict[str, int] = {}
    for r in rows:
        if not r.get("solved"):
            fail_clusters[r.get("failure_reason") or "?"] = fail_clusters.get(r.get("failure_reason") or "?", 0) + 1

    print("\n=== FOCUSED BATTERY REPORT ===")
    print(f"model={args.model}  solved={len(solved)}/{len(rows)}  wall={round(time.time()-t0,1)}s  out={out}")
    if ttf:
        print(f"time-to-flag: p50={statistics.median(ttf)}s  min={min(ttf)}s  max={max(ttf)}s")
    print("per family:")
    for fam in sorted(by_family):
        fr = by_family[fam]
        print(f"  {fam:<14} {sum(1 for r in fr if r.get('solved'))}/{len(fr)}")
    if fail_clusters:
        print("failure clusters:")
        for reason, n in sorted(fail_clusters.items(), key=lambda kv: -kv[1]):
            print(f"  {n:>2}x {reason}")
    print("SOLVED:", sorted(r["challenge_id"] for r in solved))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
