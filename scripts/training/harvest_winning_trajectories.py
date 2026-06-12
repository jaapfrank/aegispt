"""Harvest winning interactive-exploit trajectories into multi-turn SFT data (pad B / specialist).

The capability frontier is multi-turn persistence (register->login->admin, source->payload->flag),
and the existing SFT mix is SINGLE-TURN so it cannot teach it (memory: multistep-gap-is-the-frontier).
The interactive-exploit runner already persists every loop's full transcript
(`*-interactive-exploit-transcript.json`: per-step reasoning + http_request + observation). This
script turns the WINNING ones into multi-turn training examples.

Quality gate ("only proven wins", the No-Exploit-No-Report discipline applied to training data):
a transcript is kept ONLY if a flag literal actually appears in it. This rejects false-positive
"wins" (e.g. a run whose finding was a decoy/regex artifact but whose transcript has no flag).

Output: one {"messages":[...]} per line in the EXACT format the existing trainers
(qlora_train / grpo_train) consume: SYSTEM -> (assistant inline-JSON action -> user
HTTP-RESPONSE observation)* -> a final done turn. Standalone: scans the inline artifact
dir, no DB/session needed.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

# Reuse the EXACT training format the existing pipeline (qlora_train / grpo_train) expects, so
# the harvested real trajectories drop in as a replacement for make_dataset.py's SYNTHETIC toy
# data: SYSTEM (assistant emits one {"reasoning","request","done"} JSON), J() = an assistant
# action turn, obs() = an HTTP-RESPONSE user turn. Staying in sync = no format drift.
from scripts.training.make_dataset import SYSTEM, J, obs  # noqa: E402

# Match the runner's flag taxonomy (xbow / flag{...} / aegispt{...}).
_FLAG_RE = re.compile(r"(flag\{[^}\s]{1,200}\}|xbow-[0-9a-f]{8,}|aegispt\{[^}\s]{1,200}\})")


def _parse_response(resp: Any) -> tuple[int, dict, str]:
    """A transcript response is a JSON string {status, headers, body} (or an error dict)."""
    if isinstance(resp, str):
        try:
            resp = json.loads(resp)
        except Exception:
            return 0, {}, str(resp)[:1200]
    if not isinstance(resp, dict):
        return 0, {}, str(resp)[:1200]
    return int(resp.get("status") or 0), dict(resp.get("headers") or {}), str(resp.get("body") or "")[:1200]


def transcript_to_messages(transcript: list[dict[str, Any]], flag: str) -> list[dict[str, Any]]:
    """Convert a runner transcript (list of {step, assistant_text?, request?, response?}) into the
    pipeline's training format: SYSTEM + (assistant J() action -> user obs() response)* -> a final
    done turn once the flag has been observed."""
    target = ""
    for e in transcript:
        if isinstance(e, dict) and e.get("request"):
            target = str(e["request"].get("url") or "")
            break
    messages: list[dict[str, Any]] = [{"role": "system", "content": SYSTEM}]
    messages.append({"role": "user", "content": f"Goal: capture the flag on {target or 'the target'}. Begin."})
    for entry in transcript:
        if not isinstance(entry, dict):
            continue
        req = entry.get("request")
        if not req:
            continue
        reasoning = str(entry.get("assistant_text") or "Proceed to the next step.").strip()
        messages.append({"role": "assistant", "content": J(
            reasoning, req.get("method", "GET"), req.get("url", ""),
            req.get("headers") or None, req.get("body"), done=False)})
        status, headers, body = _parse_response(entry.get("response"))
        messages.append({"role": "user", "content": obs(status, headers, body)})
    # Final done turn: the goal was reached (a flag is present in the trajectory).
    messages.append({"role": "assistant", "content": J(
        f"The response contains the target flag {flag}. Goal reached.", done=True)})
    return messages


def _flag_in(transcript: list[dict[str, Any]]) -> str | None:
    m = _FLAG_RE.search(json.dumps(transcript))
    return m.group(0) if m else None


def _action_signature(messages: list[dict[str, Any]]) -> tuple[tuple[str, str], ...]:
    """Ordered (method, url) sequence of the http actions in a trajectory.

    Read from the assistant turns' inline-JSON ``request`` fields (the same format
    ``J()`` emits). Two trajectories with the identical ordered action sequence get
    the same signature and are treated as duplicates regardless of reasoning text,
    headers, or body wording. The final ``done`` turn carries no request and is
    skipped naturally (its ``request`` is ``null``)."""
    sig: list[tuple[str, str]] = []
    for m in messages:
        if m.get("role") != "assistant":
            continue
        try:
            payload = json.loads(m.get("content") or "")
        except Exception:
            continue
        req = payload.get("request")
        if not isinstance(req, dict) or not req.get("url"):
            continue
        sig.append((str(req.get("method") or "GET").upper(), str(req.get("url") or "")))
    return tuple(sig)


def _dedup(examples: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Drop trajectories whose ordered (method, url) action signature was already kept."""
    seen: set[tuple[tuple[str, str], ...]] = set()
    kept: list[dict[str, Any]] = []
    for ex in examples:
        sig = _action_signature(ex["messages"])
        if sig in seen:
            continue
        seen.add(sig)
        kept.append(ex)
    return kept


def _balance(examples: list[dict[str, Any]], max_per_challenge: int) -> list[dict[str, Any]]:
    """Keep at most ``max_per_challenge`` trajectories per challenge.

    The challenge key is the flag (``meta.flag_sha_prefix``) — every win for the same
    challenge shares the same flag literal, so capping per-flag caps per-challenge and
    stops one over-represented challenge from dominating the SFT mix."""
    if max_per_challenge <= 0:
        return list(examples)
    counts: dict[str, int] = {}
    kept: list[dict[str, Any]] = []
    for ex in examples:
        key = str(ex["meta"].get("flag_sha_prefix") or "")
        if counts.get(key, 0) >= max_per_challenge:
            continue
        counts[key] = counts.get(key, 0) + 1
        kept.append(ex)
    return kept


def harvest(
    artifacts_dir: Path,
    *,
    dedup: bool = True,
    max_per_challenge: int = 8,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    files = sorted(artifacts_dir.rglob("*-interactive-exploit-transcript.json"))
    examples: list[dict[str, Any]] = []
    stats = {
        "transcripts_found": 0, "won": 0, "kept": 0, "no_flag": 0,
        "too_short": 0, "parse_error": 0,
        "distinct_challenges": 0, "after_dedup": 0, "after_balance": 0,
    }
    for f in files:
        stats["transcripts_found"] += 1
        try:
            transcript = json.loads(f.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            stats["parse_error"] += 1
            continue
        if not isinstance(transcript, list):
            stats["parse_error"] += 1
            continue
        flag = _flag_in(transcript)
        if not flag:
            stats["no_flag"] += 1
            continue
        stats["won"] += 1
        messages = transcript_to_messages(transcript, flag)
        # need at least one real action+observation turn to be a useful trajectory
        obs_turns = sum(1 for m in messages
                        if m["role"] == "user" and str(m.get("content", "")).startswith("HTTP RESPONSE"))
        if obs_turns < 1:
            stats["too_short"] += 1
            continue
        examples.append({
            "messages": messages,
            "meta": {"source": str(f), "flag_sha_prefix": flag[:6],
                     "turns": len(messages), "http_turns": obs_turns},
        })

    # Quality pass: dedup identical action sequences, then balance per challenge so
    # one over-represented challenge cannot dominate the specialist's SFT mix.
    if dedup:
        examples = _dedup(examples)
    stats["after_dedup"] = len(examples)
    examples = _balance(examples, max_per_challenge)
    stats["after_balance"] = len(examples)
    stats["distinct_challenges"] = len({
        str(ex["meta"].get("flag_sha_prefix") or "") for ex in examples
    })
    stats["kept"] = len(examples)
    return examples, stats


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--artifacts-dir", default=".aegispt-artifacts")
    ap.add_argument("--out", default="codex/results/training/winning_trajectories.jsonl")
    ap.add_argument(
        "--dedup", action=argparse.BooleanOptionalAction, default=True,
        help="Drop trajectories with an identical ordered (method,url) action sequence "
             "(default on; use --no-dedup to keep duplicates).",
    )
    ap.add_argument(
        "--max-per-challenge", type=int, default=8,
        help="Keep at most N winning trajectories per challenge (flag); 0 = no cap. Default 8.",
    )
    args = ap.parse_args()
    examples, stats = harvest(
        Path(args.artifacts_dir),
        dedup=args.dedup,
        max_per_challenge=args.max_per_challenge,
    )
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as fh:
        for ex in examples:
            fh.write(json.dumps(ex) + "\n")
    print(json.dumps({"out": str(out), **stats}, indent=2))


if __name__ == "__main__":
    main()
