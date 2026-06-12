"""Harvest winning interactive-exploit trajectories into multi-turn SFT data (pad B / specialist).

The capability frontier is multi-turn persistence (register->login->admin, source->payload->flag),
and the existing SFT mix is SINGLE-TURN so it cannot teach it (memory: multistep-gap-is-the-frontier).
The interactive-exploit runner already persists every loop's full transcript
(`*-interactive-exploit-transcript.json`: per-step reasoning + http_request + observation). This
script turns the WINNING ones into multi-turn training examples.

Quality gate ("only proven wins", the No-Exploit-No-Report discipline applied to training data):
a transcript is kept ONLY if a flag literal actually appears in it. This rejects false-positive
"wins" (e.g. a run whose finding was a decoy/regex artifact but whose transcript has no flag).

Output: one JSON object per line, OpenAI-style multi-turn `messages` with tool calls:
  system -> (assistant: reasoning + http_request tool_call -> tool: response)* -> done.
Standalone: scans the inline artifact dir, no DB/session needed.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

# Match the runner's flag taxonomy (xbow / flag{...} / aegispt{...}). Kept local so the
# harvester has no import-time dependency on the runner/app.
_FLAG_RE = re.compile(r"(flag\{[^}\s]{1,200}\}|xbow-[0-9a-f]{8,}|aegispt\{[^}\s]{1,200}\})")

_SYSTEM_MSG = (
    "You are an authorized penetration tester solving a web security challenge. You have ONE "
    "tool: http_request(method, url, headers, body). Work evidence-first: send one request, "
    "read the FULL response, then decide the next request. Cookies/sessions persist across "
    "calls. Chain steps (observe -> probe -> confirm -> exploit) until you capture the flag. "
    "Do not stop until the flag is captured."
)


def transcript_to_messages(transcript: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Convert a runner transcript (list of {step, assistant_text?, request?, response?}) into a
    multi-turn messages list with http_request tool calls + tool results."""
    messages: list[dict[str, Any]] = [{"role": "system", "content": _SYSTEM_MSG}]
    messages.append({"role": "user", "content": "Begin. Capture the flag."})
    tool_idx = 0
    for entry in transcript:
        if not isinstance(entry, dict):
            continue
        text = str(entry.get("assistant_text") or "").strip()
        req = entry.get("request")
        if req:
            tool_idx += 1
            call_id = f"call_{tool_idx}"
            messages.append({
                "role": "assistant",
                "content": text,
                "tool_calls": [{
                    "id": call_id, "type": "function",
                    "function": {"name": "http_request", "arguments": json.dumps(req)},
                }],
            })
            messages.append({
                "role": "tool", "tool_call_id": call_id,
                "content": str(entry.get("response") or ""),
            })
        elif text:
            messages.append({"role": "assistant", "content": text})
    return messages


def _flag_in(transcript: list[dict[str, Any]]) -> str | None:
    m = _FLAG_RE.search(json.dumps(transcript))
    return m.group(0) if m else None


def harvest(artifacts_dir: Path) -> tuple[list[dict[str, Any]], dict[str, int]]:
    files = sorted(artifacts_dir.rglob("*-interactive-exploit-transcript.json"))
    examples: list[dict[str, Any]] = []
    stats = {"transcripts_found": 0, "won": 0, "kept": 0, "no_flag": 0, "too_short": 0, "parse_error": 0}
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
        messages = transcript_to_messages(transcript)
        # need at least one real request/response turn to be a useful trajectory
        if sum(1 for m in messages if m["role"] == "tool") < 1:
            stats["too_short"] += 1
            continue
        examples.append({
            "messages": messages,
            "meta": {"source": str(f), "flag_sha_prefix": flag[:6], "turns": len(messages)},
        })
        stats["kept"] += 1
    return examples, stats


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--artifacts-dir", default=".aegispt-artifacts")
    ap.add_argument("--out", default="codex/results/training/winning_trajectories.jsonl")
    args = ap.parse_args()
    examples, stats = harvest(Path(args.artifacts_dir))
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as fh:
        for ex in examples:
            fh.write(json.dumps(ex) + "\n")
    print(json.dumps({"out": str(out), **stats}, indent=2))


if __name__ == "__main__":
    main()
