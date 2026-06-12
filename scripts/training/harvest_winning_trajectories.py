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
