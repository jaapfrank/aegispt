"""Phase-1 jury pipeline (CLI) — the capstone that makes the free slice one command.

A directory of run_trace.jsonl files (one trace per file) -> evidence/coverage jury
-> training factory -> sft.jsonl / dpo_pairs.jsonl / process_reward.jsonl, with the
held-out guard applied. Source-agnostic: traces from deep_chain (from_deep_chain) or
the live runner (from_runner_tasks) both feed this. No reviewer models for this slice
(committee defaults to empty -> evidence + coverage arbiter only).

  python jury_pipeline.py --traces <dir> --held-out a_test.jsonl b_test.jsonl --out <dir>
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import jury_factory as F
import jury_review as J


def reconstruct_messages(trace: list[dict], scenario_id: str) -> list[dict]:
    """A minimal SFT/DPO conversation from the trace: assistant=action, user=tool
    observation. Good enough as training content; the jury supplies the LABEL."""
    msgs: list[dict] = [{"role": "user", "content": f"scenario:{scenario_id}"}]
    for st in trace:
        if st.get("action"):
            msgs.append({"role": "assistant", "content": str(st["action"])})
        if st.get("tool_result"):
            msgs.append({"role": "user", "content": str(st["tool_result"])})
    return msgs


def load_trace(fp: Path) -> list[dict]:
    return [json.loads(line) for line in fp.read_text().splitlines() if line.strip()]


def run(trace_dir: str, *, held_out_paths: list[str] | None = None, out_dir: str,
        committee: list | None = None) -> dict:
    held = F.load_held_out(held_out_paths or [])
    items = []
    for fp in sorted(Path(trace_dir).glob("*.jsonl")):
        trace = load_trace(fp)
        if not trace:
            continue
        # filename convention "<scenario>__<run>.jsonl" so multiple runs of the same
        # scenario share a scenario_id and can form a chosen/rejected DPO pair.
        scn = fp.stem.split("__")[0]
        decision = J.review_trace(trace, committee or [])
        items.append({"scenario_id": scn, "messages": reconstruct_messages(trace, scn),
                      "trace": trace, "decision": decision})
    manifest = F.build_training_sets(items, held_out=held, out_dir=out_dir)
    manifest["traces_seen"] = len(items)
    manifest["held_out_scenarios"] = len(held)
    return manifest


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--traces", required=True, help="dir of *.jsonl run-trace files")
    ap.add_argument("--held-out", nargs="*", default=[], help="held-out eval/test jsonl files")
    ap.add_argument("--out", required=True, help="output dir for the datasets")
    args = ap.parse_args()
    manifest = run(args.traces, held_out_paths=args.held_out, out_dir=args.out)
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
