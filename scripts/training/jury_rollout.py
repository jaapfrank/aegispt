"""Expert iteration / rejection-sampling (the RL-lite lever). Sample N rollouts of
the deep_chain scenario (temperature>0), rank them by the ENVIRONMENT's evidence
reward (flag/idor/login/steps -- evidence is the boss, NOT a model judge), and export
the BEST trajectories as SFT demonstrations. SFT on them pulls the model toward its
own best behaviour -> push 'authenticates' (combined model) toward the IDOR pivot and
the flag. Repeat for a few rounds.

  python jury_rollout.py --rollouts <dir of roll_<i>.jsonl + res_<i>.json> --out best_sft.jsonl
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def reward(result: dict) -> int:
    """Shaped env reward: flag dominates, then the IDOR pivot, then auth, then depth."""
    return (10 * int(bool(result.get("flag")))
            + 3 * int(bool(result.get("idor")))
            + 2 * int(bool(result.get("logged_in")))
            + int(result.get("steps", 0)))


def reconstruct_messages(trace: list[dict]) -> list[dict]:
    msgs: list[dict] = []
    for st in trace:
        if st.get("action"):
            msgs.append({"role": "assistant", "content": str(st["action"])})
        if st.get("tool_result"):
            msgs.append({"role": "user", "content": str(st["tool_result"])})
    return msgs


def collect(rollout_dir: str) -> list[tuple[int, dict, list[dict]]]:
    rolls = []
    for tf in sorted(Path(rollout_dir).glob("roll_*.jsonl")):
        idx = tf.stem.split("_", 1)[1]
        rf = Path(rollout_dir) / f"res_{idx}.json"
        if not rf.exists():
            continue
        trace = [json.loads(line) for line in tf.read_text().splitlines() if line.strip()]
        try:
            result = json.loads(rf.read_text())
        except Exception:
            continue
        if trace:
            rolls.append((reward(result), result, trace))
    rolls.sort(key=lambda x: x[0], reverse=True)
    return rolls


def run(rollout_dir: str, *, out: str, top_frac: float = 0.34, min_reward: int = 3) -> dict:
    rolls = collect(rollout_dir)
    if not rolls:
        Path(out).write_text("")
        return {"rollouts": 0, "kept": 0}
    k = max(1, int(len(rolls) * top_frac))
    best = [r for r in rolls[:k] if r[0] >= min_reward]
    sft = [{"messages": reconstruct_messages(t)} for _, _, t in best]
    Path(out).write_text("\n".join(json.dumps(r) for r in sft) + ("\n" if sft else ""))
    return {"rollouts": len(rolls), "best_reward": rolls[0][0], "median_reward": rolls[len(rolls) // 2][0],
            "kept": len(sft), "any_flag": any(r[1].get("flag") for r in rolls),
            "any_idor": any(r[1].get("idor") for r in rolls)}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rollouts", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--top-frac", type=float, default=0.34)
    ap.add_argument("--min-reward", type=int, default=3)
    args = ap.parse_args()
    print(json.dumps(run(args.rollouts, out=args.out, top_frac=args.top_frac, min_reward=args.min_reward), indent=2))


if __name__ == "__main__":
    main()
