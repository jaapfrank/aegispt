#!/usr/bin/env python3
"""Expert-iteration rollout collector for the iter9 P2 RL envs.

`run_oracle` produces the PERFECT (oracle) trajectory; this collects the MODEL's OWN
rollouts against `multichain_rl_envs_iter9.TrainingEnv` (temperature>0, N per scenario),
ranks them by the ENVIRONMENT's evidence reward (flag/recovered_after_block/used_revealed
/pivot/login — evidence is the boss, not a model judge), and emits the BEST as SFT
demonstrations. SFT on the model's own successes is the expert-iteration / rejection-
sampling lever that targets the diagnosed gap: blocked-goal -> backtrack -> recover.

The reward signals are STRIPPED from the observation fed back to the model (only the
HTTP status/headers/body are returned) so the model cannot game the reward.

Model endpoint is configurable so this validates against a cloud teacher NOW (GPU busy
with the re-tune) and runs against the local served model once the GPU frees:
  AEGISPT_RL_ENDPOINT=https://api.deepseek.com/v1/chat/completions  AEGISPT_RL_MODEL=deepseek-v4-pro
  AEGISPT_RL_ENDPOINT=http://127.0.0.1:8810/v1/chat/completions     AEGISPT_RL_MODEL=local

  python jury_rl_model_rollout.py --out-dir <dir> --n 6 [--scenario <id>] [--sft best.jsonl]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import multichain_rl_envs_iter9 as ENVS  # noqa: E402
import jury_rollout as ROLLOUT  # noqa: E402

ENDPOINT = os.environ.get("AEGISPT_RL_ENDPOINT", "https://api.deepseek.com/v1/chat/completions")
MODEL = os.environ.get("AEGISPT_RL_MODEL", "deepseek-v4-pro")
MAXTOK = int(os.environ.get("AEGISPT_RL_MAXTOK", "1200") or "1200")
TEMP = float(os.environ.get("AEGISPT_RL_TEMP", "0.7") or "0.7")
MAX_STEPS = int(os.environ.get("AEGISPT_RL_MAX_STEPS", "10") or "10")

SYSTEM = (
    "You are an authorized penetration-testing agent driving a target via ONE tool: "
    "http_request. Respond with EXACTLY one JSON object: "
    '{"reasoning":"...","next_action":{"args":{"method":"GET|POST","url":"...","headers":{},"body":""}},"done":false}. '
    "Maintain a running PLAN and carry session/state forward. If an action is BLOCKED "
    "(403/forbidden) at the goal, do NOT give up: backtrack and explore the hinted "
    "intermediate resource, then REUSE any token/session/credential revealed in an "
    "earlier response. When the goal is reached, read it, then set done=true."
)


def _api_key() -> str:
    if "deepseek" in ENDPOINT:
        txt = open(os.path.expanduser("~/.aegispt-secrets")).read()
        m = re.search(r"DEEPSEEK_API_KEY=(\S+)", txt)
        return m.group(1) if m else ""
    return ""


def _act(convo: list[dict]) -> str:
    body = json.dumps({"model": MODEL, "messages": convo, "max_tokens": MAXTOK,
                       "temperature": TEMP, "stream": False}).encode()
    hdrs = {"Content-Type": "application/json"}
    key = _api_key()
    if key:
        hdrs["Authorization"] = "Bearer " + key
    req = urllib.request.Request(ENDPOINT, data=body, headers=hdrs)
    with urllib.request.urlopen(req, timeout=180) as r:
        msg = json.loads(r.read().decode())["choices"][0]["message"]
    return (msg.get("content") or msg.get("reasoning_content") or "").strip()


def _extract_action(txt: str):
    """Last balanced JSON object that looks like an action (has next_action/request/done)."""
    txt = re.sub(r"<think>.*?</think>", "", txt, flags=re.S)
    found = None
    for m in re.finditer(r"\{", txt):
        depth = 0
        for j in range(m.start(), len(txt)):
            if txt[j] == "{":
                depth += 1
            elif txt[j] == "}":
                depth -= 1
                if depth == 0:
                    try:
                        o = json.loads(txt[m.start():j + 1])
                        if isinstance(o, dict) and (o.get("next_action") or o.get("request") or "done" in o):
                            found = o
                    except Exception:
                        pass
                    break
    return found


# keys the model must NOT see (reward / internal signals) — only HTTP is returned
_LEAK = ("reward", "recovered_after_block", "used_revealed_value", "signals",
         "progress", "scenario_hash", "scenario_id")


def rollout(spec) -> tuple[list[dict], dict]:
    env = ENVS.TrainingEnv(spec)
    convo = [{"role": "system", "content": SYSTEM},
             {"role": "user", "content": f"Goal: {spec.goal}\nHost: {spec.host}\nStart from nothing; explore, then exploit."}]
    trace: list[dict] = []
    for i in range(MAX_STEPS):
        try:
            txt = _act(convo)
        except Exception as exc:
            trace.append({"action": "{}", "evidence": [f"{spec.scenario_id}-err"], "failure_reason": f"act_error:{exc}",
                          "objective_progress": 0.0, "scenario_id": spec.scenario_id, "state": f"step{i+1}",
                          "tool_result": "{}"})
            break
        obj = _extract_action(txt)
        if obj is None:
            break
        obs = env.step(obj)
        trace.append({"action": json.dumps(obj, sort_keys=True),
                      "evidence": [f"{spec.scenario_id}-step-{i+1}"],
                      "failure_reason": "",
                      "objective_progress": obs["progress"],
                      "scenario_id": spec.scenario_id,
                      "state": f"step{i+1}",
                      "tool_result": json.dumps(obs, sort_keys=True)})
        public = {k: v for k, v in obs.items() if k not in _LEAK}
        convo.append({"role": "assistant", "content": json.dumps(obj)})
        convo.append({"role": "user", "content": "HTTP RESPONSE:\n" + json.dumps(public)})
        if obs.get("status") and env.state.get("flag"):
            break
        if obj.get("done"):
            break
    return trace, env.result()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--n", type=int, default=6, help="rollouts per scenario")
    ap.add_argument("--scenario", default="", help="single scenario_id (default = all)")
    ap.add_argument("--sft", default="", help="also rank + write best SFT to this path")
    args = ap.parse_args()

    specs = ([ENVS.get_spec(args.scenario)] if args.scenario else list(ENVS.scenario_specs()))
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    idx = 0
    summary = []
    for spec in specs:
        for r in range(args.n):
            trace, result = rollout(spec)
            (out / f"roll_{idx}.jsonl").write_text(
                "\n".join(json.dumps(row, sort_keys=True) for row in trace) + "\n", encoding="utf-8")
            (out / f"res_{idx}.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            summary.append((spec.scenario_id, result.get("reward"), result.get("flag"),
                            result.get("recovered_after_block"), result.get("used_revealed_value")))
            print(f"  {spec.scenario_id} roll{r}: reward={result.get('reward')} flag={result.get('flag')} "
                  f"recovered={result.get('recovered_after_block')} revealed={result.get('used_revealed_value')} steps={result.get('steps')}")
            idx += 1
    rewards = [s[1] for s in summary if isinstance(s[1], int)]
    print(f"\n{idx} rollouts | best_reward={max(rewards) if rewards else 0} "
          f"any_flag={any(s[2] for s in summary)} any_recovered={any(s[3] for s in summary)}")
    if args.sft:
        stats = ROLLOUT.run(str(out), out=args.sft, top_frac=0.34, min_reward=6)
        print("jury_rollout:", json.dumps(stats))


if __name__ == "__main__":
    main()
