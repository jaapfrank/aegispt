"""LIVE PROOF: run the jury committee (real V4-Pro reviewers) on the REAL deep-chain
traces (dpo = login-no-IDOR, iter7ct = no-login). The flywheel was only mock-tested;
this is end-to-end on real data. Cloud, GPU-free."""
import json
import os
import re
import sys

REPO = "/home/administrator/project/automation skill/AegisPT"
sys.path.insert(0, os.path.join(REPO, "scripts/training"))
TRACES = "/home/administrator/.aegispt-tools/training/jurytraces"

import jury_calibration as C  # noqa: E402
import jury_committee as JC  # noqa: E402

key = re.search(r"DEEPSEEK_API_KEY=(\S+)", open(os.path.expanduser("~/.aegispt-secrets")).read()).group(1)
EP = "https://api.deepseek.com/v1/chat/completions"
committee = JC.build_committee([
    {"id": "v4pro-process", "endpoint": EP, "model": "deepseek-v4-pro", "api_key": key,
     "angle": "process/reasoning: identify the FIRST step where the agent went wrong"},
    {"id": "v4pro-coverage", "endpoint": EP, "model": "deepseek-v4-pro", "api_key": key,
     "angle": "coverage: did it explore enough to responsibly conclude no-finding?"},
    {"id": "v4pro-safety", "endpoint": EP, "model": "deepseek-v4-pro", "api_key": key,
     "angle": "safety: any unsafe or out-of-scope action?"},
])
ledger = C.CalibrationLedger()

for name in ("dpo", "iter7ct"):
    path = f"{TRACES}/deep_chain_eval__{name}.jsonl"
    trace = [json.loads(l) for l in open(path) if l.strip()]
    d = JC.review(trace, committee, ledger)
    tr = d.get("training", {})
    print(f"\n===== {name} ({len(trace)} steps) =====")
    print(f"  arbiter DECISION : {d['decision']}  (by {d['by']}, human_review={d['human_review']})")
    print(f"  coverage label   : {(d.get('coverage') or {}).get('label')} -> {(d.get('coverage') or {}).get('training_use')}")
    print(f"  training_value   : {tr.get('training_value')}  use={tr.get('use')}  first_wrong_step={tr.get('first_wrong_step')}")
    print(f"  jury consensus   : {json.dumps(d['jury'])}")
    print("  reviewer verdicts:")
    for rid, v in d["reviews"].items():
        print(f"    {rid:16s} verdict={v.get('verdict'):8s} fws={v.get('first_wrong_step')} conf={v.get('confidence')} :: {str(v.get('reason'))[:90]}")

print("\n===== CALIBRATION LEDGER (who tracked evidence) =====")
for rid in ("v4pro-process", "v4pro-coverage", "v4pro-safety"):
    print(f"  {rid:16s} weight={round(ledger.weight(rid), 3)}")
print("\nLIVE PROOF DONE -- jury ran end-to-end on real traces with real V4-Pro reviewers")
