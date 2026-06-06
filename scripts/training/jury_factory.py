"""Training Candidate Factory (Phase 1) + held-out guard.

Turns arbitrated traces into the training datasets, with ONE hard rule baked in:
a scenario that appears in any held-out eval/gate set NEVER re-enters training
(the contamination guard from the jury direction doc). No reviewer models needed for
this slice — it runs on evidence/coverage-arbitrated traces.

An `item` is {"scenario_id": str, "messages": [...], "decision": <jury_review out>}.
Outputs (only use==True, non-held-out):
  sft.jsonl            sft_positive / safety_positive traces (good trajectories)
  dpo_pairs.jsonl      a scenario that has BOTH a positive and a negative -> {prompt,
                       chosen, rejected} (chosen=good convo, rejected=bad convo)
  process_reward.jsonl per-step (step, reward) from objective_progress + final outcome
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path


def scenario_hash(scenario_id: str) -> str:
    return hashlib.sha256(str(scenario_id).strip().lower().encode()).hexdigest()


def load_held_out(paths: list[str], *, id_keys=("scenario_id", "case_id", "id")) -> set[str]:
    """Collect scenario hashes from held-out eval/test files so they can NEVER be
    minted into training data."""
    out: set[str] = set()
    for p in paths:
        fp = Path(p)
        if not fp.exists():
            continue
        for line in fp.read_text().splitlines():
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except Exception:
                continue
            meta = row.get("metadata", row)
            for k in id_keys:
                if meta.get(k):
                    out.add(scenario_hash(meta[k]))
                    break
    return out


def _proc_rewards(item: dict) -> list[dict]:
    dec = item["decision"]
    good = dec["decision"] == "good"
    fws = dec.get("jury", {}).get("first_wrong_step")
    rows = []
    for i, st in enumerate(item.get("trace", []), start=1):
        r = 0.0
        if good:
            r = float(st.get("objective_progress", 0.0))
        elif fws is not None and i >= fws:
            r = -1.0
        rows.append({"scenario_id": item["scenario_id"], "step": i, "reward": round(r, 3)})
    return rows


def build_training_sets(items: list[dict], *, held_out: set[str] | None = None,
                        out_dir: str) -> dict:
    held_out = held_out or set()
    od = Path(out_dir)
    od.mkdir(parents=True, exist_ok=True)
    kept, skipped_heldout, skipped_unused = [], 0, 0
    for it in items:
        if scenario_hash(it["scenario_id"]) in held_out:
            skipped_heldout += 1
            continue
        if not it["decision"]["training"].get("use"):
            skipped_unused += 1
            continue
        kept.append(it)

    sft, proc, by_scn = [], [], {}
    for it in kept:
        tv = it["decision"]["training"]["training_value"]
        if tv in ("sft_positive", "safety_positive"):
            sft.append({"messages": it["messages"]})
        by_scn.setdefault(it["scenario_id"], {})[tv] = it
        proc.extend(_proc_rewards(it))

    dpo = []
    for scn, d in by_scn.items():
        pos = d.get("sft_positive") or d.get("safety_positive")
        neg = d.get("dpo_negative") or d.get("missed_finding")
        if pos and neg:
            prompt = pos["messages"][:1]  # the system/goal turn(s)
            dpo.append({"prompt": prompt, "chosen": pos["messages"], "rejected": neg["messages"]})

    (od / "sft.jsonl").write_text("\n".join(json.dumps(r) for r in sft) + ("\n" if sft else ""))
    (od / "dpo_pairs.jsonl").write_text("\n".join(json.dumps(r) for r in dpo) + ("\n" if dpo else ""))
    (od / "process_reward.jsonl").write_text("\n".join(json.dumps(r) for r in proc) + ("\n" if proc else ""))
    manifest = {"items_in": len(items), "kept": len(kept), "skipped_held_out": skipped_heldout,
                "skipped_unused": skipped_unused, "sft": len(sft), "dpo_pairs": len(dpo),
                "process_reward_steps": len(proc)}
    (od / "factory_manifest.json").write_text(json.dumps(manifest, indent=2))
    return manifest
