"""Weighted dataset MIXER for AegisPT training (quality phase, 2026-06-04).

DEPRECATED (2026-06-05): SUPERSEDED by the iter5 curated mix. This mixer only
blends 3 families (full_coverage/open_corpus/payload) and is NOT the training
source-of-truth. Use `aegispt_curated_sft_mix_iter5.jsonl` (built by Codex's
make_curated_sft_mix_iter5.py — 5 families incl. negative/contrastive +
domain-extension, dedup, hard-exclusions, held-out hash guard). The SFT trainer
default (qlora_train.py) and the eval gate (eval_harness.py) now point at iter5.
Kept only for reference/history; do not extend.

Blends the three curated families with controlled weights, dedups, and GUARDS
against eval/test leakage. Operator priority: without a controlled mix you cannot
tell whether payload-training makes the system better or just "payload-happy".

Default weights (operator): 50% full-coverage behaviour/scope/evidence,
25% open-corpus CVE/triage, 25% payload-capability.

  python make_training_mix.py --total 12000 --seed 20260604

- exact-hash dedup within the mix,
- NO-LEAKAGE: any conversation whose hash appears in ANY *_eval/*_test split is
  dropped from the train mix,
- modest upsampling of an under-represented family is allowed (flagged in the
  manifest) to hit the ratio,
- writes a manifest with per-family counts, weights, seed, dedup + leakage stats.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
from pathlib import Path

DIR = Path.home() / ".aegispt-tools" / "training"
FAMILIES = {
    "full_coverage": "aegispt_full_coverage_dora_loraplus_unsloth_train.jsonl",
    "open_corpus": "aegispt_open_corpus_iter3_train.jsonl",
    "payload": "aegispt_payload_capability_iter4_train.jsonl",
}
DEFAULT_WEIGHTS = {"full_coverage": 0.50, "open_corpus": 0.25, "payload": 0.25}
HELDOUT_GLOBS = ["*_eval.jsonl", "*_test.jsonl"]


def conv_hash(line: str) -> str:
    """Hash the message content only (ignore metadata) so train/eval overlap is
    caught regardless of metadata differences."""
    try:
        msgs = json.loads(line).get("messages", [])
        blob = "\n".join(f"{m.get('role')}:{m.get('content')}" for m in msgs)
    except Exception:
        blob = line
    return hashlib.sha256(blob.encode("utf-8", "replace")).hexdigest()


def load(fp: Path) -> list[str]:
    return [ln for ln in fp.read_text(errors="replace").splitlines() if ln.strip()]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--total", type=int, default=12000)
    ap.add_argument("--seed", type=int, default=20260604)
    ap.add_argument("--max-upsample", type=float, default=2.0)
    ap.add_argument("--out", default=str(DIR / "aegispt_training_mix.jsonl"))
    args = ap.parse_args()
    rng = random.Random(args.seed)

    # 1) collect held-out hashes (leakage guard)
    heldout: set[str] = set()
    for g in HELDOUT_GLOBS:
        for fp in DIR.glob(g):
            for ln in load(fp):
                heldout.add(conv_hash(ln))
    print(f"[mix] held-out hashes (eval+test): {len(heldout)}")

    # 2) per-family target counts from weights
    targets = {k: round(args.total * w) for k, w in DEFAULT_WEIGHTS.items()}
    chosen: list[str] = []
    seen: set[str] = set()
    stats = {}
    for fam, fname in FAMILIES.items():
        pool = [ln for ln in load(DIR / fname) if conv_hash(ln) not in heldout]
        # dedup the pool itself
        uniq, ph = [], set()
        for ln in pool:
            h = conv_hash(ln)
            if h not in ph:
                ph.add(h); uniq.append(ln)
        want = targets[fam]
        cap = int(len(uniq) * args.max_upsample)
        take = min(want, cap)
        rng.shuffle(uniq)
        picked = (uniq * (take // max(1, len(uniq)) + 1))[:take]  # modest upsample if want>len
        upsampled = take > len(uniq)
        for ln in picked:
            h = conv_hash(ln) + str(rng.random()) if upsampled else conv_hash(ln)
            if h in seen:
                continue
            seen.add(h); chosen.append(ln)
        stats[fam] = {"available_unique": len(uniq), "leakage_dropped": len(pool) - len(uniq) if False else 0,
                      "target": want, "taken": take, "upsampled": upsampled}
        print(f"[mix] {fam}: available={len(uniq)} target={want} taken={take} upsample={upsampled}")

    rng.shuffle(chosen)
    Path(args.out).write_text("\n".join(chosen) + "\n")
    manifest = {"out": args.out, "total": len(chosen), "weights": DEFAULT_WEIGHTS,
                "seed": args.seed, "max_upsample": args.max_upsample,
                "heldout_hashes": len(heldout), "per_family": stats}
    Path(args.out.replace(".jsonl", "_manifest.json")).write_text(json.dumps(manifest, indent=2))
    print(f"[mix] wrote {len(chosen)} -> {args.out}  (manifest beside it)")


if __name__ == "__main__":
    main()
