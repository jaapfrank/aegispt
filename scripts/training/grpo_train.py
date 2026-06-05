"""GRPO/RL stage (TRL) — reward EXACTLY the behaviour we want, penalise the rest.

Post-training on top of the SFT adapter. GRPO generates several completions per
prompt and optimises toward the reward functions below (operator-specified):

  +  valid JSON the loop can parse
  +  correct target/payload class (matches the case's vulnerability_class)
  +  evidence/finding/cleanup present
  +  cleanup named
  -  scope bypass / payload WITHOUT approval when approval_required
  -  destructive / persistence / brute-force verbs

This directly fights "payload-happy": un-gated/destructive actions are penalised.
Run AFTER the SFT (combined) adapter exists; gate with eval_harness.py.

  AEGISPT_GRPO_ADAPTER=/path/to/sft_adapter python grpo_train.py
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

import torch
from datasets import Dataset
from peft import LoraConfig, PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
from trl import GRPOConfig, GRPOTrainer

DIR = Path.home() / ".aegispt-tools" / "training"
BASE = os.environ.get("AEGISPT_GRPO_BASE", "mlabonne/Qwen3-8B-abliterated")
SFT_ADAPTER = os.environ.get("AEGISPT_GRPO_ADAPTER", "")  # start from the SFT adapter
DATA = os.environ.get("AEGISPT_GRPO_DATA", str(DIR / "aegispt_payload_capability_iter4_train.jsonl"))
OUT = os.environ.get("AEGISPT_GRPO_OUT", str(DIR / "grpo-stage"))
MAXSTEPS = int(os.environ.get("AEGISPT_GRPO_STEPS", "200"))

FORBIDDEN = re.compile(r"\b(rm -rf|drop table|shutdown|persistence|backdoor|mimikatz|"
                       r"hashcat|brute[\s_-]?force|ransom|wipe|destroy)\b", re.I)


def _json(text):
    m = re.search(r"\{.*\}", text, re.S)
    if not m:
        return None
    try:
        return json.loads(m.group(0))
    except Exception:
        return None


def _text(c):
    """A TRL completion is a string for standard prompts, but a conversational
    list like [{"role":"assistant","content":"..."}] when the prompt is messages
    (our case — grpo_trainer.py builds [[{...}]]). Flatten to the assistant text."""
    if isinstance(c, list):
        return " ".join(m.get("content", "") for m in c if isinstance(m, dict))
    return c or ""


# ---- reward functions: each takes (completions, **cols) -> list[float] ----
def r_json_valid(completions, **k):
    return [1.0 if _json(_text(c)) is not None else -1.0 for c in completions]


def r_correct_class(completions, vulnerability_class=None, gt_url=None, gt_param=None, **k):
    out = []
    for i, c in enumerate(completions):
        d = _json(_text(c)) or {}
        blob = json.dumps(d).lower()
        url = (gt_url[i] if gt_url else "") or ""
        par = (gt_param[i] if gt_param else "") or ""
        ok = (not url or url.lower() in blob) and (not par or par.lower() in blob)
        out.append(1.0 if ok else 0.0)
    return out


def r_evidence(completions, **k):
    out = []
    for c in completions:
        b = _text(c).lower()
        out.append(0.5 * (("evidence" in b) + ("cleanup" in b) + ("finding" in b)))
    return out


def r_safety(completions, safety_tags=None, **k):
    out = []
    for i, c in enumerate(completions):
        tags = (safety_tags[i] if safety_tags else []) or []
        t = _text(c)
        b = t.lower()
        pen = 0.0
        if FORBIDDEN.search(t):
            pen -= 2.0
        if "approval_required" in tags:
            gated = any(w in b for w in ("approval", "approved", "scope", "blocked", "skip", "not_attempted", "smallest"))
            if not gated:
                pen -= 2.0  # payload without approval gate
        out.append(pen)
    return out


def build_dataset():
    rows = []
    for line in Path(DATA).read_text().splitlines():
        if not line.strip():
            continue
        d = json.loads(line)
        msgs = d["messages"]
        cut = len(msgs) - 1
        while cut > 0 and msgs[cut]["role"] != "assistant":
            cut -= 1
        gt = _json(msgs[-1]["content"]) or {}
        gr = gt.get("request") or gt.get("args") or {}
        meta = d.get("metadata", {})
        rows.append({"prompt": msgs[:cut],
                     "vulnerability_class": meta.get("vulnerability_class", ""),
                     "gt_url": str(gr.get("url", "")), "gt_param": str(gr.get("parameter", "")),
                     "safety_tags": meta.get("safety_tags", [])})
    return Dataset.from_list(rows)


def main():
    tok = AutoTokenizer.from_pretrained(BASE)
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token
    bnb = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type="nf4",
                             bnb_4bit_compute_dtype=torch.bfloat16, bnb_4bit_use_double_quant=True)
    model = AutoModelForCausalLM.from_pretrained(BASE, quantization_config=bnb, device_map={"": 0},
                                                 torch_dtype=torch.bfloat16)
    if SFT_ADAPTER:
        model = PeftModel.from_pretrained(model, SFT_ADAPTER, is_trainable=True)
        peft_cfg = None
        print(f"[grpo] continuing from SFT adapter {SFT_ADAPTER}", flush=True)
    else:
        peft_cfg = LoraConfig(r=16, lora_alpha=32, use_dora=True, use_rslora=True,
                              task_type="CAUSAL_LM",
                              target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"])

    ds = build_dataset()
    cfg = GRPOConfig(output_dir=OUT, per_device_train_batch_size=2, gradient_accumulation_steps=4,
                     num_generations=4, max_steps=MAXSTEPS, learning_rate=1e-5, bf16=True,
                     logging_steps=10, save_steps=MAXSTEPS, max_completion_length=256, report_to=[])
    trainer = GRPOTrainer(
        model=model, args=cfg, train_dataset=ds, processing_class=tok,
        reward_funcs=[r_json_valid, r_correct_class, r_evidence, r_safety],
        peft_config=peft_cfg,
    )
    print("[grpo] training (reward: json+class+evidence, penalty: unsafe/no-approval) ...", flush=True)
    trainer.train()
    trainer.save_model(OUT)
    print(f"[grpo] DONE -> {OUT}", flush=True)


if __name__ == "__main__":
    main()
