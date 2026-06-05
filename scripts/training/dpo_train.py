"""DPO/ORPO preference stage (TRL) — teach good > bad responses.

Post-training on top of the SFT adapter using preference pairs (Codex builds the
data, my lane runs the training): for each scenario a GOOD response (scope check
-> smallest proof -> evidence -> cleanup) is preferred over a BAD one (raw exploit
spam, no evidence, out-of-scope, destructive). DPO shifts the model toward GOOD
without an explicit reward model.

Expects a preference JSONL with either:
  {"prompt": [...messages], "chosen": "<assistant text>", "rejected": "<assistant text>"}
or the conversational form {"chosen": [...msgs], "rejected": [...msgs]}.

  AEGISPT_DPO_ADAPTER=/path/to/sft_adapter \
  AEGISPT_DPO_DATA=/path/to/preference_pairs.jsonl python dpo_train.py
"""
from __future__ import annotations

import os
from pathlib import Path

import torch
from datasets import load_dataset
from peft import LoraConfig, PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
from trl import DPOConfig, DPOTrainer

DIR = Path.home() / ".aegispt-tools" / "training"
BASE = os.environ.get("AEGISPT_DPO_BASE", "mlabonne/Qwen3-8B-abliterated")
SFT_ADAPTER = os.environ.get("AEGISPT_DPO_ADAPTER", "")
# iter5 source-of-truth DPO preference data (prompt/chosen/rejected) per the handoff
DATA = os.environ.get("AEGISPT_DPO_DATA", str(DIR / "aegispt_payload_dpo_iter4_train.jsonl"))
OUT = os.environ.get("AEGISPT_DPO_OUT", str(DIR / "dpo-stage"))
MAXSTEPS = int(os.environ.get("AEGISPT_DPO_STEPS", "200"))
BETA = float(os.environ.get("AEGISPT_DPO_BETA", "0.1"))


def main():
    if not Path(DATA).exists():
        raise SystemExit(f"preference data not found: {DATA} (Codex builds the good/bad pairs)")
    tok = AutoTokenizer.from_pretrained(BASE)
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token
    bnb = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type="nf4",
                             bnb_4bit_compute_dtype=torch.bfloat16, bnb_4bit_use_double_quant=True)
    model = AutoModelForCausalLM.from_pretrained(BASE, quantization_config=bnb, device_map={"": 0},
                                                 torch_dtype=torch.bfloat16)
    # DPO needs a trainable policy; start from the SFT adapter (ref = frozen base+adapter)
    peft_cfg = None
    if SFT_ADAPTER:
        model = PeftModel.from_pretrained(model, SFT_ADAPTER, is_trainable=True)
        print(f"[dpo] policy from SFT adapter {SFT_ADAPTER}", flush=True)
    else:
        peft_cfg = LoraConfig(r=16, lora_alpha=32, use_dora=True, use_rslora=True, task_type="CAUSAL_LM",
                              target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"])

    ds = load_dataset("json", data_files=DATA, split="train")

    # Normalise to TRL conversational DPO: prompt=[msgs], chosen/rejected=[msg].
    # Codex emits chosen/rejected as a single {role,content} dict — wrap in a list.
    def _norm(ex):
        ch, rj = ex["chosen"], ex["rejected"]
        return {"prompt": ex["prompt"],
                "chosen": [ch] if isinstance(ch, dict) else ch,
                "rejected": [rj] if isinstance(rj, dict) else rj}

    keep = {"prompt", "chosen", "rejected"}
    ds = ds.map(_norm, remove_columns=[c for c in ds.column_names if c not in keep])
    cfg = DPOConfig(output_dir=OUT, per_device_train_batch_size=1, gradient_accumulation_steps=8,
                    max_steps=MAXSTEPS, learning_rate=5e-6, bf16=True, logging_steps=10,
                    save_steps=MAXSTEPS, beta=BETA, max_length=2048, report_to=[])
    trainer = DPOTrainer(model=model, args=cfg, train_dataset=ds, processing_class=tok, peft_config=peft_cfg)
    print(f"[dpo] training (beta={BETA}, prefer good>bad) ...", flush=True)
    trainer.train()
    trainer.save_model(OUT)
    print(f"[dpo] DONE -> {OUT}", flush=True)


if __name__ == "__main__":
    main()
