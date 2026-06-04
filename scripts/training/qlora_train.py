"""QLoRA fine-tune for multi-step agentic follow-through (Blackwell sm_120).

Teaches the GENERIC agentic discipline the local model lacked (XBEN-024: did the
SSRF reset but never followed through to log in as the victim + read the goal).
Base is an uncensored HF model so the result keeps the un-refused property.

Stack verified working on the RTX 5080 (sm_120): torch 2.11+cu128, bitsandbytes
0.49.2 4-bit. Run AFTER freeing the GPU (stop the qwen-gpu inference container).
"""
import os
import sys

import torch
from datasets import load_dataset
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
from transformers import (AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig,
                          TrainingArguments)
from trl import SFTTrainer

BASE = os.environ.get("AEGISPT_TRAIN_BASE", "mlabonne/Qwen3-8B-abliterated")
DATA = os.environ.get("AEGISPT_TRAIN_DATA",
                      "/home/administrator/.aegispt-tools/training/agentic_followthrough.jsonl")
OUT = os.environ.get("AEGISPT_TRAIN_OUT",
                     "/home/administrator/.aegispt-tools/training/qlora-followthrough")
MAXSTEPS = int(os.environ.get("AEGISPT_TRAIN_STEPS", "300"))

print(f"[qlora] base={BASE}  data={DATA}  out={OUT}  max_steps={MAXSTEPS}", flush=True)

bnb = BitsAndBytesConfig(
    load_in_4bit=True, bnb_4bit_quant_type="nf4",
    bnb_4bit_compute_dtype=torch.bfloat16, bnb_4bit_use_double_quant=True,
)

tok = AutoTokenizer.from_pretrained(BASE)
if tok.pad_token is None:
    tok.pad_token = tok.eos_token

model = AutoModelForCausalLM.from_pretrained(
    BASE, quantization_config=bnb, device_map={"": 0}, torch_dtype=torch.bfloat16,
)
model = prepare_model_for_kbit_training(model, use_gradient_checkpointing=True)
model.config.use_cache = False

# QDoRA: DoRA (weight-decomposed LoRA, NVIDIA/ICML-2024 nbasyl/DoRA) + 4-bit.
# Decomposes weights into magnitude + direction and trains both -> +3-4 pts over
# LoRA on LLMs, less hyperparameter-sensitive, ZERO inference overhead (merges
# back). QDoRA > QLoRA empirically. One flag in PEFT: use_dora=True. Operator
# pointed at the NVIDIA DoRA blog. Toggle via AEGISPT_TRAIN_USE_DORA=0 to compare.
_use_dora = (os.environ.get("AEGISPT_TRAIN_USE_DORA", "1") or "1").strip() not in {"0", "false", "no"}
# rsLoRA (Rank-Stabilized LoRA): scales the adapter by alpha/sqrt(r) instead of
# alpha/r, so RANK can be raised (32/64/128 for a large CoT corpus) WITHOUT
# gradient collapse / instability — 0% extra compute. PEFT flag use_rslora=True.
# Operator tip 2026-06-04. Default on; rank via AEGISPT_TRAIN_RANK.
_use_rslora = (os.environ.get("AEGISPT_TRAIN_USE_RSLORA", "1") or "1").strip() not in {"0", "false", "no"}
_rank = int(os.environ.get("AEGISPT_TRAIN_RANK", "16") or "16")
print(f"[qlora] use_dora={_use_dora} use_rslora={_use_rslora} rank={_rank}", flush=True)
lora = LoraConfig(
    r=_rank, lora_alpha=_rank * 2, lora_dropout=0.05, bias="none", task_type="CAUSAL_LM",
    use_dora=_use_dora, use_rslora=_use_rslora,
    target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
)
model = get_peft_model(model, lora)
model.print_trainable_parameters()

# LoRA+ (Hayou et al. 2024): give the LoRA B matrices a higher LR than the A
# matrices (ratio ~16) -> faster, more stable convergence. ORTHOGONAL to DoRA
# (DoRA = adapter architecture, LoRA+ = optimizer LR setting) — combine both for
# DoRA's precision + LoRA+'s stable convergence. Toggle
# AEGISPT_TRAIN_LORAPLUS_RATIO=0 to disable.
import bitsandbytes as _bnb  # noqa: E402
from peft.optimizers import create_loraplus_optimizer  # noqa: E402
_lp_ratio = float(os.environ.get("AEGISPT_TRAIN_LORAPLUS_RATIO", "16") or "16")
_loraplus_opt = None
if _lp_ratio > 0:
    _loraplus_opt = create_loraplus_optimizer(
        model, _bnb.optim.PagedAdamW8bit, lr=2e-4, loraplus_lr_ratio=_lp_ratio)
    print(f"[qlora] LoRA+ enabled (B/A lr ratio={_lp_ratio})", flush=True)
_optimizers = (_loraplus_opt, None) if _loraplus_opt is not None else (None, None)

ds = load_dataset("json", data_files=DATA, split="train")


def fmt(ex):
    return {"text": tok.apply_chat_template(ex["messages"], tokenize=False)}


ds = ds.map(fmt, remove_columns=ds.column_names)

args = TrainingArguments(
    output_dir=OUT, per_device_train_batch_size=1, gradient_accumulation_steps=8,
    max_steps=MAXSTEPS, learning_rate=2e-4, bf16=True, logging_steps=10,
    save_steps=MAXSTEPS, save_total_limit=1, lr_scheduler_type="cosine",
    warmup_ratio=0.03, optim="paged_adamw_8bit", report_to=[],
)

try:
    trainer = SFTTrainer(model=model, args=args, train_dataset=ds, optimizers=_optimizers,
                         processing_class=tok, max_seq_length=2048, dataset_text_field="text")
except TypeError:
    # trl API drift across versions — fall back to the minimal signature.
    trainer = SFTTrainer(model=model, args=args, train_dataset=ds, optimizers=_optimizers)

print("[qlora] training ...", flush=True)
trainer.train()
trainer.save_model(OUT)
tok.save_pretrained(OUT)
print(f"[qlora] DONE -> LoRA adapter saved at {OUT}", flush=True)
