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
print(f"[qlora] use_dora={_use_dora}", flush=True)
lora = LoraConfig(
    r=16, lora_alpha=32, lora_dropout=0.05, bias="none", task_type="CAUSAL_LM",
    use_dora=_use_dora,
    target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
)
model = get_peft_model(model, lora)
model.print_trainable_parameters()

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
    trainer = SFTTrainer(model=model, args=args, train_dataset=ds,
                         processing_class=tok, max_seq_length=2048, dataset_text_field="text")
except TypeError:
    # trl API drift across versions — fall back to the minimal signature.
    trainer = SFTTrainer(model=model, args=args, train_dataset=ds)

print("[qlora] training ...", flush=True)
trainer.train()
trainer.save_model(OUT)
tok.save_pretrained(OUT)
print(f"[qlora] DONE -> LoRA adapter saved at {OUT}", flush=True)
