"""Merge a LoRA/DoRA adapter into the base (fp16) so llama.cpp can convert it.

The adapter was trained on a 4-bit base, but the adapter weights themselves are
fp16 — load an fp16 base, apply the adapter, merge_and_unload, and the result is a
plain HF model `convert_hf_to_gguf.py` can turn into a GGUF. Merging also removes
DoRA's per-token decomposition overhead, so even in-process inference gets fast.

  AEGISPT_MERGE_ADAPTER=/path/to/adapter (or "base") \
  AEGISPT_MERGE_OUT=/path/to/merged_hf_dir python merge_adapter.py
"""
from __future__ import annotations

import os
from pathlib import Path

import torch
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer

BASE = os.environ.get("AEGISPT_MERGE_BASE", "mlabonne/Qwen3-8B-abliterated")
ADAPTER = os.environ.get("AEGISPT_MERGE_ADAPTER", "base")
OUT = os.environ.get("AEGISPT_MERGE_OUT", "")


def main():
    if not OUT:
        raise SystemExit("set AEGISPT_MERGE_OUT")
    tok = AutoTokenizer.from_pretrained(BASE)
    model = AutoModelForCausalLM.from_pretrained(
        BASE, torch_dtype=torch.float16, device_map="auto", low_cpu_mem_usage=True)
    if ADAPTER and ADAPTER.lower() not in {"base", "none", ""}:
        model = PeftModel.from_pretrained(model, ADAPTER)
        model = model.merge_and_unload()
        print(f"[merge] merged adapter {ADAPTER}", flush=True)
    else:
        print("[merge] BASE (no adapter) — exporting un-trained baseline", flush=True)
    Path(OUT).mkdir(parents=True, exist_ok=True)
    model.save_pretrained(OUT, safe_serialization=True)
    tok.save_pretrained(OUT)
    print(f"[merge] saved fp16 HF model -> {OUT}", flush=True)


if __name__ == "__main__":
    main()
