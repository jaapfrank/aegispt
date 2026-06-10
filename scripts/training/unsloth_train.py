"""Unsloth acceleration spike/trainer — Blackwell (sm_120) compat probe + real run.

PEFT (qlora_train.py) is the BASELINE and must never be blocked. This is the
OPTIONAL accelerator (Unsloth ~2x). It is run inside the official `unsloth/unsloth`
Docker image (or an install.sh venv) so the version stack is resolved by Unsloth,
NOT hand-picked by us (the changelog pins no torch version; the snippet that did
was wrong). FlashAttention-2 is NOT required on Blackwell — Unsloth falls back to
PyTorch SDPA, which is what we force here (xformers/FA2 were the earlier crash).

Timeboxed spike contract (per the committed training-direction doc):
  separate env, SDPA attention, 16-row dataset, ~15 steps. PASS only if the loss
  drops AND an adapter is written. Otherwise PARK — PEFT stays productive.

Env:
  AEGISPT_USL_DATA   = jsonl of {"messages":[...]}        (default spike16.jsonl)
  AEGISPT_USL_OUT    = adapter output dir                  (default unsloth-spike)
  AEGISPT_USL_STEPS  = max_steps                            (default 15)
  AEGISPT_USL_RANK   = LoRA rank                            (default 16)
  AEGISPT_USL_DORA   = 1 to enable QDoRA                    (default 1)
  AEGISPT_USL_BASE   = base model                           (default Qwen3-8B-abliterated)
"""
from __future__ import annotations

import os
from pathlib import Path

# Force Blackwell arch + SDPA (no FA2/xformers) BEFORE importing torch/unsloth.
os.environ.setdefault("TORCH_CUDA_ARCH_LIST", "12.0")
os.environ.setdefault("UNSLOTH_DISABLE_FLASH_ATTENTION", "1")  # fall back to SDPA
os.environ.setdefault("XFORMERS_DISABLED", "1")

DIR = Path(os.environ.get("AEGISPT_TRAIN_DIR", str(Path.home() / ".aegispt-tools" / "training")))
BASE = os.environ.get("AEGISPT_USL_BASE", "mlabonne/Qwen3-8B-abliterated")
DATA = os.environ.get("AEGISPT_USL_DATA", str(DIR / "spike16.jsonl"))
OUT = os.environ.get("AEGISPT_USL_OUT", str(DIR / "unsloth-spike"))
STEPS = int(os.environ.get("AEGISPT_USL_STEPS", "15"))
RANK = int(os.environ.get("AEGISPT_USL_RANK", "16"))
USE_DORA = os.environ.get("AEGISPT_USL_DORA", "1") == "1"
MAXLEN = int(os.environ.get("AEGISPT_USL_MAXLEN", "2048"))


def main():
    if not Path(DATA).exists():
        raise SystemExit(f"data not found: {DATA}")

    from unsloth import FastLanguageModel  # import after env is set
    import torch
    from datasets import load_dataset
    from trl import SFTConfig, SFTTrainer

    print(f"[usl] torch {torch.__version__} | cuda {torch.version.cuda} | "
          f"device {torch.cuda.get_device_name(0)} | cap {torch.cuda.get_device_capability(0)}",
          flush=True)

    model, tok = FastLanguageModel.from_pretrained(
        model_name=BASE,
        max_seq_length=MAXLEN,
        load_in_4bit=True,
        dtype=None,  # auto: bf16 on Blackwell
    )
    model = FastLanguageModel.get_peft_model(
        model,
        r=RANK,
        lora_alpha=RANK * 2,
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj",
                        "gate_proj", "up_proj", "down_proj"],
        use_dora=USE_DORA,
        use_rslora=True,
        use_gradient_checkpointing="unsloth",
        random_state=3407,
    )

    ds = load_dataset("json", data_files=DATA, split="train")

    def _fmt(ex):
        return {"text": tok.apply_chat_template(ex["messages"], tokenize=False,
                                                add_generation_prompt=False)}

    ds = ds.map(_fmt, remove_columns=[c for c in ds.column_names if c != "text"])

    cfg = SFTConfig(
        output_dir=OUT,
        per_device_train_batch_size=1,
        gradient_accumulation_steps=4,
        max_steps=STEPS,
        learning_rate=2e-4,
        bf16=True,
        logging_steps=1,
        # Frequent checkpoints survive a host reboot mid-train (the laptop rebooted during a
        # 400-step v2 run and lost everything because saves only happened at the end).
        save_steps=int(os.environ.get("AEGISPT_USL_SAVE_STEPS", str(STEPS)) or STEPS),
        max_length=MAXLEN,
        dataset_text_field="text",
        report_to=[],
    )
    trainer = SFTTrainer(model=model, args=cfg, train_dataset=ds, processing_class=tok)
    print(f"[usl] SPIKE start: {STEPS} steps, DoRA={USE_DORA}, SDPA attention", flush=True)
    out = trainer.train()
    loss = out.training_loss if hasattr(out, "training_loss") else None
    trainer.save_model(OUT)
    has_adapter = any(Path(OUT).glob("adapter_*")) if Path(OUT).exists() else False
    print(f"[usl] SPIKE DONE | final_loss={loss} | adapter_written={has_adapter} -> {OUT}",
          flush=True)
    print("[usl] PASS" if (loss is not None and has_adapter) else "[usl] CHECK", flush=True)


if __name__ == "__main__":
    main()
