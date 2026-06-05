"""Export iter-5 LLMSVS eval rows as OpenAI-compatible batch requests.

The output is a request JSONL plus a case-map JSONL. It does not call any model
or endpoint; it only prepares reproducible model-prediction inputs for the
offline LLMSVS scorer.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

DEFAULT_TRAINING_DIR = Path.home() / ".aegispt-tools" / "training"
DEFAULT_EVAL_PATH = DEFAULT_TRAINING_DIR / "aegispt_llmsvs_adversarial_eval_iter5_eval.jsonl"
DEFAULT_OUT_DIR = DEFAULT_TRAINING_DIR
DEFAULT_PREFIX = "aegispt_llmsvs_prediction_requests_iter5"
DEFAULT_MODEL = "candidate-adapter"


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(f"eval file not found: {path}")
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def request_row(row: dict[str, Any], *, model: str, max_tokens: int) -> dict[str, Any]:
    case_id = row["metadata"]["case_id"]
    return {
        "body": {
            "max_tokens": max_tokens,
            "messages": row["messages"],
            "model": model,
            "stream": False,
            "temperature": 0,
        },
        "custom_id": case_id,
        "method": "POST",
        "url": "/v1/chat/completions",
    }


def case_map_row(row: dict[str, Any]) -> dict[str, Any]:
    metadata = row["metadata"]
    return {
        "attack_category": metadata["attack_category"],
        "case_id": metadata["case_id"],
        "eval_only": metadata["eval_only"],
        "llmsvs_controls": metadata["llmsvs_controls"],
        "owasp_llm_top10": metadata["owasp_llm_top10"],
        "owasp_mcp_top10": metadata["owasp_mcp_top10"],
        "runtime_execution": metadata["runtime_execution"],
    }


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")


def build_requests(
    *,
    eval_path: Path = DEFAULT_EVAL_PATH,
    out_dir: Path = DEFAULT_OUT_DIR,
    prefix: str = DEFAULT_PREFIX,
    model: str = DEFAULT_MODEL,
    max_tokens: int = 512,
) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    eval_rows = load_jsonl(eval_path)
    requests = [request_row(row, model=model, max_tokens=max_tokens) for row in eval_rows]
    case_map = [case_map_row(row) for row in eval_rows]
    request_path = out_dir / f"{prefix}.jsonl"
    case_map_path = out_dir / f"{prefix}_case_map.jsonl"
    write_jsonl(request_path, requests)
    write_jsonl(case_map_path, case_map)

    categories = Counter(row["attack_category"] for row in case_map)
    manifest = {
        "dataset": prefix,
        "eval_path": str(eval_path),
        "format": "OpenAI-compatible batch request jsonl plus case-map jsonl",
        "model": model,
        "paths": {
            "case_map": str(case_map_path),
            "requests": str(request_path),
        },
        "policy": {
            "generates_predictions": False,
            "offline_export_only": True,
            "runtime_execution": False,
            "tool_calls_expected": False,
        },
        "settings": {
            "max_tokens": max_tokens,
            "temperature": 0,
        },
        "stats": {
            "attack_categories": dict(sorted(categories.items())),
            "request_count": len(requests),
        },
    }
    manifest_path = out_dir / f"{prefix}_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--eval", type=Path, default=DEFAULT_EVAL_PATH)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument("--prefix", default=DEFAULT_PREFIX)
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--max-tokens", type=int, default=512)
    args = parser.parse_args()
    manifest = build_requests(
        eval_path=args.eval,
        out_dir=args.out_dir,
        prefix=args.prefix,
        model=args.model,
        max_tokens=args.max_tokens,
    )
    print(json.dumps(manifest["stats"], indent=2, sort_keys=True))
    print(f"manifest: {args.out_dir / (args.prefix + '_manifest.json')}")


if __name__ == "__main__":
    main()
