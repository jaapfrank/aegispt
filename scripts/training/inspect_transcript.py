"""Quick inspector for an interactive-exploit transcript artifact (winning-trajectory format)."""
import json
import re
import sys


def main(path: str) -> None:
    data = json.load(open(path))
    print("steps:", len(data))
    keys = sorted({k for e in data if isinstance(e, dict) for k in e})
    print("entry keys:", keys)
    for e in data[:6]:
        if not isinstance(e, dict):
            continue
        s = e.get("step")
        if e.get("request"):
            print(f"  step{s} REQ:", json.dumps(e["request"])[:170])
        if e.get("response"):
            print(f"  step{s} RESP:", str(e["response"])[:150])
        if e.get("assistant_text"):
            print(f"  step{s} TXT:", str(e["assistant_text"])[:150])
    blob = json.dumps(data)
    flags = set(re.findall(r"(flag\{[^}]+\}|xbow-[0-9a-f]{6,}|aegispt\{[^}]+\})", blob))
    print("flags in transcript:", flags)
    print("has request/response turns:", any(isinstance(e, dict) and e.get("request") for e in data))


if __name__ == "__main__":
    main(sys.argv[1])
