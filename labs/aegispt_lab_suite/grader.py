#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request


def grade(base_url: str, challenge_id: str, flag: str) -> dict[str, object]:
    url = base_url.rstrip("/") + "/grade"
    body = json.dumps({"challenge_id": challenge_id, "flag": flag}).encode("utf-8")
    request = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return json.loads(exc.read().decode("utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(description="Grade an AegisPT lab-suite flag.")
    parser.add_argument("--base-url", default="http://127.0.0.155:8088")
    parser.add_argument("--challenge-id", required=True)
    parser.add_argument("--flag", required=True)
    args = parser.parse_args()

    result = grade(args.base_url, args.challenge_id, args.flag)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("match") is True else 1


if __name__ == "__main__":
    sys.exit(main())
