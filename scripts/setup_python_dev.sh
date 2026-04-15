#!/usr/bin/env bash
set -euo pipefail

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required before creating the AegisPT virtual environment." >&2
  exit 1
fi

if ! python3 -m venv --help >/dev/null 2>&1; then
  echo "python3 -m venv is unavailable. Install python3-venv before running this script." >&2
  exit 1
fi

python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements/dev.txt

echo "Python development environment ready."
