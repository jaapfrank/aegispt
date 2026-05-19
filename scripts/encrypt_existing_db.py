#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import sqlite3
import sys
from importlib import import_module
from pathlib import Path
from typing import Any


def _sqlcipher_driver() -> Any:
    try:
        return import_module("sqlcipher3.dbapi2")
    except ImportError as exc:
        raise RuntimeError(
            "sqlcipher3 is not installed. Install requirements/base.txt before encrypting a database."
        ) from exc


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Copy an existing plaintext AegisPT SQLite database into a SQLCipher database."
    )
    parser.add_argument("--source", required=True, help="Path to the existing plaintext SQLite database.")
    parser.add_argument("--output", required=True, help="Path for the encrypted SQLCipher database.")
    parser.add_argument(
        "--key",
        default=None,
        help="SQLCipher key. Defaults to AEGISPT_DB_KEY from the environment.",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Overwrite the output file when it already exists.",
    )
    return parser


def _sqlcipher_key_literal(key: str) -> str:
    return "'" + key.replace("'", "''") + "'"


def encrypt_existing_db(*, source: Path, output: Path, key: str, overwrite: bool = False) -> None:
    if not source.is_file():
        raise FileNotFoundError(f"source database does not exist: {source}")
    if output.exists() and not overwrite:
        raise FileExistsError(f"output already exists: {output}")

    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        output.unlink()

    driver = _sqlcipher_driver()
    plaintext = sqlite3.connect(str(source))
    encrypted = driver.connect(str(output))
    try:
        encrypted.execute(f"PRAGMA key = {_sqlcipher_key_literal(key)}")
        encrypted.execute("PRAGMA foreign_keys = OFF")
        encrypted.executescript("\n".join(plaintext.iterdump()))
        encrypted.commit()
        encrypted.execute("PRAGMA foreign_keys = ON")
        encrypted.execute("SELECT count(*) FROM sqlite_master").fetchone()
    finally:
        encrypted.close()
        plaintext.close()


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    key = args.key or os.getenv("AEGISPT_DB_KEY")
    if not key:
        print("AEGISPT_DB_KEY or --key is required.", file=sys.stderr)
        return 2

    try:
        encrypt_existing_db(
            source=Path(args.source).expanduser(),
            output=Path(args.output).expanduser(),
            key=key,
            overwrite=args.overwrite,
        )
    except Exception as exc:
        print(f"Failed to encrypt database: {exc}", file=sys.stderr)
        return 1

    print(f"Encrypted database written to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
