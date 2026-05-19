from __future__ import annotations

from pathlib import Path


def build_password_spray_command(
    *,
    binary: str,
    domain: str,
    users_file: Path,
    password: str,
    domain_controller: str | None = None,
) -> list[str]:
    command = [
        binary,
        "passwordspray",
        "-d",
        domain,
        str(users_file),
        password,
    ]
    if domain_controller:
        command.extend(["--dc", domain_controller])
    return command


def parse_password_spray_successes(output_lines: list[str]) -> list[str]:
    successes: list[str] = []
    for raw_line in output_lines:
        line = str(raw_line or "").strip()
        if "VALID LOGIN:" not in line.upper():
            continue
        remainder = line.split(":", 1)[1].strip() if ":" in line else ""
        if not remainder:
            continue
        username = remainder.split(":", 1)[0].strip()
        if username and username not in successes:
            successes.append(username)
    return successes
