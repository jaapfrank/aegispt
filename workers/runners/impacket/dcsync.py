from __future__ import annotations

from typing import Any

from workers.runners.impacket.secretsdump import build_secretsdump_command


def build_dcsync_command(
    binary: str,
    *,
    target: str,
    auth_context: dict[str, Any],
) -> list[str]:
    return build_secretsdump_command(
        binary,
        target=target,
        auth_context=auth_context,
        just_dc_user="krbtgt",
    )
