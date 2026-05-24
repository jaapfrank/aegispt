"""Code-exec-attack runner — AI writes Python exploit code per target.

Phase B of "best AI pentest system" plan (2026-05-22). Picker emits a
Python script; runner executes it in a host-process subprocess with a
scope-enforcement preamble that wraps httpx to refuse out-of-scope URLs.

This is the Naptime + Shannon-exploit-agent pattern: instead of forcing
the AI to pick from a tool menu, give it a network-enabled Python REPL
gated by Layer 0 governance.
"""
from .runner import CODE_EXEC_ATTACK_ARTIFACT_NAME, execute_code_exec_attack

__all__ = ["CODE_EXEC_ATTACK_ARTIFACT_NAME", "execute_code_exec_attack"]
