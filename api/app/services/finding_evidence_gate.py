"""No Exploit, No Report — finding evidence taxonomy (rework-4 task 1.2, answers Q3).

Shannon's winning principle: a finding is only "real" if an exploit ATTEMPT produced
evidence. This pure classifier labels a finding so the proof-loop / evidence ledger can
count ONLY exploit-proven findings, and passive observations (missing headers, clickjacking,
hidden endpoints) do not masquerade as real findings. Additive — no finding schema change,
this is a derived classification. A later slice wires it into recording/reporting.
"""
from __future__ import annotations

# Tools whose findings come FROM a real exploit attempt (request -> observe -> proof).
_EXPLOIT_TOOLS = frozenset({
    "interactive-exploit", "code-exec-attack", "exploit-developer-agent",
    "xss-proof", "sqli-proof", "ssrf-proof",
})

# Title markers indicating a CONFIRMED/proven exploit, regardless of the source tool.
_PROVEN_MARKERS = (
    "flag captured", "captured", "confirmed", "proven", "rce",
    "remote code execution", "arbitrary file read", "sensitive file disclosure",
)

# Title markers for PASSIVE observations — not an exploit, so "no report" (not counted).
_PASSIVE_MARKERS = (
    "missing", "exposes platform", "information disclosure header", "clickjacking",
    "frame protection", "hidden endpoint", "hsts", "security header",
)

PROVEN = "exploit_proven"
PASSIVE = "passive_observation"
UNPROVEN = "unproven"


def classify_finding(*, title: str = "", source_tool: str = "", evidence_ref: str = "") -> str:
    """Return one of PROVEN / PASSIVE / UNPROVEN.

    Only PROVEN satisfies "No Exploit, No Report". PASSIVE is real-but-not-an-exploit (kept
    for audit, NOT counted as a proof-loop finding). UNPROVEN is the safe default for anything
    ambiguous (also NOT counted) — the loop must produce exploit evidence to upgrade it.
    """
    t = (title or "").strip().lower()
    src = (source_tool or "").strip().lower()
    # an exploit-attempt tool that attached a concrete evidence ref is proven
    if src in _EXPLOIT_TOOLS and str(evidence_ref or "").strip():
        return PROVEN
    # confirmed-exploit markers win over passive markers (a "Reflected XSS Confirmed" finding
    # may also mention a passive header detail)
    if any(m in t for m in _PROVEN_MARKERS):
        return PROVEN
    if any(m in t for m in _PASSIVE_MARKERS):
        return PASSIVE
    return UNPROVEN


def is_reportable(*, title: str = "", source_tool: str = "", evidence_ref: str = "") -> bool:
    """No Exploit, No Report: only an exploit-proven finding is reportable as a real finding."""
    return classify_finding(title=title, source_tool=source_tool, evidence_ref=evidence_ref) == PROVEN


def partition_findings(findings) -> dict[str, list]:
    """Partition raw finding dicts by evidence class so a ledger/report counts ONLY the
    proven list (No Exploit, No Report). Each finding is a mapping with at least ``title``
    (optionally ``source_tool``/``tool`` and ``evidence_ref``). Returns
    ``{exploit_proven: [...], passive_observation: [...], unproven: [...]}`` — non-dict items
    are skipped. Pure; does not mutate inputs or the finding schema."""
    out: dict[str, list] = {PROVEN: [], PASSIVE: [], UNPROVEN: []}
    for f in findings or []:
        if not isinstance(f, dict):
            continue
        cls = classify_finding(
            title=str(f.get("title") or ""),
            source_tool=str(f.get("source_tool") or f.get("tool") or ""),
            evidence_ref=str(f.get("evidence_ref") or ""),
        )
        out[cls].append(f)
    return out
