from __future__ import annotations

from typing import Any


def calculate_risk(finding: Any) -> dict[str, Any]:
    severity = getattr(finding, "severity", None)
    exploitability = getattr(finding, "exploitability", None)
    business_impact = getattr(finding, "business_impact", None)

    return {
        "status": "placeholder",
        "severity": severity,
        "exploitability": exploitability,
        "business_impact": business_impact,
        "exposure": None,
        "overall_risk": None,
        "notes": "Future risk scoring will layer on top of existing finding severity and provenance fields without replacing them.",
    }
