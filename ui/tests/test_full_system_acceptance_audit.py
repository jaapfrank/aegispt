from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts import run_full_system_acceptance_audit as audit


def test_seeded_broken_control_fixture_is_detected() -> None:
    snapshot = {
        "screen": "settings",
        "heading": "Settings",
        "text": "Settings Coming Soon",
        "controls": [
            {
                "tag": "button",
                "label": "",
                "aria_label": "",
                "disabled": False,
                "testid": "broken-empty-button",
            },
            {
                "tag": "button",
                "label": "Coming Soon",
                "disabled": False,
                "testid": "placeholder-button",
            },
            {
                "tag": "button",
                "label": "Manage",
                "disabled": False,
                "testid": "ambiguous-manage",
            },
        ],
        "fields": [
            {
                "tag": "input",
                "input_type": "text",
                "label": "",
                "placeholder": "",
                "aria_label": "",
                "required": True,
                "testid": "unguided-required-field",
            }
        ],
    }

    defects = audit.detect_screen_defects(snapshot, queue_items=[{"index": "154", "title": "Settings readiness"}])
    codes = {defect["code"] for defect in defects}

    assert "button_without_accessible_name" in codes
    assert "clickable_placeholder_action" in codes
    assert "ambiguous_operator_action" in codes
    assert "required_field_without_guidance" in codes


def test_defect_inventory_maps_known_product_areas_to_existing_backlog() -> None:
    snapshot = {
        "screen": "mission-control",
        "heading": "Mission Control",
        "text": "Start Validation queued task no stdout",
        "controls": [
            {
                "tag": "button",
                "label": "Start Validation",
                "disabled": False,
                "testid": "start-validation",
            }
        ],
        "fields": [],
    }

    defects = audit.detect_screen_defects(snapshot, queue_items=[{"index": "150", "title": "Run lifecycle dispatch"}])

    assert any(defect["code"] == "ambiguous_operator_action" for defect in defects)
    assert any(defect["recommended_backlog_target"] == "backlog-150" for defect in defects)
