from __future__ import annotations


def _interpret(client, answer: str, configuration: dict | None = None) -> dict:
    response = client.post(
        "/api/v1/intake/interpretation",
        json={
            "question_id": "intent",
            "answer": answer,
            "configuration_json": configuration or {},
        },
    )
    assert response.status_code == 200
    return response.json()


def test_intent_planner_maps_english_full_pentest_without_redundant_depth_question(client) -> None:
    payload = _interpret(client, "Do a full pentest on https://shop.example.test")
    plan = payload["intent_mission_plan"]

    assert plan["preview_ready"] is True
    assert plan["launch_ready"] is False
    assert plan["next_missing_field"] == "authorization"
    assert plan["extracted"]["target"] == "https://shop.example.test"
    assert plan["extracted"]["assessment_type"] == "External Web App"
    assert plan["extracted"]["depth"] == "Full Pentest"
    assert plan["extracted"]["run_mode"] == "assessment_chain"
    assert plan["extracted"]["assessment_mode"] == "FULL-EXTERNAL-WEB"
    assert plan["follow_up_questions"] == []
    assert "written authorization" in plan["launch_summary"]["operator_text"].lower()
    assert "written_authorization_required" in {
        action["id"] for action in plan["launch_summary"]["required_actions"]
    }
    assert all(
        "full pentest" not in item.get("question", "").lower()
        for item in payload["follow_up_questions"] + plan["follow_up_questions"]
    )


def test_intent_planner_maps_dutch_full_pentest_to_launch_preview(client) -> None:
    payload = _interpret(client, "Doe een volledige pentest op https://portaal.example.test")
    plan = payload["intent_mission_plan"]

    assert plan["preview_ready"] is True
    assert plan["extracted"]["target"] == "https://portaal.example.test"
    assert plan["extracted"]["depth"] == "Full Pentest"
    assert plan["extracted"]["assessment_mode"] == "FULL-EXTERNAL-WEB"
    assert plan["configuration_preview"]["targets"] == {"urls": ["https://portaal.example.test"]}
    assert plan["launch_summary"]["automatic"][0]["id"] == "assessment_chain"


def test_intent_planner_marks_authorized_full_pentest_launch_ready(client) -> None:
    payload = _interpret(
        client,
        "Run a full pentest on https://authorized.example.test",
        {
            "authorization_confirmed": True,
            "assessment_mode": {
                "authorization_level": "full",
                "written_authorization_confirmed": True,
            },
        },
    )
    plan = payload["intent_mission_plan"]

    assert plan["preview_ready"] is True
    assert plan["launch_ready"] is True
    assert plan["launch_summary"]["required_actions"] == []
    assert "FULL-EXTERNAL-WEB" in plan["launch_summary"]["operator_text"]


def test_intent_planner_asks_only_for_missing_or_unsafe_information(client) -> None:
    missing_target = _interpret(client, "Do a full pentest")
    missing_plan = missing_target["intent_mission_plan"]
    assert missing_plan["preview_ready"] is False
    assert missing_plan["next_missing_field"] == "target"
    assert missing_plan["follow_up_questions"][0]["question_id"] == "scope"

    broad_scope = _interpret(client, "Scan anything reachable around https://example.test")
    broad_plan = broad_scope["intent_mission_plan"]
    assert broad_plan["preview_ready"] is False
    assert broad_plan["next_missing_field"] == "unsafe_scope"
    assert broad_plan["launch_summary"]["out_of_scope"][0]["id"] == "broad_scope_language"
    assert broad_plan["follow_up_questions"][0]["question_id"] == "scope"
    assert broad_plan["safety"]["authorization_bypass_allowed"] is False
