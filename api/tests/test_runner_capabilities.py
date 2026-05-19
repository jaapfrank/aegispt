from __future__ import annotations

from api.app.services.runner_registry import (
    REQUIRED_CAPABILITY_FIELDS,
    registered_runner_tools,
    runner_capability_registry,
)


def _fresh_registry() -> dict:
    runner_capability_registry.cache_clear()
    return runner_capability_registry()


def test_runner_capabilities_cover_registered_runners() -> None:
    registry = _fresh_registry()
    registered_tools = registered_runner_tools()
    capability_names = [capability["name"] for capability in registry["capabilities"]]

    assert registry["registered_runner_count"] == len(registered_tools)
    assert registry["capability_count"] == len(registered_tools)
    assert registry["missing_tools"] == []
    assert registry["unexpected_tools"] == []
    assert registry["complete"] is True
    assert capability_names == sorted(registered_tools)

    for capability in registry["capabilities"]:
        assert REQUIRED_CAPABILITY_FIELDS.issubset(capability)
        assert capability["triggers"]
        assert capability["expected_evidence"]


def test_runner_capability_metadata_contains_planner_gate_signals() -> None:
    capabilities = {capability["name"]: capability for capability in _fresh_registry()["capabilities"]}

    sqlmap = capabilities["sqlmap"]
    assert "injectable_parameter" in sqlmap["triggers"]
    assert "sql_error_pattern" in sqlmap["triggers"]
    assert "no_injectable_parameter" in sqlmap["blockers"]
    assert all("mysql" not in trigger.lower() for trigger in sqlmap["triggers"])
    assert all("php" not in trigger.lower() for trigger in sqlmap["triggers"])

    jwt_probe = capabilities["jwt-probe"]
    assert "jwt_in_response" in jwt_probe["triggers"]

    deserialization_probe = capabilities["deserialization-probe"]
    assert "java_indicators" in deserialization_probe["triggers"]


def test_runner_capabilities_api_returns_registry(client) -> None:
    runner_capability_registry.cache_clear()

    response = client.get("/api/v1/runners/capabilities", headers={"X-Actor": "operator"})

    assert response.status_code == 200
    payload = response.json()
    assert payload["complete"] is True
    assert payload["missing_tools"] == []
    assert payload["unexpected_tools"] == []
    assert payload["registered_runner_count"] == payload["capability_count"]
    assert "sqlmap" in {capability["name"] for capability in payload["capabilities"]}
