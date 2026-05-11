from __future__ import annotations

from api.app.services.operator_mission_compiler import compile_operator_safe_mission


def test_operator_mission_compiler_returns_bounded_full_pentest_plan() -> None:
    plan = compile_operator_safe_mission(
        "Run a full pentest on https://shop.example.test",
        authorization_confirmed=False,
    )

    assert plan["plan_status"] == "draft"
    mission = plan["mission_plan"]
    assert mission["scope"]["targets"] == [{"kind": "url", "value": "https://shop.example.test"}]
    assert mission["roe"]["operator_approval_required_before_runtime"] is True
    assert mission["roe"]["written_authorization_required"] is True
    assert "operator_mission_approval" in {item["id"] for item in mission["required_approvals"]}
    assert "written_authorization" in {item["id"] for item in mission["required_approvals"]}
    assert "active_validation_approval" in {item["id"] for item in mission["required_approvals"]}
    assert "runtime_dispatch" in {item["id"] for item in mission["forbidden_capabilities"]}
    assert any(item["id"] == "approval_gated_active_validation_planning" for item in mission["allowed_capabilities"])
    assert plan["execution_contract"]["creates_tasks"] is False
    assert plan["execution_contract"]["dispatches_work_directly"] is False
    assert plan["execution_contract"]["automatic_approval"] is False
    assert plan["execution_contract"]["generates_exploits_or_payloads"] is False


def test_operator_mission_compiler_converts_unsafe_runtime_wording_to_safe_validation() -> None:
    plan = compile_operator_safe_mission(
        "Exploit the login and get a shell on https://app.example.test",
        authorization_confirmed=True,
    )

    assert plan["plan_status"] == "draft"
    assert plan["unsafe_intent_handling"]["converted_to_safe_validation"] is True
    assert plan["unsafe_intent_handling"]["rejected"] is False
    assert "No exploit, payload, credential, shell, bypass, or brute-force action is generated." in plan["mission_plan"]["safe_validation_language"]
    assert "exploit_or_payload_generation" in {
        item["id"] for item in plan["mission_plan"]["forbidden_capabilities"]
    }
    assert plan["execution_contract"]["generates_exploits_or_payloads"] is False


def test_operator_mission_compiler_rejects_exfiltration_or_broad_scope_intent() -> None:
    exfiltration = compile_operator_safe_mission(
        "Steal data and exfiltrate customer records from https://app.example.test",
        authorization_confirmed=True,
    )
    assert exfiltration["plan_status"] == "rejected"
    assert exfiltration["unsafe_intent_handling"]["rejected"] is True
    assert "rewrite_safe_intent" in {
        item["id"] for item in exfiltration["mission_plan"]["required_approvals"]
    }
    assert "destructive_or_exfiltration_intent" in {
        item["id"] for item in exfiltration["mission_plan"]["forbidden_capabilities"]
    }

    broad = compile_operator_safe_mission("Scan the internet and whatever you can find")
    assert broad["plan_status"] == "rejected"
    assert broad["mission_plan"]["scope"]["broad_scope_rejected"] is True
    assert broad["mission_plan"]["scope"]["scope_expansion_allowed"] is False
    assert "exact_scope_confirmation" in {
        item["id"] for item in broad["mission_plan"]["required_approvals"]
    }
