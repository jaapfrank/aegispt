from __future__ import annotations

from fastapi.testclient import TestClient


def _create_engagement(client: TestClient) -> str:
    response = client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "signal-tester"},
        json={
            "name": "Signal Fingerprinting",
            "client": "AegisPT Lab",
            "roe_ref": "ROE-SIGNAL-001",
        },
    )
    assert response.status_code == 201
    return response.json()["id"]


def test_inventory_snapshot_extracts_passive_signal_profile(client: TestClient) -> None:
    engagement_id = _create_engagement(client)

    response = client.post(
        "/api/v1/inventory/runs",
        headers={"X-Actor": "inventory-operator"},
        json={
            "engagement_id": engagement_id,
            "source_tools": ["httpx", "nmap"],
            "observations": [
                {
                    "tool": "httpx",
                    "kind": "inventory",
                    "data": {
                        "request_url": "https://app.example.test",
                        "final_url": "https://app.example.test/wp-login.php?page=login",
                        "response_headers": {
                            "server": "nginx",
                            "x-powered-by": "PHP/8.2",
                            "x-generator": "WordPress 6.5",
                            "x-application-context": "spring-api:prod",
                        },
                        "body_excerpt": (
                            "<html><meta name=\"generator\" content=\"WordPress\">"
                            "<script src=\"/wp-content/theme/app.js\"></script>"
                            "You have an error in your SQL syntax"
                            "</html>"
                        ),
                        "routes": ["https://app.example.test/graphql"],
                        "forms": [
                            {
                                "action": "https://app.example.test/wp-login.php",
                                "method": "POST",
                                "inputs": [
                                    {"name": "log", "type": "text"},
                                    {"name": "pwd", "type": "password"},
                                ],
                            },
                            {
                                "action": "https://app.example.test/upload",
                                "method": "POST",
                                "inputs": [{"name": "file", "type": "file"}],
                            },
                        ],
                        "cookies": [
                            {"name": "PHPSESSID", "value_shape": "opaque"},
                            {"name": "JSESSIONID", "value_shape": "opaque"},
                            {"name": "auth", "value_shape": "jwt"},
                            {"name": "remember", "value_shape": "serialized"},
                        ],
                    },
                },
                {
                    "tool": "nmap",
                    "kind": "inventory",
                    "data": {
                        "services": [
                            {
                                "host": "app.example.test",
                                "port": 8080,
                                "service": "http",
                                "product": "Apache Tomcat",
                                "confidence": 0.8,
                            }
                        ],
                        "fingerprints": [{"product": "Apache Tomcat", "confidence": 0.8}],
                    },
                },
            ],
        },
    )

    assert response.status_code == 201
    snapshot = response.json()
    profile = snapshot["normalized_inventory_json"]["signal_profile"]
    stack = snapshot["normalized_inventory_json"]["tech_stack_profile"]
    signal_keys = {signal["key"] for signal in profile["signals"]}

    assert "wordpress_cms" in signal_keys
    assert "php_language" in signal_keys
    assert "java_spring_indicator" in signal_keys
    assert "jwt_in_response" in signal_keys
    assert "graphql_endpoint" in signal_keys
    assert "login_form_found" in signal_keys
    assert "file_upload_endpoint" in signal_keys
    assert "sql_error_pattern" in signal_keys
    assert "serialized_cookie" in signal_keys
    assert stack["cms"] == ["WordPress"]
    assert stack["jwt_present"] is True
    assert stack["graphql_present"] is True
    assert stack["java_present"] is True
    assert stack["login_forms"] == ["https://app.example.test/wp-login.php"]
    assert stack["file_upload_endpoints"] == ["https://app.example.test/upload"]
    assert snapshot["summary_json"]["signal_count"] == len(profile["signals"])
    assert "tech_stack_profile" in snapshot["summary_json"]


def test_php_mysql_labels_do_not_create_injectable_parameter_without_evidence(
    client: TestClient,
) -> None:
    engagement_id = _create_engagement(client)

    response = client.post(
        "/api/v1/inventory/runs",
        headers={"X-Actor": "inventory-operator"},
        json={
            "engagement_id": engagement_id,
            "source_tools": ["httpx"],
            "observations": [
                {
                    "tool": "httpx",
                    "kind": "inventory",
                    "data": {
                        "technologies": ["PHP", "MySQL"],
                        "response_headers": {"x-powered-by": "PHP/8.2"},
                        "body_excerpt": "<html>normal landing page</html>",
                    },
                }
            ],
        },
    )

    assert response.status_code == 201
    profile = response.json()["normalized_inventory_json"]["signal_profile"]
    signal_keys = {signal["key"] for signal in profile["signals"]}

    assert "php_language" in signal_keys
    assert "injectable_parameter" not in signal_keys
    assert "sql_error_pattern" not in signal_keys
