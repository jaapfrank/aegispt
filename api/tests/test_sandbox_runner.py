"""Unit tests for the per-step Docker sandbox argv builder.

The actual ``docker run`` execution path requires a Docker daemon on the
host and is exercised by the live XBOW harness; here we cover the pure
helpers that compose argv + validate steps, so a missing Docker
installation does not silently weaken the isolation contract.
"""
from __future__ import annotations

import pytest

from workers.orchestration.sandbox_runner import (
    SandboxConfig,
    _build_curl_argv,
    _build_docker_argv,
)


def test_curl_argv_get_minimal() -> None:
    step = {"method": "GET", "url": "http://127.0.0.1:8080/health"}
    argv = _build_curl_argv(step)
    assert argv[0] == "curl"
    assert "-X" in argv and argv[argv.index("-X") + 1] == "GET"
    assert argv[-1] == "http://127.0.0.1:8080/health"


def test_curl_argv_post_with_body_and_header() -> None:
    step = {
        "method": "POST",
        "url": "http://127.0.0.1:8080/login",
        "headers": {"Content-Type": "application/x-www-form-urlencoded"},
        "body": "username=test&password=test",
    }
    argv = _build_curl_argv(step)
    assert "-H" in argv
    assert "Content-Type: application/x-www-form-urlencoded" in argv
    assert "--data-binary" in argv
    assert "username=test&password=test" in argv


def test_curl_argv_rejects_non_allowed_method() -> None:
    with pytest.raises(ValueError, match="non-allowed method"):
        _build_curl_argv({"method": "TRACE", "url": "http://x"})


def test_curl_argv_rejects_host_header_override() -> None:
    with pytest.raises(ValueError, match="Host header"):
        _build_curl_argv({
            "method": "GET",
            "url": "http://127.0.0.1/x",
            "headers": {"Host": "attacker.com"},
        })


def test_curl_argv_rejects_missing_url() -> None:
    with pytest.raises(ValueError, match="missing url"):
        _build_curl_argv({"method": "GET", "url": ""})


def test_docker_argv_contains_isolation_flags() -> None:
    config = SandboxConfig(memory_mb=64, cpu_quota_pct=15)
    inner = ["curl", "-sS", "http://x"]
    argv = _build_docker_argv(config=config, container_name="aegispt-test-1", inner_argv=inner)
    assert argv[0] == "docker" and argv[1] == "run"
    assert "--rm" in argv
    assert "--name" in argv
    assert "aegispt-test-1" in argv
    assert "--user" in argv and argv[argv.index("--user") + 1] == "65534:65534"
    assert "--memory" in argv and argv[argv.index("--memory") + 1] == "64m"
    assert "--security-opt" in argv
    assert "no-new-privileges:true" in argv
    assert "--network" in argv and argv[argv.index("--network") + 1] == "none"
    assert "--cap-drop" in argv
    assert "ALL" in argv
    # Inner argv preserved at the end.
    assert argv[-3:] == inner


def test_docker_argv_read_only_rootfs_adds_tmpfs() -> None:
    config = SandboxConfig(read_only_rootfs=True)
    argv = _build_docker_argv(config=config, container_name="t2", inner_argv=["echo", "x"])
    assert "--read-only" in argv
    assert "--tmpfs" in argv
    tmpfs_value = argv[argv.index("--tmpfs") + 1]
    assert tmpfs_value.startswith("/tmp:")
    assert "noexec" in tmpfs_value


def test_docker_argv_labels_include_sandbox_id() -> None:
    config = SandboxConfig(extra_labels={"engagement": "eng-1"})
    argv = _build_docker_argv(config=config, container_name="t3", inner_argv=["echo", "x"])
    label_positions = [i for i, a in enumerate(argv) if a == "--label"]
    label_values = {argv[i + 1] for i in label_positions}
    assert any(v == "engagement=eng-1" for v in label_values)
    assert any(v == "aegispt.sandbox.id=t3" for v in label_values)
