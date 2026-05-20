"""Regression test for the scope-matcher: URL scopes with IP hosts must
accept any path on the same IP host, even when no CIDR entries exist.

Discovered 2026-05-20 during XBOW baseline harness work: the agent's
correct probes against deeper paths like /server-status, /challenge, or
/api/v1/something on http://127.0.0.1:PORT were silently rejected by
the post-task scope check with "out of scope (graceful fail)" because
:func:`target_value_is_allowed` short-circuited to an empty CIDR check
when the candidate host was an IP, never falling through to the
host-string match that would have accepted the same IP.

This file pins the correct behavior so the regression cannot return.
"""
from __future__ import annotations

import pytest

from api.app.services.runs import target_value_is_allowed


@pytest.mark.parametrize(
    ("allowlist", "target", "expected"),
    [
        # URL scope on IP host accepts deeper paths on the same host
        ({"urls": ["http://127.0.0.1:5000"]}, "http://127.0.0.1:5000", True),
        ({"urls": ["http://127.0.0.1:5000"]}, "http://127.0.0.1:5000/challenge", True),
        ({"urls": ["http://127.0.0.1:5000"]}, "http://127.0.0.1:5000/server-status", True),
        ({"urls": ["http://127.0.0.1:5000"]}, "http://127.0.0.1:5000/api/v1/users", True),
        # Different IP host is still rejected
        ({"urls": ["http://127.0.0.1:5000"]}, "http://10.0.0.1:5000/challenge", False),
        # Different hostname entirely is rejected
        ({"urls": ["http://127.0.0.1:5000"]}, "http://example.com/", False),
        # Domain scope: existing behavior is unchanged
        ({"urls": ["http://example.com"]}, "http://example.com/some/path", True),
        ({"urls": ["http://example.com"]}, "http://api.example.com/v1", True),
        ({"urls": ["http://example.com"]}, "http://attacker.com/", False),
        # CIDR scope on the same IP still works (path match falls through)
        ({"cidrs": ["127.0.0.0/8"]}, "http://127.0.0.1:5000/challenge", True),
        # CIDR scope rejects out-of-range IP
        ({"cidrs": ["127.0.0.0/8"]}, "http://10.0.0.1:5000/challenge", False),
        # Mixed URL + CIDR: both paths accepted on overlapping host
        (
            {"urls": ["http://127.0.0.1:5000"], "cidrs": ["127.0.0.0/8"]},
            "http://127.0.0.1:5000/server-status",
            True,
        ),
    ],
)
def test_target_value_is_allowed_ip_host_paths(allowlist, target, expected):
    """URL scopes with IP hosts must accept any path on the same IP host."""
    assert target_value_is_allowed(allowlist, target) is expected
