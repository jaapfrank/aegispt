"""Operator (2026-06-03): nmap is valuable (other open ports can host vulns) but must
run AFTER the standard web recon, not as a blocking priority-1 step. When a port-less
target's :80 probe fails, target-intel now sweeps common app ports first; if one serves
it proceeds with web recon there and demotes nmap to a low-priority other-port follow-up.
Only when NO common port serves does it keep the original nmap-priority-1 plan.
"""
from __future__ import annotations

import http.server
import threading
from urllib.parse import urlparse

from workers.runners.target_intel.runner import (
    _deferred_nmap_step,
    _port_discovery_required_analysis,
    _sweep_common_web_ports,
)


def test_deferred_nmap_is_low_priority_other_ports():
    step = _deferred_nmap_step("10.0.0.5")
    assert step["tool"] == "nmap"
    assert step["priority"] == 9  # AFTER the standard web recon
    assert "AFTER" in step["reason"] and "follow-up" in step["reason"].lower()
    assert step["params"]["target"] == "10.0.0.5"


def test_sweep_skips_target_that_already_has_a_port():
    # explicit port -> nothing to discover, no sweep
    assert _sweep_common_web_ports("http://127.0.0.1:8080", 2.0) is None


def test_sweep_returns_none_when_nothing_serves():
    # unused high IP/port space -> no common web port answers -> nmap stays the path
    assert _sweep_common_web_ports("http://127.0.0.231", 1.0) is None


def test_port_discovery_plan_unchanged_when_truly_no_port():
    # the original safety net: port-less + no response + (sweep found nothing) =>
    # deterministic nmap-priority-1 plan is still emitted.
    plan = _port_discovery_required_analysis("http://127.0.0.231", {"status": None})
    assert plan is not None
    steps = plan["test_plan"]
    assert steps[0]["tool"] == "nmap" and steps[0]["priority"] == 1


def test_port_discovery_skipped_when_port_known():
    # explicit port OR a responding default port => no nmap-first plan
    assert _port_discovery_required_analysis("http://127.0.0.231:5000", {"status": None}) is None
    assert _port_discovery_required_analysis("http://127.0.0.231", {"status": 200}) is None


def test_sweep_finds_a_live_common_port():
    # spin a real server on a common app port (8000) and confirm the sweep finds it
    class _Quiet(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *_a):  # silence
            return

    # dedicated loopback IP so we never collide with the API on 127.0.0.1:8000
    srv = http.server.HTTPServer(("127.0.0.232", 8000), _Quiet)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        found = _sweep_common_web_ports("http://127.0.0.232", 2.0)
        assert found is not None
        assert urlparse(found).port == 8000
    finally:
        srv.shutdown()
