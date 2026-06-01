"""Regression: nmap targets must be bare hosts, not URLs (2026-06-01).

Operator observed `nmap ... -sn http://127.0.0.165` -> "0 IP addresses scanned"
because the URL scheme was passed straight to nmap. build_nmap_command must
reduce a URL / host:port target to the bare host (nmap scans hosts; ports go
via -p), and a port carried in the target must be scanned, not discarded.
"""
from __future__ import annotations

from pathlib import Path

from workers.runners.nmap.runner import _split_nmap_target, build_nmap_command

OUT = Path("/tmp/nmap-results.xml")


def test_url_target_reduced_to_bare_ip():
    cmd = build_nmap_command("nmap", output_file=OUT, targets=["http://127.0.0.165"])
    assert "http://127.0.0.165" not in cmd
    assert cmd[-1] == "127.0.0.165"  # bare IP is the scan target


def test_url_with_port_scans_that_port():
    cmd = build_nmap_command(
        "nmap", output_file=OUT, targets=["http://127.0.0.165:10250"],
        discovery_only=False, skip_discovery=True,
    )
    assert cmd[-1] == "127.0.0.165"
    assert "-p" in cmd and "10250" in cmd


def test_host_port_target_scans_that_port():
    cmd = build_nmap_command(
        "nmap", output_file=OUT, targets=["127.0.0.165:10250"],
        discovery_only=False, skip_discovery=True,
    )
    assert cmd[-1] == "127.0.0.165"
    assert cmd[cmd.index("-p") + 1] == "10250"


def test_cidr_target_preserved():
    # CIDR ranges must pass through unchanged (no scheme, no single-colon port).
    host, port = _split_nmap_target("10.10.10.0/24")
    assert host == "10.10.10.0/24" and port is None


def test_bare_ip_unchanged():
    host, port = _split_nmap_target("127.0.0.155")
    assert host == "127.0.0.155" and port is None
