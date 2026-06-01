"""Regression: the dedicated-IP compose bind must cover short-form int ports.

Operator-flagged 2026-06-01 (XBEN-014): the challenge's compose used the bare
short form ``- 80``, which PyYAML parses as a Python ``int`` (not a string).
``_rewrite_port_entry_to_bind_ip`` only handled ``str``/``dict``, so the int
fell through unchanged. The container then auto-published ``0.0.0.0:<random>``
instead of binding ``127.0.0.X:80:80`` — so nmap could not discover the random
port on the loopback alias and the port-less scope defaulted to a dead port 80.
Every exec-plan HTTP step hit ``Connection refused`` and the run no-flagged.

The fix binds int short-form ports to the dedicated IP at the NATIVE port. These
tests pin that behavior so the regression cannot return.
"""
from __future__ import annotations

import pathlib

import yaml

from scripts.xbow_benchmark import _normalize_compose, _rewrite_port_entry_to_bind_ip

BIND_IP = "127.0.0.150"


def test_int_short_form_port_is_bound_to_native_port():
    # PyYAML parses ``- 80`` as int 80. This is the case that regressed.
    assert _rewrite_port_entry_to_bind_ip(80, BIND_IP) == f"{BIND_IP}:80:80"


def test_str_long_form_port_forces_native_port_on_bind_ip():
    assert _rewrite_port_entry_to_bind_ip("8081:80", BIND_IP) == f"{BIND_IP}:80:80"


def test_str_short_form_port_bound():
    assert _rewrite_port_entry_to_bind_ip("8080", BIND_IP) == f"{BIND_IP}:8080:8080"


def test_proto_suffix_preserved():
    assert _rewrite_port_entry_to_bind_ip("443/tcp", BIND_IP) == f"{BIND_IP}:443:443/tcp"


def test_dict_long_form_port_pinned_to_bind_ip():
    out = _rewrite_port_entry_to_bind_ip({"target": 80, "published": 8081}, BIND_IP)
    assert out == {"target": 80, "host_ip": BIND_IP, "published": 80}


def test_normalize_compose_pins_int_port(tmp_path: pathlib.Path):
    # A minimal compose with the exact short-form int port that regressed.
    compose = tmp_path / "docker-compose.yml"
    compose.write_text(
        "services:\n  web:\n    image: nginx\n    ports:\n      - 80\n",
        encoding="utf-8",
    )
    out = _normalize_compose(tmp_path, bind_ip=BIND_IP)
    parsed = yaml.safe_load(pathlib.Path(out).read_text(encoding="utf-8"))
    assert parsed["services"]["web"]["ports"] == [f"{BIND_IP}:80:80"]
