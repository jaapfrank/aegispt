"""Regression: pre-recon-source must detect hardcoded secrets + dict-seeded creds.

Operator-flagged 2026-06-01 (XBEN-005): the source-audit runner detected
`username=/password=` pairs but NOT (a) a hardcoded JWT signing key
(`SECRET_KEY = "a very secret key"`) — the exact JWT-forgery enabler — nor
(b) dict-shaped seed creds like `{"name": "demo", "password": "demo"}`. So a
FastAPI/JWT app whose vuln is "forge an elevated token with the disclosed secret
to read premium-gated data" reported `cred_count=0`; the loop never learned the
secret and 5 interactive-exploit attempts captured nothing. These tests pin the
generic secret/credential CLASSES (not any challenge-specific recipe).
"""
from __future__ import annotations

import json
from pathlib import Path

from workers.runners.pre_recon_source.runner import execute_pre_recon_source


def _scan(source_dir: Path):
    r = execute_pre_recon_source([], source_dir=str(source_dir))
    md = r.artifacts[0].data.decode()
    payload = json.loads(r.stdout)
    return payload, md


def test_hardcoded_jwt_secret_is_surfaced(tmp_path: Path):
    # The exact XBEN-005 shape: a hardcoded HS256 signing key.
    (tmp_path / "main.py").write_text(
        'SECRET_KEY = "a very secret key"\nALGORITHM = "HS256"\n',
        encoding="utf-8",
    )
    payload, md = _scan(tmp_path)
    assert payload["cred_count"] >= 1
    assert "hardcoded-secret" in md
    assert "a very secret key" in md
    # ALGORITHM is not in the secret-name set → its value must not be surfaced.
    assert "HS256" not in md


def test_various_secret_names(tmp_path: Path):
    (tmp_path / "conf.py").write_text(
        'JWT_SECRET = "s3cr3t-signing-key"\n'
        'API_KEY = "ak_live_deadbeef"\n'
        'DJANGO_SECRET_KEY = "django-insecure-xyz"\n',
        encoding="utf-8",
    )
    payload, md = _scan(tmp_path)
    assert payload["cred_count"] >= 3
    for v in ("s3cr3t-signing-key", "ak_live_deadbeef", "django-insecure-xyz"):
        assert v in md, f"expected secret value {v!r} surfaced"


def test_dict_seeded_name_password_pair(tmp_path: Path):
    # The exact XBEN-005 seed shape — keys are quoted, key is "name" not "username".
    (tmp_path / "seed.py").write_text(
        'companies = [{"name": "demo", "password": "demo", "level": False},\n'
        '             {"name": "company2", "password": "ajsdasd987asd87as7da9", "level": True}]\n',
        encoding="utf-8",
    )
    payload, md = _scan(tmp_path)
    assert payload["cred_count"] >= 2
    assert "user/pass-pair" in md
    assert "ajsdasd987asd87as7da9" in md  # the premium company's password


def test_bare_users_dict_seed_is_surfaced(tmp_path: Path):
    # The exact XBEN-032 shape: a bare {user: pass} mapping with NO explicit
    # `password:` key. The XXE sink sits behind @login_required, so without this
    # the exploit agent never logs in (burns every step on 401 guesses).
    (tmp_path / "app.py").write_text(
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        "users = {'john': 'password123'}\n",
        encoding="utf-8",
    )
    payload, md = _scan(tmp_path)
    assert payload["cred_count"] >= 1
    assert "users-dict-seed" in md
    assert "john" in md
    assert "password123" in md


def test_non_credential_dict_not_flagged(tmp_path: Path):
    # A same-shaped dict on a non-credential variable must NOT be flagged as creds.
    (tmp_path / "conf.py").write_text(
        "config = {'host': 'localhost', 'scheme': 'https'}\n",
        encoding="utf-8",
    )
    payload, md = _scan(tmp_path)
    assert "users-dict-seed" not in md


def test_env_var_secret_not_flagged(tmp_path: Path):
    # A secret pulled from the environment is NOT a source-disclosed literal.
    (tmp_path / "settings.py").write_text(
        'import os\nSECRET_KEY = os.environ["SECRET_KEY"]\n',
        encoding="utf-8",
    )
    payload, md = _scan(tmp_path)
    assert "hardcoded-secret" not in md
