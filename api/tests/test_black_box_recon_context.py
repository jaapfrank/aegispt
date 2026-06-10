"""The black-box exploit dispatch must seed the loop with recon-discovered endpoints, with the
URL pulled from description/metadata (where content-discovery actually stores it), not just the
title. Pins the recon-seeding that addresses the 'never reaches the goal path' gap."""
from api.app.services.assessment_loop import _black_box_recon_context


class _F:
    def __init__(self, title="", description="", summary="", metadata_json=""):
        self.title = title
        self.description = description
        self.summary = summary
        self.metadata_json = metadata_json


def test_extracts_url_from_description():
    f = _F(title="Hidden Endpoint Discovered",
           description="Content discovery found http://host/admin returning HTTP 200")
    rc = _black_box_recon_context([f])
    assert rc.startswith("RECON FINDINGS")
    assert "Hidden Endpoint Discovered" in rc
    assert "http://host/admin" in rc


def test_extracts_path_from_metadata():
    f = _F(title="Endpoint", metadata_json="{'url': '/api/secret-panel'}")
    rc = _black_box_recon_context([f])
    assert "/api/secret-panel" in rc


def test_empty_returns_blank():
    assert _black_box_recon_context([]) == ""
    assert _black_box_recon_context(None) == ""
    # a finding with no title is skipped
    assert _black_box_recon_context([_F(title="")]) == ""


def test_caps_items():
    fs = [_F(title=f"Finding{i}", description=f"/p{i}") for i in range(60)]
    rc = _black_box_recon_context(fs, max_items=40)
    assert rc.count("- Finding") == 40
