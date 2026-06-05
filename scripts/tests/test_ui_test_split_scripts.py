from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def read(path: str) -> str:
    return (REPO_ROOT / path).read_text(encoding="utf-8")


def test_legacy_app_test_script_does_not_build_or_run_react_v2() -> None:
    script = read("scripts/run_app_tests.sh")

    assert "ui/tests/test_operator_console_smoke_e2e.py" in script
    assert "ui/tests/test_mockup_port_e2e.py" in script
    assert "build_ui_v2.sh" not in script
    assert "ui-v2" not in script


def test_react_app_v2_test_script_uses_ui_v2_playwright_only() -> None:
    script = read("scripts/run_app_v2_tests.sh")

    assert 'UI_V2_ROOT="${REPO_ROOT}/ui-v2"' in script
    assert "npm run build" in script
    assert "npx playwright test" in script
    assert "ui/tests/" not in script
    assert "pytest" not in script


def test_compat_ui_fast_script_delegates_to_legacy_app_tests() -> None:
    script = read("scripts/run_ui_fast_tests.sh")

    assert "run_app_tests.sh" in script
    assert "run_app_v2_tests.sh" in script
    assert "build_ui_v2.sh" not in script


def test_ci_has_separate_legacy_app_and_react_v2_targets() -> None:
    ci = read(".github/workflows/ci.yml")
    app_v2 = read(".github/workflows/app-v2-tests.yml")

    assert "Run legacy /app fast UI smoke tests" in ci
    assert "bash scripts/run_app_tests.sh" in ci
    assert "Run React /app-v2 tests" in app_v2
    assert "bash scripts/run_app_v2_tests.sh" in app_v2
