import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from guardian.cli import app
from guardian.models import EXIT_PASS, EXIT_POLICY_FAIL, EXIT_TOOL_ERROR, EXIT_USAGE_ERROR
from guardian.scanners import trivy

runner = CliRunner()
EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def check(example: str, *extra: str) -> "object":
    project = EXAMPLES / example
    return runner.invoke(app, ["check", str(project), "--policy", str(project / "guardian.yaml"), *extra])


def test_vulnerable_example_fails_with_exit_1() -> None:
    result = check("vulnerable-app")
    assert result.exit_code == EXIT_POLICY_FAIL
    assert "RESULT: FAIL" in result.stdout


def test_secure_example_passes_with_exit_0() -> None:
    result = check("secure-app")
    assert result.exit_code == EXIT_PASS, result.stdout
    assert "RESULT: PASS" in result.stdout


def test_json_report_is_valid_and_has_schema_version() -> None:
    result = check("vulnerable-app", "--format", "json")
    payload = json.loads(result.stdout)
    assert payload["schema_version"] == "1"
    assert payload["passed"] is False
    assert payload["summary"]["violations"] >= 1
    # Severities are human-readable names, not integers.
    assert {v["severity"] for v in payload["violations"]} <= {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}


def test_missing_policy_is_exit_2(tmp_path: Path) -> None:
    result = runner.invoke(app, ["check", str(EXAMPLES / "secure-app"), "--policy", str(tmp_path / "x.yaml")])
    assert result.exit_code == EXIT_USAGE_ERROR


def test_project_without_docker_files_is_exit_2(tmp_path: Path) -> None:
    policy = tmp_path / "guardian.yaml"
    runner.invoke(app, ["init", str(policy)])
    result = runner.invoke(app, ["check", str(tmp_path), "--policy", str(policy)])
    assert result.exit_code == EXIT_USAGE_ERROR


def test_unknown_format_is_exit_2() -> None:
    assert check("secure-app", "--format", "pdf").exit_code == EXIT_USAGE_ERROR


def test_sarif_is_not_implemented_yet_and_says_so() -> None:
    # TODO(you): delete this test once render_sarif is implemented, and test the real output.
    assert check("secure-app", "--format", "sarif").exit_code == EXIT_USAGE_ERROR


def test_missing_trivy_is_exit_3_not_a_pass(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(trivy.shutil, "which", lambda _name: None)
    result = check("secure-app", "--image", "python:3.12")
    assert result.exit_code == EXIT_TOOL_ERROR


def test_init_refuses_to_overwrite_without_force(tmp_path: Path) -> None:
    path = tmp_path / "guardian.yaml"
    assert runner.invoke(app, ["init", str(path)]).exit_code == EXIT_PASS
    assert runner.invoke(app, ["init", str(path)]).exit_code == EXIT_USAGE_ERROR
    assert runner.invoke(app, ["init", str(path), "--force"]).exit_code == EXIT_PASS


def test_validate_policy_flags_unknown_rule_names(tmp_path: Path) -> None:
    path = tmp_path / "guardian.yaml"
    path.write_text("dockerfile:\n  require_non_root_usr: fail\n", encoding="utf-8")
    assert runner.invoke(app, ["validate-policy", str(path)]).exit_code == EXIT_USAGE_ERROR

# TODO(you): a test that writes --output to a file; a test that an expired waiver in the
# policy file makes `check` exit 1; a real end-to-end test with Trivy (mark it with
# @pytest.mark.integration and only run it in CI where Trivy is installed).
