from pathlib import Path

import pytest

from guardian.errors import PolicyError
from guardian.policy import DEFAULT_POLICY_YAML, Action, load_policy


def write(tmp_path: Path, text: str) -> Path:
    p = tmp_path / "guardian.yaml"
    p.write_text(text, encoding="utf-8")
    return p


def test_default_policy_is_valid(tmp_path: Path) -> None:
    policy = load_policy(write(tmp_path, DEFAULT_POLICY_YAML))
    assert policy.dockerfile["require_non_root_user"] is Action.FAIL


def test_missing_file_is_a_policy_error(tmp_path: Path) -> None:
    with pytest.raises(PolicyError, match="not found"):
        load_policy(tmp_path / "nope.yaml")


def test_unknown_top_level_key_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(PolicyError, match="fial_on|Extra inputs"):
        load_policy(write(tmp_path, "vulnerabilities:\n  fial_on: [HIGH]\n"))


def test_invalid_action_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(PolicyError):
        load_policy(write(tmp_path, "dockerfile:\n  require_non_root_user: maybe\n"))


def test_waiver_requires_reason_owner_and_expiry(tmp_path: Path) -> None:
    with pytest.raises(PolicyError):
        load_policy(write(tmp_path, "waivers:\n  - id: CVE-2024-1\n"))


def test_unknown_severity_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(PolicyError, match="unknown severity"):
        load_policy(write(tmp_path, "vulnerabilities:\n  fail_on: [SUPERBAD]\n"))
