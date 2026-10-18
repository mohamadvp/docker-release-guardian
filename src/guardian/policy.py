"""Policy file schema and loader."""

from __future__ import annotations

from datetime import date
from enum import StrEnum
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from guardian.errors import PolicyError
from guardian.models import Severity


class Action(StrEnum):
    """What to do when a rule triggers."""

    OFF = "off"    # ignore the rule completely
    WARN = "warn"  # report it, but do not fail the pipeline
    FAIL = "fail"  # report it and fail the pipeline


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class VulnerabilityPolicy(_Strict):
    fail_on: list[Severity] = Field(default_factory=lambda: [Severity.CRITICAL, Severity.HIGH])
    ignore_unfixed: bool = True

    @field_validator("fail_on", mode="before")
    @classmethod
    def _parse_severities(cls, value: list[str]) -> list[Severity]:
        try:
            return [Severity[str(v).upper()] for v in value]
        except KeyError as exc:
            valid = ", ".join(s.name for s in Severity)
            raise ValueError(f"unknown severity {exc}; valid values: {valid}") from exc


class Waiver(_Strict):
    """An accepted risk. Must have a reason, an owner and an expiry date."""

    id: str = Field(min_length=1, description="CVE ID or rule ID, e.g. CVE-2024-1234 or DG-DF-001")
    reason: str = Field(min_length=3)
    owner: str = Field(min_length=1)
    expires: date

    def is_expired(self, today: date) -> bool:
        return today > self.expires


class Policy(_Strict):
    version: int = 1
    # Used for Dockerfile/Compose rules that the policy does not mention explicitly.
    default_action: Action = Action.WARN
    vulnerabilities: VulnerabilityPolicy = Field(default_factory=VulnerabilityPolicy)
    # Keys are rule names, e.g. `require_non_root_user: fail`
    dockerfile: dict[str, Action] = Field(default_factory=dict)
    compose: dict[str, Action] = Field(default_factory=dict)
    waivers: list[Waiver] = Field(default_factory=list)

    @field_validator("version")
    @classmethod
    def _check_version(cls, value: int) -> int:
        if value != 1:
            raise ValueError("only policy version 1 is supported")
        return value


def load_policy(path: Path) -> Policy:
    """Load and validate a policy file. Raises PolicyError with a readable message."""
    if not path.is_file():
        raise PolicyError(f"policy file not found: {path}")
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise PolicyError(f"{path}: invalid YAML: {exc}") from exc
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise PolicyError(f"{path}: top level must be a mapping")
    try:
        return Policy.model_validate(raw)
    except ValidationError as exc:
        lines = [f"{path}: policy validation failed:"]
        for err in exc.errors():
            where = ".".join(str(p) for p in err["loc"]) or "<root>"
            lines.append(f"  - {where}: {err['msg']}")
        raise PolicyError("\n".join(lines)) from exc


DEFAULT_POLICY_YAML = """\
# Docker Release Guardian policy
# Actions: off | warn | fail
version: 1
default_action: warn

vulnerabilities:
  fail_on: [CRITICAL, HIGH]
  ignore_unfixed: true

dockerfile:
  require_non_root_user: fail
  forbid_latest_tag: fail
  forbid_secrets_in_env: fail
  forbid_add_remote_url: warn

compose:
  forbid_privileged: fail
  forbid_docker_socket_mount: fail
  forbid_host_network: warn

# Accepted risks. Every waiver needs a reason, an owner and an expiry date.
# An expired waiver FAILS the pipeline, so exceptions cannot be forgotten.
waivers: []
#  - id: CVE-2024-12345
#    reason: "No upstream fix; not reachable in our configuration"
#    owner: your-name
#    expires: 2027-01-31
"""
