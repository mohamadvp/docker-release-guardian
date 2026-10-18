"""Core data models shared by every part of the tool."""

from __future__ import annotations

from enum import IntEnum, StrEnum

from pydantic import BaseModel, Field, field_serializer

# Exit codes. Keeping policy failed. separate from the tool itself broke"
EXIT_PASS = 0
EXIT_POLICY_FAIL = 1
EXIT_USAGE_ERROR = 2
EXIT_TOOL_ERROR = 3


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> Severity:
        """Unknown values become INFO."""
        try:
            return cls[value.strip().upper()]
        except KeyError:
            return cls.INFO


class Source(StrEnum):
    DOCKERFILE = "dockerfile"
    COMPOSE = "compose"
    TRIVY = "trivy"
    POLICY = "policy"


class Finding(BaseModel):
    """One problem found by one analyzer or scanner."""

    id: str = Field(description="Stable ID: a rule ID like DG-DF-001 or a CVE like CVE-2024-1234")
    source: Source
    severity: Severity
    title: str
    message: str = ""
    # For Dockerfile/Compose rules: the policy key (e.g. "require_non_root_user").
    rule_name: str | None = None
    file: str | None = None
    line: int | None = None
    # Vulnerabilities only: is a fixed version available? None = not applicable.
    fixable: bool | None = None
    references: list[str] = Field(default_factory=list)

    @field_serializer("severity")
    def _severity_as_name(self, value: Severity) -> str:
        return value.name


class Decision(BaseModel):
    passed: bool
    violations: list[Finding] = Field(default_factory=list)
    warnings: list[Finding] = Field(default_factory=list)
    waived: list[Finding] = Field(default_factory=list)
    ignored: list[Finding] = Field(default_factory=list)
