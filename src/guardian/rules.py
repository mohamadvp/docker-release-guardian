"""A tiny rule registry, so adding a rule means writing one decorated function."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, NamedTuple

from guardian.models import Finding, Severity, Source


class Hit(NamedTuple):
    """What a rule function returns for each problem it finds."""

    message: str
    line: int | None = None


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    severity: Severity
    title: str
    references: tuple[str, ...]
    check: Callable[[Any], list[Hit]]


class Registry:
    def __init__(self, source: Source) -> None:
        self.source = source
        self.rules: dict[str, Rule] = {}

    def rule(
        self,
        *,
        id: str,
        name: str,
        severity: Severity,
        title: str,
        references: list[str] | None = None,
    ) -> Callable[[Callable[[Any], list[Hit]]], Callable[[Any], list[Hit]]]:
        def decorator(fn: Callable[[Any], list[Hit]]) -> Callable[[Any], list[Hit]]:
            if name in self.rules:
                raise ValueError(f"duplicate rule name: {name}")
            self.rules[name] = Rule(id, name, severity, title, tuple(references or ()), fn)
            return fn

        return decorator

    def run(self, data: Any, file: str) -> list[Finding]:
        """Run every registered rule against already-parsed input."""
        findings: list[Finding] = []
        for rule in self.rules.values():
            for hit in rule.check(data):
                findings.append(
                    Finding(
                        id=rule.id,
                        source=self.source,
                        severity=rule.severity,
                        title=rule.title,
                        message=hit.message,
                        rule_name=rule.name,
                        file=file,
                        line=hit.line,
                        references=list(rule.references),
                    )
                )
        return findings
