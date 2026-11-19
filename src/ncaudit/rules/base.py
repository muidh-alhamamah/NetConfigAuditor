"""Rule registry. A rule is a function that takes a Config and yields Hit objects.

Adding a rule: write a function in any module under ncaudit.rules, decorate it with @rule(...),
and import that module in ncaudit/rules/__init__.py.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass

from ncaudit.models import Finding, Severity
from ncaudit.parser import Config, Line
from ncaudit.redact import redact


@dataclass(frozen=True)
class Hit:
    line: Line | None              # None when the problem is a missing setting
    message: str                   # must never contain a secret value
    severity: Severity | None = None  # overrides the rule's default severity


@dataclass(frozen=True)
class Rule:
    id: str
    severity: Severity
    title: str
    recommendation: str
    check: Callable[[Config], Iterable[Hit]]

    def run(self, config: Config) -> list[Finding]:
        return [
            Finding(
                rule_id=self.id,
                severity=hit.severity or self.severity,
                title=self.title,
                line=hit.line.number if hit.line else None,
                message=hit.message,
                recommendation=self.recommendation,
                evidence=redact(hit.line.text) if hit.line else None,
            )
            for hit in self.check(config)
        ]


RULES: list[Rule] = []


def rule(rule_id: str, severity: Severity, title: str, recommendation: str):
    def register(check: Callable[[Config], Iterable[Hit]]):
        if any(r.id == rule_id for r in RULES):
            raise ValueError(f"duplicate rule id: {rule_id}")
        RULES.append(Rule(rule_id, severity, title, recommendation, check))
        return check
    return register
