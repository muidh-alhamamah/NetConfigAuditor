"""Severity levels and the Finding result type."""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.lower()

    @classmethod
    def parse(cls, value: str) -> Severity:
        try:
            return cls[value.upper()]
        except KeyError:
            raise ValueError(f"unknown severity: {value!r}") from None


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: Severity
    title: str
    line: int | None      # 1-based line in the config file; None when the problem is a missing setting
    message: str          # why this is a problem
    recommendation: str   # how to fix it
    evidence: str | None  # the offending config line, with secrets masked

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.label,
            "title": self.title,
            "line": self.line,
            "message": self.message,
            "recommendation": self.recommendation,
            "evidence": self.evidence,
        }
