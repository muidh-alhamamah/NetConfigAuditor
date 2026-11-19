"""Audit rules. Importing the modules below registers their rules in RULES."""

from __future__ import annotations

from ncaudit.models import Finding
from ncaudit.parser import Config
from ncaudit.rules import acl, credentials, interfaces, management, operational, snmp  # noqa: F401
from ncaudit.rules.base import RULES, Rule

__all__ = ["RULES", "Rule", "audit"]


def audit(config: Config) -> list[Finding]:
    """Run every rule; findings are sorted by severity (highest first), then line number."""
    findings = [finding for r in RULES for finding in r.run(config)]
    return sorted(findings, key=lambda f: (-f.severity, f.line or 0, f.rule_id))
