from __future__ import annotations

import textwrap
from pathlib import Path

from ncaudit.parser import Config
from ncaudit.rules import audit

FIXTURES = Path(__file__).parent / "fixtures"

# Fake values planted in the fixtures; none of them may ever appear in output.
FIXTURE_SECRETS = [
    "ExamplePlainEnable1", "ExamplePlainUser1", "0A1B2C3D4E5F", "EXAMPLEmd5HashNotReal0",
    "ExamplePlainVty1", "ExampleWriteCommunity", "EXAMPLEtype4HashNotReal", "ExampleMonitoring",
    "ExampleRO-community-Not-Real", "EXAMPLEfakeHASHvalueNotReal", "community public", "community private",
]


def config(text: str) -> Config:
    return Config(textwrap.dedent(text))


def rule_ids(text: str) -> list[str]:
    return [f.rule_id for f in audit(config(text))]


def findings_for(text: str, rule_id: str):
    return [f for f in audit(config(text)) if f.rule_id == rule_id]
