"""Mask secrets (passwords, hashes, keys, SNMP communities) before any text leaves the tool."""

from __future__ import annotations

import re

MASK = "******"

_KEYWORDS = r"password|secret|key-string|key|community|pre-shared-key|psk|authentication-key|md5"
# keyword [type digit] value  ->  keyword [type digit] ******
# The keyword must be a whole word (so "message-digest-key" is not "key"), and the value must not
# itself be a keyword ("... key 1 md5 VALUE" masks VALUE through "md5").
_SECRET_RE = re.compile(
    rf"(?<![\w-])({_KEYWORDS})(\s+\d{{1,2}})?(\s+)(?!(?:{_KEYWORDS})(?:\s|$))(\S+)",
    re.IGNORECASE,
)


def redact(text: str) -> str:
    return _SECRET_RE.sub(lambda m: f"{m.group(1)}{m.group(2) or ''}{m.group(3)}{MASK}", text)
