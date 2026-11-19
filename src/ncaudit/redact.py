"""Mask secrets (passwords, hashes, keys, SNMP communities) before any text leaves the tool."""

from __future__ import annotations

import re

MASK = "******"

_KEYWORDS = r"password|secret|key-string|key|community|pre-shared-key|psk|authentication-key|md5"
# keyword [type digit] value  ->  keyword [type digit] ******
# The keyword must be a whole word (so "message-digest-key" is not "key"), and the value must not
# itself be a keyword ("... key 1 md5 VALUE" masks VALUE through "md5"). A lone trailing digit is the
# type of a value that is absent (sanitized exports), so it stays visible: "secret 5" is not a secret.
_SECRET_RE = re.compile(
    rf"(?<![\w-])({_KEYWORDS})(\s+\d{{1,2}})?(\s+)(?!(?:{_KEYWORDS})(?:\s|$))(?!\d\s*$)(\S+)",
    re.IGNORECASE,
)


# SNMPv3: "... auth sha VALUE priv aes 128 VALUE"
_SNMPV3_RE = re.compile(r"\b((?:auth\s+(?:md5|sha\S*)|priv\s+(?:3des|des\S*|aes(?:\s+\d+)?))\s+)(\S+)",
                        re.IGNORECASE)
# The community (or v3 user) in
# "snmp-server host ADDR [vrf NAME] [informs|traps] [version 1|2c|3 LEVEL] VALUE ..."
_SNMP_HOST_RE = re.compile(
    r"^(snmp-server host\s+\S+(?:\s+vrf\s+\S+)?(?:\s+(?:informs|traps))?(?:\s+version\s+(?:1|2c|3\s+\S+))?\s+)(\S+)",
    re.IGNORECASE,
)


def redact(text: str) -> str:
    text = _SNMP_HOST_RE.sub(lambda m: f"{m.group(1)}{MASK}", text)
    text = _SNMPV3_RE.sub(lambda m: f"{m.group(1)}{MASK}", text)
    return _SECRET_RE.sub(lambda m: f"{m.group(1)}{m.group(2) or ''}{m.group(3)}{MASK}", text)
