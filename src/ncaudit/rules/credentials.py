"""Passwords, secrets and password policy. Messages never include the secret values."""

from __future__ import annotations

import re

from ncaudit.models import Severity
from ncaudit.parser import Config, Line
from ncaudit.rules.base import Hit, rule

# "... password|secret [type] value": a single type digit first, else the value itself (= type 0).
_CREDENTIAL_RE = {kw: re.compile(rf"\b{kw}\s+(\S+)", re.IGNORECASE) for kw in ("password", "secret")}
_NOT_A_PASSWORD_RE = re.compile(r"^(enable password|password encryption aes|service password)", re.IGNORECASE)
# SNMPv3 users never appear in show running-config; in a saved script the passphrases are cleartext.
_SNMPV3_USER_RE = re.compile(r"^snmp-server user\s.*\bauth\s+(md5|sha\S*)\s+\S+", re.IGNORECASE)


def credential_type(line: Line, keyword: str) -> str | None:
    """'0' (cleartext), '7', '5', ... for the password/secret on this line; None if there is none."""
    if keyword == "password" and _NOT_A_PASSWORD_RE.match(line.text):
        return None
    match = _CREDENTIAL_RE[keyword].search(line.text)
    if not match:
        return None
    first = match.group(1)
    return first if first.isdigit() and len(first) == 1 else "0"


def password_type(line: Line) -> str | None:
    return credential_type(line, "password")


@rule("AUTH-001", Severity.HIGH, "Weak or missing enable secret",
      "Remove 'enable password' and set 'enable secret' with a type 8 or 9 hash "
      "(e.g. 'enable algorithm-type scrypt secret <password>').")
def enable_secret(config: Config):
    passwords = config.find(r"enable password\b")
    for line in passwords:
        yield Hit(line, "'enable password' is stored in cleartext or with reversible type 7 encoding.")
    if not passwords and not config.find(r"enable secret\b"):
        yield Hit(None, "No 'enable secret' is configured to protect privileged EXEC mode.",
                  Severity.MEDIUM)


@rule("AUTH-002", Severity.HIGH, "Cleartext password in configuration",
      "Use 'secret' instead of 'password' (e.g. 'username <name> algorithm-type scrypt secret ...'); "
      "for line passwords prefer 'login local' or AAA.")
def cleartext_passwords(config: Config):
    for line in config.lines:
        if _SNMPV3_USER_RE.match(line.text):
            yield Hit(line, "SNMPv3 authentication/privacy passphrases are stored in cleartext in "
                            "this file.")
        elif password_type(line) == "0" or credential_type(line, "secret") == "0":
            yield Hit(line, "A password is stored in cleartext and is readable by anyone with "
                            "access to the configuration.")


@rule("AUTH-003", Severity.MEDIUM, "Reversible type 7 password",
      "Replace type 7 passwords with type 8 or 9 secrets; type 7 only hides passwords from "
      "casual viewing.")
def type7_passwords(config: Config):
    for line in config.lines:
        if password_type(line) == "7":
            yield Hit(line, "Type 7 encoding is reversible with public tools.")


@rule("AUTH-004", Severity.MEDIUM, "Weak secret hash algorithm",
      "Re-create the secret with type 8 (PBKDF2) or type 9 (scrypt): 'algorithm-type scrypt secret ...'.")
def weak_secret_hash(config: Config):
    for line in config.lines:
        kind = credential_type(line, "secret")
        if kind == "4":
            yield Hit(line, "Type 4 secrets use a flawed SHA-256 implementation and are easily cracked.",
                      Severity.HIGH)
        elif kind == "5":
            yield Hit(line, "Type 5 secrets use MD5, which is fast to brute-force.")


@rule("AUTH-005", Severity.LOW, "Password encryption service disabled",
      "Enable 'service password-encryption' so any remaining type 0 passwords are at least obscured.")
def password_encryption(config: Config):
    if not config.find(r"service password-encryption$"):
        yield Hit(None, "'service password-encryption' is not enabled.")


@rule("AUTH-006", Severity.LOW, "No minimum password length",
      "Set 'security passwords min-length 10' (or higher).")
def min_length(config: Config):
    setting = config.find(r"security passwords min-length\s+\d+")
    if not setting:
        yield Hit(None, "No minimum password length is enforced.")
    elif int(setting[-1].text.split()[-1]) < 8:
        yield Hit(setting[-1], "The minimum password length is shorter than 8 characters.")
