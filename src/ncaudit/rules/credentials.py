"""Passwords, secrets and password policy. Messages never include the secret values."""

from __future__ import annotations

import re

from ncaudit.models import Severity
from ncaudit.parser import Config, Line
from ncaudit.rules.base import Hit, rule

# "... password [type] value": type 0 or no type = cleartext, 7 = reversible encoding.
_PASSWORD_RE = re.compile(r"\bpassword\s+(\S+)(\s+\S+)?", re.IGNORECASE)
_NOT_A_PASSWORD_RE = re.compile(r"^(enable password|password encryption aes|service password)", re.IGNORECASE)


def password_type(line: Line) -> str | None:
    """'0' (cleartext), '7' (reversible) or another type digit; None if the line holds no password."""
    if _NOT_A_PASSWORD_RE.match(line.text):
        return None
    match = _PASSWORD_RE.search(line.text)
    if not match:
        return None
    first, value = match.group(1), match.group(2)
    return first if value and first.isdigit() and len(first) == 1 else "0"


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
        if password_type(line) == "0":
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
        match = re.search(r"\bsecret\s+([45])\s+\S+", line.text, re.IGNORECASE)
        if match and match.group(1) == "4":
            yield Hit(line, "Type 4 secrets use a flawed SHA-256 implementation and are easily cracked.",
                      Severity.HIGH)
        elif match:
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
