"""SNMP v1/v2c community strings. Messages never include the community value."""

from __future__ import annotations

from ncaudit.models import Severity
from ncaudit.parser import Config, Line
from ncaudit.rules.base import Hit, rule

_DEFAULT_COMMUNITIES = {"public", "private"}


def communities(config: Config) -> list[Line]:
    return config.find(r"snmp-server community\s+\S+")


def community_parts(line: Line) -> tuple[str, str | None, str | None]:
    """(community, access 'ro'/'rw' or None, ACL name or None) from
    'snmp-server community NAME [view V] [RO|RW] [ipv6 ACL] [ACL]'."""
    tokens = line.text.split()[2:]
    name, rest = tokens[0], tokens[1:]
    if len(rest) >= 2 and rest[0].lower() == "view":
        rest = rest[2:]
    access = None
    if rest and rest[0].lower() in ("ro", "rw"):
        access, rest = rest[0].lower(), rest[1:]
    if rest and rest[0].lower() == "ipv6":
        rest = rest[2:]
    return name, access, rest[0] if rest else None


@rule("SNMP-001", Severity.CRITICAL, "Default SNMP community string",
      "Replace it with a long, unique community restricted by an ACL, or migrate to SNMPv3 "
      "with authPriv.")
def default_community(config: Config):
    for line in communities(config):
        if community_parts(line)[0].lower() in _DEFAULT_COMMUNITIES:
            yield Hit(line, "The community string is a well-known default that attackers try first.")


@rule("SNMP-002", Severity.HIGH, "Read-write SNMP community",
      "Use read-only (RO) communities; perform changes through SSH or SNMPv3 with authPriv.")
def rw_community(config: Config):
    for line in communities(config):
        if community_parts(line)[1] == "rw":
            yield Hit(line, "This community grants SNMP write access, allowing configuration changes.")


@rule("SNMP-003", Severity.MEDIUM, "SNMP community without an access list",
      "Append an ACL that permits only your monitoring servers: "
      "'snmp-server community <string> RO <ACL>'.")
def community_without_acl(config: Config):
    for line in communities(config):
        if community_parts(line)[2] is None:
            yield Hit(line, "Any host that knows the community string can query the device.")
