"""Access lists: overly broad permits and references to ACLs that do not exist."""

from __future__ import annotations

import re
from collections.abc import Iterator

from ncaudit.models import Severity
from ncaudit.parser import Config, Line
from ncaudit.rules.base import Hit, rule
from ncaudit.rules.snmp import communities, community_parts

# "permit any" (standard) / "permit ip any any" (extended), optionally logged, nothing narrower.
_BROAD_PERMIT_RE = re.compile(r"permit(\s+(ip|tcp|udp))?\s+any(\s+any)?(\s+log(-input)?)?$", re.IGNORECASE)


def access_entries(config: Config) -> Iterator[tuple[Line, str]]:
    """(line, entry text without ACL name or sequence number) for numbered and named ACLs."""
    for line in config.find(r"access-list\s+\S+\s+(permit|deny)\b"):
        yield line, " ".join(line.text.split()[2:])
    for block in config.find(r"ip access-list\s+(standard|extended)\s+\S+"):
        for entry in block.children:
            yield entry, re.sub(r"^\d+\s+", "", entry.text)


def defined_acls(config: Config) -> set[str]:
    names = {line.text.split()[1] for line in config.find(r"access-list\s+\S+")}
    names |= {line.text.split()[3] for line in config.find(r"ip access-list\s+(standard|extended)\s+\S+")}
    return names


@rule("ACL-001", Severity.HIGH, "Access list permits any traffic",
      "Replace the entry with permits for the specific sources, destinations and ports that are "
      "required, followed by an explicit deny.")
def broad_permit(config: Config):
    for line, entry in access_entries(config):
        if _BROAD_PERMIT_RE.match(entry):
            yield Hit(line, "This entry permits traffic from any source, which defeats the purpose "
                            "of the access list.")


@rule("ACL-002", Severity.MEDIUM, "Reference to an undefined access list",
      "Create the missing access list or correct the name; on many platforms an undefined ACL "
      "filters nothing.")
def undefined_acl(config: Config):
    defined = defined_acls(config)
    references: list[tuple[Line, str]] = []
    for block in config.find(r"(interface|line)\s"):
        for item in block.child(r"(ip access-group|access-class)\s+\S+\s+(in|out)\b"):
            tokens = item.text.split()  # "ip access-group NAME in" / "access-class NAME in [vrf-also]"
            references.append((item, tokens[2] if tokens[0].lower() == "ip" else tokens[1]))
    for line in communities(config):
        acl = community_parts(line)[2]
        if acl:
            references.append((line, acl))
    for line, name in references:
        if name not in defined:
            yield Hit(line, f"Access list '{name}' is referenced but not defined in this configuration.")
