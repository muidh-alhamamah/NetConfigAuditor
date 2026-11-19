"""Interfaces: unused ports left enabled and risky per-interface settings."""

from __future__ import annotations

from ncaudit.models import Severity
from ncaudit.parser import Config
from ncaudit.rules.base import Hit, rule

_PHYSICAL = (r"interface\s+(GigabitEthernet|FastEthernet|Ethernet|TenGigabitEthernet|TwentyFiveGigE|"
             r"FortyGigabitEthernet|HundredGigE|Serial)\S*")
# Any of these means the interface is deliberately configured for use.
_IN_USE = (r"(ip address\s+\d|ip address dhcp|ipv6 address|switchport|channel-group|encapsulation|"
           r"xconnect|bridge-group|pppoe|service-instance)")


@rule("IF-001", Severity.LOW, "Unused interface not shut down",
      "Administratively disable unused ports with 'shutdown' (and place switch ports in an unused VLAN).")
def unused_interfaces(config: Config):
    for interface in config.find(_PHYSICAL):
        if not interface.child(r"shutdown$") and not interface.child(_IN_USE):
            yield Hit(interface, "Physical interface has no addressing or switching configuration "
                                 "but is enabled.")


@rule("IF-002", Severity.MEDIUM, "IP directed broadcast enabled",
      "Remove it with 'no ip directed-broadcast' on the interface.")
def directed_broadcast(config: Config):
    for interface in config.find(r"interface\s"):
        for item in interface.child(r"ip directed-broadcast\b"):
            yield Hit(item, "Directed broadcasts can be abused for smurf amplification attacks.")
