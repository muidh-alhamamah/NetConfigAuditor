"""Interfaces: enabled interfaces with no configuration and risky per-interface settings."""

from __future__ import annotations

from ncaudit.models import Severity
from ncaudit.parser import Config
from ncaudit.rules.base import Hit, rule

_PHYSICAL = (r"interface\s+(GigabitEthernet|FastEthernet|Ethernet|TenGigabitEthernet|TwentyFiveGigE|"
             r"FortyGigabitEthernet|HundredGigE|Serial)\S*")
# Any of these means the interface is deliberately configured for use. "ip address" covers numeric,
# dhcp, negotiated and placeholder forms; an explicit "no shutdown" never appears in
# show running-config, so in a pasted script it signals the port was enabled on purpose.
_IN_USE = (r"(ip address\s+\S|ip unnumbered\s|ipv6 address|switchport|channel-group|encapsulation|"
           r"xconnect|bridge-group|pppoe|service-instance|no shutdown$)")


# On a Layer 2 switch an interface with no configuration is still an access port in VLAN 1 and may
# well be in use; the configuration alone cannot tell, so such devices are not judged.
_SWITCHING = r"(switchport|spanning-tree\s|vlan\s+\d|interface\s+vlan\d)"


def is_switch(config: Config) -> bool:
    return bool(config.find(_SWITCHING, top_only=False))


@rule("IF-001", Severity.LOW, "Enabled router interface without configuration",
      "If the interface is not in use, disable it with 'shutdown'.")
def unconfigured_interfaces(config: Config):
    if is_switch(config):
        return
    for interface in config.find(_PHYSICAL):
        if not interface.child(r"shutdown$") and not interface.child(_IN_USE):
            yield Hit(interface, "The interface is enabled but has no IP address or other configuration "
                                 "that lets it carry traffic.")


@rule("IF-002", Severity.MEDIUM, "IP directed broadcast enabled",
      "Remove it with 'no ip directed-broadcast' on the interface.")
def directed_broadcast(config: Config):
    for interface in config.find(r"interface\s"):
        for item in interface.child(r"ip directed-broadcast\b"):
            yield Hit(item, "Directed broadcasts can be abused for smurf amplification attacks.")
