"""Operational hygiene: identity, time, logging and addressing mistakes."""

from __future__ import annotations

from ncaudit.models import Severity
from ncaudit.parser import Config
from ncaudit.rules.base import Hit, rule


@rule("OPS-001", Severity.LOW, "Default or missing hostname",
      "Set a unique, descriptive hostname: 'hostname <name>'.")
def hostname(config: Config):
    names = config.find(r"hostname\s+\S+")
    if not names:
        yield Hit(None, "No hostname is configured.")
    elif names[-1].text.split()[1].lower() in ("router", "switch"):
        yield Hit(names[-1], "The device still uses the factory-default hostname.")


@rule("OPS-002", Severity.LOW, "No NTP server configured",
      "Configure at least one NTP server ('ntp server <address>') so logs carry accurate timestamps.")
def ntp(config: Config):
    if not config.find(r"ntp server\s"):
        yield Hit(None, "Without NTP, log and event timestamps drift and are hard to correlate.")


@rule("OPS-003", Severity.LOW, "No remote syslog server",
      "Send logs to a central server: 'logging host <address>'.")
def remote_logging(config: Config):
    if not config.find(r"logging\s+(host\s+\S|\d)"):
        yield Hit(None, "Logs stay only on the device and are lost on reload or tampering.")


@rule("OPS-004", Severity.MEDIUM, "Duplicate interface IP address",
      "Assign each interface a unique IP address.")
def duplicate_ip(config: Config):
    seen: dict[str, tuple[str, int]] = {}
    for interface in config.find(r"interface\s"):
        for item in interface.child(r"ip address\s+\d"):
            address = item.text.split()[2]
            if address in seen:
                name, number = seen[address]
                yield Hit(item, f"IP address {address} is also configured on {name} (line {number}).")
            else:
                seen[address] = (interface.text.split(None, 1)[1], item.number)
