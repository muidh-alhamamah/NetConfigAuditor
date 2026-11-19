"""Management-plane access: Telnet, HTTP, SSH, VTY/console line protection."""

from __future__ import annotations

import re

from ncaudit.models import Severity
from ncaudit.parser import Config, Line
from ncaudit.rules.base import Hit, rule


def vty_lines(config: Config) -> list[Line]:
    return config.find(r"line vty\b")


def remote_access_enabled(vty: Line) -> bool:
    transport = vty.child(r"transport input\b")
    return not (transport and transport[-1].text.split()[-1].lower() == "none")


@rule("MGMT-001", Severity.HIGH, "Telnet allowed on VTY lines",
      "Allow only SSH on every VTY line: 'transport input ssh'.")
def telnet_on_vty(config: Config):
    for vty in vty_lines(config):
        transport = vty.child(r"transport input\b")
        if not transport:
            yield Hit(vty, "No 'transport input' is set; depending on the IOS version the default "
                           "accepts Telnet.", Severity.MEDIUM)
        elif re.search(r"\b(telnet|all)\b", transport[-1].text, re.IGNORECASE):
            yield Hit(transport[-1], "VTY lines accept Telnet, which sends credentials and session "
                                     "data in cleartext.")


@rule("MGMT-002", Severity.MEDIUM, "HTTP management server enabled",
      "Disable it with 'no ip http server'; if web management is required, use "
      "'ip http secure-server' restricted by an access list.")
def http_server(config: Config):
    for line in config.find(r"ip http server$"):
        yield Hit(line, "The plain-HTTP management interface is enabled and sends credentials "
                        "unencrypted.")


@rule("MGMT-003", Severity.MEDIUM, "SSH version 2 not enforced",
      "Configure 'ip ssh version 2' (after generating an RSA key of at least 2048 bits).")
def ssh_version(config: Config):
    versions = config.find(r"ip ssh version\b")
    if versions and versions[-1].text.split()[-1] == "1":
        yield Hit(versions[-1], "SSH version 1 is enabled; it has known cryptographic weaknesses.",
                  Severity.HIGH)
    elif not versions:
        yield Hit(None, "'ip ssh version 2' is not configured, so the device may also accept "
                        "SSH version 1 clients.")


@rule("MGMT-004", Severity.MEDIUM, "VTY lines without an access-class",
      "Restrict remote management to trusted sources: 'access-class <ACL> in' on every VTY line.")
def vty_access_class(config: Config):
    for vty in vty_lines(config):
        if remote_access_enabled(vty) and not vty.child(r"access-class\s+\S+\s+in\b"):
            yield Hit(vty, "Any IP address can reach the login prompt on these VTY lines.")


@rule("MGMT-005", Severity.LOW, "Idle session timeout disabled",
      "Set an idle timeout on console and VTY lines, e.g. 'exec-timeout 10 0'.")
def exec_timeout(config: Config):
    for line in config.find(r"line (vty|con|console|aux)\b"):
        for timeout in line.child(r"(exec-timeout 0( 0)?|no exec-timeout)$"):
            yield Hit(timeout, "Idle management sessions never time out.")


@rule("MGMT-006", Severity.CRITICAL, "Line access without authentication",
      "Remove 'no login' and use 'login local' or AAA ('login authentication <list>').")
def no_login(config: Config):
    for line in config.find(r"line (vty|con|console|aux)\b"):
        for item in line.child(r"no login$"):
            yield Hit(item, "'no login' gives access to this line without any authentication.")
