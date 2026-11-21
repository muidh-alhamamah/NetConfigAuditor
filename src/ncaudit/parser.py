"""Parse a Cisco IOS / IOS XE text configuration into an indentation tree.

IOS nests sub-commands by leading spaces ("interface X" -> " ip address ..."). Comment lines ("!"),
blank lines and banner bodies are dropped so rules never match text inside a banner.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from ncaudit.errors import ConfigError

MAX_FILE_BYTES = 10 * 1024 * 1024

_BANNER_RE = re.compile(r"^banner\s+\S+\s*(.*)$", re.IGNORECASE)
# At least one of these top-level commands must appear for a file to count as an IOS config.
# ("end" is deliberately not a marker: FortiOS and other syntaxes use it too.)
_IOS_MARKER_RE = re.compile(
    r"^(version|hostname|interface|line|router|service|enable|username|aaa|ip|ipv6|"
    r"access-list|snmp-server|logging|ntp|crypto|boot|vlan|spanning-tree|banner)\b",
    re.IGNORECASE,
)
# Syntax that identifies another platform; checked first so the error can name it.
_UNSUPPORTED_PLATFORMS = [
    ("FortiOS (Fortinet FortiGate)", re.compile(r"^(#config-version=|config (system|firewall|router|vpn|user|log)\b)", re.M)),
    ("Cisco ASA", re.compile(r"^(: Saved|(ASA|PIX) Version )", re.M)),
    ("Cisco NX-OS", re.compile(r"^(feature \S+|boot nxos )", re.M)),
    ("Cisco IOS XR", re.compile(r"^!! IOS XR", re.M)),
    ("Juniper Junos", re.compile(r"^(set (system|interfaces|protocols) |(system|interfaces|protocols) \{)", re.M)),
]


@dataclass(eq=False)
class Line:
    number: int
    text: str
    indent: int
    children: list[Line] = field(default_factory=list)

    def child(self, pattern: str) -> list[Line]:
        """Direct children whose text matches the regex (anchored at the start, case-insensitive)."""
        rx = re.compile(pattern, re.IGNORECASE)
        return [c for c in self.children if rx.match(c.text)]


class Config:
    def __init__(self, text: str) -> None:
        self.lines: list[Line] = []  # every config line in file order
        self.top: list[Line] = []    # top-level lines (their sub-commands are in .children)
        stack: list[Line] = []
        banner_end: str | None = None
        for number, raw in enumerate(text.splitlines(), 1):
            if banner_end is not None:
                if banner_end in raw:
                    banner_end = None
                continue
            stripped = raw.strip()
            if not stripped or stripped.startswith("!"):
                continue
            line = Line(number, stripped, len(raw) - len(raw.lstrip()))
            while stack and stack[-1].indent >= line.indent:
                stack.pop()
            (stack[-1].children if stack else self.top).append(line)
            stack.append(line)
            self.lines.append(line)
            banner_end = _banner_delimiter(stripped)

    def find(self, pattern: str, top_only: bool = True) -> list[Line]:
        """Lines whose text matches the regex (anchored at the start, case-insensitive)."""
        rx = re.compile(pattern, re.IGNORECASE)
        return [line for line in (self.top if top_only else self.lines) if rx.match(line.text)]


def _banner_delimiter(text: str) -> str | None:
    """For a multi-line banner start, return the delimiter that ends it; else None."""
    match = _BANNER_RE.match(text)
    if not match or not match.group(1):
        return None
    rest = match.group(1)
    delimiter = "^C" if rest.startswith("^C") else rest[0]
    body = rest[len(delimiter):]
    return None if delimiter in body else delimiter


def read_config(path: str | Path) -> Config:
    """Read and parse a config file, raising ConfigError with a clear message on bad input."""
    path = Path(path)
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            raise ConfigError(f"file is larger than {MAX_FILE_BYTES // (1024 * 1024)} MB")
        data = path.read_bytes()
    except FileNotFoundError:
        raise ConfigError("file not found") from None
    except IsADirectoryError:
        raise ConfigError("is a directory, not a file") from None
    except PermissionError:
        # Windows reports reading a directory as PermissionError too.
        raise ConfigError(f"{'is a directory, not a file' if path.is_dir() else 'permission denied'}") from None
    except OSError as exc:
        raise ConfigError(f"cannot read file ({exc.strerror or exc})") from None
    if b"\x00" in data:
        raise ConfigError("binary file, not a text configuration")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        text = data.decode("latin-1")  # never fails; old configs are often Latin-1
    if not text.strip():
        raise ConfigError("file is empty")
    for platform, signature in _UNSUPPORTED_PLATFORMS:
        if signature.search(text):
            raise ConfigError(f"{platform} configuration is not supported (only Cisco IOS / IOS XE)")
    config = Config(text)
    if not any(_IOS_MARKER_RE.match(line.text) for line in config.top):
        raise ConfigError("does not look like a Cisco IOS configuration")
    return config
