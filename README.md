# NetConfig Auditor

`ncaudit` is a command-line tool that audits saved **Cisco IOS and IOS XE** configuration files for
common security weaknesses and operational mistakes. For every finding it reports the rule, severity,
line number, reason and a recommended fix, as a readable text report or as JSON.

- **Offline and read-only**: it only reads text files you provide. It never connects to a device and
  never runs commands.
- **Secrets stay hidden**: passwords, hashes, keys and SNMP communities are masked (`******`) in
  every report.
- **No dependencies**: Python standard library only.

## Requirements

- Python 3.10 or newer (tested on Windows and Linux; pure Python, no OS-specific code).
- A configuration saved as text, e.g. the output of `show running-config` or a TFTP/SCP backup.

## Installation

```
pip install .
```

This installs the `ncaudit` command. Without installing, run it from the repository root with
`PYTHONPATH=src python -m ncaudit ...` (PowerShell: `$env:PYTHONPATH="src"; python -m ncaudit ...`).

## Usage

```
ncaudit audit router.cfg                       # text report
ncaudit audit r1.cfg r2.cfg sw1.cfg            # several files
ncaudit audit router.cfg --format json         # JSON report
ncaudit audit router.cfg --min-severity high   # only high and critical
ncaudit audit router.cfg --fail-on critical    # exit 1 only for critical findings
ncaudit rules                                  # list all rules
ncaudit --version
```

| Option | Meaning |
|---|---|
| `-f`, `--format text\|json` | report format (default `text`) |
| `-s`, `--min-severity LEVEL` | report only findings at or above `low`, `medium`, `high` or `critical` (default `low`) |
| `--fail-on LEVEL\|none` | exit with code 1 when a reported finding is at or above this level (default `low`) |

### Exit codes

| Code | Meaning |
|---|---|
| `0` | no findings at or above `--fail-on` |
| `1` | findings at or above `--fail-on` |
| `2` | invalid usage, or a file could not be audited (missing, empty, binary, not an IOS config) |

When several files are given, the valid ones are still audited if one fails; the exit code is then `2`.

### Example

Output for the fictitious switch configuration in `tests/fixtures/insecure_switch.txt`
(shortened to two findings):

```
$ ncaudit audit insecure_switch.txt --min-severity medium
== insecure_switch.txt: 7 findings (critical 1, high 2, medium 4)

[CRITICAL] SNMP-001  Default SNMP community string  (line 20)
  Evidence: snmp-server community ****** view ALL RO
  Reason:   The community string is a well-known default that attackers try first.
  Fix:      Replace it with a long, unique community restricted by an ACL, or migrate to SNMPv3 with authPriv.

[HIGH] AUTH-004  Weak secret hash algorithm  (line 6)
  Evidence: enable secret 4 ******
  Reason:   Type 4 secrets use a flawed SHA-256 implementation and are easily cracked.
  Fix:      Re-create the secret with type 8 (PBKDF2) or type 9 (scrypt): 'algorithm-type scrypt secret ...'.

...

Summary: 1 file audited, 7 findings (critical 1, high 2, medium 4)
```

### JSON output

```json
{
  "tool": "ncaudit",
  "version": "0.1.0",
  "files": [
    {
      "file": "insecure_switch.txt",
      "findings": [
        {
          "rule_id": "SNMP-001",
          "severity": "critical",
          "title": "Default SNMP community string",
          "line": 20,
          "message": "The community string is a well-known default that attackers try first.",
          "recommendation": "Replace it with a long, unique community restricted by an ACL, or migrate to SNMPv3 with authPriv.",
          "evidence": "snmp-server community ****** view ALL RO"
        }
      ],
      "summary": {"total": 1, "critical": 1, "high": 0, "medium": 0, "low": 0}
    }
  ],
  "errors": [],
  "summary": {"total": 1, "critical": 1, "high": 0, "medium": 0, "low": 0}
}
```

`line` and `evidence` are `null` when the finding is about a missing setting (for example no NTP
server). JSON is ASCII-only, so it stays valid whatever console encoding or redirection is used.

## Rules

| ID | Severity | Checks for |
|---|---|---|
| MGMT-001 | high (medium if `transport input` is unset) | Telnet allowed on VTY lines |
| MGMT-002 | medium | `ip http server` (plain-HTTP management) enabled |
| MGMT-003 | medium (high for SSHv1) | `ip ssh version 2` not configured, or SSH version 1 enabled |
| MGMT-004 | medium | VTY lines that accept remote logins without an inbound `access-class` |
| MGMT-005 | low | `exec-timeout 0 0` / `no exec-timeout` on console, AUX or VTY lines |
| MGMT-006 | critical | `no login` on a line (access without authentication) |
| AUTH-001 | high (medium if missing) | `enable password` used, or no `enable secret` at all |
| AUTH-002 | high | cleartext (type 0) passwords |
| AUTH-003 | medium | reversible type 7 passwords |
| AUTH-004 | medium (high for type 4) | weak secret hashes: type 5 (MD5) or type 4 |
| AUTH-005 | low | `service password-encryption` not enabled |
| AUTH-006 | low | no `security passwords min-length`, or shorter than 8 |
| SNMP-001 | critical | default community `public` or `private` |
| SNMP-002 | high | read-write (RW) community |
| SNMP-003 | medium | community without an access list |
| ACL-001 | high | ACL entries that permit any source (`permit any`, `permit ip any any`) |
| ACL-002 | medium | interfaces, VTY lines or SNMP communities referencing an ACL that is not defined |
| IF-001 | low | physical interfaces with no addressing or switching config that are not shut down |
| IF-002 | medium | `ip directed-broadcast` enabled on an interface |
| OPS-001 | low | missing or factory-default hostname (`Router`, `Switch`) |
| OPS-002 | low | no NTP server |
| OPS-003 | low | no remote syslog server |
| OPS-004 | medium | the same IP address on more than one interface |

Run `ncaudit rules` for the recommendation attached to each rule.

## Scope and limitations

- **Supported**: Cisco IOS and IOS XE configuration text. Banner bodies and `!` comments are ignored.
- **Not supported**: other vendors and other Cisco operating systems (NX-OS, IOS XR, ASA). These are
  rejected only if they do not look like IOS at all, so results for them are not meaningful.
- The checks are static: the tool sees only the configuration file, not the running device state,
  the software version's defaults, or the network around it. Some findings (for example a missing
  `transport input`) depend on defaults that vary by IOS version and are reported at reduced severity.
- A clean report means none of the rules above matched. It is not proof that a device is secure, and
  it does not replace a full security review or vendor hardening guides.
- Interface names must be in the full form that `show running-config` prints (e.g.
  `GigabitEthernet0/1`, not `Gi0/1`).

## Development

```
pip install -e ".[dev]"
pytest
```

Without installing anything, from the repository root:

```
PYTHONPATH=src python -m unittest discover -s tests -t tests
```

PowerShell: `$env:PYTHONPATH="src"; python -m unittest discover -s tests -t tests`

All test fixtures are fictitious: documentation IP ranges (RFC 5737), placeholder names and fake
password values.

### Adding a rule

Rules live in `src/ncaudit/rules/`. A rule is a function that receives the parsed configuration and
yields `Hit` objects; the `@rule` decorator registers it:

```python
@rule("OPS-005", Severity.LOW, "No login banner", "Configure 'banner login' with a legal notice.")
def login_banner(config):
    if not config.find(r"banner (login|motd)\b"):
        yield Hit(None, "No login or MOTD banner is configured.")
```

Add the function to an existing module (or a new module imported in `rules/__init__.py`), then add
tests. Never put secret values in a `Hit` message; evidence lines are masked automatically.

## Project layout

```
src/ncaudit/
  cli.py          argparse entry point and exit codes
  parser.py       file reading/validation and the IOS indentation tree
  rules/          audit rules, grouped by area (management, credentials, snmp, acl, interfaces, operational)
  report.py       text and JSON reports
  redact.py       secret masking
  models.py       Severity and Finding
tests/            unittest suite and fictitious fixtures
```

## License

MIT, see [LICENSE](LICENSE).
