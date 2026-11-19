import unittest

from helpers import FIXTURES, findings_for, rule_ids

from ncaudit.models import Severity
from ncaudit.parser import read_config
from ncaudit.rules import RULES, audit

# A clean baseline: rules about missing global settings stay quiet, so each test sees only its rule.
BASE = """\
hostname EXAMPLE-R1
service password-encryption
security passwords min-length 12
enable secret 9 $9$fake$fake
ip ssh version 2
logging host 198.51.100.50
ntp server 198.51.100.123
"""


def ids(extra: str) -> list[str]:
    return rule_ids(BASE + extra)


class RegistryTests(unittest.TestCase):
    def test_rules_are_unique_and_documented(self) -> None:
        self.assertEqual(len({r.id for r in RULES}), len(RULES))
        self.assertGreaterEqual(len(RULES), 20)
        for r in RULES:
            self.assertTrue(r.title and r.recommendation, r.id)

    def test_baseline_is_clean(self) -> None:
        self.assertEqual(ids(""), [])


class FixtureTests(unittest.TestCase):
    def test_secure_config_has_no_findings(self) -> None:
        self.assertEqual(audit(read_config(FIXTURES / "secure_router.txt")), [])

    def test_insecure_router(self) -> None:
        found = {f.rule_id for f in audit(read_config(FIXTURES / "insecure_router.txt"))}
        expected = {"MGMT-001", "MGMT-002", "MGMT-003", "MGMT-004", "MGMT-005", "MGMT-006",
                    "AUTH-001", "AUTH-002", "AUTH-003", "AUTH-004", "AUTH-005", "AUTH-006",
                    "SNMP-001", "SNMP-002", "SNMP-003", "ACL-001", "ACL-002", "IF-001", "IF-002",
                    "OPS-001", "OPS-002", "OPS-003", "OPS-004"}
        self.assertEqual(found, expected)

    def test_findings_sorted_by_severity_then_line(self) -> None:
        findings = audit(read_config(FIXTURES / "insecure_router.txt"))
        keys = [(-f.severity, f.line or 0) for f in findings]
        self.assertEqual(keys, sorted(keys))


class ManagementTests(unittest.TestCase):
    def test_telnet(self) -> None:
        self.assertIn("MGMT-001", ids("line vty 0 4\n transport input telnet ssh\n"))
        self.assertIn("MGMT-001", ids("line vty 0 4\n transport input all\n"))
        self.assertNotIn("MGMT-001", ids("line vty 0 4\n transport input ssh\n"))
        [f] = findings_for(BASE + "line vty 0 4\n login local\n", "MGMT-001")
        self.assertEqual(f.severity, Severity.MEDIUM)  # transport not set: default may allow telnet

    def test_http_server(self) -> None:
        self.assertIn("MGMT-002", ids("ip http server\n"))
        self.assertNotIn("MGMT-002", ids("no ip http server\nip http secure-server\n"))

    def test_ssh_version(self) -> None:
        [f] = findings_for(BASE.replace("ip ssh version 2", "ip ssh version 1"), "MGMT-003")
        self.assertEqual((f.severity, f.line), (Severity.HIGH, 5))
        [f] = findings_for(BASE.replace("ip ssh version 2\n", ""), "MGMT-003")
        self.assertEqual((f.severity, f.line), (Severity.MEDIUM, None))

    def test_access_class(self) -> None:
        self.assertIn("MGMT-004", ids("line vty 0 4\n transport input ssh\n"))
        self.assertNotIn("MGMT-004", ids("line vty 0 4\n access-class MGMT in\n transport input ssh\n"))
        self.assertNotIn("MGMT-004", ids("line vty 5 15\n transport input none\n"))

    def test_exec_timeout(self) -> None:
        for setting in ("exec-timeout 0 0", "exec-timeout 0", "no exec-timeout"):
            with self.subTest(setting=setting):
                self.assertIn("MGMT-005", ids(f"line con 0\n {setting}\n"))
        self.assertNotIn("MGMT-005", ids("line con 0\n exec-timeout 0 30\n"))
        self.assertNotIn("MGMT-005", ids("line con 0\n exec-timeout 10 0\n"))

    def test_no_login(self) -> None:
        [f] = findings_for(BASE + "line aux 0\n no login\n", "MGMT-006")
        self.assertEqual(f.severity, Severity.CRITICAL)


class CredentialTests(unittest.TestCase):
    def test_enable(self) -> None:
        self.assertIn("AUTH-001", ids("enable password 7 0A1B2C\n"))
        [f] = findings_for(BASE.replace("enable secret 9 $9$fake$fake\n", ""), "AUTH-001")
        self.assertEqual((f.severity, f.line), (Severity.MEDIUM, None))

    def test_password_types(self) -> None:
        self.assertEqual(ids("username u1 privilege 15 password 0 FakePass\n"), ["AUTH-002"])
        self.assertEqual(ids("line vty 0 4\n password FakePass\n transport input ssh\n access-class A in\n"
                             "access-list A permit 198.51.100.1\n"), ["AUTH-002"])
        self.assertEqual(ids("username u1 password 7 0A1B2C\n"), ["AUTH-003"])
        self.assertEqual(ids("username u1 secret 9 $9$fake$fake\n"), [])

    def test_untyped_secret_is_cleartext(self) -> None:
        # Saved CLI scripts contain "secret <value>" as typed; IOS hashes it only when applied.
        self.assertEqual(rule_ids(BASE.replace("enable secret 9 $9$fake$fake", "enable secret FakePlain1")), ["AUTH-002"])
        self.assertEqual(ids("username u1 privilege 15 secret FakePlain1\n"), ["AUTH-002"])
        self.assertEqual(ids("username u1 algorithm-type scrypt secret FakePlain1\n"), ["AUTH-002"])
        self.assertEqual(ids("username u1 secret 0 FakePlain1\n"), ["AUTH-002"])

    def test_snmpv3_user_passphrases(self) -> None:
        [f] = findings_for(BASE + "snmp-server user u1 G1 v3 auth sha FakeAuth1 priv aes 128 FakePriv1\n", "AUTH-002")
        self.assertIn("SNMPv3", f.message)
        self.assertNotIn("FakeAuth1", f.evidence + f.message)
        self.assertNotIn("FakePriv1", f.evidence)
        self.assertEqual(ids("snmp-server group G1 v3 priv\nsnmp-server user u1 G1 v3\n"), [])

    def test_type_digit_without_value(self) -> None:
        # Sanitized exports sometimes drop the value; the type digit alone still identifies the format.
        [f] = findings_for(BASE + "username u1 secret 5\n", "AUTH-004")
        self.assertEqual(f.severity, Severity.MEDIUM)
        self.assertEqual(ids("username u1 password 7\n"), ["AUTH-003"])

    def test_not_passwords(self) -> None:
        self.assertEqual(ids("password encryption aes\n"), [])

    def test_weak_hashes(self) -> None:
        [f] = findings_for(BASE + "username u1 secret 5 $1$fake$fake\n", "AUTH-004")
        self.assertEqual(f.severity, Severity.MEDIUM)
        [f] = findings_for(BASE.replace("secret 9", "secret 4"), "AUTH-004")
        self.assertEqual(f.severity, Severity.HIGH)

    def test_password_policy(self) -> None:
        self.assertIn("AUTH-005", rule_ids(BASE.replace("service password-encryption\n", "")))
        self.assertIn("AUTH-006", rule_ids(BASE.replace("min-length 12", "min-length 6")))
        self.assertNotIn("AUTH-006", rule_ids(BASE.replace("min-length 12", "min-length 8")))


class SnmpTests(unittest.TestCase):
    def test_default_and_rw(self) -> None:
        self.assertEqual(sorted(ids("access-list 5 permit 198.51.100.9\nsnmp-server community public RO 5\n")),
                         ["SNMP-001"])
        self.assertEqual(sorted(ids("access-list 5 permit 198.51.100.9\nsnmp-server community Fake-Str RW 5\n")),
                         ["SNMP-002"])

    def test_acl_detection(self) -> None:
        self.assertEqual(ids("snmp-server community Fake-Str RO\n"), ["SNMP-003"])
        self.assertEqual(ids("ip access-list standard NMS\n permit 198.51.100.9\n"
                             "snmp-server community Fake-Str view V1 RO NMS\n"), [])
        self.assertEqual(ids("snmp-server community Fake-Str view V1 RO\n"), ["SNMP-003"])


class AclTests(unittest.TestCase):
    def test_broad_permits(self) -> None:
        for entry in ("access-list 101 permit ip any any", "access-list 10 permit any",
                      "access-list 101 permit ip any any log",
                      "ip access-list extended X\n 10 permit ip any any"):
            with self.subTest(entry=entry):
                self.assertIn("ACL-001", ids(entry + "\n"))

    def test_narrow_entries_ok(self) -> None:
        for entry in ("access-list 101 permit tcp any host 192.0.2.1 eq 22",
                      "access-list 101 permit icmp any any", "access-list 101 deny ip any any",
                      "access-list 10 permit 198.51.100.0 0.0.0.255"):
            with self.subTest(entry=entry):
                self.assertNotIn("ACL-001", ids(entry + "\n"))

    def test_undefined_references(self) -> None:
        self.assertEqual(ids("interface GigabitEthernet0/0\n ip address 192.0.2.1 255.255.255.0\n"
                             " ip access-group NOPE in\n"), ["ACL-002"])
        self.assertEqual(ids("line vty 0 4\n access-class 99 in vrf-also\n transport input ssh\n"), ["ACL-002"])
        self.assertEqual(ids("access-list 99 permit 198.51.100.1\nline vty 0 4\n access-class 99 in\n"
                             " transport input ssh\n"), [])


class InterfaceAndOpsTests(unittest.TestCase):
    def test_unused_interface(self) -> None:
        self.assertIn("IF-001", ids("interface GigabitEthernet0/3\n description spare\n"))
        for body in (" shutdown", " ip address 192.0.2.9 255.255.255.0", " switchport mode access",
                     " channel-group 1 mode active", " ip address negotiated", " ip address dhcp",
                     " ip unnumbered Loopback0", " ip address X.X.X.X X.X.X.X", " no shutdown"):
            with self.subTest(body=body):
                self.assertNotIn("IF-001", ids(f"interface GigabitEthernet0/3\n{body}\n"))
        self.assertNotIn("IF-001", ids("interface Loopback1\n"))

    def test_directed_broadcast(self) -> None:
        self.assertIn("IF-002", ids("interface Vlan1\n ip directed-broadcast\n"))
        self.assertNotIn("IF-002", ids("interface Vlan1\n no ip directed-broadcast\n"))

    def test_global_hygiene(self) -> None:
        self.assertIn("OPS-001", rule_ids(BASE.replace("EXAMPLE-R1", "Switch")))
        self.assertIn("OPS-001", rule_ids(BASE.replace("hostname EXAMPLE-R1\n", "")))
        self.assertIn("OPS-002", rule_ids(BASE.replace("ntp server 198.51.100.123\n", "")))
        self.assertIn("OPS-003", rule_ids(BASE.replace("logging host 198.51.100.50\n", "logging buffered 8192\n")))
        self.assertNotIn("OPS-003", rule_ids(BASE.replace("logging host 198.51.100.50", "logging 198.51.100.50")))

    def test_duplicate_ip(self) -> None:
        [f] = findings_for(BASE + "interface Vlan1\n ip address 192.0.2.1 255.255.255.0\n"
                                  "interface Vlan2\n ip address 192.0.2.1 255.255.255.0\n", "OPS-004")
        self.assertIn("Vlan1", f.message)
        self.assertEqual(ids("interface Vlan1\n ip address 192.0.2.1 255.255.255.0\n"
                             "interface Vlan2\n ip address 192.0.2.2 255.255.255.0\n"), [])


if __name__ == "__main__":
    unittest.main()
