import unittest

from ncaudit.redact import MASK, redact


class RedactTests(unittest.TestCase):
    def test_masks_secret_values(self) -> None:
        cases = {
            "enable password FakeEnable": f"enable password {MASK}",
            "username a privilege 15 password 0 FakeUser": f"username a privilege 15 password 0 {MASK}",
            "username a secret 9 $9$fake$hash": f"username a secret 9 {MASK}",
            " password 7 0A1B2C3D": f" password 7 {MASK}",
            "snmp-server community FakeStr RO 10": f"snmp-server community {MASK} RO 10",
            "tacacs-server key 7 0A1B2C": f"tacacs-server key 7 {MASK}",
            "crypto isakmp key FakeKey address 192.0.2.9": f"crypto isakmp key {MASK} address 192.0.2.9",
            " key-string FakeKeyString": f" key-string {MASK}",
            " ip ospf message-digest-key 1 md5 FakeMd5": f" ip ospf message-digest-key 1 md5 {MASK}",
            "password 12345": f"password {MASK}",
            "snmp-server user u1 G1 v3 auth sha FakeAuth1 priv aes 128 FakePriv1":
                f"snmp-server user u1 G1 v3 auth sha {MASK} priv aes 128 {MASK}",
            "snmp-server user u1 G1 v3 auth md5 FakeAuth1 priv des FakePriv1":
                f"snmp-server user u1 G1 v3 auth md5 {MASK} priv des {MASK}",
            "snmp-server host 192.0.2.5 FakeComm": f"snmp-server host 192.0.2.5 {MASK}",
            "snmp-server host 192.0.2.5 version 2c FakeComm": f"snmp-server host 192.0.2.5 version 2c {MASK}",
            "snmp-server host 192.0.2.5 vrf MGMT informs version 2c FakeComm udp-port 162":
                f"snmp-server host 192.0.2.5 vrf MGMT informs version 2c {MASK} udp-port 162",
            "enable secret FakePlain": f"enable secret {MASK}",
            "enable secret 5 $1$fake$hash": f"enable secret 5 {MASK}",
            # type digit kept when the value itself is absent (sanitized exports)
            "enable secret 5": "enable secret 5",
            "username u1 privilege 15 secret 4": "username u1 privilege 15 secret 4",
            " ppp chap password 7 ": f" ppp chap password 7 ",
        }
        for raw, expected in cases.items():
            with self.subTest(raw=raw):
                self.assertEqual(redact(raw), expected)

    def test_leaves_non_secrets_alone(self) -> None:
        for text in ("service password-encryption", "security passwords min-length 10",
                     "ip ssh version 2", "transport input telnet ssh", "interface GigabitEthernet0/0"):
            with self.subTest(text=text):
                self.assertEqual(redact(text), text)


if __name__ == "__main__":
    unittest.main()
