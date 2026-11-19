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
