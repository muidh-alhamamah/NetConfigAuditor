import os
import tempfile
import unittest
from pathlib import Path

from helpers import FIXTURES, config

from ncaudit.errors import ConfigError
from ncaudit.parser import read_config


class TreeTests(unittest.TestCase):
    def test_children_and_line_numbers(self) -> None:
        c = config("""\
            hostname R1
            !
            interface GigabitEthernet0/0
             description uplink
             ip address 192.0.2.1 255.255.255.0
            line vty 0 4
             transport input ssh
            """)
        self.assertEqual([l.text for l in c.top], ["hostname R1", "interface GigabitEthernet0/0", "line vty 0 4"])
        interface = c.top[1]
        self.assertEqual(interface.number, 3)
        self.assertEqual([(l.number, l.text) for l in interface.children],
                         [(4, "description uplink"), (5, "ip address 192.0.2.1 255.255.255.0")])
        self.assertEqual(len(c.lines), 6)  # the "!" comment is dropped

    def test_nested_children(self) -> None:
        c = config("""\
            router bgp 65000
             address-family ipv4
              network 192.0.2.0
            """)
        self.assertEqual(c.top[0].children[0].children[0].text, "network 192.0.2.0")

    def test_banner_body_is_skipped(self) -> None:
        for banner in ("banner motd ^C\nip http server\n^C", "banner login #\nno login\n#",
                       "banner exec \x03\nip http server\n\x03"):
            with self.subTest(banner=banner[:15]):
                c = config(f"hostname R1\n{banner}\nip ssh version 2\n")
                self.assertEqual([l.text.split()[0] for l in c.top], ["hostname", "banner", "ip"])
                self.assertEqual(c.top[2].number, 5)

    def test_single_line_banner(self) -> None:
        c = config("banner motd #Authorized only#\nhostname R1\n")
        self.assertEqual(len(c.top), 2)

    def test_crlf_and_find_is_case_insensitive(self) -> None:
        c = config("Hostname R1\r\nIP HTTP SERVER\r\n")
        self.assertEqual(len(c.find(r"ip http server$")), 1)


class ReadConfigTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def write(self, name: str, data: bytes) -> Path:
        path = Path(self.tmp.name, name)
        path.write_bytes(data)
        return path

    def assertConfigError(self, path, message: str) -> None:
        with self.assertRaises(ConfigError) as ctx:
            read_config(path)
        self.assertIn(message, str(ctx.exception))

    def test_fixture_loads(self) -> None:
        self.assertGreater(len(read_config(FIXTURES / "secure_router.txt").top), 10)

    def test_bad_inputs(self) -> None:
        self.assertConfigError(Path(self.tmp.name, "missing.txt"), "file not found")
        self.assertConfigError(Path(self.tmp.name), "is a directory")
        self.assertConfigError(self.write("empty.txt", b""), "file is empty")
        self.assertConfigError(self.write("blank.txt", b"  \n\n\t\n"), "file is empty")
        self.assertConfigError(self.write("bin.cfg", b"hostname R1\x00\x01\x02"), "binary file")
        self.assertConfigError(self.write("notes.txt", b"shopping list\nmilk\n"), "does not look like")
        self.assertConfigError(self.write("comments.txt", b"!\n! only comments\n!\n"), "does not look like")

    def test_unsupported_platforms_rejected(self) -> None:
        samples = {
            "FortiOS": b"#config-version=FGT60F-7.2.5-FW-build1517:opmode=0\nconfig system global\n"
                       b"    set hostname EXAMPLE-FGT\nend\nconfig system interface\n    edit port1\n    next\nend\n",
            "FortiOS (no header)": b"config system global\n    set admin-sport 443\nend\n",
            "Cisco ASA": b": Saved\n:\nASA Version 9.16(4)\n!\nhostname EXAMPLE-ASA\ninterface GigabitEthernet0/0\n",
            "Cisco NX-OS": b"version 9.3(8) Bios:version 05.45\nhostname EXAMPLE-N9K\nfeature ospf\ninterface Ethernet1/1\n",
            "Cisco IOS XR": b"!! IOS XR Configuration 7.3.2\nhostname EXAMPLE-XR\ninterface GigabitEthernet0/0/0/0\n",
            "Juniper Junos": b"set system host-name EXAMPLE-MX\nset interfaces ge-0/0/0 unit 0 family inet\n",
        }
        for name, data in samples.items():
            expected = name.split(" (")[0]
            with self.subTest(platform=name):
                self.assertConfigError(self.write("cfg.txt", data), f"{expected}")
                self.assertConfigError(self.write("cfg.txt", data), "not supported (only Cisco IOS / IOS XE)")

    def test_end_alone_is_not_ios(self) -> None:
        self.assertConfigError(self.write("x.txt", b"something else\n    with lines\nend\n"), "does not look like")

    def test_too_large(self) -> None:
        path = self.write("big.txt", b"hostname R1\n")
        with unittest.mock.patch("ncaudit.parser.MAX_FILE_BYTES", 5):
            self.assertConfigError(path, "larger than")

    def test_latin1_and_bom(self) -> None:
        self.assertEqual(read_config(self.write("l1.txt", "hostname R\xe9\n".encode("latin-1"))).top[0].text, "hostname R\xe9")
        self.assertEqual(read_config(self.write("bom.txt", b"\xef\xbb\xbfhostname R1\n")).top[0].text, "hostname R1")

    @unittest.skipIf(os.name == "nt", "POSIX permissions")
    def test_permission_denied(self) -> None:
        path = self.write("locked.txt", b"hostname R1\n")
        path.chmod(0)
        self.addCleanup(path.chmod, 0o600)
        if os.access(path, os.R_OK):  # running as root
            self.skipTest("root can read any file")
        self.assertConfigError(path, "permission denied")


import unittest.mock  # noqa: E402  (used via unittest.mock.patch above)

if __name__ == "__main__":
    unittest.main()
