import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from helpers import FIXTURE_SECRETS, FIXTURES

from ncaudit import __version__
from ncaudit.cli import main

SECURE = str(FIXTURES / "secure_router.txt")
ROUTER = str(FIXTURES / "insecure_router.txt")
SWITCH = str(FIXTURES / "insecure_switch.txt")


def run(*argv: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = main(list(argv))
        except SystemExit as exc:  # argparse --help / --version / usage errors
            code = int(exc.code or 0)
    return code, out.getvalue(), err.getvalue()


class AuditCommandTests(unittest.TestCase):
    def test_secure_config(self) -> None:
        code, out, err = run("audit", SECURE)
        self.assertEqual((code, err), (0, ""))
        self.assertIn("0 findings", out)

    def test_text_report(self) -> None:
        code, out, _ = run("audit", ROUTER)
        self.assertEqual(code, 1)
        self.assertIn("25 findings (critical 2, high 7, medium 9, low 7)", out)
        self.assertIn("[CRITICAL] SNMP-001  Default SNMP community string  (line 28)", out)
        self.assertIn("  Evidence: snmp-server community ****** RO", out)
        self.assertIn("(not configured)", out)
        self.assertIn("Summary: 1 file audited, 25 findings", out)

    def test_json_report(self) -> None:
        code, out, _ = run("audit", ROUTER, SWITCH, "--format", "json")
        self.assertEqual(code, 1)
        report = json.loads(out)
        self.assertEqual((report["tool"], report["version"], report["errors"]), ("ncaudit", __version__, []))
        self.assertEqual([f["file"] for f in report["files"]], [ROUTER, SWITCH])
        self.assertEqual(report["summary"]["total"], 33)  # switch fixture: IF-001 not judged on switches
        finding = report["files"][0]["findings"][0]
        self.assertEqual(set(finding), {"rule_id", "severity", "title", "line", "message", "recommendation", "evidence"})
        out.encode("ascii")  # ASCII-only JSON

    def test_secrets_never_printed(self) -> None:
        for fmt in ("text", "json"):
            _, out, err = run("audit", ROUTER, SWITCH, SECURE, "-f", fmt)
            for secret in FIXTURE_SECRETS:
                with self.subTest(fmt=fmt, secret=secret):
                    self.assertNotIn(secret, out + err)

    def test_min_severity_and_fail_on(self) -> None:
        _, out, _ = run("audit", ROUTER, "-f", "json", "--min-severity", "critical")
        self.assertEqual({f["severity"] for f in json.loads(out)["files"][0]["findings"]}, {"critical"})
        self.assertEqual(run("audit", SWITCH, "--fail-on", "critical")[0], 1)
        self.assertEqual(run("audit", SWITCH, "-s", "high", "--fail-on", "critical")[0], 1)
        self.assertEqual(run("audit", ROUTER, "--fail-on", "none")[0], 0)
        _, out, _ = run("audit", SECURE, "-s", "high")
        self.assertIn("0 findings", out)

    def test_input_errors_exit_2_and_continue(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            empty = Path(tmp, "empty.txt")
            empty.write_bytes(b"")
            code, out, err = run("audit", str(empty), ROUTER, str(Path(tmp, "missing.txt")), "-f", "json")
        self.assertEqual(code, 2)
        report = json.loads(out)
        self.assertEqual([e["error"] for e in report["errors"]], ["file is empty", "file not found"])
        self.assertEqual(report["summary"]["total"], 25)  # the valid file was still audited
        self.assertIn("ncaudit: error:", err)
        self.assertIn("empty.txt: file is empty", err)

    def test_unsupported_platform_exit_2(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            forti = Path(tmp, "fgt.conf")
            forti.write_bytes(b"config system global\n    set hostname EXAMPLE-FGT\nend\n")
            code, out, err = run("audit", str(forti), "-f", "json")
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(out)["errors"][0]["error"],
                         "FortiOS (Fortinet FortiGate) configuration is not supported (only Cisco IOS / IOS XE)")
        self.assertIn("fgt.conf: FortiOS (Fortinet FortiGate) configuration is not supported", err)

    def test_text_error_entry(self) -> None:
        code, out, _ = run("audit", "definitely-missing.cfg")
        self.assertEqual(code, 2)
        self.assertIn("== definitely-missing.cfg: ERROR: file not found", out)
        self.assertIn("0 files audited, 0 findings, 1 error(s)", out)


class UsageTests(unittest.TestCase):
    def test_usage_errors(self) -> None:
        for argv in ((), ("audit",), ("audit", SECURE, "-s", "severe"), ("audit", SECURE, "-f", "xml"), ("scan",)):
            with self.subTest(argv=argv):
                self.assertEqual(run(*argv)[0], 2)

    def test_version_and_help(self) -> None:
        code, out, _ = run("--version")
        self.assertEqual((code, out.strip()), (0, f"ncaudit {__version__}"))
        code, out, _ = run("audit", "--help")
        self.assertEqual(code, 0)
        self.assertIn("--min-severity", out)

    def test_rules_command(self) -> None:
        code, out, _ = run("rules")
        self.assertEqual(code, 0)
        self.assertIn("MGMT-001", out)
        rules = json.loads(run("rules", "-f", "json")[1])
        self.assertGreaterEqual(len(rules), 20)
        self.assertEqual(set(rules[0]), {"id", "severity", "title", "recommendation"})


if __name__ == "__main__":
    unittest.main()
