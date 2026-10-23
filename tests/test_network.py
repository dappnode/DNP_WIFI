"""Exercise network state transitions with fixture sysctls and an iptables model."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
RULE = ["POSTROUTING", "-s", "10.20.12.0/24", "!", "-d", "10.20.12.0/24", "-j", "MASQUERADE"]
UNRELATED = ["POSTROUTING", "-s", "192.0.2.0/24", "-j", "MASQUERADE"]
FAKE_IPTABLES = r'''
import json, os, pathlib, sys
args = sys.argv[1:]
if args[:4] != ["-w", "5", "-t", "nat"]:
    sys.exit(2)
operation, rule = args[4], args[5:]
if operation == os.environ.get("FAIL_OPERATION"):
    sys.exit(int(os.environ.get("FAIL_STATUS", "4")))
path = pathlib.Path(os.environ["RULES_FILE"])
rules = json.loads(path.read_text())
if operation == "-C":
    sys.exit(0 if rule in rules else 1)
if operation == "-A":
    rules.append(rule)
elif operation == "-D" and rule in rules:
    rules.remove(rule)
else:
    sys.exit(2)
path.write_text(json.dumps(rules))
'''


class NetworkTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.sysctls = self.directory / "sysctls"
        self.sysctls.mkdir()
        self.set_forwarding("0", "0")
        self.rules_file = self.directory / "rules.json"
        self.rules_file.write_text("[]")
        binary = self.directory / "iptables"
        binary.write_text(f"#!{sys.executable}\n" + FAKE_IPTABLES)
        binary.chmod(0o755)
        self.env = dict(os.environ, PATH=f"{self.directory}:{os.environ['PATH']}",
                        RULES_FILE=str(self.rules_file), SUBNET="10.20.12.0", NAT="true")

    def set_forwarding(self, dynaddr, forwarding):
        (self.sysctls / "ip_dynaddr").write_text(dynaddr + "\n")
        (self.sysctls / "ip_forward").write_text(forwarding + "\n")

    def run_network(self, commands, **env):
        return subprocess.run(["bash", "-c", 'source "$1"; ' + commands,
                               "network-test", str(ROOT / "src/network.sh"), str(self.sysctls)],
                              env=dict(self.env, **env), text=True, capture_output=True)

    def assert_success(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def rules(self):
        return json.loads(self.rules_file.read_text())

    def test_disabled_forwarding_is_enabled(self):
        self.assert_success(self.run_network('ip_forward "$2"'))
        self.assertEqual((self.sysctls / "ip_dynaddr").read_text(), "1\n")
        self.assertEqual((self.sysctls / "ip_forward").read_text(), "1\n")

    def test_enabled_forwarding_is_not_rewritten(self):
        self.set_forwarding("1", "1")
        before = {path.name: path.stat().st_mtime_ns for path in self.sysctls.iterdir()}
        self.assert_success(self.run_network('ip_forward "$2"'))
        self.assertEqual(before, {path.name: path.stat().st_mtime_ns for path in self.sysctls.iterdir()})

    def test_mixed_forwarding_state_is_enabled(self):
        self.set_forwarding("1", "0")
        self.assert_success(self.run_network('ip_forward "$2"'))
        self.assertEqual((self.sysctls / "ip_forward").read_text(), "1\n")

    def test_missing_sysctl_fails(self):
        (self.sysctls / "ip_forward").unlink()
        result = self.run_network('ip_forward "$2"')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Cannot read IPv4 ip_forward", result.stderr)

    @unittest.skipIf(os.geteuid() == 0, "Run as a non-root user to exercise filesystem write denial")
    def test_readonly_sysctl_fails(self):
        (self.sysctls / "ip_forward").chmod(0o444)
        result = self.run_network('ip_forward "$2"')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Cannot enable IPv4 ip_forward", result.stderr)

    def test_nat_default_and_repeated_setup(self):
        self.assert_success(self.run_network("nat_setup && nat_setup"))
        self.assertEqual(self.rules(), [RULE])

    def test_nat_false_adds_no_rule(self):
        self.assert_success(self.run_network("nat_setup", NAT="false"))
        self.assertEqual(self.rules(), [])

    def test_nat_false_removes_legacy_duplicates_only(self):
        self.rules_file.write_text(json.dumps([UNRELATED, RULE, RULE]))
        self.assert_success(self.run_network("nat_setup && nat_setup", NAT="false"))
        self.assertEqual(self.rules(), [UNRELATED])

    def test_nat_mode_transitions(self):
        self.rules_file.write_text(json.dumps([UNRELATED]))
        for mode, expected in [("true", [UNRELATED, RULE]), ("false", [UNRELATED]),
                               ("true", [UNRELATED, RULE])]:
            self.assert_success(self.run_network("nat_setup", NAT=mode))
            self.assertEqual(self.rules(), expected)

    def test_forwarding_is_independent_of_nat(self):
        for mode in ["true", "false"]:
            self.set_forwarding("0", "0")
            self.assert_success(self.run_network('ip_forward "$2" && nat_setup', NAT=mode))
            self.assertEqual((self.sysctls / "ip_forward").read_text(), "1\n")

    def test_invalid_nat_values_fail_without_changing_rules(self):
        for mode in ["yes", "1", "FALSE", "", "false; echo invalid"]:
            result = self.run_network("nat_setup", NAT=mode)
            self.assertNotEqual(result.returncode, 0, mode)
            self.assertEqual(self.rules(), [])

    def test_rule_inspection_errors_fail_in_both_modes(self):
        for mode in ["true", "false"]:
            result = self.run_network("nat_setup", NAT=mode, FAIL_OPERATION="-C")
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(self.rules(), [])

    def test_rule_append_error_fails(self):
        result = self.run_network("nat_setup", FAIL_OPERATION="-A")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.rules(), [])

    def test_rule_delete_error_fails(self):
        self.rules_file.write_text(json.dumps([RULE]))
        result = self.run_network("nat_setup", NAT="false", FAIL_OPERATION="-D")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.rules(), [RULE])


if __name__ == "__main__":
    unittest.main()
