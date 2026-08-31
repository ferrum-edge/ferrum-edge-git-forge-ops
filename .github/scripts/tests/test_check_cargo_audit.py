import json
import subprocess
import sys
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "check_cargo_audit.py"
TODAY = "2026-08-30"


def vulnerability(advisory="RUSTSEC-2023-0071", package="rsa", version="0.9.10"):
    return {
        "advisory": {"id": advisory},
        "package": {
            "name": package,
            "version": version,
            "source": "registry+https://github.com/rust-lang/crates.io-index",
        },
    }


def warning(kind, package, version, advisory=None):
    return {
        "kind": kind,
        "advisory": {"id": advisory} if advisory else None,
        "package": {
            "name": package,
            "version": version,
            "source": "registry+https://github.com/rust-lang/crates.io-index",
        },
    }


def report(vulnerabilities=None, warnings=None):
    return {
        "vulnerabilities": {"list": vulnerabilities or []},
        "warnings": warnings or {},
    }


def exception(**overrides):
    value = {
        "kind": "vulnerability",
        "advisory": "RUSTSEC-2023-0071",
        "package": "rsa",
        "version": "0.9.10",
        "source": "registry+https://github.com/rust-lang/crates.io-index",
        "owner": "@security-owner",
        "review_by": "2026-11-30",
        "rationale": "Only public-key encryption is reachable.",
        "affected_call_paths": ["app -> age -> rsa"],
        "compensating_controls": ["No private key is accepted."],
        "upstream": "https://example.invalid/upstream",
    }
    value.update(overrides)
    return value


class CargoAuditPolicyTests(unittest.TestCase):
    def run_check(self, audit_report, exceptions=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report_path = root / "audit.json"
            policy_path = root / "policy.json"
            report_path.write_text(json.dumps(audit_report), encoding="utf-8")
            policy_path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "exceptions": [exception()] if exceptions is None else exceptions,
                    }
                ),
                encoding="utf-8",
            )
            return subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--audit-json",
                    str(report_path),
                    "--policy",
                    str(policy_path),
                    "--today",
                    TODAY,
                ],
                check=False,
                capture_output=True,
                text=True,
            )

    def test_exact_reviewed_finding_passes(self):
        result = self.run_check(report([vulnerability()]))

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("REVIEWED until 2026-11-30", result.stdout)

    def test_new_vulnerability_fails(self):
        result = self.run_check(
            report(
                [
                    vulnerability(),
                    vulnerability("RUSTSEC-2099-0001", "new-crate", "1.2.3"),
                ]
            )
        )

        self.assertEqual(result.returncode, 1)
        self.assertIn("RUSTSEC-2099-0001", result.stderr)

    def test_new_unsound_or_yanked_warning_fails(self):
        cases = {
            "unsound": warning(
                "unsound", "unsafe-crate", "1.0.0", "RUSTSEC-2099-0002"
            ),
            "yanked": warning("yanked", "withdrawn-crate", "2.0.0"),
        }
        for kind, finding in cases.items():
            with self.subTest(kind=kind):
                result = self.run_check(
                    report([vulnerability()], warnings={kind: [finding]})
                )
                self.assertEqual(result.returncode, 1)
                self.assertIn(kind, result.stderr)

    def test_expired_exception_fails_closed(self):
        expired = exception(review_by="2026-08-29")
        result = self.run_check(report([vulnerability()]), [expired])

        self.assertEqual(result.returncode, 2)
        self.assertIn("expired", result.stderr)

    def test_exception_cannot_be_evergreen(self):
        evergreen = exception(review_by="2027-08-30")
        result = self.run_check(report([vulnerability()]), [evergreen])

        self.assertEqual(result.returncode, 2)
        self.assertIn("maximum is 120", result.stderr)

    def test_stale_exception_must_be_removed(self):
        result = self.run_check(report(), [exception()])

        self.assertEqual(result.returncode, 1)
        self.assertIn("Stale cargo-audit exceptions", result.stderr)

    def test_exception_metadata_is_required(self):
        malformed = deepcopy(exception())
        malformed["compensating_controls"] = []
        result = self.run_check(report([vulnerability()]), [malformed])

        self.assertEqual(result.returncode, 2)
        self.assertIn("compensating_controls", result.stderr)


if __name__ == "__main__":
    unittest.main()
