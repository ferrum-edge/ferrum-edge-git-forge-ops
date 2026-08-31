import json
import importlib.util
import subprocess
import sys
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "check_cargo_audit.py"
TODAY = "2026-08-30"
SPEC = importlib.util.spec_from_file_location("check_cargo_audit", SCRIPT)
check_cargo_audit = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = check_cargo_audit
SPEC.loader.exec_module(check_cargo_audit)


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
            manifest_path = root / "Cargo.toml"
            delivery_path = root / "src" / "secrets" / "delivery.rs"
            dependency_tree_path = root / "cargo-tree.txt"
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
            manifest_path.write_text(
                '[package]\nname = "gitforgeops"\nversion = "0.1.0"\n'
                '[dependencies]\nage = { version = "0.12", features = ["ssh", "armor"] }\n',
                encoding="utf-8",
            )
            delivery_path.parent.mkdir(parents=True)
            delivery_path.write_text(
                "use age::ssh::Recipient;\n"
                "fn reviewed(r: &dyn age::Recipient) {\n"
                "    let _ = age::Encryptor::with_recipients([r]);\n"
                "    let _ = age::armor::ArmoredWriter::wrap_output;\n"
                "    let _ = age::armor::Format::AsciiArmor;\n"
                "    let _ = core::mem::size_of::<Recipient>();\n"
                "}\n",
                encoding="utf-8",
            )
            dependency_tree_path.write_text(
                "rsa v0.9.10\n"
                "└── age v0.12.1\n"
                f"    └── gitforgeops v0.1.0 ({root})\n",
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
                    "--source-root",
                    str(root),
                    "--dependency-tree",
                    str(dependency_tree_path),
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

    def test_rsa_exception_rejects_decryption_api_and_feature_drift(self):
        cases = {
            "decryptor": "age::Decryptor",
            "identity": "age::ssh::Identity",
            "extra-feature": 'features = ["ssh", "armor", "plugin"]',
        }
        for name, marker in cases.items():
            with self.subTest(name=name):
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    (root / "src" / "secrets").mkdir(parents=True)
                    manifest = (
                        '[package]\nname = "gitforgeops"\nversion = "0.1.0"\n'
                        '[dependencies]\nage = { version = "0.12", features = ["ssh", "armor"] }\n'
                    )
                    source = (
                        "use age::ssh::Recipient;\n"
                        "fn reviewed(r: &dyn age::Recipient) {\n"
                        " let _ = age::Encryptor::with_recipients([r]);\n"
                        " let _ = age::armor::ArmoredWriter::wrap_output;\n"
                        " let _ = age::armor::Format::AsciiArmor;\n"
                        "}\n"
                    )
                    if name == "extra-feature":
                        manifest = manifest.replace(
                            'features = ["ssh", "armor"]', marker
                        )
                    else:
                        source += f"fn forbidden() {{ let _ = {marker}; }}\n"
                    (root / "Cargo.toml").write_text(manifest, encoding="utf-8")
                    (root / "src" / "secrets" / "delivery.rs").write_text(
                        source, encoding="utf-8"
                    )
                    tree = root / "tree.txt"
                    tree.write_text(
                        "rsa v0.9.10\n└── age v0.12.1\n"
                        f"    └── gitforgeops v0.1.0 ({root})\n",
                        encoding="utf-8",
                    )
                    policy = {
                        check_cargo_audit.RSA_EXCEPTION_KEY: exception()
                    }
                    with self.assertRaises(check_cargo_audit.PolicyError):
                        check_cargo_audit.verify_rsa_exception_reachability(
                            policy, root, tree
                        )

    def test_rsa_exception_rejects_a_second_dependency_path(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "src" / "secrets").mkdir(parents=True)
            (root / "Cargo.toml").write_text(
                '[package]\nname = "gitforgeops"\nversion = "0.1.0"\n'
                '[dependencies]\nage = { version = "0.12", features = ["ssh", "armor"] }\n',
                encoding="utf-8",
            )
            (root / "src" / "secrets" / "delivery.rs").write_text(
                "use age::ssh::Recipient;\n"
                "fn reviewed(r: &dyn age::Recipient) {\n"
                " let _ = age::Encryptor::with_recipients([r]);\n"
                " let _ = age::armor::ArmoredWriter::wrap_output;\n"
                " let _ = age::armor::Format::AsciiArmor;\n"
                "}\n",
                encoding="utf-8",
            )
            tree = root / "tree.txt"
            tree.write_text(
                "rsa v0.9.10\n"
                "├── age v0.12.1\n"
                f"│   └── gitforgeops v0.1.0 ({root})\n"
                "└── another-crate v1.0.0\n",
                encoding="utf-8",
            )
            with self.assertRaises(check_cargo_audit.PolicyError):
                check_cargo_audit.verify_rsa_exception_reachability(
                    {check_cargo_audit.RSA_EXCEPTION_KEY: exception()}, root, tree
                )


if __name__ == "__main__":
    unittest.main()
