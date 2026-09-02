import json
import importlib.util
import subprocess
import sys
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "check_cargo_audit.py"
TODAY = "2026-08-30"
SPEC = importlib.util.spec_from_file_location("check_cargo_audit", SCRIPT)
check_cargo_audit = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = check_cargo_audit
SPEC.loader.exec_module(check_cargo_audit)


REVIEWED_MANIFEST = (
    '[package]\nname = "gitforgeops"\nversion = "0.1.0"\n'
    '[dependencies]\nage = { version = "0.12", features = ["ssh", "armor"] }\n'
)
REVIEWED_SOURCE = (
    "use age::ssh::Recipient;\n"
    "fn reviewed(r: &dyn age::Recipient) {\n"
    "    let _ = age::Encryptor::with_recipients([r]);\n"
    "    let _ = age::armor::ArmoredWriter::wrap_output;\n"
    "    let _ = age::armor::Format::AsciiArmor;\n"
    "    let _ = core::mem::size_of::<Recipient>();\n"
    "}\n"
)


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


def report(vulnerabilities=None, warnings=None, count=None):
    vulnerability_section = {"list": vulnerabilities or []}
    if count is not None:
        vulnerability_section["count"] = count
    return {
        "vulnerabilities": vulnerability_section,
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


def indexed(*exceptions):
    return {check_cargo_audit._finding_key(item): item for item in exceptions}


def write_reviewed_tree(
    root,
    manifest=REVIEWED_MANIFEST,
    source=REVIEWED_SOURCE,
    rsa_version="0.9.10",
    age_version="0.12.1",
    tree=None,
    extra_sources=None,
):
    """Lay out a minimal repository that satisfies the RSA reachability premise."""
    (root / "src" / "secrets").mkdir(parents=True, exist_ok=True)
    (root / "Cargo.toml").write_text(manifest, encoding="utf-8")
    (root / "src" / "secrets" / "delivery.rs").write_text(source, encoding="utf-8")
    for relative, text in (extra_sources or {}).items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    tree_path = root / "cargo-tree.txt"
    tree_path.write_text(
        tree
        if tree is not None
        else (
            f"rsa v{rsa_version}\n"
            f"└── age v{age_version}\n"
            f"    └── gitforgeops v0.1.0 ({root})\n"
        ),
        encoding="utf-8",
    )
    return tree_path


class CargoAuditPolicyTests(unittest.TestCase):
    def run_check(
        self, audit_report, exceptions=None, today=TODAY, audit_exit_status=None
    ):
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
            dependency_tree_path = write_reviewed_tree(root)
            command = [
                sys.executable,
                str(SCRIPT),
                "--audit-json",
                str(report_path),
                "--policy",
                str(policy_path),
                "--today",
                today,
                "--source-root",
                str(root),
                "--dependency-tree",
                str(dependency_tree_path),
            ]
            if audit_exit_status is not None:
                command += ["--audit-exit-status", str(audit_exit_status)]
            return subprocess.run(
                command,
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

    def test_unmaintained_warning_is_reported_without_failing(self):
        result = self.run_check(
            report(
                [vulnerability()],
                warnings={
                    "unmaintained": [
                        warning(
                            "unmaintained", "abandoned-crate", "3.1.0", "RUSTSEC-2099-0003"
                        )
                    ],
                    "notice": [
                        warning("notice", "chatty-crate", "1.0.0", "RUSTSEC-2099-0004")
                    ],
                },
            )
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(
            "::warning::cargo-audit unmaintained RUSTSEC-2099-0003 affects "
            "abandoned-crate 3.1.0",
            result.stdout,
        )
        self.assertIn("::warning::cargo-audit notice RUSTSEC-2099-0004", result.stdout)
        self.assertNotIn("Unreviewed cargo-audit findings", result.stderr)

    def test_expired_exception_fails_closed(self):
        expired = exception(review_by="2026-08-29")
        result = self.run_check(report([vulnerability()]), [expired])

        self.assertEqual(result.returncode, 2)
        self.assertIn("expired", result.stderr)

    def test_review_deadline_inside_the_warning_window_annotates(self):
        result = self.run_check(report([vulnerability()]), today="2026-11-20")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("::warning::cargo-audit exception for rsa 0.9.10", result.stdout)
        self.assertIn("due for re-review by 2026-11-30", result.stdout)
        self.assertIn("10 day(s) left", result.stdout)

    def test_review_deadline_outside_the_warning_window_is_quiet(self):
        result = self.run_check(report([vulnerability()]))

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("due for re-review", result.stdout)

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

    def test_audit_failure_this_gate_cannot_parse_is_fatal(self):
        result = self.run_check(report(), [], audit_exit_status=1)

        self.assertEqual(result.returncode, 2)
        self.assertIn(
            "cargo audit reported findings this gate could not parse", result.stderr
        )

    def test_vulnerability_count_must_match_the_parsed_list(self):
        result = self.run_check(report(count=2), [], audit_exit_status=1)

        self.assertEqual(result.returncode, 2)
        self.assertIn("reported 2 vulnerabilities but this gate parsed 0", result.stderr)

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
                    manifest = REVIEWED_MANIFEST
                    source = REVIEWED_SOURCE
                    if name == "extra-feature":
                        manifest = manifest.replace(
                            'features = ["ssh", "armor"]', marker
                        )
                    else:
                        source += f"fn forbidden() {{ let _ = {marker}; }}\n"
                    tree = write_reviewed_tree(root, manifest=manifest, source=source)
                    with self.assertRaises(check_cargo_audit.PolicyError):
                        check_cargo_audit.verify_exception_reachability(
                            indexed(exception()), root, tree
                        )

    def test_reachability_checks_survive_an_exception_version_bump(self):
        """An rsa patch bump must not silently switch the verifier off (F1)."""
        bumped = exception(version="0.9.11")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            hostile = REVIEWED_SOURCE + "fn forbidden() { let _ = age::Decryptor; }\n"
            tree = write_reviewed_tree(root, source=hostile, rsa_version="0.9.11")
            with self.assertRaises(check_cargo_audit.PolicyError) as raised:
                check_cargo_audit.verify_exception_reachability(
                    indexed(bumped), root, tree
                )
            self.assertIn("age::Decryptor", str(raised.exception))

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tree = write_reviewed_tree(root, rsa_version="0.9.11")
            check_cargo_audit.verify_exception_reachability(indexed(bumped), root, tree)

    def test_rsa_exception_without_a_verifier_is_a_policy_error(self):
        orphan = exception(advisory="RUSTSEC-2099-0009")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tree = write_reviewed_tree(root)
            with self.assertRaises(check_cargo_audit.PolicyError) as raised:
                check_cargo_audit.verify_exception_reachability(
                    indexed(orphan), root, tree
                )
            self.assertIn("no reachability verifier", str(raised.exception))

    def test_unknown_reachability_verifier_is_a_policy_error(self):
        unknown = exception(reachability="hand-waving")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tree = write_reviewed_tree(root)
            with self.assertRaises(check_cargo_audit.PolicyError) as raised:
                check_cargo_audit.verify_exception_reachability(
                    indexed(unknown), root, tree
                )
            self.assertIn("unknown reachability verifier", str(raised.exception))

    def test_declared_reachability_selects_the_verifier(self):
        declared = exception(
            advisory="RUSTSEC-2099-0010", reachability="age-encryption-only"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            hostile = REVIEWED_SOURCE + "fn forbidden() { let _ = age::Decryptor; }\n"
            tree = write_reviewed_tree(root, source=hostile)
            with self.assertRaises(check_cargo_audit.PolicyError):
                check_cargo_audit.verify_exception_reachability(
                    indexed(declared), root, tree
                )

    def test_patch_bumps_of_age_and_rsa_are_accepted(self):
        for rsa_version, age_version in (
            ("0.9.10", "0.12.2"),
            ("0.9.12", "0.12.9"),
        ):
            with self.subTest(rsa=rsa_version, age=age_version):
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    tree = write_reviewed_tree(
                        root, rsa_version=rsa_version, age_version=age_version
                    )
                    check_cargo_audit.verify_exception_reachability(
                        indexed(exception(version=rsa_version)), root, tree
                    )

    def test_feature_order_and_disabled_defaults_are_accepted(self):
        manifests = {
            "reordered": '[package]\nname = "gitforgeops"\nversion = "0.1.0"\n'
            '[dependencies]\nage = { version = "0.12", features = ["armor", "ssh"] }\n',
            "no-default-features": '[package]\nname = "gitforgeops"\nversion = "0.1.0"\n'
            '[dependencies]\nage = { version = "0.12", default-features = false, '
            'features = ["ssh", "armor"] }\n',
            "patch-pinned": '[package]\nname = "gitforgeops"\nversion = "0.1.0"\n'
            '[dependencies]\nage = { version = "0.12.2", features = ["ssh", "armor"] }\n',
        }
        for name, manifest in manifests.items():
            with self.subTest(name=name):
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    tree = write_reviewed_tree(root, manifest=manifest)
                    check_cargo_audit.verify_exception_reachability(
                        indexed(exception()), root, tree
                    )

    def test_unused_allowlisted_age_apis_are_accepted(self):
        """Dropping armor usage is a reduction in reach, not a policy breach (F2)."""
        source = (
            "use age::ssh::Recipient;\n"
            "fn reviewed(r: &dyn age::Recipient) {\n"
            "    let _ = age::Encryptor::with_recipients([r]);\n"
            "}\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tree = write_reviewed_tree(root, source=source)
            check_cargo_audit.verify_exception_reachability(
                indexed(exception()), root, tree
            )

    def test_comments_and_string_literals_are_not_api_references(self):
        source = (
            "use age::ssh::Recipient;\n"
            "/// Never call age::Decryptor here; see docs/dependency-security.md.\n"
            "// age::ssh::Identity is deliberately unreachable.\n"
            "/* block note about age::Decryptor and age::x25519::Identity */\n"
            "fn reviewed(r: &dyn age::Recipient) {\n"
            '    let note = "age::Decryptor is forbidden";\n'
            '    let raw = r#"age::ssh::Identity"#;\n'
            "    let quote = '\\'';\n"
            "    let _ = age::Encryptor::with_recipients([r]);\n"
            "    let _ = (note, raw, quote);\n"
            "}\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tree = write_reviewed_tree(root, source=source)
            check_cargo_audit.verify_exception_reachability(
                indexed(exception()), root, tree
            )

    def test_commented_out_age_reference_outside_the_module_is_accepted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tree = write_reviewed_tree(
                root,
                extra_sources={
                    "src/jwt.rs": "// age::Decryptor is never used for admin tokens.\n"
                    "pub fn mint() {}\n"
                },
            )
            check_cargo_audit.verify_exception_reachability(
                indexed(exception()), root, tree
            )

    def test_real_age_reference_outside_the_module_still_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tree = write_reviewed_tree(
                root,
                extra_sources={"src/jwt.rs": "pub fn mint() { let _ = age::Decryptor; }\n"},
            )
            with self.assertRaises(check_cargo_audit.PolicyError) as raised:
                check_cargo_audit.verify_exception_reachability(
                    indexed(exception()), root, tree
                )
            self.assertIn("src/jwt.rs", str(raised.exception))

    def test_rsa_exception_rejects_a_second_dependency_path(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tree = write_reviewed_tree(
                root,
                tree=(
                    "rsa v0.9.10\n"
                    "├── age v0.12.1\n"
                    f"│   └── gitforgeops v0.1.0 ({root})\n"
                    "└── another-crate v1.0.0\n"
                ),
            )
            with self.assertRaises(check_cargo_audit.PolicyError):
                check_cargo_audit.verify_exception_reachability(
                    indexed(exception()), root, tree
                )

    def test_rsa_absent_from_the_graph_reports_a_stale_exception(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_reviewed_tree(root)
            completed = subprocess.CompletedProcess(
                [],
                101,
                "",
                "error: package ID specification `rsa@0.9.10` did not match any packages\n",
            )
            with mock.patch.object(
                check_cargo_audit.subprocess, "run", return_value=completed
            ):
                with self.assertRaises(check_cargo_audit.PolicyError) as raised:
                    check_cargo_audit.verify_exception_reachability(
                        indexed(exception()), root, None
                    )
            message = str(raised.exception)
            self.assertIn("stale exception", message)
            self.assertIn(".github/cargo-audit-policy.json", message)

    def test_live_dependency_tree_disables_forced_terminal_color(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_reviewed_tree(root)
            tree = (
                "rsa v0.9.10\n"
                "└── age v0.12.1\n"
                f"    └── gitforgeops v0.1.0 ({root})\n"
            )
            completed = subprocess.CompletedProcess([], 0, tree, "")
            with mock.patch.object(
                check_cargo_audit.subprocess, "run", return_value=completed
            ) as run:
                check_cargo_audit.verify_exception_reachability(
                    indexed(exception()), root, None
                )

            command = run.call_args.args[0]
            self.assertEqual(command[command.index("--color") + 1], "never")
            self.assertEqual(command[command.index("-i") + 1], "rsa@0.9.10")


class RustSourceStrippingTests(unittest.TestCase):
    def strip(self, text):
        return check_cargo_audit.strip_rust_comments_and_strings(text)

    def test_line_and_doc_comments_are_blanked(self):
        stripped = self.strip("let a = 1; // age::Decryptor\n/// age::Decryptor\nb;\n")

        self.assertNotIn("age::Decryptor", stripped)
        self.assertIn("let a = 1;", stripped)
        self.assertEqual(stripped.count("\n"), 3)

    def test_nested_block_comments_are_blanked(self):
        stripped = self.strip("a /* outer /* age::Decryptor */ still */ b")

        self.assertNotIn("age::Decryptor", stripped)
        self.assertIn("a", stripped)
        self.assertIn("b", stripped)

    def test_string_and_raw_string_literals_are_blanked(self):
        stripped = self.strip(
            'let s = "age::Decryptor \\" still";\nlet r = r#"age::ssh::Identity"#;\n'
        )

        self.assertNotIn("age::", stripped)

    def test_lifetimes_survive_char_literal_stripping(self):
        stripped = self.strip("fn f<'a>(x: &'a str) -> char { 'z' }")

        self.assertIn("<'a>", stripped)
        self.assertIn("&'a str", stripped)
        self.assertNotIn("'z'", stripped)

    def test_code_outside_literals_is_preserved(self):
        stripped = self.strip("let _ = age::Encryptor::with_recipients(r);\n")

        self.assertIn("age::Encryptor::with_recipients", stripped)


if __name__ == "__main__":
    unittest.main()
