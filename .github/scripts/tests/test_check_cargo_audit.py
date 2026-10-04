import json
import importlib.util
import io
import os
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
    (root / "Cargo.lock").write_text("version = 4\n", encoding="utf-8")
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


HOSTILE_CARGO_CONFIG = (
    '[alias]\naudit = ["run", "--quiet", "--bin", "forged-audit"]\n'
    '[env]\nRUSTSEC_FORGED = "1"\n'
)
HOSTILE_AUDIT_CONFIG = '[advisories]\nignore = ["RUSTSEC-2099-0001"]\n'
HOSTILE_TOOLCHAIN = '[toolchain]\npath = "./forged-toolchain"\n'


def write_hostile_cargo_inputs(root):
    """Every candidate file that steers cargo, rustup or cargo-audit by location."""
    (root / ".cargo").mkdir(parents=True, exist_ok=True)
    (root / ".cargo" / "config.toml").write_text(HOSTILE_CARGO_CONFIG, encoding="utf-8")
    (root / ".cargo" / "config").write_text(HOSTILE_CARGO_CONFIG, encoding="utf-8")
    (root / ".cargo" / "audit.toml").write_text(HOSTILE_AUDIT_CONFIG, encoding="utf-8")
    (root / "rust-toolchain.toml").write_text(HOSTILE_TOOLCHAIN, encoding="utf-8")
    (root / "rust-toolchain").write_text("forged\n", encoding="utf-8")
    (root / "Cargo.lock").write_text("version = 4\n", encoding="utf-8")


# A stand-in `cargo` that answers the way a steered cargo would whenever it can
# see candidate configuration where cargo, rustup or cargo-audit look for it
# (the working directory and its ancestors, CARGO_HOME, CARGO_ALIAS_*,
# RUSTUP_TOOLCHAIN), and honestly otherwise. Every call is recorded.
FAKE_CARGO = r"""
import json
import os
import sys
from pathlib import Path

HIERARCHICAL = (".cargo/config", ".cargo/config.toml", "rust-toolchain", "rust-toolchain.toml")
HOME_CONFIG = ("config", "config.toml", "audit.toml")


def steered():
    cwd = Path.cwd()
    for directory in (cwd, *cwd.parents):
        if any(os.path.lexists(directory / name) for name in HIERARCHICAL):
            return True
    if os.path.lexists(cwd / ".cargo" / "audit.toml"):
        return True
    cargo_home = Path(os.environ.get("CARGO_HOME") or Path.home() / ".cargo")
    if any(os.path.lexists(cargo_home / name) for name in HOME_CONFIG):
        return True
    return any(
        key.startswith("CARGO_ALIAS_") or key == "RUSTUP_TOOLCHAIN" for key in os.environ
    )


mode = "steered" if steered() else "honest"
with open(os.environ["FAKE_CARGO_RECORD"], "a", encoding="utf-8") as record:
    record.write(
        json.dumps(
            {
                "args": sys.argv[1:],
                "cwd": os.getcwd(),
                "cargo_home": os.environ.get("CARGO_HOME"),
                "home": os.environ.get("HOME"),
                "rustup_home": os.environ.get("RUSTUP_HOME"),
                "mode": mode,
            }
        )
        + "\n"
    )
with open(os.environ["FAKE_CARGO_OUTPUTS"], encoding="utf-8") as outputs:
    output = json.load(outputs)[sys.argv[1]][mode]
sys.stdout.write(output["stdout"])
sys.exit(output["exit"])
"""

REVIEWED_RSA_TREE = (
    "rsa v0.9.10\n"
    "└── age v0.12.1\n"
    "    └── gitforgeops v0.1.0 (/candidate)\n"
)
SECOND_RSA_PATH_TREE = (
    "rsa v0.9.10\n"
    "├── age v0.12.1\n"
    "│   └── gitforgeops v0.1.0 (/candidate)\n"
    "└── forged-free v1.0.0\n"
    "    └── gitforgeops v0.1.0 (/candidate)\n"
)


def fake_cargo_outputs():
    return {
        "audit": {
            "honest": {
                "stdout": json.dumps(
                    report(
                        [vulnerability("RUSTSEC-2099-0001", "forged-free", "1.0.0")],
                        count=1,
                    )
                ),
                "exit": 1,
            },
            "steered": {"stdout": json.dumps(report()), "exit": 0},
        },
        "tree": {
            "honest": {"stdout": SECOND_RSA_PATH_TREE, "exit": 0},
            "steered": {"stdout": REVIEWED_RSA_TREE, "exit": 0},
        },
    }


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
            self.assertEqual(
                command[command.index("--manifest-path") + 1], str(root / "Cargo.toml")
            )
            workdir = Path(run.call_args.kwargs["cwd"]).resolve()
            self.assertNotIn(root.resolve(), (workdir, *workdir.parents))


class CandidateCargoIsolationTests(unittest.TestCase):
    """Candidate cargo, rustup and cargo-audit configuration cannot steer the gate."""

    def install_fake_cargo(self, scratch, candidate):
        bindir = scratch / "bin"
        bindir.mkdir()
        cargo = bindir / "cargo"
        cargo.write_text(f"#!{sys.executable}\n{FAKE_CARGO}", encoding="utf-8")
        cargo.chmod(0o755)
        outputs = scratch / "outputs.json"
        outputs.write_text(json.dumps(fake_cargo_outputs()), encoding="utf-8")
        environment = dict(os.environ)
        environment.update(
            {
                "PATH": f"{bindir}{os.pathsep}{os.environ.get('PATH', '')}",
                "FAKE_CARGO_RECORD": str(scratch / "record.jsonl"),
                "FAKE_CARGO_OUTPUTS": str(outputs),
                # Inherited selection variables pointing back at the candidate.
                "CARGO_HOME": str(candidate / ".cargo"),
                "CARGO_ALIAS_AUDIT": "run --quiet --bin forged-audit",
                "RUSTUP_TOOLCHAIN": "forged",
            }
        )
        return cargo, environment

    def run_gate(self, scratch, candidate, environment, exceptions):
        policy = scratch / "policy.json"
        policy.write_text(
            json.dumps({"schema_version": 1, "exceptions": exceptions}), encoding="utf-8"
        )
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--policy",
                str(policy),
                "--today",
                TODAY,
                "--source-root",
                str(candidate),
            ],
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )

    def records(self, scratch):
        lines = (scratch / "record.jsonl").read_text(encoding="utf-8").splitlines()
        return [json.loads(line) for line in lines]

    def assert_outside_candidate(self, call, candidate):
        root = candidate.resolve()
        workdir = Path(call["cwd"]).resolve()
        cargo_home = Path(call["cargo_home"]).resolve()
        home = Path(call["home"]).resolve()
        self.assertNotIn(root, (workdir, *workdir.parents))
        self.assertNotIn(root, (cargo_home, *cargo_home.parents))
        self.assertNotIn(root, (home, *home.parents))
        self.assertNotIn(root, Path(call["rustup_home"]).resolve().parents)
        self.assertEqual(call["mode"], "honest")

    def test_candidate_configuration_cannot_forge_a_clean_audit(self):
        with tempfile.TemporaryDirectory() as directory:
            scratch = Path(directory)
            candidate = scratch / "candidate"
            candidate.mkdir()
            write_hostile_cargo_inputs(candidate)
            (candidate / "Cargo.toml").write_text(REVIEWED_MANIFEST, encoding="utf-8")
            cargo, environment = self.install_fake_cargo(scratch, candidate)

            # Control: from inside the candidate tree, the stand-in is steered
            # and reports a clean lockfile, as a steered cargo-audit would.
            control_environment = dict(environment)
            control_environment["FAKE_CARGO_RECORD"] = str(scratch / "control.jsonl")
            control = subprocess.run(
                [str(cargo), "audit", "--json"],
                cwd=candidate,
                env=control_environment,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(control.returncode, 0, control.stderr)
            self.assertEqual(json.loads(control.stdout), report())

            result = self.run_gate(scratch, candidate, environment, [])

            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertIn("Unreviewed cargo-audit findings", result.stderr)
            self.assertIn("RUSTSEC-2099-0001", result.stderr)
            for name in (".cargo/config.toml", ".cargo/audit.toml", "rust-toolchain.toml"):
                self.assertIn(name, result.stdout)
            (call,) = self.records(scratch)
            self.assertEqual(call["args"][0], "audit")
            self.assertEqual(
                call["args"][call["args"].index("--file") + 1],
                str(candidate.resolve() / "Cargo.lock"),
            )
            self.assert_outside_candidate(call, candidate)

    def test_candidate_configuration_cannot_forge_the_rsa_dependency_path(self):
        with tempfile.TemporaryDirectory() as directory:
            scratch = Path(directory)
            candidate = scratch / "candidate"
            candidate.mkdir()
            write_reviewed_tree(candidate)
            write_hostile_cargo_inputs(candidate)
            _cargo, environment = self.install_fake_cargo(scratch, candidate)

            result = self.run_gate(scratch, candidate, environment, [exception()])

            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn("dependency path changed", result.stderr)
            (call,) = self.records(scratch)
            self.assertEqual(call["args"][0], "tree")
            self.assertEqual(
                call["args"][call["args"].index("--manifest-path") + 1],
                str(candidate.resolve() / "Cargo.toml"),
            )
            self.assertIn("--locked", call["args"])
            self.assert_outside_candidate(call, candidate)

    def test_inherited_cargo_selection_variables_are_scrubbed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Cargo.toml").write_text(REVIEWED_MANIFEST, encoding="utf-8")
            write_hostile_cargo_inputs(root)
            hostile_environment = {
                "CARGO": "/bin/false",
                "CARGO_HOME": str(root / ".cargo"),
                "CARGO_ALIAS_AUDIT": "tree",
                "CARGO_BUILD_RUSTC_WRAPPER": "/bin/false",
                "RUSTC_BOOTSTRAP": "1",
                "RUSTC_WRAPPER": "/bin/false",
                "RUSTFLAGS": "--cfg forged",
                "RUSTUP_TOOLCHAIN": "forged",
                "__CARGO_TEST_CHANNEL_OVERRIDE_DO_NOT_USE_THIS": "nightly",
                "__CARGO_FIX_YOLO": "1",
            }
            # Every explicitly scrubbed name is exercised, not just a sample.
            for name in check_cargo_audit.SCRUBBED_ENVIRONMENT:
                hostile_environment.setdefault(name, "/bin/false")
            seen = {}

            def fake_run(command, **kwargs):
                workdir = Path(kwargs["cwd"])
                environment = kwargs["env"]
                seen["command"] = command
                seen["cwd"] = workdir
                seen["env"] = environment
                seen["cwd_entries"] = sorted(path.name for path in workdir.iterdir())
                seen["home_entries"] = sorted(
                    path.name for path in Path(environment["CARGO_HOME"]).iterdir()
                )
                return subprocess.CompletedProcess(command, 0, json.dumps(report()), "")

            with mock.patch.dict(os.environ, hostile_environment):
                inherited_path = os.environ.get("PATH")
                with mock.patch.object(
                    check_cargo_audit.subprocess, "run", side_effect=fake_run
                ):
                    audit_report, status = check_cargo_audit.run_cargo_audit(root)

            self.assertEqual((audit_report, status), (report(), 0))
            environment = seen["env"]
            for name in hostile_environment:
                if name != "CARGO_HOME":
                    self.assertNotIn(name, environment)
            self.assertEqual(
                [name for name in environment if name.startswith(("CARGO_", "__CARGO_"))],
                ["CARGO_HOME"],
                "only the isolated CARGO_HOME reaches cargo",
            )
            cargo_home = Path(environment["CARGO_HOME"]).resolve()
            home = Path(environment["HOME"]).resolve()
            self.assertNotIn(root.resolve(), (cargo_home, *cargo_home.parents))
            self.assertNotIn(root.resolve(), (home, *home.parents))
            self.assertEqual(
                environment["RUSTUP_HOME"],
                str(Path(os.environ.get("RUSTUP_HOME") or Path.home() / ".rustup").resolve()),
            )
            self.assertEqual(environment.get("PATH"), inherited_path)
            self.assertEqual(seen["cwd_entries"], [])
            self.assertEqual(seen["home_entries"], [])
            self.assertNotIn(root.resolve(), (seen["cwd"], *seen["cwd"].parents))
            self.assertFalse(seen["cwd"].exists(), "the isolated directory is removed")
            command = seen["command"]
            self.assertEqual(command[command.index("--file") + 1], str(root / "Cargo.lock"))

    def test_lockfile_and_manifest_must_be_regular_candidate_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with mock.patch.object(check_cargo_audit.subprocess, "run") as run:
                with self.assertRaises(check_cargo_audit.PolicyError) as missing:
                    check_cargo_audit.run_cargo_audit(root)
                (root / "elsewhere.lock").write_text("version = 4\n", encoding="utf-8")
                (root / "Cargo.lock").symlink_to(root / "elsewhere.lock")
                with self.assertRaises(check_cargo_audit.PolicyError) as linked_lock:
                    check_cargo_audit.run_cargo_audit(root)
                (root / "elsewhere.toml").write_text(REVIEWED_MANIFEST, encoding="utf-8")
                (root / "Cargo.toml").symlink_to(root / "elsewhere.toml")
                with self.assertRaises(check_cargo_audit.PolicyError) as linked_manifest:
                    check_cargo_audit._read_dependency_tree("rsa", "0.9.10", root, None)
            run.assert_not_called()
            for raised in (missing, linked_lock, linked_manifest):
                self.assertIn("must be a regular file", str(raised.exception))

    def test_isolated_directory_must_be_outside_the_candidate_tree(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "tmp").mkdir()
            with mock.patch.object(check_cargo_audit.tempfile, "tempdir", str(root / "tmp")):
                with self.assertRaises(check_cargo_audit.PolicyError) as raised:
                    with check_cargo_audit.isolated_cargo(root):
                        self.fail("isolation must refuse before cargo runs")
            self.assertIn("inside the candidate tree", str(raised.exception))

    def test_cargo_configuration_above_the_isolated_directory_is_refused(self):
        for name in check_cargo_audit.CARGO_CONTROL_FILES:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                outer = Path(directory)
                candidate = outer / "candidate"
                candidate.mkdir()
                scratch = outer / "scratch"
                control = scratch / name
                control.parent.mkdir(parents=True, exist_ok=True)
                control.write_text("", encoding="utf-8")
                with mock.patch.object(check_cargo_audit.tempfile, "tempdir", str(scratch)):
                    with self.assertRaises(check_cargo_audit.PolicyError) as raised:
                        with check_cargo_audit.isolated_cargo(candidate):
                            self.fail("isolation must refuse before cargo runs")
                self.assertIn("cargo would read", str(raised.exception))


def locked_package(name="rsa", version="0.9.10", checksum="a" * 64, **overrides):
    package = {
        "name": name,
        "version": version,
        "source": check_cargo_audit.CRATES_IO_SOURCE,
        "checksum": checksum,
    }
    package.update(overrides)
    return package


def write_lockfile(root, packages):
    text = "version = 4\n"
    for package in packages:
        text += "\n[[package]]\n"
        for key, value in package.items():
            text += f"{key} = {json.dumps(value)}\n"
    (root / "Cargo.lock").write_text(text, encoding="utf-8")


def index_entry(package, yanked=False):
    return {
        "name": package["name"],
        "vers": package["version"],
        "cksum": package["checksum"],
        "yanked": yanked,
    }


class IndexResponse(io.BytesIO):
    def __init__(self, url, data, status=200, headers=None):
        super().__init__(data)
        self.url = url
        self.status = status
        self.headers = {} if headers is None else headers

    def geturl(self):
        return self.url


class CompleteCargoAuditGateTests(unittest.TestCase):
    """Drive main, including real input validation, reachability and scan logic.

    Only external Cargo and HTTP calls are replaced. A reviewed RSA report
    and an unchanged inverse tree cannot hide an incomplete yanked scan.
    """

    def run_gate(
        self, root, entries=None, audit_report=None, audit_stderr="", http=None, audit_status=1
    ):
        policy = root / "policy.json"
        policy.write_text(
            json.dumps({"schema_version": 1, "exceptions": [exception()]}),
            encoding="utf-8",
        )
        argv = [
            str(SCRIPT),
            "--source-root",
            str(root),
            "--policy",
            str(policy),
            "--today",
            TODAY,
        ]
        stdout, stderr = io.StringIO(), io.StringIO()
        calls = []

        def cargo(command, **kwargs):
            calls.append((command, kwargs))
            if command[1] == "tree":
                return subprocess.CompletedProcess(command, 0, REVIEWED_RSA_TREE, "")
            return subprocess.CompletedProcess(
                command,
                audit_status,
                json.dumps(report([vulnerability()]) if audit_report is None else audit_report),
                audit_stderr,
            )

        def fetch(request, **kwargs):
            name = request.full_url.rsplit("/", 1)[-1]
            value = entries[name]
            if isinstance(value, Exception):
                raise value
            data = "\n".join(json.dumps(entry) for entry in value).encode("utf-8") + b"\n"
            return IndexResponse(request.full_url, data)

        with (
            mock.patch.object(sys, "argv", argv),
            mock.patch.object(sys, "stdout", stdout),
            mock.patch.object(sys, "stderr", stderr),
            mock.patch.object(check_cargo_audit.subprocess, "run", side_effect=cargo),
            mock.patch.object(
                check_cargo_audit.urllib.request, "urlopen", side_effect=http or fetch
            ) as urlopen,
        ):
            status = check_cargo_audit.main()
        return status, stdout.getvalue(), stderr.getvalue(), calls, urlopen

    def test_workspace_redirect_cannot_hide_an_effective_lockfile_dependency(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = REVIEWED_MANIFEST.replace(
                '[package]\n', '[package]\nworkspace = "audit-workspace"\n'
            )
            write_reviewed_tree(root, manifest=manifest)
            write_lockfile(root, [locked_package()])
            workspace = root / "audit-workspace"
            workspace.mkdir()
            (workspace / "Cargo.toml").write_text(
                '[workspace]\nmembers = [".."]\n', encoding="utf-8"
            )
            write_lockfile(
                workspace, [locked_package(), locked_package("vulnerable", "1.0.0")]
            )

            status, stdout, stderr, calls, http = self.run_gate(root)

            self.assertEqual(status, 2, stderr)
            self.assertIn("single-package", stderr)
            self.assertIn("different dependency graph or lockfile", stderr)
            self.assertNotIn("policy passed", stdout)
            self.assertEqual(calls, [])
            http.assert_not_called()

    def test_workspace_table_and_implicit_ancestor_workspace_are_refused(self):
        for kind in ("root", "ancestor"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                outer = Path(directory)
                root = outer / "candidate"
                root.mkdir()
                write_reviewed_tree(root)
                if kind == "root":
                    (root / "Cargo.toml").write_text(
                        REVIEWED_MANIFEST + "\n[workspace]\n", encoding="utf-8"
                    )
                else:
                    (outer / "Cargo.toml").write_text(
                        '[workspace]\nmembers = ["candidate"]\n', encoding="utf-8"
                    )
                status, _stdout, stderr, calls, http = self.run_gate(root)
                self.assertEqual(status, 2, stderr)
                self.assertIn("workspace", stderr)
                self.assertEqual(calls, [])
                http.assert_not_called()

    def test_both_inputs_are_validated_before_any_content_read_or_subprocess(self):
        for name in ("Cargo.toml", "Cargo.lock"):
            for kind in ("missing", "symlink", "directory", "fifo", "oversized"):
                with self.subTest(name=name, kind=kind):
                    with tempfile.TemporaryDirectory() as directory:
                        root = Path(directory)
                        write_reviewed_tree(root)
                        path = root / name
                        path.unlink()
                        if kind == "symlink":
                            # Reading this target would never reach EOF.
                            path.symlink_to("/dev/zero")
                        elif kind == "directory":
                            path.mkdir()
                        elif kind == "fifo":
                            os.mkfifo(path)
                        elif kind == "oversized":
                            limit = (
                                check_cargo_audit.MAX_MANIFEST_BYTES
                                if name == "Cargo.toml"
                                else check_cargo_audit.MAX_LOCKFILE_BYTES
                            )
                            with path.open("wb") as stream:
                                stream.truncate(limit + 1)
                        with mock.patch.object(check_cargo_audit, "_read_regular_text") as read:
                            status, _stdout, stderr, calls, http = self.run_gate(root)
                        self.assertEqual(status, 2, stderr)
                        read.assert_not_called()
                        self.assertEqual(calls, [])
                        http.assert_not_called()

    def test_replaced_file_and_growth_cannot_turn_validation_into_an_unbounded_read(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "Cargo.toml"
            path.symlink_to("/dev/zero")
            with self.assertRaises(check_cargo_audit.PolicyError):
                check_cargo_audit._read_regular_text(path, 32)
            path.unlink()
            os.mkfifo(path)
            with self.assertRaises(check_cargo_audit.PolicyError):
                check_cargo_audit._read_regular_text(path, 32)
            path.unlink()
            path.write_bytes(b"x" * 33)
            with self.assertRaises(check_cargo_audit.PolicyError) as raised:
                check_cargo_audit._read_regular_text(path, 32)
            self.assertIn("byte limit", str(raised.exception))
        # Even an unexpected device input is refused before reading bytes.
        with self.assertRaises(check_cargo_audit.PolicyError):
            check_cargo_audit._read_regular_text(Path("/dev/zero"), 32)

    def test_whole_index_failure_is_fatal_with_or_without_upstream_warning(self):
        for upstream_stderr in ("", "warning: couldn't update crates.io index\n"):
            with self.subTest(stderr=upstream_stderr), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                write_reviewed_tree(root)
                write_lockfile(root, [locked_package()])
                status, stdout, stderr, calls, _http = self.run_gate(
                    root,
                    entries={"rsa": OSError("index unavailable")},
                    audit_stderr=upstream_stderr,
                )
                self.assertEqual(status, 2, stderr)
                self.assertIn("complete yanked scan", stderr)
                self.assertIn("index unavailable", stderr)
                self.assertNotIn("policy passed", stdout)
                self.assertNotIn("yanked scan complete:", stdout)
                self.assertEqual([call[0][1] for call in calls], ["tree", "audit"])

    def test_one_failed_lookup_cannot_pass_with_a_reviewed_rsa_advisory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_reviewed_tree(root)
            rsa, age = locked_package(), locked_package("age", "0.12.1")
            write_lockfile(root, [rsa, age])
            status, stdout, stderr, _calls, http = self.run_gate(
                root,
                entries={"rsa": [index_entry(rsa)], "age": OSError("lookup failed")},
                audit_stderr="error: couldn't check if the package is yanked\n",
            )
            self.assertEqual(status, 2, stderr)
            self.assertIn("lookup failed", stderr)
            self.assertNotIn("policy passed", stdout)
            self.assertEqual(http.call_count, 2)

    def test_incomplete_or_ambiguous_version_evidence_is_fatal(self):
        package = locked_package()
        valid = index_entry(package)
        cases = {
            "missing version": [dict(valid, vers="0.9.9")],
            "missing crate": [dict(valid, name="other")],
            "missing status": [{key: value for key, value in valid.items() if key != "yanked"}],
            "nonboolean status": [dict(valid, yanked=0)],
            "wrong checksum": [dict(valid, cksum="b" * 64)],
            "duplicate version": [valid, valid],
        }
        for kind, entries in cases.items():
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                write_reviewed_tree(root)
                write_lockfile(root, [package])
                status, stdout, stderr, _calls, _http = self.run_gate(
                    root, entries={"rsa": entries}
                )
                self.assertEqual(status, 2, stderr)
                self.assertNotIn("policy passed", stdout)

    def test_complete_scan_passes_and_covers_multiple_locked_versions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_reviewed_tree(root)
            rsa = locked_package()
            old, new = locked_package("dep", "1.0.0"), locked_package("dep", "2.0.0")
            write_lockfile(root, [rsa, old, new])
            status, stdout, stderr, calls, http = self.run_gate(
                root,
                entries={"rsa": [index_entry(rsa)], "dep": [index_entry(old), index_entry(new)]},
            )
            self.assertEqual(status, 0, stderr)
            self.assertIn("yanked scan complete: 3 crates.io package version(s), 0 yanked", stdout)
            self.assertIn("1 reviewed exception(s)", stdout)
            self.assertEqual(http.call_count, 2, "one fresh request per crate")
            for _command, options in calls:
                environment = options["env"]
                self.assertNotIn(root, Path(environment["HOME"]).parents)
                self.assertNotIn(root, Path(environment["CARGO_HOME"]).parents)
                self.assertNotIn("RUSTUP_TOOLCHAIN", environment)

    def test_yanked_version_blocks_even_when_cargo_audit_omits_the_warning(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_reviewed_tree(root)
            package = locked_package()
            write_lockfile(root, [package])
            status, stdout, stderr, _calls, _http = self.run_gate(
                root, entries={"rsa": [index_entry(package, yanked=True)]}
            )
            self.assertEqual(status, 1, stderr)
            self.assertIn("yanked scan complete: 1 crates.io package version(s), 1 yanked", stdout)
            self.assertIn("yanked: rsa 0.9.10", stderr)

    def test_existing_yanked_warning_is_not_counted_twice(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_reviewed_tree(root)
            package = locked_package()
            write_lockfile(root, [package])
            status, _stdout, stderr, _calls, _http = self.run_gate(
                root,
                entries={"rsa": [index_entry(package, yanked=True)]},
                audit_report=report(
                    [vulnerability()], {"yanked": [warning("yanked", "rsa", "0.9.10")]}
                ),
            )
            self.assertEqual(status, 1, stderr)
            self.assertEqual(stderr.count("yanked: rsa 0.9.10"), 1)

    def test_saved_audit_json_still_requires_complete_yanked_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tree = write_reviewed_tree(root)
            write_lockfile(root, [locked_package()])
            policy, saved = root / "policy.json", root / "audit.json"
            policy.write_text(json.dumps({"schema_version": 1, "exceptions": [exception()]}))
            saved.write_text(json.dumps(report([vulnerability()])))
            argv = [
                str(SCRIPT),
                "--source-root",
                str(root),
                "--policy",
                str(policy),
                "--today",
                TODAY,
                "--audit-json",
                str(saved),
                "--dependency-tree",
                str(tree),
            ]
            with (
                mock.patch.object(sys, "argv", argv),
                mock.patch.object(sys, "stderr", io.StringIO()) as stderr,
                mock.patch.object(check_cargo_audit.subprocess, "run") as cargo,
                mock.patch.object(
                    check_cargo_audit.urllib.request, "urlopen", side_effect=OSError("offline")
                ),
            ):
                self.assertEqual(check_cargo_audit.main(), 2)
            self.assertIn("complete yanked scan", stderr.getvalue())
            cargo.assert_not_called()

    def test_unsupported_registry_or_malformed_lockfile_fails_before_cargo(self):
        packages = [
            locked_package(source="registry+https://registry.example.invalid/index"),
            locked_package(checksum=""),
            locked_package(name="../escape"),
            locked_package(version="invalid"),
            locked_package(source=42),
        ]
        for package in packages:
            with self.subTest(package=package), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                write_reviewed_tree(root)
                write_lockfile(root, [package])
                status, stdout, stderr, calls, http = self.run_gate(root)
                self.assertEqual(status, 2, stderr)
                self.assertNotIn("policy passed", stdout)
                self.assertEqual(calls, [])
                http.assert_not_called()

    def test_registry_response_errors_never_produce_complete_scan_evidence(self):
        package = locked_package()
        data = json.dumps(index_entry(package)).encode("utf-8") + b"\n"
        cases = {
            "invalid JSON": (b"not JSON", 200, {}, None),
            "empty body": (b"", 200, {}, None),
            "nonobject row": (b"[]\n", 200, {}, None),
            "HTTP failure": (data, 503, {}, None),
            "truncated body": (data, 200, {"Content-Length": str(len(data) + 1)}, None),
            "unexpected redirect": (data, 200, {}, "https://example.invalid/forged"),
        }
        for kind, (body, status_code, headers, redirect) in cases.items():
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                write_reviewed_tree(root)
                write_lockfile(root, [package])

                def fetch(request, **kwargs):
                    return IndexResponse(redirect or request.full_url, body, status_code, headers)

                status, stdout, stderr, _calls, _http = self.run_gate(root, http=fetch)
                self.assertEqual(status, 2, stderr)
                self.assertNotIn("yanked scan complete:", stdout)

    def test_sparse_path_rules_timeout_and_response_bound(self):
        cases = (("a", "1/a"), ("ab", "2/ab"), ("Abc", "3/a/abc"), ("Cargo", "ca/rg/cargo"))
        for name, suffix in cases:
            with self.subTest(name=name):
                def fetch(request, **kwargs):
                    self.assertEqual(request.full_url, f"https://index.crates.io/{suffix}")
                    self.assertEqual(kwargs["timeout"], check_cargo_audit.INDEX_TIMEOUT_SECONDS)
                    self.assertEqual(request.get_header("Cache-control"), "no-cache")
                    return IndexResponse(request.full_url, b"{}\n")

                with mock.patch.object(
                    check_cargo_audit.urllib.request, "urlopen", side_effect=fetch
                ):
                    self.assertEqual(check_cargo_audit._fetch_crate_index(name), [{}])
        response = IndexResponse("https://index.crates.io/3/r/rsa", b"x" * 33)
        with (
            mock.patch.object(check_cargo_audit, "MAX_INDEX_BYTES", 32),
            mock.patch.object(check_cargo_audit.urllib.request, "urlopen", return_value=response),
        ):
            with self.assertRaises(check_cargo_audit.PolicyError) as raised:
                check_cargo_audit._fetch_crate_index("rsa")
        self.assertIn("byte limit", str(raised.exception))

    def test_independent_findings_cannot_hide_an_unparseable_or_failed_audit(self):
        cases = ((report(), 1), (report([vulnerability()]), 2), ([], 0), (report(count=2), 1))
        for audit_report, audit_status in cases:
            with self.subTest(report=audit_report, status=audit_status):
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    write_reviewed_tree(root)
                    package = locked_package()
                    write_lockfile(root, [package])
                    status, stdout, stderr, _calls, http = self.run_gate(
                        root,
                        entries={"rsa": [index_entry(package, yanked=True)]},
                        audit_report=audit_report,
                        audit_status=audit_status,
                    )
                    self.assertEqual(status, 2, stderr)
                    self.assertNotIn("policy passed", stdout)
                    http.assert_not_called()

    def test_local_and_git_packages_do_not_require_registry_status(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_reviewed_tree(root)
            rsa = locked_package()
            write_lockfile(
                root,
                [
                    rsa,
                    {"name": "gitforgeops", "version": "0.1.0"},
                    {
                        "name": "git-dep",
                        "version": "1.0.0",
                        "source": "git+https://example.invalid/repo#abc",
                    },
                ],
            )
            status, stdout, stderr, _calls, http = self.run_gate(
                root, entries={"rsa": [index_entry(rsa)]}
            )
            self.assertEqual(status, 0, stderr)
            self.assertIn("yanked scan complete: 1 crates.io package version(s)", stdout)
            self.assertEqual(http.call_count, 1)

    def test_candidate_rustup_store_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with mock.patch.dict(os.environ, {"RUSTUP_HOME": str(root / "toolchain")}):
                with self.assertRaises(check_cargo_audit.PolicyError) as raised:
                    with check_cargo_audit.isolated_cargo(root):
                        self.fail("candidate toolchains must not run")
            self.assertIn("RUSTUP_HOME", str(raised.exception))


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
