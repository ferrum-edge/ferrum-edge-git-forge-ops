import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[3]
SCRIPT = Path(__file__).parents[1] / "credential_bundles.py"
SPEC = importlib.util.spec_from_file_location("credential_bundles", SCRIPT)
assert SPEC and SPEC.loader
credential_bundles = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(credential_bundles)


class CredentialBundleTests(unittest.TestCase):
    def test_enumerated_bundle_vars_are_collected_into_a_private_file(self):
        with tempfile.TemporaryDirectory() as temp:
            destination = Path(temp) / "creds.json"
            first = json.dumps({"ferrum/app/keyauth/key": "secret"})
            second = json.dumps({"ferrum/app/jwt/secret": "long-secret"})
            environ = {
                "FERRUM_ADMIN_JWT_SECRET": "must-not-be-collected",
                "FERRUM_CREDS_BUNDLE": first,
                "FERRUM_CREDS_BUNDLE_1": second,
            }

            self.assertEqual(credential_bundles.extract(environ, destination), 2)
            self.assertEqual(
                json.loads(destination.read_text()),
                {"FERRUM_CREDS_BUNDLE": first, "FERRUM_CREDS_BUNDLE_1": second},
            )
            if os.name == "posix":
                self.assertEqual(destination.stat().st_mode & 0o777, 0o600)

    def test_unset_and_blank_bindings_are_treated_as_absent(self):
        # Every shard is bound by name in the workflow, so most of them arrive
        # empty on a repository that has allocated only a handful of slots.
        with tempfile.TemporaryDirectory() as temp:
            destination = Path(temp) / "creds.json"
            bundle = json.dumps({"ferrum/app/keyauth/key": "secret"})
            environ = {name: "" for name in credential_bundles.bundle_names()}
            environ["FERRUM_CREDS_BUNDLE_2"] = bundle
            environ["FERRUM_CREDS_BUNDLE_3"] = "   \n"
            del environ["FERRUM_CREDS_BUNDLE_4"]

            self.assertEqual(credential_bundles.extract(environ, destination), 1)
            self.assertEqual(
                json.loads(destination.read_text()),
                {"FERRUM_CREDS_BUNDLE_2": bundle},
            )

    def test_no_bundles_at_all_still_publishes_an_empty_payload(self):
        with tempfile.TemporaryDirectory() as temp:
            destination = Path(temp) / "creds.json"
            self.assertEqual(credential_bundles.extract({}, destination), 0)
            self.assertEqual(json.loads(destination.read_text()), {})

    def test_malformed_bundles_fail_closed_without_output(self):
        cases = [
            {"FERRUM_CREDS_BUNDLE": "not-json"},
            {"FERRUM_CREDS_BUNDLE": json.dumps({"slot": 123})},
            {"FERRUM_CREDS_BUNDLE_1": json.dumps(["slot"])},
            # Named outside the bound range: silently dropping it would make
            # the binary re-allocate every slot the shard holds.
            {"FERRUM_CREDS_BUNDLE_0": json.dumps({})},
            {
                f"FERRUM_CREDS_BUNDLE_{credential_bundles.MAX_BUNDLE_SHARDS}": json.dumps(
                    {"slot": "value"}
                )
            },
            {"FERRUM_CREDS_BUNDLE_BAD": json.dumps({})},
        ]
        for index, environ in enumerate(cases):
            with self.subTest(index=index), tempfile.TemporaryDirectory() as temp:
                destination = Path(temp) / "creds.json"
                with self.assertRaises(credential_bundles.BundleError):
                    credential_bundles.extract(environ, destination)
                self.assertFalse(destination.exists())

    def test_existing_destination_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as temp:
            destination = Path(temp) / "creds.json"
            destination.write_text("keep")
            with self.assertRaises(FileExistsError):
                credential_bundles.extract({}, destination)
            self.assertEqual(destination.read_text(), "keep")

    def test_cli_reads_the_process_environment_and_logs_no_secret_bytes(self):
        with tempfile.TemporaryDirectory() as temp:
            destination = Path(temp) / "creds.json"
            environ = dict(os.environ)
            environ["FERRUM_CREDS_BUNDLE"] = json.dumps(
                {"ferrum/app/keyauth/key": "s3cr3t-value"}
            )
            result = subprocess.run(
                [sys.executable, str(SCRIPT), str(destination)],
                env=environ,
                check=False,
                text=True,
                capture_output=True,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("Loaded 1 credential slot(s)", result.stdout)
            self.assertNotIn("s3cr3t-value", result.stdout + result.stderr)
            self.assertEqual(
                json.loads(destination.read_text()),
                {"FERRUM_CREDS_BUNDLE": environ["FERRUM_CREDS_BUNDLE"]},
            )

    def test_shard_ceiling_matches_the_rust_constant(self):
        source = (ROOT / "src/secrets/bundle.rs").read_text(encoding="utf-8")
        match = re.search(
            r"^pub const MAX_BUNDLE_SHARDS\s*:\s*u32\s*=\s*(\d+)\s*;",
            source,
            re.MULTILINE,
        )
        self.assertIsNotNone(match, "src/secrets/bundle.rs must declare the ceiling")
        self.assertEqual(int(match.group(1)), credential_bundles.MAX_BUNDLE_SHARDS)
        self.assertEqual(
            credential_bundles.bundle_names()[-1],
            f"FERRUM_CREDS_BUNDLE_{credential_bundles.MAX_BUNDLE_SHARDS - 1}",
        )


if __name__ == "__main__":
    unittest.main()
