import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "credential_bundles.py"
SPEC = importlib.util.spec_from_file_location("credential_bundles", SCRIPT)
assert SPEC and SPEC.loader
credential_bundles = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(credential_bundles)


class CredentialBundleTests(unittest.TestCase):
    def test_extract_preserves_valid_bundle_strings_in_a_private_file(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "all.json"
            destination = root / "creds.json"
            first = json.dumps({"ferrum/app/keyauth/key": "secret"})
            second = json.dumps({"ferrum/app/jwt/secret": "long-secret"})
            source.write_text(
                json.dumps(
                    {
                        "UNRELATED": "ignored",
                        "FERRUM_CREDS_BUNDLE": first,
                        "FERRUM_CREDS_BUNDLE_1": second,
                    }
                )
            )

            self.assertEqual(credential_bundles.extract(source, destination), 2)
            self.assertEqual(
                json.loads(destination.read_text()),
                {"FERRUM_CREDS_BUNDLE": first, "FERRUM_CREDS_BUNDLE_1": second},
            )
            if os.name == "posix":
                self.assertEqual(destination.stat().st_mode & 0o777, 0o600)

    def test_invalid_outer_or_inner_json_fails_without_output(self):
        cases = [
            "not-json",
            json.dumps({"FERRUM_CREDS_BUNDLE": "not-json"}),
            json.dumps({"FERRUM_CREDS_BUNDLE": json.dumps({"slot": 123})}),
            json.dumps({"FERRUM_CREDS_BUNDLE_BAD": json.dumps({})}),
        ]
        for index, payload in enumerate(cases):
            with self.subTest(index=index), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                source = root / "all.json"
                destination = root / "creds.json"
                source.write_text(payload)
                with self.assertRaises(credential_bundles.BundleError):
                    credential_bundles.extract(source, destination)
                self.assertFalse(destination.exists())

    def test_existing_destination_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "all.json"
            destination = root / "creds.json"
            source.write_text("{}")
            destination.write_text("keep")
            with self.assertRaises(FileExistsError):
                credential_bundles.extract(source, destination)
            self.assertEqual(destination.read_text(), "keep")


if __name__ == "__main__":
    unittest.main()
