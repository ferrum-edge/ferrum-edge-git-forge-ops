import hashlib
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


INSTALLER = Path(__file__).parents[1] / "install-ferrum-edge.sh"
RELEASE_IDENTITY = "release-379454492"
BINARY_ASSET_ID = "537268718"
CHECKSUM_ASSET_ID = "537268721"


class InstallerTests(unittest.TestCase):
    def run_installer(
        self,
        binary: bytes,
        published_digest: str,
        expected_digest: str,
        github_token: str | None = None,
    ):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            curl = fake_bin / "curl"
            curl.write_text(
                """#!/usr/bin/env python3
import os, pathlib, sys
headers = [sys.argv[index + 1] for index, value in enumerate(sys.argv[:-1]) if value == '-H']
expected_auth = os.environ.get('FAKE_EXPECT_AUTH')
if expected_auth and expected_auth not in headers:
    raise SystemExit('missing expected authorization header')
output = pathlib.Path(sys.argv[sys.argv.index('--output') + 1])
url = next(arg for arg in sys.argv if arg.startswith('https://'))
if url.endswith('/' + os.environ['FAKE_CHECKSUM_ASSET_ID']):
    output.write_text(os.environ['FAKE_PUBLISHED'] + '  ferrum-edge-linux-x86_64\\n')
elif url.endswith('/' + os.environ['FAKE_BINARY_ASSET_ID']):
    output.write_bytes(bytes.fromhex(os.environ['FAKE_BINARY_HEX']))
else:
    raise SystemExit('unexpected asset URL: ' + url)
"""
            )
            curl.chmod(0o755)
            destination = root / "installed"
            environment = os.environ.copy()
            environment.pop("GITHUB_TOKEN", None)
            environment["PATH"] = f"{fake_bin}:{environment['PATH']}"
            environment["FAKE_BINARY_HEX"] = binary.hex()
            environment["FAKE_PUBLISHED"] = published_digest
            environment["FAKE_BINARY_ASSET_ID"] = BINARY_ASSET_ID
            environment["FAKE_CHECKSUM_ASSET_ID"] = CHECKSUM_ASSET_ID
            if github_token is not None:
                environment["GITHUB_TOKEN"] = github_token
                environment["FAKE_EXPECT_AUTH"] = f"Authorization: Bearer {github_token}"
            policy = root / "checksums.txt"
            policy.write_text(
                f"{RELEASE_IDENTITY} ferrum-edge-linux-x86_64 "
                f"{BINARY_ASSET_ID} {CHECKSUM_ASSET_ID} {expected_digest}\n"
            )
            return subprocess.run(
                [
                    "bash",
                    str(INSTALLER),
                    RELEASE_IDENTITY,
                    str(destination),
                    str(policy),
                ],
                text=True,
                capture_output=True,
                env=environment,
                check=False,
            )

    def test_valid_binary_matches_publisher_and_repository_pin(self):
        binary = b"verified ferrum edge"
        digest = hashlib.sha256(binary).hexdigest()
        result = self.run_installer(binary, digest, digest)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_github_token_authenticates_both_asset_requests(self):
        binary = b"authenticated validator"
        digest = hashlib.sha256(binary).hexdigest()
        result = self.run_installer(binary, digest, digest, github_token="test-token")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_replaced_release_assets_fail_repository_pin(self):
        trusted = hashlib.sha256(b"trusted ferrum edge").hexdigest()
        replacement = b"attacker replacement"
        replacement_digest = hashlib.sha256(replacement).hexdigest()
        result = self.run_installer(replacement, replacement_digest, trusted)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("repository-pinned SHA-256", result.stderr)

    def test_binary_that_disagrees_with_published_checksum_fails(self):
        binary = b"download corruption"
        expected = hashlib.sha256(binary).hexdigest()
        published = hashlib.sha256(b"different bytes").hexdigest()
        result = self.run_installer(binary, published, expected)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("published checksum", result.stderr)

    def test_release_without_a_checked_in_pin_fails_before_download(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            policy = root / "checksums.txt"
            policy.write_text(
                "release-1 ferrum-edge-linux-x86_64 1 2 " + "a" * 64 + "\n"
            )
            result = subprocess.run(
                [
                    "bash",
                    str(INSTALLER),
                    RELEASE_IDENTITY,
                    str(root / "installed"),
                    str(policy),
                ],
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("exactly one pin", result.stderr)

    def test_movable_release_tags_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            result = subprocess.run(
                ["bash", str(INSTALLER), "latest", str(root / "installed")],
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("immutable release identity", result.stderr)


if __name__ == "__main__":
    unittest.main()
