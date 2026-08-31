import hashlib
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


INSTALLER = Path(__file__).parents[1] / "install-ferrum-edge.sh"


class InstallerTests(unittest.TestCase):
    def run_installer(self, binary: bytes, published_digest: str, expected_digest: str):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            curl = fake_bin / "curl"
            curl.write_text(
                """#!/usr/bin/env python3
import os, pathlib, sys
output = pathlib.Path(sys.argv[sys.argv.index('--output') + 1])
url = next(arg for arg in sys.argv if arg.startswith('https://'))
if url.endswith('.sha256'):
    output.write_text(os.environ['FAKE_PUBLISHED'] + '  ferrum-edge-linux-x86_64\\n')
else:
    output.write_bytes(bytes.fromhex(os.environ['FAKE_BINARY_HEX']))
"""
            )
            curl.chmod(0o755)
            destination = root / "installed"
            environment = os.environ.copy()
            environment["PATH"] = f"{fake_bin}:{environment['PATH']}"
            environment["FAKE_BINARY_HEX"] = binary.hex()
            environment["FAKE_PUBLISHED"] = published_digest
            policy = root / "checksums.txt"
            policy.write_text(
                f"latest ferrum-edge-linux-x86_64 {expected_digest}\n"
            )
            return subprocess.run(
                ["bash", str(INSTALLER), "latest", str(destination), str(policy)],
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
                "v1.0.0 ferrum-edge-linux-x86_64 " + "a" * 64 + "\n"
            )
            result = subprocess.run(
                [
                    "bash",
                    str(INSTALLER),
                    "latest",
                    str(root / "installed"),
                    str(policy),
                ],
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("exactly one pin", result.stderr)


if __name__ == "__main__":
    unittest.main()
