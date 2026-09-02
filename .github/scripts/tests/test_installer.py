import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


INSTALLER = Path(__file__).parents[1] / "install-ferrum-edge.sh"
ASSET = "ferrum-edge-linux-x86_64"
ASSET_BASE = "https://api.github.com/repos/ferrum-edge/ferrum-edge/releases/assets"
BINARY_ASSET_ID = "540524068"
CHECKSUM_ASSET_ID = "540524071"

# The installer reaches the network only through curl, so a fake curl on PATH
# makes every case below hermetic: no upstream release is contacted, and the
# rolling `latest` release can be reshaped per test.
FAKE_CURL = """#!/usr/bin/env python3
import os
import pathlib
import sys

argv = sys.argv[1:]
headers = [argv[index + 1] for index, value in enumerate(argv[:-1]) if value == '-H']
expected_auth = os.environ.get('FAKE_EXPECT_AUTH')
if expected_auth and expected_auth not in headers:
    raise SystemExit('missing expected authorization header')
for required in ("--proto", "--tlsv1.2", "--fail"):
    if required not in argv:
        raise SystemExit('installer must pass ' + required)
url = next(arg for arg in argv if arg.startswith('https://'))
output = pathlib.Path(argv[argv.index('--output') + 1])

if url.endswith('/releases/tags/latest'):
    if os.environ.get('FAKE_TAG_MISSING'):
        raise SystemExit(22)
    output.write_text(os.environ['FAKE_RELEASE_JSON'])
elif url.endswith('/releases?per_page=5'):
    payload = os.environ.get('FAKE_RELEASE_LIST_JSON')
    if payload is None:
        raise SystemExit(22)
    output.write_text(payload)
elif url.endswith('/' + os.environ['FAKE_CHECKSUM_ASSET_ID']):
    output.write_text(os.environ['FAKE_PUBLISHED'] + '  %s\\n')
elif url.endswith('/' + os.environ['FAKE_BINARY_ASSET_ID']):
    output.write_bytes(bytes.fromhex(os.environ['FAKE_BINARY_HEX']))
else:
    raise SystemExit('unexpected URL: ' + url)
""" % ASSET


def release(assets=(ASSET, f"{ASSET}.sha256"), tag="latest"):
    ids = {ASSET: BINARY_ASSET_ID, f"{ASSET}.sha256": CHECKSUM_ASSET_ID}
    return {
        "tag_name": tag,
        "draft": False,
        "published_at": "2026-09-02T03:02:29Z",
        "assets": [
            {"name": name, "url": f"{ASSET_BASE}/{ids[name]}"} for name in assets
        ],
    }


class InstallerTests(unittest.TestCase):
    def run_installer(
        self,
        binary: bytes,
        published_digest: str,
        allowlist_text: str,
        *,
        github_token: str | None = None,
        release_json: dict | None = None,
        release_list_json: list | None = None,
        tag_missing: bool = False,
        symlink_allowlist: bool = False,
    ):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            curl = fake_bin / "curl"
            curl.write_text(FAKE_CURL)
            curl.chmod(0o755)

            destination = root / "installed"
            environment = os.environ.copy()
            environment.pop("GITHUB_TOKEN", None)
            environment.pop("GITHUB_PATH", None)
            environment.pop("RUNNER_TEMP", None)
            environment["PATH"] = f"{fake_bin}:{environment['PATH']}"
            environment["FAKE_BINARY_HEX"] = binary.hex()
            environment["FAKE_PUBLISHED"] = published_digest
            environment["FAKE_BINARY_ASSET_ID"] = BINARY_ASSET_ID
            environment["FAKE_CHECKSUM_ASSET_ID"] = CHECKSUM_ASSET_ID
            environment["FAKE_RELEASE_JSON"] = json.dumps(
                release_json if release_json is not None else release()
            )
            if release_list_json is not None:
                environment["FAKE_RELEASE_LIST_JSON"] = json.dumps(release_list_json)
            if tag_missing:
                environment["FAKE_TAG_MISSING"] = "1"
            if github_token is not None:
                environment["GITHUB_TOKEN"] = github_token
                environment["FAKE_EXPECT_AUTH"] = f"Authorization: Bearer {github_token}"

            allowlist = root / "checksums.txt"
            if symlink_allowlist:
                real = root / "real-checksums.txt"
                real.write_text(allowlist_text)
                allowlist.symlink_to(real)
            else:
                allowlist.write_text(allowlist_text)

            result = subprocess.run(
                ["bash", str(INSTALLER), str(destination), str(allowlist)],
                text=True,
                capture_output=True,
                env=environment,
                check=False,
            )
            return result, destination.exists()

    @staticmethod
    def allowlist(*digests: str) -> str:
        header = "# Reviewed SHA-256 allowlist.\n\n"
        body = "".join(
            f"{digest}  {ASSET}  # 2026-09-0{index + 1}T00:00:00Z release latest\n"
            for index, digest in enumerate(digests)
        )
        return header + body

    def test_allowlisted_digest_installs(self):
        binary = b"verified ferrum edge"
        digest = hashlib.sha256(binary).hexdigest()
        result, installed = self.run_installer(
            binary, digest, self.allowlist(digest)
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(installed)
        self.assertIn(f"sha256:{digest}", result.stdout)
        self.assertIn("2026-09-02T03:02:29Z", result.stdout)

    def test_github_token_authenticates_every_request(self):
        binary = b"authenticated validator"
        digest = hashlib.sha256(binary).hexdigest()
        result, installed = self.run_installer(
            binary, digest, self.allowlist(digest), github_token="test-token"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(installed)

    def test_multiple_allowlist_lines_are_accepted(self):
        binary = b"second approved build"
        digest = hashlib.sha256(binary).hexdigest()
        superseded = hashlib.sha256(b"first approved build").hexdigest()
        result, installed = self.run_installer(
            binary, digest, self.allowlist(superseded, digest)
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(installed)
        self.assertIn(f"sha256:{digest}", result.stdout)

    def test_rebuilt_release_that_is_not_allowlisted_never_installs(self):
        binary = b"unreviewed upstream rebuild"
        digest = hashlib.sha256(binary).hexdigest()
        reviewed = hashlib.sha256(b"reviewed build").hexdigest()
        result, installed = self.run_installer(
            binary, digest, self.allowlist(reviewed)
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(installed, "unreviewed bytes must never become executable")
        self.assertIn("unreviewed", result.stderr)
        self.assertIn("refresh-ferrum-edge-pin.sh", result.stderr)

    def test_publisher_checksum_mismatch_fails(self):
        binary = b"download corruption"
        digest = hashlib.sha256(binary).hexdigest()
        published = hashlib.sha256(b"different bytes").hexdigest()
        result, installed = self.run_installer(
            binary, published, self.allowlist(digest)
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(installed)
        self.assertIn("published checksum", result.stderr)

    def test_missing_asset_in_the_release_fails(self):
        binary = b"unreachable"
        digest = hashlib.sha256(binary).hexdigest()
        result, installed = self.run_installer(
            binary,
            digest,
            self.allowlist(digest),
            release_json=release(assets=(f"{ASSET}.sha256",)),
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(installed)
        self.assertIn("exactly one", result.stderr)

    def test_malformed_allowlist_line_is_rejected(self):
        binary = b"never downloaded"
        digest = hashlib.sha256(binary).hexdigest()
        for malformed in (
            f"{digest.upper()}  {ASSET}\n",
            f"{digest}  ferrum-edge-macos-x86_64\n",
            f"{digest}\n",
            f"{digest}  {ASSET}  540524068\n",
        ):
            with self.subTest(malformed=malformed.strip()):
                result, installed = self.run_installer(binary, digest, malformed)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(installed)
                self.assertIn("Malformed digest allowlist entry", result.stderr)

    def test_comment_only_allowlist_approves_nothing(self):
        binary = b"never downloaded"
        digest = hashlib.sha256(binary).hexdigest()
        result, installed = self.run_installer(binary, digest, "# nothing approved\n")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(installed)
        self.assertIn("approves no", result.stderr)

    def test_symlinked_allowlist_is_rejected(self):
        binary = b"never downloaded"
        digest = hashlib.sha256(binary).hexdigest()
        result, installed = self.run_installer(
            binary, digest, self.allowlist(digest), symlink_allowlist=True
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(installed)
        self.assertIn("symlink", result.stderr)

    def test_release_list_fallback_when_the_rolling_tag_is_gone(self):
        binary = b"resolved from the release list"
        digest = hashlib.sha256(binary).hexdigest()
        result, installed = self.run_installer(
            binary,
            digest,
            self.allowlist(digest),
            tag_missing=True,
            release_list_json=[
                {
                    "tag_name": "older",
                    "draft": False,
                    "published_at": "2026-08-01T00:00:00Z",
                    "assets": [],
                },
                release(tag="rebuilt"),
            ],
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(installed)
        self.assertIn("rebuilt", result.stdout)

    def test_asset_url_outside_the_upstream_repository_is_refused(self):
        binary = b"never downloaded"
        digest = hashlib.sha256(binary).hexdigest()
        hostile = release()
        hostile["assets"][0]["url"] = "https://example.invalid/releases/assets/1"
        result, installed = self.run_installer(
            binary, digest, self.allowlist(digest), release_json=hostile
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(installed)
        self.assertIn("unexpected asset URL", result.stderr)


if __name__ == "__main__":
    unittest.main()
