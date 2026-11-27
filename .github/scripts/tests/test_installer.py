import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


SCRIPTS = Path(__file__).parents[1]
INSTALLER = SCRIPTS / "install-ferrum-edge.sh"
REFRESH = SCRIPTS / "refresh-ferrum-edge-pin.sh"
ASSET = "ferrum-edge-linux-x86_64"
ASSET_BASE = "https://api.github.com/repos/ferrum-edge/ferrum-edge/releases/assets"
BINARY_ASSET_ID = "540524068"
CHECKSUM_ASSET_ID = "540524071"
PINNED_TAG = "v0.9.21"

# The scripts reach the network only through curl, so a fake curl on PATH makes
# every case below hermetic: no upstream release is contacted, and the pinned
# release, the newest release and the release list can be reshaped per test.
# Every URL the fake serves is logged so a test can prove which release was
# resolved.
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
        raise SystemExit('script must pass ' + required)
url = next(arg for arg in argv if arg.startswith('https://'))
output = pathlib.Path(argv[argv.index('--output') + 1])
with open(os.environ['FAKE_URL_LOG'], 'a') as log:
    log.write(url + '\\n')

tags_prefix = 'https://api.github.com/repos/ferrum-edge/ferrum-edge/releases/tags/'
if url.endswith('/releases/latest'):
    if os.environ.get('FAKE_LATEST_MISSING'):
        raise SystemExit(22)
    output.write_text(os.environ['FAKE_LATEST_JSON'])
elif url.endswith('/releases?per_page=5'):
    payload = os.environ.get('FAKE_RELEASE_LIST_JSON')
    if payload is None:
        raise SystemExit(22)
    output.write_text(payload)
elif url.startswith(tags_prefix):
    payload = os.environ.get('FAKE_TAG_JSON')
    if payload is None or url[len(tags_prefix):] != os.environ['FAKE_TAG']:
        raise SystemExit(22)
    output.write_text(payload)
elif url.endswith('/' + os.environ['FAKE_CHECKSUM_ASSET_ID']):
    output.write_text(os.environ['FAKE_PUBLISHED'] + '  %s\\n')
elif url.endswith('/' + os.environ['FAKE_BINARY_ASSET_ID']):
    output.write_bytes(bytes.fromhex(os.environ['FAKE_BINARY_HEX']))
else:
    raise SystemExit('unexpected URL: ' + url)
""" % ASSET


def release(
    assets=(ASSET, f"{ASSET}.sha256"),
    tag=PINNED_TAG,
    *,
    draft=False,
    prerelease=False,
    published_at="2026-11-22T06:29:03Z",
):
    ids = {ASSET: BINARY_ASSET_ID, f"{ASSET}.sha256": CHECKSUM_ASSET_ID}
    return {
        "tag_name": tag,
        "draft": draft,
        "prerelease": prerelease,
        "published_at": published_at,
        "assets": [
            {"name": name, "url": f"{ASSET_BASE}/{ids[name]}"} for name in assets
        ],
    }


def baseline(tag=PINNED_TAG, sha256="0" * 64, asset=ASSET):
    return {
        "schema_version": 1,
        "status": "pending",
        "validator": {"version": tag, "asset": asset, "sha256": sha256},
        "tested_gateway": {"version": tag, "binary_sha256": sha256},
    }


def allowlist(*digests: str) -> str:
    header = "# Reviewed SHA-256 allowlist.\n\n"
    body = "".join(
        f"{digest}  {ASSET}  # 2026-11-0{index + 1}T00:00:00Z release v0.9.{19 + index}\n"
        for index, digest in enumerate(digests)
    )
    return header + body


class Harness:
    """A throwaway repository layout (`.github/ferrum-edge-checksums.txt` and
    `release/baseline.json`) plus the fake network."""

    def __init__(
        self,
        binary: bytes,
        published_digest: str,
        allowlist_text: str,
        baseline_record,
        *,
        github_token: str | None = None,
        tag_json=None,
        tag: str = PINNED_TAG,
        latest_json=None,
        release_list_json=None,
        latest_missing: bool = False,
        symlink_allowlist: bool = False,
        symlink_baseline: bool = False,
    ):
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.root = root
        fake_bin = root / "bin"
        fake_bin.mkdir()
        curl = fake_bin / "curl"
        curl.write_text(FAKE_CURL)
        curl.chmod(0o755)
        self.url_log = root / "urls.log"
        self.url_log.write_text("")

        self.repo = root / "repo"
        (self.repo / ".github").mkdir(parents=True)
        (self.repo / "release").mkdir()
        self.allowlist = self.repo / ".github/ferrum-edge-checksums.txt"
        self.baseline = self.repo / "release/baseline.json"
        self._write(self.allowlist, allowlist_text, symlink_allowlist)
        baseline_text = (
            baseline_record
            if isinstance(baseline_record, str)
            else json.dumps(baseline_record)
        )
        self._write(self.baseline, baseline_text, symlink_baseline)

        environment = os.environ.copy()
        for name in ("GITHUB_TOKEN", "GITHUB_PATH", "RUNNER_TEMP"):
            environment.pop(name, None)
        environment["PATH"] = f"{fake_bin}:{environment['PATH']}"
        environment["FAKE_URL_LOG"] = str(self.url_log)
        environment["FAKE_BINARY_HEX"] = binary.hex()
        environment["FAKE_PUBLISHED"] = published_digest
        environment["FAKE_BINARY_ASSET_ID"] = BINARY_ASSET_ID
        environment["FAKE_CHECKSUM_ASSET_ID"] = CHECKSUM_ASSET_ID
        environment["FAKE_TAG"] = tag
        environment["FAKE_TAG_JSON"] = json.dumps(
            tag_json if tag_json is not None else release(tag=tag)
        )
        environment["FAKE_LATEST_JSON"] = json.dumps(
            latest_json if latest_json is not None else release(tag=tag)
        )
        if release_list_json is not None:
            environment["FAKE_RELEASE_LIST_JSON"] = json.dumps(release_list_json)
        if latest_missing:
            environment["FAKE_LATEST_MISSING"] = "1"
        if github_token is not None:
            environment["GITHUB_TOKEN"] = github_token
            environment["FAKE_EXPECT_AUTH"] = f"Authorization: Bearer {github_token}"
        self.environment = environment
        self.destination = root / "installed"

    def _write(self, path: Path, text: str, symlink: bool):
        if symlink:
            real = self.root / f"real-{path.name}"
            real.write_text(text)
            path.symlink_to(real)
        else:
            path.write_text(text)

    def close(self):
        self.temporary.cleanup()

    def urls(self) -> list[str]:
        return self.url_log.read_text().splitlines()

    def install(self, *extra: str):
        result = subprocess.run(
            ["bash", str(INSTALLER), str(self.destination), str(self.allowlist), *extra],
            text=True,
            capture_output=True,
            env=self.environment,
            check=False,
        )
        return result, self.destination.exists()

    def refresh(self, *args: str):
        return subprocess.run(
            ["bash", str(REFRESH), *args],
            text=True,
            capture_output=True,
            env=self.environment,
            check=False,
        )


class InstallerTests(unittest.TestCase):
    def harness(self, binary, published, allowlist_text, baseline_record, **options):
        harness = Harness(binary, published, allowlist_text, baseline_record, **options)
        self.addCleanup(harness.close)
        return harness

    def pinned(self, binary: bytes, **options):
        digest = hashlib.sha256(binary).hexdigest()
        return self.harness(
            binary, digest, allowlist(digest), baseline(sha256=digest), **options
        ), digest

    def test_pinned_release_installs_from_its_tag(self):
        harness, digest = self.pinned(b"verified ferrum edge")
        result, installed = harness.install()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(installed)
        self.assertIn(f"sha256:{digest}", result.stdout)
        self.assertIn(f"from release {PINNED_TAG}", result.stdout)
        self.assertIn(
            f"https://api.github.com/repos/ferrum-edge/ferrum-edge/releases/tags/{PINNED_TAG}",
            harness.urls(),
        )

    def test_the_baseline_beside_the_allowlist_is_the_default(self):
        # The third argument is optional: the baseline comes from the same
        # tree as the allowlist. An explicit path works too.
        harness, _ = self.pinned(b"default baseline")
        moved = harness.root / "elsewhere.json"
        moved.write_text(harness.baseline.read_text())
        harness.baseline.unlink()
        result, installed = harness.install()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(installed)
        self.assertIn("Release baseline is missing", result.stderr)
        result, installed = harness.install(str(moved))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(installed)

    def test_a_newer_upstream_release_is_reported_but_never_installed(self):
        harness, digest = self.pinned(
            b"pinned build", latest_json=release(tag="v0.9.22")
        )
        result, installed = harness.install()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(installed)
        self.assertIn("newest published Ferrum Edge release is v0.9.22", result.stderr)
        self.assertIn(f"pins {PINNED_TAG}", result.stderr)
        self.assertIn(f"from release {PINNED_TAG}", result.stdout)
        self.assertNotIn(
            "https://api.github.com/repos/ferrum-edge/ferrum-edge/releases/tags/v0.9.22",
            harness.urls(),
        )

    def test_newest_lookup_failure_does_not_fail_the_pinned_install(self):
        harness, _ = self.pinned(b"offline newest", latest_missing=True)
        result, installed = harness.install()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(installed)
        self.assertIn("could not be determined", result.stderr)

    def test_release_list_fallback_reports_the_newest_published_release(self):
        harness, _ = self.pinned(
            b"fallback newest",
            latest_missing=True,
            release_list_json=[
                release(tag="v0.9.23-rc.1", prerelease=True, published_at="2026-12-03T00:00:00Z"),
                release(tag="v0.9.23", draft=True, published_at="2026-12-02T00:00:00Z"),
                release(tag="v0.9.22", published_at="2026-12-01T00:00:00Z"),
                release(tag=PINNED_TAG),
            ],
        )
        result, installed = harness.install()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(installed)
        self.assertIn("newest published Ferrum Edge release is v0.9.22", result.stderr)
        self.assertNotIn("v0.9.23", result.stderr)

    def test_github_token_authenticates_every_request(self):
        harness, _ = self.pinned(b"authenticated validator", github_token="test-token")
        result, installed = harness.install()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(installed)

    def test_previous_allowlist_lines_are_kept_but_only_the_pin_installs(self):
        binary = b"second approved build"
        digest = hashlib.sha256(binary).hexdigest()
        superseded = hashlib.sha256(b"first approved build").hexdigest()
        harness = self.harness(
            binary, digest, allowlist(superseded, digest), baseline(sha256=digest)
        )
        result, installed = harness.install()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(installed)

    def test_baseline_digest_missing_from_the_allowlist_fails_before_any_download(self):
        binary = b"unreviewed pin"
        digest = hashlib.sha256(binary).hexdigest()
        reviewed = hashlib.sha256(b"reviewed build").hexdigest()
        harness = self.harness(binary, digest, allowlist(reviewed), baseline(sha256=digest))
        result, installed = harness.install()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(installed)
        self.assertIn("does not approve", result.stderr)
        self.assertIn("refresh-ferrum-edge-pin.sh", result.stderr)
        self.assertEqual(harness.urls(), [])

    def test_rebuilt_release_that_is_not_the_pinned_build_never_installs(self):
        # The publisher checksum agrees with the bytes, but the bytes are not
        # the build the baseline (and allowlist) approved.
        rebuilt = b"unreviewed upstream rebuild"
        rebuilt_digest = hashlib.sha256(rebuilt).hexdigest()
        reviewed = hashlib.sha256(b"reviewed build").hexdigest()
        harness = self.harness(
            rebuilt, rebuilt_digest, allowlist(reviewed), baseline(sha256=reviewed)
        )
        result, installed = harness.install()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(installed, "unpinned bytes must never become executable")
        self.assertIn("does not pin", result.stderr)

    def test_publisher_checksum_mismatch_fails(self):
        binary = b"download corruption"
        digest = hashlib.sha256(binary).hexdigest()
        published = hashlib.sha256(b"different bytes").hexdigest()
        harness = self.harness(binary, published, allowlist(digest), baseline(sha256=digest))
        result, installed = harness.install()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(installed)
        self.assertIn("published checksum", result.stderr)

    def test_pinned_tag_that_is_draft_prerelease_or_another_tag_is_refused(self):
        binary = b"never installed"
        digest = hashlib.sha256(binary).hexdigest()
        for tag_json in (
            release(draft=True),
            release(prerelease=True),
            release(tag="v0.9.22"),
            {"message": "Not Found"},
        ):
            with self.subTest(tag_json=tag_json):
                harness = self.harness(
                    binary, digest, allowlist(digest), baseline(sha256=digest), tag_json=tag_json
                )
                result, installed = harness.install()
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(installed)
                self.assertIn("not a published", result.stderr)

    def test_unresolvable_pinned_tag_fails(self):
        binary = b"never installed"
        digest = hashlib.sha256(binary).hexdigest()
        harness = self.harness(
            binary, digest, allowlist(digest), baseline(sha256=digest), tag="v0.9.99"
        )
        result, installed = harness.install()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(installed)
        self.assertIn(f"Cannot resolve the pinned Ferrum Edge release {PINNED_TAG}", result.stderr)

    def test_malformed_baseline_is_refused_before_any_download(self):
        binary = b"never downloaded"
        digest = hashlib.sha256(binary).hexdigest()
        for record, message in (
            ("not json", "must name validator.version"),
            ({"validator": {"version": PINNED_TAG, "asset": ASSET}}, "must name validator.version"),
            (baseline(tag="v0.9.21-rc.1", sha256=digest), "invalid validator version"),
            (baseline(tag="latest", sha256=digest), "invalid validator version"),
            (baseline(tag="0.9.21", sha256=digest), "invalid validator version"),
            (baseline(sha256=digest, asset="ferrum-edge-linux-aarch64"), "installs only"),
            (baseline(sha256=digest.upper()), "64 lowercase hex"),
        ):
            with self.subTest(record=record):
                harness = self.harness(binary, digest, allowlist(digest), record)
                result, installed = harness.install()
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(installed)
                self.assertIn(message, result.stderr)
                self.assertEqual(harness.urls(), [])

    def test_symlinked_baseline_is_rejected(self):
        binary = b"never downloaded"
        digest = hashlib.sha256(binary).hexdigest()
        harness = self.harness(
            binary, digest, allowlist(digest), baseline(sha256=digest), symlink_baseline=True
        )
        result, installed = harness.install()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(installed)
        self.assertIn("symlink", result.stderr)

    def test_missing_asset_in_the_release_fails(self):
        binary = b"unreachable"
        digest = hashlib.sha256(binary).hexdigest()
        harness = self.harness(
            binary,
            digest,
            allowlist(digest),
            baseline(sha256=digest),
            tag_json=release(assets=(f"{ASSET}.sha256",)),
        )
        result, installed = harness.install()
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
                harness = self.harness(binary, digest, malformed, baseline(sha256=digest))
                result, installed = harness.install()
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(installed)
                self.assertIn("Malformed digest allowlist entry", result.stderr)

    def test_comment_only_allowlist_approves_nothing(self):
        binary = b"never downloaded"
        digest = hashlib.sha256(binary).hexdigest()
        harness = self.harness(binary, digest, "# nothing approved\n", baseline(sha256=digest))
        result, installed = harness.install()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(installed)
        self.assertIn("approves no", result.stderr)

    def test_symlinked_allowlist_is_rejected(self):
        binary = b"never downloaded"
        digest = hashlib.sha256(binary).hexdigest()
        harness = self.harness(
            binary, digest, allowlist(digest), baseline(sha256=digest), symlink_allowlist=True
        )
        result, installed = harness.install()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(installed)
        self.assertIn("symlink", result.stderr)

    def test_asset_url_outside_the_upstream_repository_is_refused(self):
        binary = b"never downloaded"
        digest = hashlib.sha256(binary).hexdigest()
        hostile = release()
        hostile["assets"][0]["url"] = "https://example.invalid/releases/assets/1"
        harness = self.harness(
            binary, digest, allowlist(digest), baseline(sha256=digest), tag_json=hostile
        )
        result, installed = harness.install()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(installed)
        self.assertIn("unexpected asset URL", result.stderr)


class RefreshPinTests(unittest.TestCase):
    def harness(self, binary, published, allowlist_text, baseline_record, **options):
        harness = Harness(binary, published, allowlist_text, baseline_record, **options)
        self.addCleanup(harness.close)
        return harness

    def test_default_resolves_the_baseline_pin_and_checks_its_digest(self):
        binary = b"pinned refresh"
        digest = hashlib.sha256(binary).hexdigest()
        harness = self.harness(binary, digest, "# empty\n", baseline(sha256=digest))
        result = harness.refresh("--baseline", str(harness.baseline))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout,
            f"{digest}  {ASSET}  # 2026-11-22T06:29:03Z release {PINNED_TAG}\n",
        )
        self.assertNotIn(
            "https://api.github.com/repos/ferrum-edge/ferrum-edge/releases/latest",
            harness.urls(),
        )

    def test_default_refuses_bytes_the_baseline_does_not_pin(self):
        binary = b"rebuilt refresh"
        digest = hashlib.sha256(binary).hexdigest()
        harness = self.harness(binary, digest, "# empty\n", baseline(sha256="1" * 64))
        result = harness.refresh("--baseline", str(harness.baseline))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertIn("does not match the digest release/baseline.json pins", result.stderr)

    def test_explicit_release_moves_the_pin_and_appends(self):
        binary = b"next release"
        digest = hashlib.sha256(binary).hexdigest()
        harness = self.harness(
            binary,
            digest,
            "# reviewed\n",
            baseline(sha256="1" * 64),
            tag="v0.9.22",
            tag_json=release(tag="v0.9.22", published_at="2026-12-01T00:00:00Z"),
        )
        result = harness.refresh(
            "--release", "v0.9.22", "--append", "--allowlist", str(harness.allowlist)
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        line = f"{digest}  {ASSET}  # 2026-12-01T00:00:00Z release v0.9.22\n"
        self.assertEqual(result.stdout, line)
        self.assertTrue(harness.allowlist.read_text().endswith(line))

    def test_explicit_release_must_be_a_plain_version_tag(self):
        harness = self.harness(b"x", "0" * 64, "# reviewed\n", baseline())
        for tag in ("latest", "v0.9.22-rc.1", "0.9.22", "v0.9"):
            with self.subTest(tag=tag):
                result = harness.refresh("--release", tag)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("expected vMAJOR.MINOR.PATCH", result.stderr)
        self.assertEqual(harness.urls(), [])

    def test_prerelease_or_draft_release_is_refused(self):
        binary = b"prerelease"
        digest = hashlib.sha256(binary).hexdigest()
        for tag_json in (release(prerelease=True), release(draft=True)):
            with self.subTest(tag_json=tag_json):
                harness = self.harness(
                    binary, digest, "# empty\n", baseline(sha256=digest), tag_json=tag_json
                )
                result = harness.refresh("--baseline", str(harness.baseline))
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("not a published", result.stderr)

    def test_newest_prints_only_the_newest_published_tag(self):
        harness = self.harness(
            b"x", "0" * 64, "# empty\n", baseline(), latest_json=release(tag="v0.9.22")
        )
        result = harness.refresh("--newest")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "v0.9.22\n")
        self.assertFalse(
            any("/releases/assets/" in url for url in harness.urls()),
            "--newest must not download any asset",
        )

    def test_newest_falls_back_to_the_published_release_list(self):
        harness = self.harness(
            b"x",
            "0" * 64,
            "# empty\n",
            baseline(),
            latest_missing=True,
            release_list_json=[
                release(tag="latest", prerelease=True, published_at="2026-12-03T00:00:00Z"),
                release(tag="v0.9.23", draft=True, published_at="2026-12-02T00:00:00Z"),
                release(tag="v0.9.22", published_at="2026-12-01T00:00:00Z"),
                release(tag=PINNED_TAG),
            ],
        )
        result = harness.refresh("--newest")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "v0.9.22\n")

    def test_newest_cannot_append(self):
        harness = self.harness(b"x", "0" * 64, "# empty\n", baseline())
        result = harness.refresh("--newest", "--append")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("cannot be combined", result.stderr)


if __name__ == "__main__":
    unittest.main()
