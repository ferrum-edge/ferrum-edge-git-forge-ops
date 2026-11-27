"""The release record must stay aligned with the version, docs, and gateway pin."""

import importlib.util
import json
import os
import re
import shutil
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / ".github/scripts/check_release_baseline.py"
SPEC = importlib.util.spec_from_file_location("check_release_baseline", SCRIPT)
check_release_baseline = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = check_release_baseline
SPEC.loader.exec_module(check_release_baseline)

RECORD = json.loads((ROOT / "release/baseline.json").read_text(encoding="utf-8"))
NOTES = check_release_baseline.notes_path(RECORD)
EDGE_VERSION = RECORD["validator"]["version"]

INPUTS = (
    "Cargo.toml",
    "README.md",
    "docs/quickstart.md",
    "release/baseline.json",
    "release/README.md",
    NOTES,
    ".github/ferrum-edge-checksums.txt",
    ".github/workflows/release.yml",
    "Dockerfile",
    "contracts/ferrum-contracts/PIN",
    "src/config/edge_version.rs",
    "release/records/README.md",
)
TAG = RECORD["gitforgeops"]["tag"]
RUN_URL = "https://github.com/ferrum-edge/ferrum-edge-git-forge-ops/actions/runs/123"


@unittest.skipIf(
    os.environ.get("GITHUB_REPOSITORY", "ferrum-edge/ferrum-edge-git-forge-ops")
    != "ferrum-edge/ferrum-edge-git-forge-ops",
    "the upstream release baseline does not constrain customer copies",
)
class ReleaseBaselineTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        for relative in INPUTS:
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, target)

    def record(self):
        return json.loads((self.root / "release/baseline.json").read_text())

    def write_record(self, record):
        (self.root / "release/baseline.json").write_text(
            json.dumps(record), encoding="utf-8"
        )

    def finalized(self):
        """The committed candidate, finalized as a published release."""
        record = json.loads(json.dumps(RECORD))
        record["status"] = "supported"
        record["gitforgeops"]["source_sha"] = "a" * 40
        record["gitforgeops"]["image_digest"] = "sha256:" + "b" * 64
        record["lifecycle"]["run_url"] = RUN_URL
        return record

    def write_finalized(self, record, name=None):
        path = self.root / "release/records" / (name or f"{record['gitforgeops']['tag']}.json")
        path.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
        return path

    def prepare_next_patch(self):
        """Publish the candidate, then move the candidate to the next patch."""
        published = self.finalized()
        self.write_finalized(published)
        major, minor, patch = (int(part) for part in TAG[1:].split("."))
        version = f"{major}.{minor}.{patch + 1}"
        cargo = self.root / "Cargo.toml"
        text = cargo.read_text(encoding="utf-8")
        changed = text.replace(f'version = "{TAG[1:]}"', f'version = "{version}"', 1)
        self.assertNotEqual(changed, text)
        cargo.write_text(changed, encoding="utf-8")
        record = json.loads(json.dumps(RECORD))
        record["gitforgeops"]["version"] = version
        record["gitforgeops"]["tag"] = f"v{version}"
        self.write_record(record)
        notes = (self.root / NOTES).read_text(encoding="utf-8")
        (self.root / f"release/notes-v{version}.md").write_text(
            notes.replace(f"# GitForgeOps {TAG} release notes", f"# GitForgeOps v{version} release notes"),
            encoding="utf-8",
        )
        quickstart = self.root / "docs/quickstart.md"
        text = quickstart.read_text(encoding="utf-8")
        changed = text.replace(
            f"Release baseline: [{TAG}](../release/README.md)",
            f"Release baseline: [v{version}](../release/README.md)",
        )
        self.assertNotEqual(changed, text)
        quickstart.write_text(changed, encoding="utf-8")
        return f"v{version}"

    def test_pending_baseline_is_consistent(self):
        self.assertEqual(check_release_baseline.check(self.root), [])

    def test_a_finalized_release_has_an_identical_record(self):
        record = self.finalized()
        self.write_record(record)
        self.assertIn(
            f"a supported baseline must be finalized as release/records/{TAG}.json "
            "with identical content",
            check_release_baseline.check(self.root),
        )
        self.write_finalized(record)
        self.assertEqual(check_release_baseline.check(self.root), [])

        changed = json.loads(json.dumps(record))
        changed["lifecycle"]["run_url"] = RUN_URL + "4"
        self.write_finalized(changed)
        self.assertIn(
            f"a supported baseline must be finalized as release/records/{TAG}.json "
            "with identical content",
            check_release_baseline.check(self.root),
        )

    def test_preparing_the_next_patch_keeps_the_published_record_and_milestone(self):
        candidate = self.prepare_next_patch()
        # The README keeps naming the first supported baseline, not the
        # candidate, and the published record stays supported.
        self.assertEqual(check_release_baseline.check(self.root), [])
        readme = self.root / "README.md"
        text = readme.read_text(encoding="utf-8")
        readme.write_text(
            text.replace(
                f"First supported baseline: [{TAG}](release/README.md)",
                f"First supported baseline: [{candidate}](release/README.md)",
            ),
            encoding="utf-8",
        )
        self.assertEqual(
            check_release_baseline.check(self.root),
            [f"README Development status must link to the first supported baseline {TAG}"],
        )

    def test_a_published_release_cannot_be_reopened_as_pending(self):
        self.write_finalized(self.finalized())
        self.assertEqual(
            check_release_baseline.check(self.root),
            [
                f"release/records/{TAG}.json is already finalized; prepare a new version "
                "instead of reopening a published one"
            ],
        )

    def test_records_must_be_complete_finalized_and_named_for_their_tag(self):
        self.prepare_next_patch()
        for mutate, expected in (
            (lambda r: r.__setitem__("status", "pending"), "must be finalized with status supported"),
            (lambda r: r["gitforgeops"].__setitem__("source_sha", None), "needs an exact source SHA"),
            (lambda r: r["gitforgeops"].__setitem__("image_digest", "latest"), "needs an immutable image digest"),
            (lambda r: r["lifecycle"].__setitem__("run_url", None), "needs a lifecycle run URL"),
            (lambda r: r["validator"].__setitem__("sha256", "0" * 64), "one allowlisted validator"),
            (lambda r: r["tested_gateway"].__setitem__("image_digest", None), "tested gateway image digest"),
        ):
            with self.subTest(expected=expected):
                record = self.finalized()
                mutate(record)
                self.write_finalized(record)
                issues = check_release_baseline.check(self.root)
                self.assertTrue(any(expected in issue for issue in issues), issues)
        self.write_finalized(self.finalized())
        self.assertEqual(check_release_baseline.check(self.root), [])

        wrong = self.write_finalized(self.finalized(), name="v9.9.9.json")
        issues = check_release_baseline.check(self.root)
        self.assertIn(f"release/records/v9.9.9.json must be named {TAG}.json", issues)
        wrong.unlink()

        (self.root / NOTES).unlink()
        issues = check_release_baseline.check(self.root)
        self.assertTrue(any("must stay committed" in issue for issue in issues), issues)

    def test_supported_baseline_requires_all_release_evidence(self):
        record = self.record()
        record["status"] = "supported"
        record["gitforgeops"]["source_sha"] = None
        record["gitforgeops"]["image_digest"] = None
        record["lifecycle"]["run_url"] = None
        self.write_record(record)
        # Three missing evidence fields, and no finalized record.
        self.assertEqual(len(check_release_baseline.check(self.root)), 4)

        record["gitforgeops"]["source_sha"] = "a" * 40
        record["gitforgeops"]["image_digest"] = "sha256:" + "b" * 64
        record["lifecycle"]["run_url"] = RUN_URL
        self.write_record(record)
        self.write_finalized(record)
        self.assertEqual(check_release_baseline.check(self.root), [])

    def test_pending_record_rejects_partial_publication(self):
        record = self.record()
        record["status"] = "pending"
        record["gitforgeops"]["source_sha"] = "a" * 40
        self.write_record(record)
        self.assertTrue(any("pending" in issue for issue in check_release_baseline.check(self.root)))

    def test_wrong_validator_pin_or_gateway_base_is_rejected(self):
        record = self.record()
        record["validator"]["sha256"] = "0" * 64
        self.write_record(record)
        issues = check_release_baseline.check(self.root)
        self.assertTrue(any("allowlist" in issue for issue in issues), issues)
        self.assertTrue(any("gateway binary" in issue for issue in issues), issues)

        record = self.record()
        record["tested_gateway"]["image_digest"] = "sha256:" + "0" * 64
        self.write_record(record)
        issues = check_release_baseline.check(self.root)
        self.assertTrue(any("Dockerfile gateway base" in issue for issue in issues), issues)

        # Start again from the committed record: the cases above rewrote it.
        record = json.loads(json.dumps(RECORD))
        record["validator"]["version"] = "v0.9.14"
        self.write_record(record)
        issues = check_release_baseline.check(self.root)
        self.assertIn("validator and tested gateway versions must agree", issues)
        self.assertIn(
            f"the allowlist approves the validator SHA-256 for release {EDGE_VERSION}, "
            "not v0.9.14",
            issues,
        )
        self.assertIn("contracts PIN edge_version must match the validator version", issues)

    def test_docs_and_cargo_version_drift_are_rejected(self):
        cargo = self.root / "Cargo.toml"
        original = cargo.read_text(encoding="utf-8")
        version = tomllib.loads(original)["package"]["version"]
        major, minor, _ = (int(part) for part in version.split("."))
        changed = original.replace(
            f'version = "{version}"', f'version = "{major}.{minor + 1}.0"', 1
        )
        self.assertNotEqual(changed, original, "the package version declaration was not found")
        cargo.write_text(changed, encoding="utf-8")
        self.assertNotEqual(tomllib.loads(changed)["package"]["version"], version)
        issues = check_release_baseline.check(self.root)
        self.assertTrue(any("Cargo.toml" in issue for issue in issues), issues)
        self.assertTrue(any("README Development status" in issue for issue in issues), issues)
        self.assertTrue(any("quickstart" in issue for issue in issues), issues)

    def test_former_allowlisted_pairing_does_not_certify_the_new_baseline(self):
        record = self.record()
        previous_pin = "446e5aa4a85f03bc33a4cd2d618904a676ecf06f657954dca5b67a9563dec818"
        previous_image = "sha256:0e2ed6d720cbc474e29cfa6bcd3945db010674d69988e2bd795a26399c3cb80e"
        record["validator"]["version"] = "v0.9.19"
        record["validator"]["sha256"] = previous_pin
        record["tested_gateway"]["version"] = "v0.9.19"
        record["tested_gateway"]["binary_sha256"] = previous_pin
        record["tested_gateway"]["image_digest"] = previous_image
        self.write_record(record)
        (self.root / "Dockerfile").write_text(
            f"FROM ferrumedge/ferrum-edge:v0.9.19@{previous_image} AS ferrum-edge\n"
        )
        # The former pairing is internally consistent (allowlist note,
        # Dockerfile), but the contracts pin, the CLI default and the docs all
        # name the current pairing, so it cannot certify a release.
        self.assertEqual(
            check_release_baseline.check(self.root),
            [
                "contracts PIN edge_version must match the validator version",
                "DEFAULT_EDGE_VERSION must match the validator version",
                "release notes must name the paired Ferrum Edge version",
                "release/README.md must name the paired Ferrum Edge version",
            ],
        )

    def test_release_notes_file_follows_the_recorded_tag(self):
        self.assertEqual(NOTES, f"release/notes-{RECORD['gitforgeops']['tag']}.md")
        (self.root / NOTES).unlink()
        issues = check_release_baseline.check(self.root)
        self.assertEqual(len(issues), 1, issues)
        self.assertIn("release baseline input cannot be read", issues[0])

        record = self.record()
        record["gitforgeops"]["tag"] = "v1.0.0-rc.1"
        self.write_record(record)
        self.assertEqual(
            check_release_baseline.check(self.root),
            ["release/baseline.json must name a vMAJOR.MINOR.PATCH gitforgeops.tag"],
        )

    def test_edge_version_must_be_a_plain_release_tag(self):
        for version in ("latest", f"{EDGE_VERSION}-rc.1", EDGE_VERSION.removeprefix("v")):
            with self.subTest(version=version):
                record = self.record()
                record["validator"]["version"] = version
                record["tested_gateway"]["version"] = version
                self.write_record(record)
                issues = check_release_baseline.check(self.root)
                self.assertIn(
                    "validator version must be a vMAJOR.MINOR.PATCH Ferrum Edge release tag",
                    issues,
                )

    def test_every_pairing_copy_must_follow_the_baseline(self):
        for relative, needle in (
            ("contracts/ferrum-contracts/PIN", f"edge_version={EDGE_VERSION}"),
            ("src/config/edge_version.rs", "pub const DEFAULT_EDGE_VERSION"),
            (NOTES, f"Ferrum Edge {EDGE_VERSION}"),
            ("release/README.md", f"Ferrum Edge {EDGE_VERSION}"),
        ):
            with self.subTest(relative=relative):
                path = self.root / relative
                original = path.read_text(encoding="utf-8")
                self.assertIn(needle, original)
                path.write_text(original.replace(needle, "stale"), encoding="utf-8")
                self.assertEqual(len(check_release_baseline.check(self.root)), 1)
                path.write_text(original, encoding="utf-8")
        self.assertEqual(check_release_baseline.check(self.root), [])

    def test_allowlist_line_must_name_the_pinned_release(self):
        policy = self.root / ".github/ferrum-edge-checksums.txt"
        pin = self.record()["validator"]["sha256"]
        lines = policy.read_text(encoding="utf-8").splitlines(keepends=True)
        changed = [
            f"{pin}  ferrum-edge-linux-x86_64  # reviewed\n"
            if line.startswith(f"{pin} ")
            else line
            for line in lines
        ]
        self.assertNotEqual(changed, lines)
        policy.write_text("".join(changed), encoding="utf-8")
        self.assertEqual(
            check_release_baseline.check(self.root),
            [
                "the allowlist line approving the validator SHA-256 must note "
                f"`release {EDGE_VERSION}`"
            ],
        )

    def test_quickstart_must_require_a_supported_record(self):
        quickstart = self.root / "docs/quickstart.md"
        original = quickstart.read_text(encoding="utf-8")
        changed = re.sub(r"`status` is\s+`supported`", "`status` is `pending`", original)
        self.assertNotEqual(changed, original)
        quickstart.write_text(changed, encoding="utf-8")
        issues = check_release_baseline.check(self.root)
        self.assertIn("quickstart must require a supported release record", issues)

    def test_only_a_release_tag_publishes(self):
        # A branch trigger would republish for the record-only commit that
        # fills the image digest, and fail its gate on every merge (#700).
        workflow = self.root / ".github/workflows/release.yml"
        original = workflow.read_text(encoding="utf-8")
        self.assertEqual(check_release_baseline.check(self.root), [])
        workflow.write_text(
            original.replace("  push:\n", "  push:\n    branches: [main]\n", 1),
            encoding="utf-8",
        )
        self.assertIn(
            "record-only finalization must not trigger another image publication",
            check_release_baseline.check(self.root),
        )
        workflow.write_text(original.replace("    tags: ['v*']\n", ""), encoding="utf-8")
        self.assertIn(
            "release.yml must publish on release tags", check_release_baseline.check(self.root)
        )

    def test_release_gate_must_use_recorded_gateway_digest(self):
        workflow = self.root / ".github/workflows/release.yml"
        workflow.write_text(
            workflow.read_text().replace(
                "gateway_args=(--gateway \"$(jq -er '.tested_gateway.binary_sha256' release/baseline.json)\"",
                "--gateway-allowlist .github/ferrum-edge-checksums.txt",
            )
        )
        issues = check_release_baseline.check(self.root)
        self.assertTrue(any("lifecycle gate" in issue for issue in issues), issues)


if __name__ == "__main__":
    unittest.main()
