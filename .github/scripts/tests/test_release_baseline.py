"""The release record must stay aligned with the version, docs, and gateway pin."""

import importlib.util
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / ".github/scripts/check_release_baseline.py"
SPEC = importlib.util.spec_from_file_location("check_release_baseline", SCRIPT)
check_release_baseline = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = check_release_baseline
SPEC.loader.exec_module(check_release_baseline)

INPUTS = (
    "Cargo.toml",
    "README.md",
    "docs/quickstart.md",
    "release/baseline.json",
    "release/notes-v0.1.0.md",
    ".github/ferrum-edge-checksums.txt",
    ".github/workflows/release.yml",
    "Dockerfile",
)


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

    def test_pending_baseline_is_consistent(self):
        self.assertEqual(check_release_baseline.check(self.root), [])

    def test_supported_baseline_requires_all_release_evidence(self):
        record = self.record()
        record["status"] = "supported"
        record["gitforgeops"]["source_sha"] = None
        record["gitforgeops"]["image_digest"] = None
        record["lifecycle"]["run_url"] = None
        self.write_record(record)
        self.assertEqual(len(check_release_baseline.check(self.root)), 3)

        record["gitforgeops"]["source_sha"] = "a" * 40
        record["gitforgeops"]["image_digest"] = "sha256:" + "b" * 64
        record["lifecycle"]["run_url"] = (
            "https://github.com/ferrum-edge/ferrum-edge-git-forge-ops/actions/runs/123"
        )
        self.write_record(record)
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

    def test_docs_and_cargo_version_drift_are_rejected(self):
        cargo = self.root / "Cargo.toml"
        cargo.write_text(cargo.read_text().replace('version = "0.1.0"', 'version = "0.2.0"', 1))
        issues = check_release_baseline.check(self.root)
        self.assertTrue(any("Cargo.toml" in issue for issue in issues), issues)
        self.assertTrue(any("README Development status" in issue for issue in issues), issues)
        self.assertTrue(any("quickstart" in issue for issue in issues), issues)

    def test_quickstart_must_require_a_supported_record(self):
        quickstart = self.root / "docs/quickstart.md"
        original = quickstart.read_text(encoding="utf-8")
        changed = original.replace("`status` is\n`supported`", "`status` is\n`pending`", 1)
        self.assertNotEqual(changed, original)
        quickstart.write_text(changed, encoding="utf-8")
        issues = check_release_baseline.check(self.root)
        self.assertIn("quickstart must require a supported release record", issues)

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
