#!/usr/bin/env python3
"""Check the committed release pairing against source, docs, and pins."""

from __future__ import annotations

import json
import re
import sys
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SHA = re.compile(r"[0-9a-f]{40}\Z")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
RUN_URL = re.compile(
    r"https://github\.com/ferrum-edge/ferrum-edge-git-forge-ops/actions/runs/[0-9]+\Z"
)


def check(root: Path) -> list[str]:
    issues: list[str] = []
    try:
        record = json.loads((root / "release/baseline.json").read_text(encoding="utf-8"))
        cargo = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))
        readme = (root / "README.md").read_text(encoding="utf-8")
        quickstart = (root / "docs/quickstart.md").read_text(encoding="utf-8")
        notes = (root / "release/notes-v0.1.0.md").read_text(encoding="utf-8")
        policy = (root / ".github/ferrum-edge-checksums.txt").read_text(encoding="utf-8")
        dockerfile = (root / "Dockerfile").read_text(encoding="utf-8")
        workflow = (root / ".github/workflows/release.yml").read_text(encoding="utf-8")
    except (OSError, ValueError) as error:
        return [f"release baseline input cannot be read: {error}"]

    if not isinstance(record, dict) or record.get("schema_version") != 1:
        return ["release/baseline.json must be a version-1 object"]
    engine = record.get("gitforgeops", {})
    validator = record.get("validator", {})
    gateway = record.get("tested_gateway", {})
    lifecycle = record.get("lifecycle", {})
    if not all(isinstance(item, dict) for item in (engine, validator, gateway, lifecycle)):
        return ["release/baseline.json has an invalid component object"]

    version = cargo.get("package", {}).get("version")
    if engine.get("version") != version or engine.get("tag") != f"v{version}":
        issues.append("GitForgeOps release version and tag must match Cargo.toml")
    if f"First supported baseline: [v{version}](release/README.md)" not in readme:
        issues.append("README Development status must link to the recorded version")
    if f"Release baseline: [v{version}](../release/README.md)" not in quickstart:
        issues.append("quickstart must link to the recorded version")
    if f"# GitForgeOps v{version} release notes" not in notes:
        issues.append("release notes must name the recorded version")
    if (
        "`status` is `pending`" not in readme
        or "`status` becomes `supported`" not in readme
    ):
        issues.append("README Development status must explain pending and supported states")
    if "`status` is `supported`" not in " ".join(quickstart.split()):
        issues.append("quickstart must require a supported release record")

    pin = validator.get("sha256")
    gateway_binary = gateway.get("binary_sha256")
    if validator.get("version") != gateway.get("version"):
        issues.append("validator and tested gateway versions must agree")
    if (
        pin != gateway_binary
        or not isinstance(pin, str)
        or not re.fullmatch(r"[0-9a-f]{64}", pin)
    ):
        issues.append("tested gateway binary must match the validator SHA-256")
    asset = validator.get("asset")
    if not isinstance(asset, str) or not any(
        line.split("#", 1)[0].strip() == f"{pin}  {asset}"
        for line in policy.splitlines()
    ):
        issues.append("validator SHA-256 must appear in the checked-in allowlist")
    if validator.get("version") != "v0.9.5":
        issues.append("the first baseline must name the verified v0.9.5 validator")

    image = gateway.get("image")
    image_digest = gateway.get("image_digest")
    if (
        image != "docker.io/ferrumedge/ferrum-edge"
        or not isinstance(image_digest, str)
        or not DIGEST.fullmatch(image_digest)
    ):
        issues.append("tested gateway must have the versioned Docker Hub image digest")
    elif (
        f"FROM ferrumedge/ferrum-edge:{gateway.get('version')}@{image_digest} AS ferrum-edge"
        not in dockerfile
    ):
        issues.append("Dockerfile gateway base must match the tested gateway version and digest")

    status = record.get("status")
    source_sha = engine.get("source_sha")
    artifact_digest = engine.get("image_digest")
    run_url = lifecycle.get("run_url")
    if status == "pending":
        if any(value is not None for value in (source_sha, artifact_digest, run_url)):
            issues.append("pending release must leave source, image, and evidence slots empty")
    elif status == "supported":
        if not isinstance(source_sha, str) or not SHA.fullmatch(source_sha):
            issues.append("supported release needs an exact source SHA")
        if not isinstance(artifact_digest, str) or not DIGEST.fullmatch(artifact_digest):
            issues.append("supported release needs an immutable image digest")
        if not isinstance(run_url, str) or not RUN_URL.fullmatch(run_url):
            issues.append("supported release needs a lifecycle run URL")
    else:
        issues.append("release status must be pending or supported")

    if "- 'release/**'" not in workflow:
        issues.append("record-only finalization must not trigger another image publication")
    if workflow.count("python3 .github/scripts/check_release_baseline.py") != 2:
        issues.append("both release jobs must check the baseline")
    exact_gateway_arg = (
        "gateway_args=(--gateway \"$(jq -er '.tested_gateway.binary_sha256' "
        "release/baseline.json)\""
    )
    if exact_gateway_arg not in workflow:
        issues.append("release lifecycle gate must use the exact tested gateway binary")
    return issues


def main() -> int:
    issues = check(ROOT)
    for issue in issues:
        print(f"release baseline: {issue}", file=sys.stderr)
    if issues:
        return 1
    print("Release baseline record, docs, validator pin, and gateway base agree.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
