#!/usr/bin/env python3
"""Check the committed release pairing against source, docs, and pins.

Everything version-specific is derived from `release/baseline.json`: the
release notes file is `release/notes-<gitforgeops.tag>.md`, and the paired
Ferrum Edge version is `validator.version`. That version must be a plain
`vMAJOR.MINOR.PATCH` tag and must agree with every other place the pairing is
recorded (the allowlist line approving the pinned digest, the Dockerfile
gateway stage, the vendored contracts PIN, the CLI's `DEFAULT_EDGE_VERSION`,
the release notes and the release README), so moving the pin is one reviewed
change that cannot leave a stale copy behind.

`release/baseline.json` describes the release under preparation (the
candidate, whose version is `Cargo.toml`'s). Each published release keeps a
finalized support record in `release/records/<tag>.json`: status
`supported`, every evidence field filled, and its release notes committed.
Records are immutable once on the protected branch (`check_supply_chain.py`
compares them with the base tree). A finalized candidate must equal its
record, a `pending` candidate may not reuse a finalized tag, and the README's
"First supported baseline" names the lowest recorded release (the candidate
before any release is recorded).
"""

from __future__ import annotations

import json
import os
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


_SHA256_HEX_RE = re.compile(r"[0-9a-f]{64}")
RELEASE_TAG = re.compile(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z")
DEFAULT_EDGE_VERSION = re.compile(
    r"pub const DEFAULT_EDGE_VERSION: EdgeVersion = EdgeVersion::new\("
    r"(?P<major>[0-9]+), (?P<minor>[0-9]+), (?P<patch>[0-9]+)\);"
)


def notes_path(record: object) -> str | None:
    """The release notes file the record's GitForgeOps tag names."""
    if not isinstance(record, dict):
        return None
    engine = record.get("gitforgeops")
    tag = engine.get("tag") if isinstance(engine, dict) else None
    if not isinstance(tag, str) or not RELEASE_TAG.fullmatch(tag):
        return None
    return f"release/notes-{tag}.md"


def allowlist_releases(policy: str, digest: str, asset: str) -> list[str]:
    """The `release <tag>` notes on every allowlist line approving `digest`."""
    releases = []
    for line in policy.splitlines():
        record, _, note = line.partition("#")
        if record.strip() != f"{digest}  {asset}":
            continue
        words = note.split()
        releases.extend(
            words[index + 1]
            for index, word in enumerate(words[:-1])
            if word == "release"
        )
    return releases


RECORDS_DIR = "release/records"


def version_key(tag: str) -> tuple[int, int, int]:
    major, minor, patch = (int(part) for part in tag.removeprefix("v").split("."))
    return major, minor, patch


def finalized_record_issues(record: object, name: str, policy: str, root: Path) -> list[str]:
    """Why `record` is not a complete support record for a published release."""
    where = f"{RECORDS_DIR}/{name}"
    if not isinstance(record, dict) or record.get("schema_version") != 1:
        return [f"{where} must be a version-1 object"]
    engine = record.get("gitforgeops")
    validator = record.get("validator")
    gateway = record.get("tested_gateway")
    lifecycle = record.get("lifecycle")
    if not all(isinstance(item, dict) for item in (engine, validator, gateway, lifecycle)):
        return [f"{where} has an invalid component object"]
    issues = []
    tag = engine.get("tag")
    version = engine.get("version")
    if not isinstance(tag, str) or not RELEASE_TAG.fullmatch(tag) or tag != f"v{version}":
        return [f"{where} must name a vMAJOR.MINOR.PATCH tag matching its version"]
    if name != f"{tag}.json":
        issues.append(f"{where} must be named {tag}.json")
    if record.get("status") != "supported":
        issues.append(f"{where} must be finalized with status supported")
    if not isinstance(engine.get("source_sha"), str) or not SHA.fullmatch(engine["source_sha"]):
        issues.append(f"{where} needs an exact source SHA")
    if not isinstance(engine.get("image_digest"), str) or not DIGEST.fullmatch(
        engine["image_digest"]
    ):
        issues.append(f"{where} needs an immutable image digest")
    if not isinstance(lifecycle.get("run_url"), str) or not RUN_URL.fullmatch(
        lifecycle["run_url"]
    ):
        issues.append(f"{where} needs a lifecycle run URL")
    edge_version = validator.get("version")
    pin = validator.get("sha256")
    asset = validator.get("asset")
    if (
        not isinstance(edge_version, str)
        or not RELEASE_TAG.fullmatch(edge_version)
        or gateway.get("version") != edge_version
        or not isinstance(pin, str)
        or not _SHA256_HEX_RE.fullmatch(pin)
        or gateway.get("binary_sha256") != pin
        or not isinstance(asset, str)
        or not any(
            line.split("#", 1)[0].strip() == f"{pin}  {asset}" for line in policy.splitlines()
        )
    ):
        issues.append(f"{where} must name one allowlisted validator and matching tested gateway")
    if gateway.get("image") != "docker.io/ferrumedge/ferrum-edge" or not (
        isinstance(gateway.get("image_digest"), str) and DIGEST.fullmatch(gateway["image_digest"])
    ):
        issues.append(f"{where} must name the tested gateway image digest")
    notes = root / f"release/notes-{tag}.md"
    try:
        notes_text = notes.read_text(encoding="utf-8")
    except OSError:
        issues.append(f"{where}: release notes release/notes-{tag}.md must stay committed")
    else:
        if f"# GitForgeOps {tag} release notes" not in notes_text:
            issues.append(f"release/notes-{tag}.md must name {tag}")
    return issues


def load_records(root: Path, policy: str) -> tuple[dict[str, dict], list[str]]:
    """The finalized support records, keyed by release tag."""
    directory = root / RECORDS_DIR
    if not directory.exists():
        return {}, []
    if directory.is_symlink() or not directory.is_dir():
        return {}, [f"{RECORDS_DIR} must be a directory"]
    records: dict[str, dict] = {}
    issues: list[str] = []
    for path in sorted(directory.iterdir()):
        if path.name == "README.md":
            continue
        if path.is_symlink() or not path.is_file() or path.suffix != ".json":
            issues.append(f"{RECORDS_DIR}/{path.name} is not a release record (<tag>.json)")
            continue
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as error:
            issues.append(f"{RECORDS_DIR}/{path.name} cannot be read: {error}")
            continue
        problems = finalized_record_issues(record, path.name, policy, root)
        issues.extend(problems)
        if not problems:
            records[record["gitforgeops"]["tag"]] = record
    return records, issues


def pin_edge_version(pin: str) -> str | None:
    for line in pin.splitlines():
        if line.startswith("edge_version="):
            return line.removeprefix("edge_version=")
    return None


UPSTREAM_RECORDS = (
    "https://github.com/ferrum-edge/ferrum-edge-git-forge-ops/blob/main/release/records"
)


def check(root: Path, release_ref: str | None = None) -> list[str]:
    """Issues with the committed release pairing.

    `release_ref` is the tag being published (`release.yml` passes the pushed
    tag); it must be exactly the candidate's tag and `v` + the Cargo version.
    """
    issues: list[str] = []
    try:
        record = json.loads((root / "release/baseline.json").read_text(encoding="utf-8"))
        notes_file = notes_path(record)
        if notes_file is None:
            return ["release/baseline.json must name a vMAJOR.MINOR.PATCH gitforgeops.tag"]
        cargo = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))
        readme = (root / "README.md").read_text(encoding="utf-8")
        quickstart = (root / "docs/quickstart.md").read_text(encoding="utf-8")
        notes = (root / notes_file).read_text(encoding="utf-8")
        release_readme = (root / "release/README.md").read_text(encoding="utf-8")
        policy = (root / ".github/ferrum-edge-checksums.txt").read_text(encoding="utf-8")
        dockerfile = (root / "Dockerfile").read_text(encoding="utf-8")
        workflow = (root / ".github/workflows/release.yml").read_text(encoding="utf-8")
        contracts_pin = (root / "contracts/ferrum-contracts/PIN").read_text(encoding="utf-8")
        edge_version_source = (root / "src/config/edge_version.rs").read_text(
            encoding="utf-8"
        )
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
    records, record_issues = load_records(root, policy)
    issues.extend(record_issues)
    # The first supported baseline is a milestone, not the candidate: once a
    # release is recorded it stays the lowest recorded version.
    first = min(records, key=version_key) if records else f"v{version}"
    if f"First supported baseline: [{first}](release/README.md)" not in readme:
        issues.append(
            f"README Development status must link to the first supported baseline {first}"
        )
    if RECORDS_DIR + "/" not in readme:
        issues.append("README Development status must point to the finalized release records")
    # The quickstart describes the release being prepared, so it names and
    # links that release's own record (which exists once it is published).
    if f"Release baseline: [v{version}]({UPSTREAM_RECORDS}/v{version}.json)" not in quickstart:
        issues.append("quickstart must name and link the record of the release it describes")
    if release_ref is not None and (
        release_ref != engine.get("tag") or release_ref != f"v{version}"
    ):
        issues.append(
            f"the pushed tag {release_ref} must equal release/baseline.json's "
            f"gitforgeops.tag {engine.get('tag')} and v + the Cargo version v{version}"
        )
    if f"# GitForgeOps v{version} release notes" not in notes:
        issues.append("release notes must name the recorded version")
    if "`status` is `supported`" not in " ".join(quickstart.split()):
        issues.append("quickstart must require a supported release record")

    pin = validator.get("sha256")
    gateway_binary = gateway.get("binary_sha256")
    if validator.get("version") != gateway.get("version"):
        issues.append("validator and tested gateway versions must agree")
    if (
        pin != gateway_binary
        or not isinstance(pin, str)
        or not _SHA256_HEX_RE.fullmatch(pin)
    ):
        issues.append("tested gateway binary must match the validator SHA-256")
    asset = validator.get("asset")
    if not isinstance(asset, str) or not any(
        line.split("#", 1)[0].strip() == f"{pin}  {asset}"
        for line in policy.splitlines()
    ):
        issues.append("validator SHA-256 must appear in the checked-in allowlist")
    edge_version = validator.get("version")
    if not isinstance(edge_version, str) or not RELEASE_TAG.fullmatch(edge_version):
        issues.append("validator version must be a vMAJOR.MINOR.PATCH Ferrum Edge release tag")
    else:
        # The digest must be the one the allowlist approved for this release,
        # so a former pairing's digest cannot certify a new version (or the
        # reverse).
        if isinstance(pin, str) and isinstance(asset, str):
            releases = allowlist_releases(policy, pin, asset)
            if releases and edge_version not in releases:
                issues.append(
                    f"the allowlist approves the validator SHA-256 for release "
                    f"{', '.join(releases)}, not {edge_version}"
                )
            elif not releases and any(
                line.split("#", 1)[0].strip() == f"{pin}  {asset}"
                for line in policy.splitlines()
            ):
                issues.append(
                    f"the allowlist line approving the validator SHA-256 must note "
                    f"`release {edge_version}`"
                )
        if pin_edge_version(contracts_pin) != edge_version:
            issues.append("contracts PIN edge_version must match the validator version")
        default = DEFAULT_EDGE_VERSION.search(edge_version_source)
        if default is None or (
            f"v{default['major']}.{default['minor']}.{default['patch']}" != edge_version
        ):
            issues.append("DEFAULT_EDGE_VERSION must match the validator version")
        if f"Ferrum Edge {edge_version}" not in " ".join(notes.split()):
            issues.append("release notes must name the paired Ferrum Edge version")
        if f"Ferrum Edge {edge_version}" not in " ".join(release_readme.split()):
            issues.append("release/README.md must name the paired Ferrum Edge version")

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
    candidate_tag = engine.get("tag")
    if status == "pending":
        if any(value is not None for value in (source_sha, artifact_digest, run_url)):
            issues.append("pending release must leave source, image, and evidence slots empty")
        if candidate_tag in records:
            issues.append(
                f"{RECORDS_DIR}/{candidate_tag}.json is already finalized; prepare a new "
                "version instead of reopening a published one"
            )
    elif status == "supported":
        if not isinstance(source_sha, str) or not SHA.fullmatch(source_sha):
            issues.append("supported release needs an exact source SHA")
        if not isinstance(artifact_digest, str) or not DIGEST.fullmatch(artifact_digest):
            issues.append("supported release needs an immutable image digest")
        if not isinstance(run_url, str) or not RUN_URL.fullmatch(run_url):
            issues.append("supported release needs a lifecycle run URL")
        if records.get(candidate_tag) != record:
            issues.append(
                f"a supported baseline must be finalized as {RECORDS_DIR}/{candidate_tag}.json "
                "with identical content"
            )
    else:
        issues.append("release status must be pending or supported")

    # Only a release tag publishes, so the record-only commit that fills the
    # image digest after publication cannot publish again.
    push = re.search(r"^  push:[ \t]*\n(?P<body>(?:(?:    .*)?\n)*)", workflow, re.MULTILINE)
    if push is None or "tags: ['v*']" not in push.group("body"):
        issues.append("release.yml must publish on release tags")
    elif re.search(r"^\s+branches(?:-ignore)?\s*:", push.group("body"), re.MULTILINE | re.IGNORECASE):
        issues.append("record-only finalization must not trigger another image publication")
    if workflow.count("python3 -I .github/scripts/check_release_baseline.py") != 2:
        issues.append("both release jobs must check the baseline")
    exact_gateway_arg = (
        "gateway_args=(--gateway \"$(jq -er '.tested_gateway.binary_sha256' "
        "release/baseline.json)\""
    )
    if exact_gateway_arg not in workflow:
        issues.append("release lifecycle gate must use the exact tested gateway binary")
    return issues


def published_tag() -> str | None:
    """The tag `release.yml` is publishing, from the Actions environment."""
    ref = os.environ.get("GITHUB_REF", "")
    if ref.startswith("refs/tags/"):
        return ref.removeprefix("refs/tags/")
    return None


def main() -> int:
    issues = check(ROOT, release_ref=published_tag())
    for issue in issues:
        print(f"release baseline: {issue}", file=sys.stderr)
    if issues:
        return 1
    print("Release baseline record, docs, validator pin, and gateway base agree.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
