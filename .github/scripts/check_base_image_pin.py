#!/usr/bin/env python3
"""Decide whether the Dockerfile's pinned runtime security packages are still
needed, still sufficient, and still fetchable.

The runtime stage pins a digest of the Debian base and then installs a reviewed
set of point-release packages by exact version and SHA-256, because the pinned
base predates those fixes. That stage is temporary by design: it has to go once
a rebuilt base carries the same versions. Left to a comment, "remove this once
the base catches up" is noticed when a pull request turns red, which is how the
perl-base and libsqlite3 gap was found.

This checker reads the Dockerfile as the single source of truth and compares it
with a Trivy report for the *moving* base tag. Three outcomes:

  retire  the current base tag reports no fixed CRITICAL/HIGH vulnerability, so
          the package stage is redundant and the digest can be bumped to it
  stale   the base reports a fix this repository does not cover — a newer point
          release than the pinned version, or a package that is neither pinned
          nor purged from the runtime image — or a pinned .deb has left the
          Debian pool, which fails the image build on a 404 that reads like
          nothing to do with this stage
  ok      every reported fix is covered by a pinned package or by one the
          runtime purges, and every pinned .deb is still in the pool

Nothing here needs Docker: it consumes a Trivy JSON report produced by the
canary workflow, so the canary and the `trivy-image` gate judge the same data.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# `FROM <ref>` optionally followed by `AS <stage>`. The final stage is the
# runtime image, and every ref is digest-pinned (check_supply_chain.py).
FROM_LINE = re.compile(r"^FROM\s+(\S+)(?:\s+AS\s+(\S+))?\s*$", re.MULTILINE | re.IGNORECASE)
# `<sha256>  <name>_<version>_<arch>.deb`, as written into the SHA256SUMS
# heredoc, one reviewed package per line.
PACKAGE_ENTRY = re.compile(
    r"(?P<digest>[0-9a-f]{64})\s+(?P<name>[a-z0-9][a-z0-9+.-]*)"
    r"_(?P<version>[^_\s]+)_(?P<arch>[a-z0-9]+)\.deb"
)
# `<name>_*) pool=<path> ;;` from the pool-directory case statement, including
# the alternation form `libc6_*|libc-bin_*)` where one source package ships
# several binary packages.
POOL_ENTRY = re.compile(r"(?P<patterns>[A-Za-z0-9_*.|+-]+)\)\s*pool=(?P<pool>\S+)")
# The mirror the stage fetches from, e.g. "https://deb.debian.org/debian/".
MIRROR = re.compile(r'"(?P<mirror>https://[^"]*?)\$pool/\$file"')

DIGITS = "0123456789"


# --------------------------------------------------------------------------
# Debian version ordering (dpkg's verrevcmp)
# --------------------------------------------------------------------------


def _order(char: str) -> int:
    """dpkg's per-character weight: `~` sorts before everything, including the
    end of a string, so 1.0~rc1 precedes 1.0 and ~deb13u1 precedes ~deb13u2."""
    if char in DIGITS:
        return 0
    if char.isascii() and char.isalpha():
        return ord(char)
    if char == "~":
        return -1
    if char:
        return ord(char) + 256
    return 0


def _compare_part(left: str, right: str) -> int:
    """Compare one version part (upstream or revision) the way dpkg does:
    alternating runs of non-digits, compared by weight, and digits, compared
    numerically with leading zeros ignored."""
    i = j = 0
    while i < len(left) or j < len(right):
        first_diff = 0
        while (i < len(left) and left[i] not in DIGITS) or (
            j < len(right) and right[j] not in DIGITS
        ):
            weight_left = _order(left[i]) if i < len(left) else 0
            weight_right = _order(right[j]) if j < len(right) else 0
            if weight_left != weight_right:
                return -1 if weight_left < weight_right else 1
            i += 1
            j += 1
        while i < len(left) and left[i] == "0":
            i += 1
        while j < len(right) and right[j] == "0":
            j += 1
        while i < len(left) and left[i] in DIGITS and j < len(right) and right[j] in DIGITS:
            if not first_diff:
                first_diff = int(left[i]) - int(right[j])
            i += 1
            j += 1
        # A longer digit run is the larger number.
        if i < len(left) and left[i] in DIGITS:
            return 1
        if j < len(right) and right[j] in DIGITS:
            return -1
        if first_diff:
            return -1 if first_diff < 0 else 1
    return 0


def split_version(version: str) -> tuple[int, str, str]:
    """Split `[epoch:]upstream[-revision]`."""
    rest = version.strip()
    epoch = 0
    head, separator, tail = rest.partition(":")
    if separator and head and all(char in DIGITS for char in head):
        epoch = int(head)
        rest = tail
    if "-" in rest:
        upstream, _, revision = rest.rpartition("-")
    else:
        upstream, revision = rest, ""
    return epoch, upstream, revision


def compare_debian_versions(left: str, right: str) -> int:
    """-1, 0 or 1 as `left` sorts before, with, or after `right`."""
    epoch_left, upstream_left, revision_left = split_version(left)
    epoch_right, upstream_right, revision_right = split_version(right)
    if epoch_left != epoch_right:
        return -1 if epoch_left < epoch_right else 1
    result = _compare_part(upstream_left, upstream_right)
    if result:
        return result
    return _compare_part(revision_left, revision_right)


# --------------------------------------------------------------------------
# Dockerfile
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class PinnedPackage:
    name: str
    version: str
    arch: str
    digest: str

    @property
    def filename(self) -> str:
        return f"{self.name}_{self.version}_{self.arch}.deb"


@dataclass
class BasePin:
    """What the Dockerfile's runtime stage declares."""

    image: str
    digest: str
    packages: list[PinnedPackage] = field(default_factory=list)
    purged: list[str] = field(default_factory=list)
    pools: dict[str, str] = field(default_factory=dict)
    mirror: str = ""

    @property
    def reference(self) -> str:
        return f"{self.image}@{self.digest}"

    def versions_by_name(self) -> dict[str, dict[str, str]]:
        """name -> {arch: version}. Every architecture must be covered, or a
        pin that only caught up on amd64 would read as covering both."""
        by_name: dict[str, dict[str, str]] = {}
        for package in self.packages:
            by_name.setdefault(package.name, {})[package.arch] = package.version
        return by_name

    def url_for(self, package: PinnedPackage) -> str | None:
        pool = self.pools.get(package.name)
        if pool is None or not self.mirror:
            return None
        return f"{self.mirror}{pool}/{package.filename}"


def logical_lines(text: str) -> list[str]:
    """Join backslash continuations so a multi-line RUN reads as one command."""
    joined: list[str] = []
    buffer = ""
    for raw in text.splitlines():
        line = raw.rstrip()
        if line.lstrip().startswith("#"):
            continue
        if line.endswith("\\"):
            buffer += line[:-1].rstrip() + " "
            continue
        joined.append((buffer + line).strip())
        buffer = ""
    if buffer:
        joined.append(buffer.strip())
    return [line for line in joined if line]


def parse_purged(text: str) -> list[str]:
    """Package names the runtime stage purges from the pinned base."""
    purged: list[str] = []
    for line in logical_lines(text):
        if "dpkg --purge" not in line:
            continue
        for token in line.split():
            if token in {"RUN", "dpkg"} or token.startswith("-"):
                continue
            if re.fullmatch(r"[a-z0-9][a-z0-9+.-]*", token):
                purged.append(token)
    return purged


def parse_dockerfile(text: str) -> BasePin:
    stages = FROM_LINE.findall(text)
    if not stages:
        raise ValueError("Dockerfile declares no FROM stage")
    runtime_ref = stages[-1][0]
    if "@sha256:" not in runtime_ref:
        raise ValueError(f"runtime base image is not digest-pinned: {runtime_ref}")
    image, _, digest = runtime_ref.partition("@")
    packages = [
        PinnedPackage(
            name=match.group("name"),
            version=match.group("version"),
            arch=match.group("arch"),
            digest=match.group("digest"),
        )
        for match in PACKAGE_ENTRY.finditer(text)
    ]
    pools: dict[str, str] = {}
    for match in POOL_ENTRY.finditer(text):
        for pattern in match.group("patterns").split("|"):
            name = pattern.strip().rstrip("*").rstrip("_")
            if name:
                pools[name] = match.group("pool")
    mirror_match = MIRROR.search(text)
    return BasePin(
        image=image,
        digest=digest,
        packages=packages,
        purged=parse_purged(text),
        pools=pools,
        mirror=mirror_match.group("mirror") if mirror_match else "",
    )


# --------------------------------------------------------------------------
# Trivy report
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Finding:
    vulnerability: str
    severity: str
    package: str
    installed: str
    fixed: str


GATED_SEVERITIES = ("CRITICAL", "HIGH")


def parse_trivy_report(document: dict) -> tuple[list[Finding], str]:
    """Fixed CRITICAL/HIGH OS-package findings, plus the digest actually
    scanned. The gate ignores unfixed findings and everything below HIGH; this
    filters the same way rather than trusting the caller's flags."""
    findings: list[Finding] = []
    for result in document.get("Results") or []:
        if result.get("Class") not in (None, "os-pkgs"):
            continue
        for item in result.get("Vulnerabilities") or []:
            severity = (item.get("Severity") or "").upper()
            fixed = item.get("FixedVersion") or ""
            if severity not in GATED_SEVERITIES or not fixed:
                continue
            findings.append(
                Finding(
                    vulnerability=item.get("VulnerabilityID") or "",
                    severity=severity,
                    package=item.get("PkgName") or "",
                    installed=item.get("InstalledVersion") or "",
                    fixed=fixed,
                )
            )
    digest = ""
    for repo_digest in (document.get("Metadata") or {}).get("RepoDigests") or []:
        _, _, tail = str(repo_digest).partition("@")
        if tail:
            digest = tail
            break
    return findings, digest


# --------------------------------------------------------------------------
# Classification
# --------------------------------------------------------------------------


@dataclass
class Report:
    state: str = "ok"
    pinned_digest: str = ""
    current_digest: str = ""
    image: str = ""
    covered_by_pin: list[str] = field(default_factory=list)
    covered_by_purge: list[str] = field(default_factory=list)
    uncovered: list[str] = field(default_factory=list)
    stale_pins: list[str] = field(default_factory=list)
    redundant_pins: list[str] = field(default_factory=list)
    missing_from_pool: list[str] = field(default_factory=list)
    unverified_pool: list[str] = field(default_factory=list)

    @property
    def digest_moved(self) -> bool:
        return bool(self.current_digest) and self.current_digest != self.pinned_digest


def classify(findings: list[Finding], pin: BasePin) -> Report:
    report = Report(image=pin.image, pinned_digest=pin.digest)
    pinned = pin.versions_by_name()
    purged = set(pin.purged)
    reported = {finding.package for finding in findings}

    for finding in findings:
        label = (
            f"{finding.vulnerability} {finding.severity} {finding.package} "
            f"{finding.installed} -> {finding.fixed}"
        )
        if finding.package in purged:
            report.covered_by_purge.append(f"{label} (purged from the runtime image)")
            continue
        versions = pinned.get(finding.package)
        if not versions:
            report.uncovered.append(f"{label} (neither pinned nor purged)")
            continue
        behind = sorted(
            f"{arch}: pinned {version}"
            for arch, version in versions.items()
            if compare_debian_versions(version, finding.fixed) < 0
        )
        if behind:
            report.stale_pins.append(f"{label} ({'; '.join(behind)})")
        else:
            report.covered_by_pin.append(label)

    for name in sorted(pinned):
        if name not in reported:
            report.redundant_pins.append(name)

    if report.uncovered or report.stale_pins:
        report.state = "stale"
    elif not findings:
        report.state = "retire"
    return report


# --------------------------------------------------------------------------
# Debian pool availability
# --------------------------------------------------------------------------


def head_status(url: str, *, timeout: float = 20.0, attempts: int = 2) -> int | None:
    """HTTP status for a HEAD request, or None when the request never
    completed. A transient network failure must not read as a missing file."""
    last: int | None = None
    for attempt in range(attempts):
        request = urllib.request.Request(url, method="HEAD")
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return response.status
        except urllib.error.HTTPError as error:
            return error.code
        except (urllib.error.URLError, TimeoutError, OSError):
            last = None
            if attempt + 1 == attempts:
                return last
    return last


def check_pool(pin: BasePin, report: Report, *, fetch=head_status) -> None:
    """A superseded point release is dropped from the archive pool, and the
    image build then fails on a 404. Notice it here instead."""
    for package in sorted(pin.packages, key=lambda item: (item.name, item.arch)):
        url = pin.url_for(package)
        if url is None:
            report.unverified_pool.append(f"{package.filename} (no pool directory in the Dockerfile)")
            continue
        status = fetch(url)
        if status == 200:
            continue
        if status is None:
            report.unverified_pool.append(f"{package.filename} (pool check did not complete)")
        else:
            report.missing_from_pool.append(f"{package.filename} (HTTP {status} at {url})")
    if report.missing_from_pool:
        report.state = "stale"


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------


HEADLINE = {
    "ok": "The pinned runtime security packages are still required and still sufficient.",
    "retire": "The base image has caught up: the pinned package stage can be retired.",
    "stale": "The pinned runtime security packages no longer cover the base image.",
}


def render(report: Report) -> str:
    lines = [HEADLINE[report.state], ""]
    lines.append(f"- Runtime base image: `{report.image}`")
    lines.append(f"- Digest pinned in the Dockerfile: `{report.pinned_digest}`")
    lines.append(f"- Digest the `{report.image}` tag resolves to now: `{report.current_digest or 'unknown'}`")
    lines.append(
        "- The tag has been rebuilt since the pin."
        if report.digest_moved
        else "- The tag still resolves to the pinned digest."
    )
    lines.append("")

    if report.state == "retire":
        lines += [
            "The current base tag reports no fixed CRITICAL or HIGH vulnerability, so",
            "the reviewed point-release packages add nothing the base does not already",
            "carry. To retire the stage:",
            "",
            f"1. Repin the runtime `FROM` to `{report.image}@{report.current_digest}`.",
            "2. Delete the `runtime-security-updates` builder stage, the `COPY` that",
            "   carries it into the runtime, and the `dpkg --install` that consumes it.",
            "3. Keep the `dpkg --purge` step: it removes packages from the base rather",
            "   than adding any, and the runtime smoke test asserts they stay gone.",
            "4. Let the `trivy-image` gate confirm the rebuilt image before merging.",
            "",
        ]

    if report.stale_pins:
        lines += [
            "**Pinned below the fixed version.** The base reports a fix newer than what",
            "this repository pins, so the built image still ships the vulnerable version:",
            "",
        ]
        lines += [f"- {entry}" for entry in report.stale_pins] + [""]

    if report.uncovered:
        lines += [
            "**Neither pinned nor purged.** The base reports a fix for a package the",
            "runtime stage does not address, so the `trivy-image` gate will fail:",
            "",
        ]
        lines += [f"- {entry}" for entry in report.uncovered] + [""]

    if report.missing_from_pool:
        lines += [
            "**Gone from the Debian pool.** The archive drops a superseded point",
            "release, and `docker build` then fails on a 404 that reads like nothing to",
            "do with this stage. Repin these to the current point release:",
            "",
        ]
        lines += [f"- {entry}" for entry in report.missing_from_pool] + [""]

    if report.stale_pins or report.uncovered or report.missing_from_pool:
        lines += [
            "Refresh a pin by replacing the version and SHA-256 for **every**",
            "architecture in the Dockerfile's `SHA256SUMS` block, from the package's",
            "immutable pool path. Do not reach for `apt` in the image: the release",
            "stages are required to build from reviewed digests only.",
            "",
        ]

    if report.redundant_pins:
        lines += [
            "Pinned, but the base reports no fixed CRITICAL or HIGH finding for them.",
            "That can mean the base already carries the pinned version, or that the",
            "advisory no longer meets the gate. Confirm against the image before",
            "dropping a pin; carrying a redundant one is harmless:",
            "",
        ]
        lines += [f"- {name}" for name in report.redundant_pins] + [""]

    if report.covered_by_pin:
        lines += ["Covered by a pinned package:", ""]
        lines += [f"- {entry}" for entry in report.covered_by_pin] + [""]

    if report.covered_by_purge:
        lines += ["Covered by a package the runtime purges:", ""]
        lines += [f"- {entry}" for entry in report.covered_by_purge] + [""]

    if report.unverified_pool:
        lines += [
            "Pool availability could not be confirmed for (not treated as missing):",
            "",
        ]
        lines += [f"- {entry}" for entry in report.unverified_pool] + [""]

    return "\n".join(lines).rstrip() + "\n"


def write_github_output(report: Report) -> None:
    destination = os.environ.get("GITHUB_OUTPUT")
    if not destination:
        return
    with open(destination, "a", encoding="utf-8") as handle:
        handle.write(f"state={report.state}\n")
        handle.write(f"current_digest={report.current_digest}\n")
        handle.write(f"pinned_digest={report.pinned_digest}\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--root", default=str(ROOT), help="repository root")
    parser.add_argument("--trivy-report", help="Trivy JSON report for the moving base tag")
    parser.add_argument("--report-file", help="write the Markdown report here")
    parser.add_argument(
        "--print-base-ref",
        action="store_true",
        help="print the runtime base image without its digest and exit, so the "
        "workflow scans the tag the Dockerfile names",
    )
    parser.add_argument("--skip-pool-check", action="store_true", help="do not contact the Debian mirror")
    args = parser.parse_args(argv)

    root = Path(args.root).resolve()
    try:
        pin = parse_dockerfile((root / "Dockerfile").read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        print(f"cannot read the runtime base pin: {error}", file=sys.stderr)
        return 2

    if args.print_base_ref:
        print(pin.image)
        return 0

    if not args.trivy_report:
        parser.error("--trivy-report is required unless --print-base-ref is given")

    try:
        document = json.loads(Path(args.trivy_report).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        print(f"cannot read the Trivy report: {error}", file=sys.stderr)
        return 2

    findings, current_digest = parse_trivy_report(document)
    report = classify(findings, pin)
    report.current_digest = current_digest
    if not args.skip_pool_check:
        check_pool(pin, report)

    rendered = render(report)
    print(rendered, end="")
    if args.report_file:
        Path(args.report_file).write_text(rendered, encoding="utf-8")
    write_github_output(report)
    return 1 if report.state == "stale" else 0


if __name__ == "__main__":
    raise SystemExit(main())
