import contextlib
import importlib.util
import io
import json
import os
import re
import sys
import tempfile
import unittest
import urllib.error
from datetime import date, datetime, timezone
from pathlib import Path
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / "check_base_image_pin.py"
REPO_ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location("check_base_image_pin", SCRIPT)
check_base_image_pin = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = check_base_image_pin
SPEC.loader.exec_module(check_base_image_pin)

compare = check_base_image_pin.compare_debian_versions
State = check_base_image_pin.State
WORKFLOW = REPO_ROOT / ".github/workflows/base-image-pin-canary.yml"

DOCKERFILE = """\
FROM ferrumedge/ferrum-edge:latest@sha256:aaaa AS ferrum-edge

FROM rust:1.98.0-bookworm@sha256:bbbb AS builder
RUN cargo build --release --locked

ARG TARGETARCH
RUN set -eu; \\
    arch="${TARGETARCH:-$(dpkg --print-architecture)}"; \\
    case "$arch" in \\
      amd64) printf '%s  %s\\n' \\
        1111111111111111111111111111111111111111111111111111111111111111 perl-base_5.40.1-6+deb13u1_amd64.deb \\
        2222222222222222222222222222222222222222222222222222222222222222 gzip_1.13-1+deb13u1_amd64.deb \\
        > SHA256SUMS ;; \\
      arm64) printf '%s  %s\\n' \\
        3333333333333333333333333333333333333333333333333333333333333333 perl-base_5.40.1-6+deb13u1_arm64.deb \\
        4444444444444444444444444444444444444444444444444444444444444444 gzip_1.13-1+deb13u1_arm64.deb \\
        > SHA256SUMS ;; \\
      *) echo "unsupported target architecture: $arch" >&2; exit 1 ;; \\
    esac; \\
    while read -r digest file; do \\
      case "$file" in \\
        perl-base_*) pool=pool/main/p/perl ;; \\
        gzip_*) pool=pool/main/g/gzip ;; \\
        *) echo "unexpected package: $file" >&2; exit 1 ;; \\
      esac; \\
      curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location \\
        "https://deb.debian.org/debian/$pool/$file" --output "$file"; \\
    done < SHA256SUMS; \\
    sha256sum --check --strict SHA256SUMS

FROM debian:trixie-slim@sha256:cccc
COPY --from=builder /opt/runtime-security-updates /tmp/runtime-security-updates
RUN dpkg --install /tmp/runtime-security-updates/*.deb
RUN dpkg --purge --force-depends \\
    apt \\
    libapt-pkg7.0 \\
    libssl3t64 \\
    openssl-provider-legacy
ENTRYPOINT ["/app/gitforgeops"]
"""

RETIRED_DOCKERFILE = """\
FROM ferrumedge/ferrum-edge:latest@sha256:aaaa AS ferrum-edge

FROM rust:1.98.0-bookworm@sha256:bbbb AS builder
RUN cargo build --release --locked

FROM debian:trixie-slim@sha256:cccc
RUN dpkg --purge --force-depends \\
    apt \\
    libapt-pkg7.0 \\
    libssl3t64 \\
    openssl-provider-legacy
ENTRYPOINT ["/app/gitforgeops"]
"""


def report_document(vulnerabilities, digest="sha256:cccc"):
    return {
        "Metadata": {"RepoDigests": [f"debian@{digest}"]},
        "Results": [{"Class": "os-pkgs", "Vulnerabilities": vulnerabilities}],
    }


def vulnerability(package, fixed, *, installed="0", severity="HIGH", cve="CVE-2026-1"):
    return {
        "VulnerabilityID": cve,
        "Severity": severity,
        "PkgName": package,
        "InstalledVersion": installed,
        "FixedVersion": fixed,
    }


class DebianVersionTests(unittest.TestCase):
    def test_point_releases_order_by_their_trailing_number(self):
        self.assertEqual(compare("5.40.1-6", "5.40.1-6+deb13u1"), -1)
        self.assertEqual(compare("5.40.1-6+deb13u1", "5.40.1-6+deb13u2"), -1)
        self.assertEqual(compare("5.40.1-6+deb13u2", "5.40.1-6+deb13u1"), 1)

    def test_a_tilde_sorts_before_everything_including_the_end_of_a_version(self):
        # 10.46-1~deb13u1 is the version pcre2 actually ships; an ordering that
        # treats `~` as an ordinary character would call it newer than 10.46-1.
        self.assertEqual(compare("10.46-1~deb13u1", "10.46-1"), -1)
        self.assertEqual(compare("10.46-1~deb13u1", "10.46-1~deb13u2"), -1)
        self.assertEqual(compare("1.0~rc1", "1.0"), -1)

    def test_digit_runs_compare_numerically_not_lexically(self):
        self.assertEqual(compare("1.10", "1.9"), 1)
        self.assertEqual(compare("2.41-12+deb13u4", "2.41-12+deb13u10"), -1)
        self.assertEqual(compare("1.01", "1.1"), 0)

    def test_epochs_dominate(self):
        self.assertEqual(compare("1:1.0", "2.0"), 1)
        self.assertEqual(compare("1.0", "1:0.1"), -1)
        self.assertEqual(compare("2:1.0", "2:1.0"), 0)

    def test_equal_versions_and_missing_revisions(self):
        self.assertEqual(compare("3.46.1-7+deb13u2", "3.46.1-7+deb13u2"), 0)
        self.assertEqual(compare("1.13", "1.13-1"), -1)
        self.assertEqual(compare(" 1.13-1 ", "1.13-1"), 0)


class DockerfileParsingTests(unittest.TestCase):
    def test_the_runtime_stage_is_the_last_from(self):
        pin = check_base_image_pin.parse_dockerfile(DOCKERFILE)
        self.assertEqual(pin.image, "debian:trixie-slim")
        self.assertEqual(pin.digest, "sha256:cccc")

    def test_every_pinned_package_is_read_with_its_architecture(self):
        pin = check_base_image_pin.parse_dockerfile(DOCKERFILE)
        self.assertEqual(
            pin.versions_by_name(),
            {
                "perl-base": {"amd64": "5.40.1-6+deb13u1", "arm64": "5.40.1-6+deb13u1"},
                "gzip": {"amd64": "1.13-1+deb13u1", "arm64": "1.13-1+deb13u1"},
            },
        )

    def test_purged_packages_and_pool_urls_come_from_the_dockerfile(self):
        pin = check_base_image_pin.parse_dockerfile(DOCKERFILE)
        self.assertEqual(
            sorted(pin.purged), ["apt", "libapt-pkg7.0", "libssl3t64", "openssl-provider-legacy"]
        )
        package = next(p for p in pin.packages if p.name == "gzip" and p.arch == "amd64")
        self.assertEqual(
            pin.url_for(package),
            "https://deb.debian.org/debian/pool/main/g/gzip/gzip_1.13-1+deb13u1_amd64.deb",
        )

    def test_the_install_command_is_not_mistaken_for_a_purge(self):
        pin = check_base_image_pin.parse_dockerfile(DOCKERFILE)
        self.assertNotIn("runtime-security-updates", pin.purged)
        self.assertNotIn("tmp", pin.purged)

    def test_an_undigested_runtime_base_is_refused(self):
        with self.assertRaises(ValueError):
            check_base_image_pin.parse_dockerfile("FROM debian:trixie-slim\n")

    def test_a_retired_dockerfile_has_no_packages_and_keeps_the_purge(self):
        pin = check_base_image_pin.parse_dockerfile(RETIRED_DOCKERFILE)
        self.assertEqual(pin.packages, [])
        self.assertEqual(pin.pools, {})
        self.assertEqual(pin.mirror, "")
        self.assertEqual(
            sorted(pin.purged), ["apt", "libapt-pkg7.0", "libssl3t64", "openssl-provider-legacy"]
        )


class ArchitectureAllTests(unittest.TestCase):
    """An `Architecture: all` file is attributed to the block that lists it."""

    def pin(self, amd64_line, arm64_line):
        text = (
            DOCKERFILE.replace(
                "2222222222222222222222222222222222222222222222222222222222222222 gzip_1.13-1+deb13u1_amd64.deb",
                amd64_line,
            ).replace(
                "4444444444444444444444444444444444444444444444444444444444444444 gzip_1.13-1+deb13u1_arm64.deb",
                arm64_line,
            )
        )
        return check_base_image_pin.parse_dockerfile(text)

    def test_an_all_file_in_both_blocks_covers_both_architectures(self):
        pin = self.pin(
            "5555555555555555555555555555555555555555555555555555555555555555 gzip_1.13-1+deb13u1_all.deb",
            "5555555555555555555555555555555555555555555555555555555555555555 gzip_1.13-1+deb13u1_all.deb",
        )
        self.assertEqual(
            pin.versions_by_name()["gzip"],
            {"amd64": "1.13-1+deb13u1", "arm64": "1.13-1+deb13u1"},
        )

    def test_an_all_file_lagging_in_one_block_is_stale(self):
        pin = self.pin(
            "5555555555555555555555555555555555555555555555555555555555555555 gzip_1.13-1+deb13u1_all.deb",
            "6666666666666666666666666666666666666666666666666666666666666666 gzip_1.13-1_all.deb",
        )
        report = check_base_image_pin.classify(
            check_base_image_pin.parse_trivy_report(
                report_document([vulnerability("gzip", "1.13-1+deb13u1", installed="1.13-1")])
            )[0],
            pin,
        )
        self.assertTrue(report.stale_pins, report)

    def test_an_all_file_in_one_block_only_leaves_the_other_uncovered(self):
        pin = self.pin(
            "5555555555555555555555555555555555555555555555555555555555555555 gzip_1.13-1+deb13u1_all.deb",
            "4444444444444444444444444444444444444444444444444444444444444444 perl-base_5.40.1-6+deb13u1_arm64.deb",
        )
        self.assertEqual(sorted(pin.versions_by_name()["gzip"]), ["amd64"])
        report = check_base_image_pin.classify(
            check_base_image_pin.parse_trivy_report(
                report_document([vulnerability("gzip", "1.13-1+deb13u1", installed="1.13-1")])
            )[0],
            pin,
        )
        self.assertEqual(report.state, check_base_image_pin.State.STALE)
        self.assertIn("arm64: not pinned", report.stale_pins[0])


class RealDockerfileTests(unittest.TestCase):
    """The parser is only useful if it keeps matching the file it reads."""

    def setUp(self):
        self.pin = check_base_image_pin.parse_dockerfile(
            (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
        )

    def test_the_runtime_base_is_a_digest_pinned_debian(self):
        self.assertTrue(self.pin.image.startswith("debian:"), self.pin.image)
        self.assertTrue(self.pin.digest.startswith("sha256:"), self.pin.digest)

    def test_the_purge_list_is_read(self):
        self.assertIn("libssl3t64", self.pin.purged)
        instructions = "\n".join(
            line
            for line in (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8").splitlines()
            if not line.lstrip().startswith("#")
        )
        self.assertIn("dpkg --purge", instructions)

    def test_the_live_dockerfile_pins_exactly_the_fixes_the_base_lacks(self):
        self.assertEqual(
            self.pin.versions_by_name(),
            {
                "zlib1g": {
                    "amd64": "1.3.dfsg+really1.3.1-1+deb13u1",
                    "arm64": "1.3.dfsg+really1.3.1-1+deb13u1",
                },
                "libc6": {"amd64": "2.41-12+deb13u5", "arm64": "2.41-12+deb13u5"},
                "libc-bin": {"amd64": "2.41-12+deb13u5", "arm64": "2.41-12+deb13u5"},
                "libzstd1": {"amd64": "1.5.7+dfsg-1+deb13u1", "arm64": "1.5.7+dfsg-1+deb13u1"},
                # Architecture: all; the same file is listed in both blocks.
                "login.defs": {"amd64": "4.17.4-2+deb13u1", "arm64": "4.17.4-2+deb13u1"},
                "passwd": {"amd64": "4.17.4-2+deb13u1", "arm64": "4.17.4-2+deb13u1"},
            },
        )
        self.assertEqual(
            {(package.name, package.target): package.digest for package in self.pin.packages},
            {
                ("zlib1g", "amd64"): "8c27c342230503b73dfde629642c3b352e87b554e06d60cf58772f236a305ceb",
                ("zlib1g", "arm64"): "0e41b3d7ad8ad7fcd36dd4d61ca91a70018478fc4af652e044f4be770784ddff",
                ("libc6", "amd64"): "b59b0625cd1a791375d40dab23a4d5d3d0641e3d0a773501becdc3725b7f99cf",
                ("libc6", "arm64"): "0966fc3da1a26cc57647c68b5736f791b6e7eb498173a7993f63b6c89b4ed4f5",
                ("libc-bin", "amd64"): "f30ee7381a9c6a3936165259bcd58e65f4b288e351606d200c8435724c5876dd",
                ("libc-bin", "arm64"): "889850625c686a6d0b26a8baee5fb96f33e9f3305882f3a6751bb4c9433063e1",
                ("libzstd1", "amd64"): "23a6f8a774d5dceda5f759b4ecdcdd652dfbefbf8271912e6a7ab0ee3250dc75",
                ("libzstd1", "arm64"): "ab5ad90f986b315bfa12be50f438aa3453e32da3b29540844d2d847800d2ce08",
                ("login.defs", "amd64"): "5573474d7bdfab60b27abdb6cbd5c5d4bf898e86d17fd8956eed6a4ebf1a4246",
                ("login.defs", "arm64"): "5573474d7bdfab60b27abdb6cbd5c5d4bf898e86d17fd8956eed6a4ebf1a4246",
                ("passwd", "amd64"): "e7f364ab275542ba9cfdf0c6bec9276fbac3ef6fe27d3a65674bd29ba3d32096",
                ("passwd", "arm64"): "49acfe766c3dea4f760e330ff9f1142c052ba2198442a35ad7d22ecf65508f6f",
            },
        )
        self.assertEqual(
            self.pin.pools,
            {
                "zlib1g": "debian-security/pool/updates/main/z/zlib",
                # Debian 13.8 shipped the glibc fixes through the main archive.
                "libc6": "debian/pool/main/g/glibc",
                "libc-bin": "debian/pool/main/g/glibc",
                "libzstd1": "debian-security/pool/updates/main/libz/libzstd",
                "login.defs": "debian-security/pool/updates/main/s/shadow",
                "passwd": "debian-security/pool/updates/main/s/shadow",
            },
        )
        self.assertEqual(self.pin.epochs, {"zlib1g": 1, "login.defs": 1, "passwd": 1})
        self.assertEqual(self.pin.mirror, "https://deb.debian.org/")
        self.assertEqual(
            self.pin.url_for(
                next(package for package in self.pin.packages if package.name == "libc6")
            ),
            "https://deb.debian.org/debian/pool/main/g/glibc/libc6_2.41-12+deb13u5_amd64.deb",
        )
        self.assertEqual(
            self.pin.url_for(
                next(package for package in self.pin.packages if package.name == "zlib1g")
            ),
            "https://deb.debian.org/debian-security/pool/updates/main/z/zlib/"
            "zlib1g_1.3.dfsg+really1.3.1-1+deb13u1_amd64.deb",
        )
        instructions = "\n".join(
            line
            for line in (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8").splitlines()
            if not line.lstrip().startswith("#")
        )
        self.assertIn("runtime-security-updates", instructions)
        self.assertIn("dpkg --install", instructions)
        self.assertEqual(
            self.pin.digest,
            "sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2",
        )
        self.assertIn(
            "installed package metadata confirms it\n# already carries the fixes",
            (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8"),
        )

    def test_every_pinned_package_carries_both_architectures_and_a_pool(self):
        # Both architectures and their pool directory must stay in step.
        versions = self.pin.versions_by_name()
        for name, by_arch in versions.items():
            self.assertEqual(
                sorted(by_arch), ["amd64", "arm64"], f"{name} is not pinned for both architectures"
            )
            self.assertIn(name, self.pin.pools, f"{name} has no pool directory")
        # Each block lists one file per package: its own architecture's, or the
        # shared `Architecture: all` file.
        seen = set()
        for package in self.pin.packages:
            self.assertIn(
                package.arch,
                (package.target, "all"),
                f"{package.filename} is in the {package.target} block",
            )
            self.assertNotIn(
                (package.name, package.target),
                seen,
                f"{package.name} is listed twice for {package.target}",
            )
            seen.add((package.name, package.target))
        for package in self.pin.packages:
            self.assertIsNotNone(self.pin.url_for(package))

    def test_the_same_version_is_pinned_for_both_architectures(self):
        for name, by_arch in self.pin.versions_by_name().items():
            self.assertEqual(
                len(set(by_arch.values())), 1, f"{name} pins different versions per architecture"
            )


    def test_the_override_git_assessment_is_dated_within_one_window(self):
        # #673: the canary enforces the review-by date daily; a pull request
        # cannot grant the assessment more than one window.
        self.assertTrue(self.pin.copies_override_git)
        reviewed = self.pin.assessment_reviewed
        review_by = self.pin.assessment_review_by
        self.assertIsNotNone(reviewed)
        self.assertIsNotNone(review_by)
        self.assertLess(reviewed, review_by)
        self.assertLessEqual(
            review_by - reviewed, check_base_image_pin.MAX_ASSESSMENT_WINDOW
        )
        report = check_base_image_pin.Report()
        check_base_image_pin.check_assessment(self.pin, report, reviewed)
        self.assertEqual(report.assessment_due, [])
        # sol F2 / dsf F1: the live last-reviewed date has already happened,
        # so the deadline is at most one window from now. Only a future date
        # fails here; time passing never does (the canary enforces expiry).
        self.assertLessEqual(
            reviewed,
            datetime.now(timezone.utc).date() + check_base_image_pin.ASSESSMENT_CLOCK_SKEW,
        )


OVERRIDE_GIT_DOCKERFILE = DOCKERFILE.replace(
    "RUN cargo build --release --locked\n",
    "# Override Git assessment: last reviewed 2026-11-16, review by 2027-02-14.\n"
    "RUN set -eu; \\\n"
    "    mkdir -p /opt/override-git/lib; \\\n"
    "    cp /usr/bin/git /opt/override-git/git\n"
    "RUN cargo build --release --locked\n",
)


class AssessmentTests(unittest.TestCase):
    """#673: the override Git CVE assessment carries an enforced review-by date."""

    def due(self, dockerfile, today):
        pin = check_base_image_pin.parse_dockerfile(dockerfile)
        report = check_base_image_pin.Report(has_pins=True)
        check_base_image_pin.check_assessment(pin, report, today)
        return report

    def test_the_fixture_reads_the_copy_and_both_dates(self):
        pin = check_base_image_pin.parse_dockerfile(OVERRIDE_GIT_DOCKERFILE)
        self.assertTrue(pin.copies_override_git)
        self.assertEqual(pin.assessment_reviewed, date(2026, 11, 16))
        self.assertEqual(pin.assessment_review_by, date(2027, 2, 14))

    def test_an_assessment_within_its_window_is_ok(self):
        for today in (date(2026, 11, 16), date(2027, 2, 14)):
            with self.subTest(today=today):
                report = self.due(OVERRIDE_GIT_DOCKERFILE, today)
                self.assertEqual(report.assessment_due, [])
                self.assertIs(report.state, State.OK)

    def test_a_passed_review_by_date_is_stale_with_its_own_headline(self):
        report = self.due(OVERRIDE_GIT_DOCKERFILE, date(2027, 2, 15))
        self.assertIs(report.state, State.STALE)
        self.assertEqual(len(report.assessment_due), 1)
        self.assertIn("2027-02-14 has passed", report.assessment_due[0])
        text = check_base_image_pin.render(report)
        self.assertTrue(text.startswith(check_base_image_pin.ASSESSMENT_HEADLINE), text)
        for url in check_base_image_pin.ASSESSMENT_TRACKERS:
            self.assertIn(url, text)
        self.assertNotIn("SHA256SUMS", text)

    def test_a_package_failure_keeps_the_package_headline(self):
        report = self.due(OVERRIDE_GIT_DOCKERFILE, date(2027, 3, 1))
        report.uncovered = ["CVE-2026-1 HIGH perl-base 1 -> 2 (neither pinned nor purged)"]
        text = check_base_image_pin.render(report)
        self.assertTrue(text.startswith(check_base_image_pin.HEADLINE[State.STALE]), text)
        self.assertIn("Override Git assessment due", text)

    def test_a_copy_without_a_dated_assessment_is_stale(self):
        dockerfile = OVERRIDE_GIT_DOCKERFILE.replace(
            "# Override Git assessment: last reviewed 2026-11-16, review by 2027-02-14.\n", ""
        )
        report = self.due(dockerfile, date(2026, 11, 17))
        self.assertIs(report.state, State.STALE)
        self.assertIn("carries no", report.assessment_due[0])

    def test_a_window_longer_than_the_limit_is_stale_before_it_ends(self):
        for line in (
            "review by 2027-02-17.",  # 93 days
            "review by 2026-11-16.",  # no window at all
        ):
            with self.subTest(line=line):
                dockerfile = OVERRIDE_GIT_DOCKERFILE.replace("review by 2027-02-14.", line)
                report = self.due(dockerfile, date(2026, 11, 16))
                self.assertIs(report.state, State.STALE)
                self.assertIn("review window", report.assessment_due[0])

    def test_a_future_last_reviewed_date_is_stale(self):
        # sol F2 / dsf F1: a 90-day window that starts in the future would
        # keep the canary green until it ends.
        dockerfile = OVERRIDE_GIT_DOCKERFILE.replace(
            "last reviewed 2026-11-16, review by 2027-02-14.",
            "last reviewed 2040-01-01, review by 2040-02-14.",
        )
        report = self.due(dockerfile, date(2026, 11, 17))
        self.assertIs(report.state, State.STALE)
        self.assertEqual(len(report.assessment_due), 1, report.assessment_due)
        self.assertIn("2040-01-01 is in the future", report.assessment_due[0])

    def test_one_day_of_clock_skew_is_allowed_and_two_are_not(self):
        self.assertEqual(self.due(OVERRIDE_GIT_DOCKERFILE, date(2026, 11, 15)).assessment_due, [])
        report = self.due(OVERRIDE_GIT_DOCKERFILE, date(2026, 11, 14))
        self.assertIs(report.state, State.STALE)
        self.assertEqual(len(report.assessment_due), 1, report.assessment_due)
        self.assertIn("2026-11-16 is in the future", report.assessment_due[0])

    def test_two_assessment_lines_are_refused(self):
        line = "# Override Git assessment: last reviewed 2026-11-16, review by 2027-02-14.\n"
        with self.assertRaises(ValueError):
            check_base_image_pin.parse_dockerfile(
                OVERRIDE_GIT_DOCKERFILE.replace(line, line + line)
            )

    def test_a_dockerfile_without_the_copy_needs_no_assessment(self):
        report = self.due(DOCKERFILE, date(2030, 1, 1))
        self.assertEqual(report.assessment_due, [])

    def test_main_enforces_the_date_against_todays_utc_date(self):
        stale_line = "# Override Git assessment: last reviewed 2020-01-01, review by 2020-03-01.\n"
        dockerfile = OVERRIDE_GIT_DOCKERFILE.replace(
            "# Override Git assessment: last reviewed 2026-11-16, review by 2027-02-14.\n",
            stale_line,
        )
        code, body = MainTests().run_main(
            [vulnerability("perl-base", "5.40.1-6+deb13u1")], dockerfile=dockerfile
        )
        self.assertEqual(code, 1)
        self.assertIn(check_base_image_pin.ASSESSMENT_HEADLINE, body)


class TrivyReportTests(unittest.TestCase):
    def test_only_fixed_critical_and_high_os_findings_count(self):
        document = report_document(
            [
                vulnerability("perl-base", "5.40.1-6+deb13u1", severity="CRITICAL"),
                vulnerability("gzip", "1.13-1+deb13u1", severity="HIGH"),
                vulnerability("zlib1g", "1.3", severity="MEDIUM"),
                vulnerability("openssl", "", severity="CRITICAL"),
            ]
        )
        findings, digest = check_base_image_pin.parse_trivy_report(document)
        self.assertEqual(sorted(f.package for f in findings), ["gzip", "perl-base"])
        self.assertEqual(digest, "sha256:cccc")

    def test_library_results_are_ignored(self):
        document = {
            "Results": [
                {"Class": "lang-pkgs", "Vulnerabilities": [vulnerability("serde", "1.0")]},
                {"Class": "os-pkgs", "Vulnerabilities": None},
            ]
        }
        findings, digest = check_base_image_pin.parse_trivy_report(document)
        self.assertEqual(findings, [])
        self.assertEqual(digest, "")


class ClassificationTests(unittest.TestCase):
    def setUp(self):
        self.pin = check_base_image_pin.parse_dockerfile(DOCKERFILE)

    def classify(self, vulnerabilities):
        findings, _ = check_base_image_pin.parse_trivy_report(report_document(vulnerabilities))
        return check_base_image_pin.classify(findings, self.pin)

    def test_a_clean_scan_does_not_prove_the_pinned_version_is_in_the_base(self):
        report = self.classify([])
        self.assertIs(report.state, State.OK)
        self.assertEqual(sorted(report.redundant_pins), ["gzip", "perl-base"])

    def test_a_pin_at_the_fixed_version_covers_the_finding(self):
        report = self.classify([vulnerability("perl-base", "5.40.1-6+deb13u1")])
        self.assertIs(report.state, State.OK)
        self.assertEqual(len(report.covered_by_pin), 1)
        self.assertEqual(report.redundant_pins, ["gzip"])

    def test_a_pin_newer_than_the_fixed_version_still_covers_it(self):
        report = self.classify([vulnerability("gzip", "1.13-1")])
        self.assertIs(report.state, State.OK)
        self.assertEqual(len(report.covered_by_pin), 1)

    ZLIB_DOCKERFILE = (
        DOCKERFILE.replace("gzip_1.13-1+deb13u1_amd64.deb", "zlib1g_1.3.1-1+deb13u1_amd64.deb")
        .replace("gzip_1.13-1+deb13u1_arm64.deb", "zlib1g_1.3.1-1+deb13u1_arm64.deb")
        .replace("gzip_*) pool=pool/main/g/gzip ;;", "zlib1g_*) pool=pool/main/z/zlib epoch=1 ;;")
    )

    def classify_zlib(self, dockerfile, fixed, installed):
        findings, _ = check_base_image_pin.parse_trivy_report(
            report_document([vulnerability("zlib1g", fixed, installed=installed)])
        )
        return check_base_image_pin.classify(
            findings, check_base_image_pin.parse_dockerfile(dockerfile)
        )

    def test_a_declared_epoch_lets_the_pin_cover_its_fix(self):
        # zlib1g ships with epoch 1, which its pool file name omits.
        report = self.classify_zlib(self.ZLIB_DOCKERFILE, "1:1.3.1-1+deb13u1", "1:1.3.1-1+b1")
        self.assertIs(report.state, State.OK)
        self.assertEqual(len(report.covered_by_pin), 1)

        report = self.classify_zlib(self.ZLIB_DOCKERFILE, "1:1.3.1-1+deb13u2", "1:1.3.1-1+b1")
        self.assertIs(report.state, State.STALE)
        self.assertIn("amd64: pinned 1:1.3.1-1+deb13u1", report.stale_pins[0])

    def test_an_undeclared_epoch_is_never_borrowed_from_the_scan(self):
        # The moving base tag's epoch says nothing about the pinned bytes, so
        # an epoch-bearing fix stays stale until the epoch is declared.
        undeclared = self.ZLIB_DOCKERFILE.replace(" epoch=1 ;;", " ;;")
        report = self.classify_zlib(undeclared, "1:1.3.1-1+deb13u1", "1:1.3.1-1+b1")
        self.assertIs(report.state, State.STALE)
        self.assertIn("amd64: pinned 1.3.1-1+deb13u1", report.stale_pins[0])

    def test_a_base_that_crossed_to_a_higher_epoch_leaves_the_pin_stale(self):
        # The epoch-1 pin sorts below every epoch-2 version, however low its
        # upstream part: borrowing the scanned epoch would certify it.
        report = self.classify_zlib(self.ZLIB_DOCKERFILE, "2:1.1-1", "2:1.0-1")
        self.assertIs(report.state, State.STALE)
        self.assertIn("amd64: pinned 1:1.3.1-1+deb13u1", report.stale_pins[0])

    def test_declared_epochs_are_read_beside_their_pool(self):
        pin = check_base_image_pin.parse_dockerfile(self.ZLIB_DOCKERFILE)
        self.assertEqual(pin.epochs, {"zlib1g": 1})
        self.assertEqual(pin.pools["zlib1g"], "pool/main/z/zlib")
        self.assertEqual(pin.debian_version("perl-base", "5.40.1-6+deb13u1"), "5.40.1-6+deb13u1")

    def test_a_newer_point_release_than_the_pin_is_stale(self):
        # Exactly the shape of the perl-base gap that turned every pull request
        # red: the base reports a fix the pinned version does not reach.
        report = self.classify([vulnerability("perl-base", "5.40.1-6+deb13u2")])
        self.assertIs(report.state, State.STALE)
        self.assertEqual(len(report.stale_pins), 1)
        self.assertIn("amd64: pinned 5.40.1-6+deb13u1", report.stale_pins[0])
        self.assertIn("arm64: pinned 5.40.1-6+deb13u1", report.stale_pins[0])

    def test_a_package_that_is_neither_pinned_nor_purged_is_stale(self):
        report = self.classify([vulnerability("libsqlite3-0", "3.46.1-7+deb13u2")])
        self.assertIs(report.state, State.STALE)
        self.assertIn("neither pinned nor purged", report.uncovered[0])

    def test_a_purged_package_is_covered_without_a_pin(self):
        report = self.classify([vulnerability("libssl3t64", "3.5.7-1~deb13u2")])
        self.assertIs(report.state, State.OK)
        self.assertEqual(len(report.covered_by_purge), 1)
        self.assertEqual(report.uncovered, [])

    def test_a_retired_stage_with_a_clean_base_is_ok_not_retirable(self):
        pin = check_base_image_pin.parse_dockerfile(RETIRED_DOCKERFILE)
        findings, _ = check_base_image_pin.parse_trivy_report(report_document([]))
        report = check_base_image_pin.classify(findings, pin)
        self.assertIs(report.state, State.OK)
        self.assertFalse(report.has_pins)
        self.assertEqual(report.redundant_pins, [])

    def test_a_retired_stage_with_a_moved_clean_base_requires_a_repin(self):
        pin = check_base_image_pin.parse_dockerfile(RETIRED_DOCKERFILE)
        findings, digest = check_base_image_pin.parse_trivy_report(
            report_document([], "sha256:dddd")
        )
        report = check_base_image_pin.classify(findings, pin, digest)
        self.assertIs(report.state, State.REPIN)
        self.assertTrue(report.digest_moved)

    def test_a_retired_stage_still_covers_a_purged_package(self):
        pin = check_base_image_pin.parse_dockerfile(RETIRED_DOCKERFILE)
        findings, _ = check_base_image_pin.parse_trivy_report(
            report_document([vulnerability("libssl3t64", "3.5.7-1~deb13u2")])
        )
        report = check_base_image_pin.classify(findings, pin)
        self.assertIs(report.state, State.OK)
        self.assertEqual(len(report.covered_by_purge), 1)
        self.assertEqual(report.uncovered, [])

    def test_a_retired_stage_is_stale_when_a_new_finding_is_neither_pinned_nor_purged(self):
        pin = check_base_image_pin.parse_dockerfile(RETIRED_DOCKERFILE)
        findings, _ = check_base_image_pin.parse_trivy_report(
            report_document([vulnerability("perl-base", "5.40.1-6+deb13u2")])
        )
        report = check_base_image_pin.classify(findings, pin)
        self.assertIs(report.state, State.STALE)
        self.assertFalse(report.has_pins)
        self.assertIn("neither pinned nor purged", report.uncovered[0])

    def test_a_pin_that_lags_on_one_architecture_is_stale(self):
        dockerfile = DOCKERFILE.replace(
            "3333333333333333333333333333333333333333333333333333333333333333 "
            "perl-base_5.40.1-6+deb13u1_arm64.deb",
            "3333333333333333333333333333333333333333333333333333333333333333 "
            "perl-base_5.40.1-6_arm64.deb",
        )
        pin = check_base_image_pin.parse_dockerfile(dockerfile)
        findings, _ = check_base_image_pin.parse_trivy_report(
            report_document([vulnerability("perl-base", "5.40.1-6+deb13u1")])
        )
        report = check_base_image_pin.classify(findings, pin)
        self.assertIs(report.state, State.STALE)
        self.assertIn("arm64: pinned 5.40.1-6", report.stale_pins[0])
        self.assertNotIn("amd64", report.stale_pins[0])


class PoolAvailabilityTests(unittest.TestCase):
    def setUp(self):
        self.pin = check_base_image_pin.parse_dockerfile(DOCKERFILE)
        self.report = check_base_image_pin.Report(has_pins=True)

    def test_present_packages_leave_the_state_alone(self):
        check_base_image_pin.check_pool(self.pin, self.report, fetch=lambda url: 200)
        self.assertIs(self.report.state, State.OK)
        self.assertEqual(self.report.missing_from_pool, [])

    def test_a_package_dropped_from_the_pool_is_stale(self):
        def fetch(url):
            return 404 if "perl-base" in url else 200

        check_base_image_pin.check_pool(self.pin, self.report, fetch=fetch)
        self.assertIs(self.report.state, State.STALE)
        self.assertEqual(len(self.report.missing_from_pool), 2)  # both architectures
        self.assertIn("HTTP 404", self.report.missing_from_pool[0])

    def test_an_unreachable_mirror_is_unknown_never_ok(self):
        # A pool check that never completed must not read as a confirmed pool:
        # `ok` is what lets the workflow close the tracking issue.
        check_base_image_pin.check_pool(self.pin, self.report, fetch=lambda url: None)
        self.assertIs(self.report.state, State.UNKNOWN)
        self.assertEqual(len(self.report.unverified_pool), 4)
        self.assertIn("could not all be confirmed", check_base_image_pin.headline(self.report))

    def test_one_unanswered_package_makes_the_whole_pool_unknown(self):
        def fetch(url):
            return None if "gzip" in url and "arm64" in url else 200

        check_base_image_pin.check_pool(self.pin, self.report, fetch=fetch)
        self.assertIs(self.report.state, State.UNKNOWN)
        self.assertEqual(len(self.report.unverified_pool), 1)

    def test_a_package_without_a_pool_directory_is_unknown(self):
        pin = check_base_image_pin.parse_dockerfile(
            DOCKERFILE.replace("        gzip_*) pool=pool/main/g/gzip ;; \\\n", "")
        )
        check_base_image_pin.check_pool(pin, self.report, fetch=lambda url: 200)
        self.assertIs(self.report.state, State.UNKNOWN)
        self.assertTrue(
            all("no pool directory" in entry for entry in self.report.unverified_pool),
            self.report.unverified_pool,
        )

    def test_a_missing_package_stays_stale_when_others_are_unverified(self):
        def fetch(url):
            return 404 if "perl-base" in url else None

        check_base_image_pin.check_pool(self.pin, self.report, fetch=fetch)
        self.assertIs(self.report.state, State.STALE)
        # The issue is opened for the stale package, so the inconclusive ones
        # must not claim that no issue action happens.
        text = check_base_image_pin.render(self.report)
        self.assertIn("Pool availability could not be confirmed", text)
        self.assertNotIn("neither opened nor closed", text)


class RenderTests(unittest.TestCase):
    def test_a_clean_report_keeps_redundant_pins_until_base_metadata_is_verified(self):
        report = check_base_image_pin.Report(
            image="debian:trixie-slim",
            pinned_digest="sha256:cccc",
            current_digest="sha256:dddd",
            has_pins=True,
        )
        report.redundant_pins = ["libpcre2-8-0"]
        text = check_base_image_pin.render(report)
        self.assertIn("does not confirm the installed package version", text)
        self.assertIn("metadata before dropping a pin", text)

    def test_the_stale_report_explains_how_to_refresh_a_pin(self):
        report = check_base_image_pin.Report(image="debian:trixie-slim", has_pins=True)
        report.stale_pins = ["CVE-2026-1 HIGH perl-base 5.40.1-6 -> 5.40.1-6+deb13u2 (amd64: pinned 5.40.1-6+deb13u1)"]
        text = check_base_image_pin.render(report)
        self.assertIn("every**", text)
        self.assertIn("immutable pool path", text)
        self.assertIn("SHA256SUMS", text)

    def test_a_retired_ok_report_does_not_ask_to_delete_a_missing_stage(self):
        report = check_base_image_pin.Report(
            image="debian:trixie-slim",
            pinned_digest="sha256:cccc",
            current_digest="sha256:cccc",
            has_pins=False,
        )
        text = check_base_image_pin.render(report)
        self.assertIn("needs no point-release package stage", text)
        self.assertNotIn("can be retired", text)
        self.assertNotIn("Delete the `runtime-security-updates`", text)

    def test_a_stale_report_without_pins_explains_how_to_reintroduce_the_stage(self):
        report = check_base_image_pin.Report(image="debian:trixie-slim", has_pins=False)
        report.uncovered = ["CVE-2026-1 HIGH perl-base 5.40.1-6 -> 5.40.1-6+deb13u2 (neither pinned nor purged)"]
        text = check_base_image_pin.render(report)
        self.assertIn("Reintroduce the reviewed `runtime-security-updates` builder stage", text)
        self.assertNotIn("SHA256SUMS", text)


class MainTests(unittest.TestCase):
    def run_main(
        self,
        vulnerabilities,
        extra_args=(),
        dockerfile=DOCKERFILE,
        digest="sha256:cccc",
        check_pool=False,
    ):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Dockerfile").write_text(dockerfile, encoding="utf-8")
            report_path = root / "scan.json"
            report_path.write_text(
                json.dumps(report_document(vulnerabilities, digest)), encoding="utf-8"
            )
            body = root / "report.md"
            with contextlib.redirect_stdout(io.StringIO()):
                code = check_base_image_pin.main(
                    [
                        "--root",
                        str(root),
                        "--trivy-report",
                        str(report_path),
                        "--report-file",
                        str(body),
                        *([] if check_pool else ["--skip-pool-check"]),
                        *extra_args,
                    ]
                )
            return code, body.read_text(encoding="utf-8")

    def test_a_covered_base_exits_zero(self):
        code, body = self.run_main([vulnerability("perl-base", "5.40.1-6+deb13u1")])
        self.assertEqual(code, 0)
        self.assertIn("No uncovered fixed CRITICAL/HIGH", body)

    def test_a_clean_scan_exits_zero_and_retains_unverified_package_pins(self):
        code, body = self.run_main([])
        self.assertEqual(code, 0)
        self.assertIn("does not confirm the installed package version", body)

    def test_a_stale_pin_exits_non_zero(self):
        code, body = self.run_main([vulnerability("perl-base", "5.40.1-6+deb13u2")])
        self.assertEqual(code, 1)
        self.assertIn("no longer cover the base image", body)

    def test_a_retired_dockerfile_with_a_clean_base_exits_zero_as_ok(self):
        code, body = self.run_main([], dockerfile=RETIRED_DOCKERFILE)
        self.assertEqual(code, 0)
        self.assertIn("needs no point-release package stage", body)

    def test_a_retired_dockerfile_with_a_moved_clean_base_requests_a_repin(self):
        code, body = self.run_main(
            [], dockerfile=RETIRED_DOCKERFILE, digest="sha256:dddd"
        )
        self.assertEqual(code, 0)
        self.assertIn("pins an older digest", body)
        self.assertIn("debian:trixie-slim@sha256:dddd", body)

    def test_an_unreachable_mirror_writes_state_unknown_and_exits_zero(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "github-output"
            output.write_text("", encoding="utf-8")
            unreachable = mock.patch.object(
                check_base_image_pin.urllib.request,
                "urlopen",
                side_effect=urllib.error.URLError("mirror unreachable"),
            )
            with unreachable, mock.patch.dict(os.environ, {"GITHUB_OUTPUT": str(output)}):
                code, body = self.run_main(
                    [vulnerability("perl-base", "5.40.1-6+deb13u1")], check_pool=True
                )
            written = output.read_text(encoding="utf-8")
        self.assertEqual(code, 0)
        self.assertIn("state=unknown\n", written)
        self.assertIn("could not all be confirmed", body)
        self.assertIn("pool check did not complete", body)

    def test_print_base_ref_emits_the_tag_without_a_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Dockerfile").write_text(DOCKERFILE, encoding="utf-8")
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                code = check_base_image_pin.main(["--root", str(root), "--print-base-ref"])
        self.assertEqual(code, 0)
        self.assertEqual(stdout.getvalue().strip(), "debian:trixie-slim")

    def test_a_missing_dockerfile_is_an_error_not_a_verdict(self):
        with tempfile.TemporaryDirectory() as directory:
            with contextlib.redirect_stderr(io.StringIO()):
                code = check_base_image_pin.main(["--root", directory, "--print-base-ref"])
        self.assertEqual(code, 2)


_STEP_IF_RE = re.compile(r"^        if: (.+)$", re.MULTILINE)


def step_condition(name):
    """The `if:` of the canary step called `name`."""
    text = WORKFLOW.read_text(encoding="utf-8")
    section = text.split(f"      - name: {name}\n", 1)[1].split("\n      - name:", 1)[0]
    match = _STEP_IF_RE.search(section)
    if match is None:
        raise AssertionError(f"missing if: for {name}")
    return match.group(1)


_STATE_TERM_RE = re.compile(r"steps\.evaluate\.outputs\.state (==|!=) '([a-z-]+)'")


def runs_for(condition, state):
    """Evaluate a disjunction of `steps.evaluate.outputs.state ==/!= '<x>'`
    terms, the only form these step conditions take."""
    terms = condition.split(" || ")
    results = []
    for term in terms:
        match = _STATE_TERM_RE.fullmatch(term)
        if match is None:
            raise AssertionError(f"unexpected condition term: {term!r}")
        operator, value = match.groups()
        results.append((state == value) if operator == "==" else (state != value))
    return any(results)


_STATE_CASE_RE = re.compile(
    r'^          case "\$STATE" in\n            ([a-z|]+)\) ;;$',
    re.MULTILINE,
)


class WorkflowRoutingTests(unittest.TestCase):
    OPEN = "Open or update the tracking issue"
    CLOSE = "Close a resolved tracking issue"
    FAIL = "Fail when the pinned packages no longer cover the base image"

    def test_each_state_routes_to_exactly_its_issue_action(self):
        expected = {
            State.OK: {self.CLOSE},
            State.REPIN: {self.OPEN},
            State.STALE: {self.OPEN, self.FAIL},
            # Unknown is never a pass: it neither closes the issue nor
            # replaces the evidence it was opened for.
            State.UNKNOWN: set(),
        }
        for state, steps in expected.items():
            with self.subTest(state=state):
                ran = {
                    step
                    for step in (self.OPEN, self.CLOSE, self.FAIL)
                    if runs_for(step_condition(step), state.value)
                }
                self.assertEqual(ran, steps)

    def test_an_unrecognized_checker_state_is_refused_before_any_issue_action(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        guard = "      - name: Refuse an unrecognized checker state\n"
        self.assertIn(guard, text, "the checker's state must be checked")
        # Before both issue actions, so an unknown value never reaches them.
        self.assertLess(text.index(guard), text.index(f"      - name: {self.OPEN}\n"))
        self.assertLess(text.index(guard), text.index(f"      - name: {self.CLOSE}\n"))
        section = text.split(guard, 1)[1].split("\n      - name:", 1)[0]
        # Read from the step output through env, never from the output file.
        self.assertIn("STATE: ${{ steps.evaluate.outputs.state }}", section)
        self.assertNotIn("GITHUB_OUTPUT", section)
        match = _STATE_CASE_RE.search(section)
        self.assertIsNotNone(match, "the guard must enumerate the checker's states")
        self.assertEqual(set(match.group(1).split("|")), {state.value for state in State})


if __name__ == "__main__":
    unittest.main()
