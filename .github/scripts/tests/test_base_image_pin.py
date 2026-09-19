import contextlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "check_base_image_pin.py"
REPO_ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location("check_base_image_pin", SCRIPT)
check_base_image_pin = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = check_base_image_pin
SPEC.loader.exec_module(check_base_image_pin)

compare = check_base_image_pin.compare_debian_versions

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

    def test_the_live_dockerfile_has_retired_the_package_stage(self):
        self.assertEqual(self.pin.packages, [])
        self.assertEqual(self.pin.pools, {})
        self.assertEqual(self.pin.mirror, "")
        self.assertEqual(self.pin.versions_by_name(), {})
        instructions = "\n".join(
            line
            for line in (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8").splitlines()
            if not line.lstrip().startswith("#")
        )
        self.assertNotIn("runtime-security-updates", instructions)
        self.assertNotIn("dpkg --install", instructions)
        self.assertNotEqual(
            self.pin.digest,
            "sha256:d7e12182ce18b85b93007c1dedf31f2d29e01ccf3182cc4017c709b6259bc132",
        )
        self.assertEqual(
            self.pin.digest,
            "sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a",
        )

    def test_every_pinned_package_carries_both_architectures_and_a_pool(self):
        # Completeness guard if the temporary stage is reintroduced: both
        # architectures and a pool directory must stay in step. The live
        # Dockerfile currently has no pins (issue #257).
        versions = self.pin.versions_by_name()
        for name, by_arch in versions.items():
            self.assertEqual(
                sorted(by_arch), ["amd64", "arm64"], f"{name} is not pinned for both architectures"
            )
            self.assertIn(name, self.pin.pools, f"{name} has no pool directory")
        for package in self.pin.packages:
            self.assertIsNotNone(self.pin.url_for(package))

    def test_the_same_version_is_pinned_for_both_architectures(self):
        for name, by_arch in self.pin.versions_by_name().items():
            self.assertEqual(
                len(set(by_arch.values())), 1, f"{name} pins different versions per architecture"
            )


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

    def test_a_clean_base_means_the_stage_can_be_retired(self):
        report = self.classify([])
        self.assertEqual(report.state, "retire")
        self.assertEqual(sorted(report.redundant_pins), ["gzip", "perl-base"])

    def test_a_pin_at_the_fixed_version_covers_the_finding(self):
        report = self.classify([vulnerability("perl-base", "5.40.1-6+deb13u1")])
        self.assertEqual(report.state, "ok")
        self.assertEqual(len(report.covered_by_pin), 1)
        self.assertEqual(report.redundant_pins, ["gzip"])

    def test_a_pin_newer_than_the_fixed_version_still_covers_it(self):
        report = self.classify([vulnerability("gzip", "1.13-1")])
        self.assertEqual(report.state, "ok")
        self.assertEqual(len(report.covered_by_pin), 1)

    def test_a_newer_point_release_than_the_pin_is_stale(self):
        # Exactly the shape of the perl-base gap that turned every pull request
        # red: the base reports a fix the pinned version does not reach.
        report = self.classify([vulnerability("perl-base", "5.40.1-6+deb13u2")])
        self.assertEqual(report.state, "stale")
        self.assertEqual(len(report.stale_pins), 1)
        self.assertIn("amd64: pinned 5.40.1-6+deb13u1", report.stale_pins[0])
        self.assertIn("arm64: pinned 5.40.1-6+deb13u1", report.stale_pins[0])

    def test_a_package_that_is_neither_pinned_nor_purged_is_stale(self):
        report = self.classify([vulnerability("libsqlite3-0", "3.46.1-7+deb13u2")])
        self.assertEqual(report.state, "stale")
        self.assertIn("neither pinned nor purged", report.uncovered[0])

    def test_a_purged_package_is_covered_without_a_pin(self):
        report = self.classify([vulnerability("libssl3t64", "3.5.7-1~deb13u2")])
        self.assertEqual(report.state, "ok")
        self.assertEqual(len(report.covered_by_purge), 1)
        self.assertEqual(report.uncovered, [])

    def test_a_retired_stage_with_a_clean_base_is_ok_not_retirable(self):
        pin = check_base_image_pin.parse_dockerfile(RETIRED_DOCKERFILE)
        findings, _ = check_base_image_pin.parse_trivy_report(report_document([]))
        report = check_base_image_pin.classify(findings, pin)
        self.assertEqual(report.state, "ok")
        self.assertFalse(report.has_pins)
        self.assertEqual(report.redundant_pins, [])

    def test_a_retired_stage_still_covers_a_purged_package(self):
        pin = check_base_image_pin.parse_dockerfile(RETIRED_DOCKERFILE)
        findings, _ = check_base_image_pin.parse_trivy_report(
            report_document([vulnerability("libssl3t64", "3.5.7-1~deb13u2")])
        )
        report = check_base_image_pin.classify(findings, pin)
        self.assertEqual(report.state, "ok")
        self.assertEqual(len(report.covered_by_purge), 1)
        self.assertEqual(report.uncovered, [])

    def test_a_retired_stage_is_stale_when_a_new_finding_is_neither_pinned_nor_purged(self):
        pin = check_base_image_pin.parse_dockerfile(RETIRED_DOCKERFILE)
        findings, _ = check_base_image_pin.parse_trivy_report(
            report_document([vulnerability("perl-base", "5.40.1-6+deb13u2")])
        )
        report = check_base_image_pin.classify(findings, pin)
        self.assertEqual(report.state, "stale")
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
        self.assertEqual(report.state, "stale")
        self.assertIn("arm64: pinned 5.40.1-6", report.stale_pins[0])
        self.assertNotIn("amd64", report.stale_pins[0])


class PoolAvailabilityTests(unittest.TestCase):
    def setUp(self):
        self.pin = check_base_image_pin.parse_dockerfile(DOCKERFILE)
        self.report = check_base_image_pin.Report(state="ok")

    def test_present_packages_leave_the_state_alone(self):
        check_base_image_pin.check_pool(self.pin, self.report, fetch=lambda url: 200)
        self.assertEqual(self.report.state, "ok")
        self.assertEqual(self.report.missing_from_pool, [])

    def test_a_package_dropped_from_the_pool_is_stale(self):
        def fetch(url):
            return 404 if "perl-base" in url else 200

        check_base_image_pin.check_pool(self.pin, self.report, fetch=fetch)
        self.assertEqual(self.report.state, "stale")
        self.assertEqual(len(self.report.missing_from_pool), 2)  # both architectures
        self.assertIn("HTTP 404", self.report.missing_from_pool[0])

    def test_an_unreachable_mirror_is_reported_without_failing(self):
        check_base_image_pin.check_pool(self.pin, self.report, fetch=lambda url: None)
        self.assertEqual(self.report.state, "ok")
        self.assertEqual(len(self.report.unverified_pool), 4)

    def test_a_retirable_state_survives_a_healthy_pool_check(self):
        report = check_base_image_pin.Report(state="retire")
        check_base_image_pin.check_pool(self.pin, report, fetch=lambda url: 200)
        self.assertEqual(report.state, "retire")


class RenderTests(unittest.TestCase):
    def test_the_retirement_report_names_the_digest_to_move_to(self):
        report = check_base_image_pin.Report(
            state="retire",
            image="debian:trixie-slim",
            pinned_digest="sha256:cccc",
            current_digest="sha256:dddd",
        )
        text = check_base_image_pin.render(report)
        self.assertIn("can be retired", text)
        self.assertIn("debian:trixie-slim@sha256:dddd", text)
        self.assertIn("Keep the `dpkg --purge` step", text)
        self.assertIn("The tag has been rebuilt since the pin.", text)

    def test_the_stale_report_explains_how_to_refresh_a_pin(self):
        report = check_base_image_pin.Report(
            state="stale", image="debian:trixie-slim", has_pins=True
        )
        report.stale_pins = ["CVE-2026-1 HIGH perl-base 5.40.1-6 -> 5.40.1-6+deb13u2 (amd64: pinned 5.40.1-6+deb13u1)"]
        text = check_base_image_pin.render(report)
        self.assertIn("every**", text)
        self.assertIn("immutable pool path", text)
        self.assertIn("SHA256SUMS", text)

    def test_a_retired_ok_report_does_not_ask_to_delete_a_missing_stage(self):
        report = check_base_image_pin.Report(
            state="ok",
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
        report = check_base_image_pin.Report(
            state="stale", image="debian:trixie-slim", has_pins=False
        )
        report.uncovered = ["CVE-2026-1 HIGH perl-base 5.40.1-6 -> 5.40.1-6+deb13u2 (neither pinned nor purged)"]
        text = check_base_image_pin.render(report)
        self.assertIn("Reintroduce the reviewed `runtime-security-updates` builder stage", text)
        self.assertNotIn("SHA256SUMS", text)


class MainTests(unittest.TestCase):
    def run_main(self, vulnerabilities, extra_args=(), dockerfile=DOCKERFILE):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Dockerfile").write_text(dockerfile, encoding="utf-8")
            report_path = root / "scan.json"
            report_path.write_text(json.dumps(report_document(vulnerabilities)), encoding="utf-8")
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
                        "--skip-pool-check",
                        *extra_args,
                    ]
                )
            return code, body.read_text(encoding="utf-8")

    def test_a_covered_base_exits_zero(self):
        code, body = self.run_main([vulnerability("perl-base", "5.40.1-6+deb13u1")])
        self.assertEqual(code, 0)
        self.assertIn("still required and still sufficient", body)

    def test_a_retirable_base_exits_zero_because_nothing_is_broken(self):
        code, body = self.run_main([])
        self.assertEqual(code, 0)
        self.assertIn("can be retired", body)

    def test_a_stale_pin_exits_non_zero(self):
        code, body = self.run_main([vulnerability("perl-base", "5.40.1-6+deb13u2")])
        self.assertEqual(code, 1)
        self.assertIn("no longer cover the base image", body)

    def test_a_retired_dockerfile_with_a_clean_base_exits_zero_as_ok(self):
        code, body = self.run_main([], dockerfile=RETIRED_DOCKERFILE)
        self.assertEqual(code, 0)
        self.assertIn("needs no point-release package stage", body)

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


if __name__ == "__main__":
    unittest.main()
