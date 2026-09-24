"""The release gate's one job: refuse to be satisfied by an absence.

A gate that only catches "the suite failed and we shipped anyway" catches the
loud case. These tests pin the quiet ones — never ran, ran for a different
revision, ran against a different gateway, was cancelled mid-run, or skipped a
scenario and reported no failures.
"""

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path


ROOT = Path(__file__).parents[3]
SCRIPT = Path(__file__).parents[1] / "lifecycle_result.py"
SPEC = importlib.util.spec_from_file_location("lifecycle_result", SCRIPT)
lifecycle_result = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = lifecycle_result
SPEC.loader.exec_module(lifecycle_result)

REVISION = "a" * 40
OTHER_REVISION = "b" * 40
GATEWAY = "c" * 64
NOW = datetime(2026, 9, 21, 12, 0, tzinfo=timezone.utc)


def passing_result(**overrides):
    result = lifecycle_result.empty_result()
    for identifier in lifecycle_result.REQUIRED_SCENARIO_IDS:
        lifecycle_result.record(result, identifier, lifecycle_result.PASSED, "ok")
    lifecycle_result.seal(result, REVISION, GATEWAY, NOW - timedelta(hours=1))
    result.update(overrides)
    return result


def reasons(result, revision=REVISION, gateway=GATEWAY, max_age=None, now=NOW):
    return lifecycle_result.blockers(
        result,
        revision,
        gateway,
        max_age or lifecycle_result.DEFAULT_MAX_AGE_HOURS,
        now,
    )


class CertificationTests(unittest.TestCase):
    def test_a_complete_passing_recent_result_certifies_the_revision(self):
        self.assertEqual(reasons(passing_result()), [])

    def test_a_result_for_another_revision_certifies_nothing(self):
        found = reasons(passing_result(), revision=OTHER_REVISION)
        self.assertTrue(any("certifies" in reason for reason in found), found)

    def test_a_result_from_another_gateway_build_certifies_nothing(self):
        found = reasons(passing_result(), gateway="d" * 64)
        self.assertTrue(
            any("gateway build" in reason for reason in found), found
        )

    def test_an_unsealed_result_is_a_cancelled_run(self):
        result = passing_result()
        result["gitforgeops_revision"] = None
        result["sealed_at"] = None
        found = reasons(result)
        self.assertTrue(any("did not finish" in reason for reason in found), found)

    def test_a_stale_result_certifies_nothing(self):
        result = passing_result()
        lifecycle_result.seal(result, REVISION, GATEWAY, NOW - timedelta(days=30))
        found = reasons(result)
        self.assertTrue(any("beyond the" in reason for reason in found), found)

    def test_a_skipped_scenario_is_not_a_passing_one(self):
        result = passing_result()
        lifecycle_result.record(
            result, "drift-monitoring", lifecycle_result.SKIPPED, "no gateway"
        )
        found = reasons(result)
        self.assertTrue(
            any(
                "drift-monitoring" in reason and "not a passing one" in reason
                for reason in found
            ),
            found,
        )

    def test_a_scenario_that_never_ran_is_not_a_passing_one(self):
        result = lifecycle_result.empty_result()
        lifecycle_result.seal(result, REVISION, GATEWAY, NOW)
        found = reasons(result)
        self.assertEqual(len(found), len(lifecycle_result.REQUIRED_SCENARIO_IDS))

    def test_an_absent_scenario_is_not_a_passing_one(self):
        # A result missing a key entirely — an older suite, or a truncated
        # write — must not read as "nothing to report here".
        result = passing_result()
        del result["scenarios"]["create-and-route"]
        found = reasons(result)
        self.assertTrue(
            any("absent from the result" in reason for reason in found), found
        )

    def test_only_passed_authorizes(self):
        self.assertEqual(
            lifecycle_result.AUTHORIZING, frozenset({lifecycle_result.PASSED})
        )
        for status in lifecycle_result.STATUSES:
            if status == lifecycle_result.PASSED:
                continue
            self.assertNotIn(status, lifecycle_result.AUTHORIZING)

    def test_a_missing_result_file_is_not_a_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(lifecycle_result.ResultError) as raised:
                lifecycle_result.load(Path(directory) / "absent.json")
        self.assertIn("absence of a result", str(raised.exception))

    def test_an_unknown_scenario_or_status_is_refused(self):
        result = lifecycle_result.empty_result()
        with self.assertRaises(lifecycle_result.ResultError):
            lifecycle_result.record(result, "invented", lifecycle_result.PASSED)
        with self.assertRaises(lifecycle_result.ResultError):
            lifecycle_result.record(result, "create-and-route", "probably_fine")


GITHUB_HALF = (
    "credentials-generate-and-rotate",
    "partial-failure-recovery",
    "ledger-publication-failure",
    "runner-interruption",
    "scheduling-and-attribution",
    "staged-promotion",
)


def ci_result():
    """What CI actually produces: the local half passed, the GitHub half skipped."""
    result = lifecycle_result.empty_result()
    for identifier in lifecycle_result.REQUIRED_SCENARIO_IDS:
        status = (
            lifecycle_result.SKIPPED
            if identifier in GITHUB_HALF
            else lifecycle_result.PASSED
        )
        lifecycle_result.record(result, identifier, status, "ci")
    lifecycle_result.seal(result, REVISION, GATEWAY, NOW - timedelta(hours=1))
    return result


def operator_attestation(
    revision=REVISION,
    status=lifecycle_result.PASSED,
    gateway=GATEWAY,
    sealed_at=NOW - timedelta(hours=2),
):
    attestation = lifecycle_result.empty_result()
    for identifier in GITHUB_HALF:
        lifecycle_result.record(attestation, identifier, status, "run 123: ok")
    lifecycle_result.seal(attestation, revision, gateway, sealed_at)
    return attestation


def attest(result, attestation, revision=REVISION, attested_by="maintainer"):
    return lifecycle_result.attest(result, attestation, revision, attested_by, now=NOW)


class AttestationTests(unittest.TestCase):
    """The GitHub half has to be able to reach the gate — and nothing else may."""

    def test_ci_alone_never_certifies_a_release(self):
        found = reasons(ci_result())
        self.assertEqual(len(found), len(GITHUB_HALF), found)

    def test_an_attestation_fills_the_skipped_scenarios_and_certifies(self):
        result = ci_result()
        filled = attest(result, operator_attestation())
        self.assertEqual(sorted(filled), sorted(GITHUB_HALF))
        self.assertEqual(reasons(result), [])
        entry = result["scenarios"]["staged-promotion"]
        self.assertIn("attested by @maintainer", entry["detail"])
        self.assertIn("@maintainer", lifecycle_result.render(result))

    def test_an_attestation_never_overwrites_what_the_suite_ran(self):
        result = ci_result()
        lifecycle_result.record(
            result, "create-and-route", lifecycle_result.FAILED, "route 502"
        )
        attestation = operator_attestation()
        lifecycle_result.record(
            attestation, "create-and-route", lifecycle_result.PASSED, "trust me"
        )
        attest(result, attestation)
        self.assertEqual(
            result["scenarios"]["create-and-route"]["status"], lifecycle_result.FAILED
        )

    def test_an_attested_failure_is_recorded_as_a_failure(self):
        result = ci_result()
        attest(result, operator_attestation(status=lifecycle_result.FAILED))
        self.assertEqual(
            result["scenarios"]["staged-promotion"]["status"], lifecycle_result.FAILED
        )
        self.assertTrue(reasons(result))

    def test_an_attestation_for_other_code_is_refused(self):
        with self.assertRaises(lifecycle_result.ResultError) as raised:
            attest(ci_result(), operator_attestation(revision=OTHER_REVISION))
        self.assertIn("proves nothing about this revision", str(raised.exception))

    def test_an_unsealed_attestation_is_refused(self):
        attestation = operator_attestation()
        attestation["gitforgeops_revision"] = None
        with self.assertRaises(lifecycle_result.ResultError):
            attest(ci_result(), attestation)

    def test_an_attestation_from_another_gateway_build_is_refused(self):
        result = ci_result()
        before = json.loads(json.dumps(result))
        with self.assertRaises(lifecycle_result.ResultError) as raised:
            attest(result, operator_attestation(gateway="e" * 64))
        self.assertIn("gateway build", str(raised.exception))
        self.assertEqual(result, before)

    def test_an_attestation_without_a_gateway_build_is_refused(self):
        attestation = operator_attestation()
        attestation["gateway_build"] = None
        with self.assertRaises(lifecycle_result.ResultError):
            attest(ci_result(), attestation)

    def test_an_attestation_into_an_unsealed_run_is_refused(self):
        # Two absent gateway builds are not a match.
        result = ci_result()
        result["gateway_build"] = None
        attestation = operator_attestation()
        attestation["gateway_build"] = None
        with self.assertRaises(lifecycle_result.ResultError):
            attest(result, attestation)

    def test_a_stale_attestation_is_refused(self):
        result = ci_result()
        before = json.loads(json.dumps(result))
        stale = operator_attestation(
            sealed_at=NOW
            - timedelta(hours=lifecycle_result.DEFAULT_MAX_AGE_HOURS + 1)
        )
        with self.assertRaises(lifecycle_result.ResultError) as raised:
            attest(result, stale)
        self.assertIn("window", str(raised.exception))
        self.assertEqual(result, before)

    def test_an_attestation_inside_the_window_is_accepted(self):
        recent = operator_attestation(
            sealed_at=NOW
            - timedelta(hours=lifecycle_result.DEFAULT_MAX_AGE_HOURS - 1)
        )
        self.assertEqual(sorted(attest(ci_result(), recent)), sorted(GITHUB_HALF))

    def test_an_attestation_without_sealed_at_is_refused(self):
        for sealed_at in (None, "not a timestamp"):
            with self.subTest(sealed_at=sealed_at):
                attestation = operator_attestation()
                attestation["sealed_at"] = sealed_at
                with self.assertRaises(lifecycle_result.ResultError):
                    attest(ci_result(), attestation)

    def test_the_lifecycle_workflow_accepts_an_attestation_only_by_dispatch(self):
        workflow = (ROOT / ".github/workflows/lifecycle.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("github_acceptance:", workflow)
        self.assertIn("lifecycle_result.py attest", workflow)
        # Through the environment, never interpolated into the script.
        self.assertIn("ATTESTATION: ${{ inputs.github_acceptance }}", workflow)
        self.assertNotIn('"${{ inputs.github_acceptance }}"', workflow)
        self.assertIn("--attested-by \"$ATTESTED_BY\"", workflow)


class GatewayAllowlistTests(unittest.TestCase):
    ALLOWLIST = f"# comment\n{GATEWAY}  ferrum-edge-linux-x86_64  # note\n\n"

    def test_an_allowlisted_gateway_build_certifies(self):
        allowlist = lifecycle_result.allowlisted_digests(self.ALLOWLIST)
        self.assertEqual(allowlist, [GATEWAY])
        found = lifecycle_result.blockers(
            passing_result(), REVISION, None, 72, NOW, allowlist
        )
        self.assertEqual(found, [])

    def test_a_build_outside_the_allowlist_certifies_nothing(self):
        found = lifecycle_result.blockers(
            passing_result(), REVISION, None, 72, NOW, ["f" * 64]
        )
        self.assertTrue(any("allowlist" in reason for reason in found), found)

    def test_the_release_gate_binds_the_result_to_the_allowlist(self):
        release = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        self.assertIn(
            "--gateway-allowlist .github/ferrum-edge-checksums.txt", release
        )


class CoverageTests(unittest.TestCase):
    """The declared scenarios are the product's promises, enumerated."""

    def test_every_acceptance_scenario_from_the_issue_is_declared(self):
        # One id per acceptance bullet in #263, plus the promotion path #268
        # asks this suite to exercise. Adding a fail-closed gate to `apply`
        # without adding a scenario here narrows what the suite certifies
        # without narrowing what ships.
        self.assertEqual(
            set(lifecycle_result.REQUIRED_SCENARIO_IDS),
            {
                "create-and-route",
                "reapply-is-a-no-op",
                "modify-and-delete-in-order",
                "credentials-generate-and-rotate",
                "partial-failure-recovery",
                "ledger-publication-failure",
                "runner-interruption",
                "scheduling-and-attribution",
                "staged-promotion",
                "drift-monitoring",
                "file-and-mesh-boundary",
            },
        )

    def test_the_driver_implements_every_declared_scenario(self):
        spec = importlib.util.spec_from_file_location(
            "lifecycle_scenarios", ROOT / "tests/lifecycle/scenarios.py"
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.assertEqual(
            sorted(module.SCENARIOS), sorted(lifecycle_result.REQUIRED_SCENARIO_IDS)
        )

    def test_the_runbook_documents_every_declared_scenario(self):
        runbook = (ROOT / "tests/lifecycle/README.md").read_text(encoding="utf-8")
        for identifier, _ in lifecycle_result.REQUIRED_SCENARIOS:
            self.assertIn(identifier, runbook, identifier)


class RenderingTests(unittest.TestCase):
    def test_the_summary_names_the_revision_gateway_and_every_scenario(self):
        rendered = lifecycle_result.render(passing_result())
        self.assertIn(REVISION, rendered)
        self.assertIn(GATEWAY, rendered)
        for identifier in lifecycle_result.REQUIRED_SCENARIO_IDS:
            self.assertIn(f"`{identifier}`", rendered)
        self.assertIn("none of them authorizes a release", rendered)

    def test_an_unsealed_result_renders_as_unsealed_rather_than_blank(self):
        rendered = lifecycle_result.render(lifecycle_result.empty_result())
        self.assertIn("UNSEALED", rendered)


class CliTests(unittest.TestCase):
    def _run(self, *args):
        return subprocess.run(
            [sys.executable, str(SCRIPT), *args],
            check=False,
            text=True,
            capture_output=True,
        )

    def test_init_record_seal_verify_round_trip(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "result.json"
            self.assertEqual(self._run("init", "--result", str(path)).returncode, 0)

            # Unsealed and unrecorded: refused.
            blocked = self._run(
                "verify", "--result", str(path), "--revision", REVISION
            )
            self.assertEqual(blocked.returncode, 1)
            self.assertIn("::error::", blocked.stdout)

            for identifier in lifecycle_result.REQUIRED_SCENARIO_IDS:
                self.assertEqual(
                    self._run(
                        "record",
                        "--result", str(path),
                        "--scenario", identifier,
                        "--status", "passed",
                        "--detail", "ok",
                    ).returncode,
                    0,
                )
            self.assertEqual(
                self._run(
                    "seal",
                    "--result", str(path),
                    "--revision", REVISION,
                    "--gateway", GATEWAY,
                ).returncode,
                0,
            )
            ok = self._run(
                "verify",
                "--result", str(path),
                "--revision", REVISION,
                "--gateway", GATEWAY,
            )
            self.assertEqual(ok.returncode, 0, ok.stdout)
            self.assertIn("::notice::", ok.stdout)

            written = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(written["gitforgeops_revision"], REVISION)

    def test_attest_refuses_an_attestation_from_another_gateway_build(self):
        with tempfile.TemporaryDirectory() as directory:
            result_path = Path(directory) / "result.json"
            attestation_path = Path(directory) / "attestation.json"
            for path, gateway in ((result_path, GATEWAY), (attestation_path, "e" * 64)):
                self.assertEqual(self._run("init", "--result", str(path)).returncode, 0)
                for identifier in GITHUB_HALF:
                    self.assertEqual(
                        self._run(
                            "record",
                            "--result", str(path),
                            "--scenario", identifier,
                            "--status", "skipped" if path == result_path else "passed",
                        ).returncode,
                        0,
                    )
                sealed = self._run(
                    "seal",
                    "--result", str(path),
                    "--revision", REVISION,
                    "--gateway", gateway,
                )
                self.assertEqual(sealed.returncode, 0)
            before = result_path.read_text(encoding="utf-8")
            refused = self._run(
                "attest",
                "--result", str(result_path),
                "--attestation", str(attestation_path),
                "--revision", REVISION,
                "--attested-by", "maintainer",
            )
            self.assertEqual(refused.returncode, 1, refused.stdout)
            self.assertIn("::error::", refused.stdout)
            self.assertIn("gateway build", refused.stdout)
            self.assertEqual(result_path.read_text(encoding="utf-8"), before)

    def test_verify_refuses_a_missing_file_rather_than_passing(self):
        with tempfile.TemporaryDirectory() as directory:
            result = self._run(
                "verify",
                "--result", str(Path(directory) / "absent.json"),
                "--revision", REVISION,
            )
        self.assertEqual(result.returncode, 1)
        self.assertIn("absence of a result", result.stdout)


class ReleaseGateWiringTests(unittest.TestCase):
    """The gate has to be wired into publication, not merely shipped."""

    def setUp(self) -> None:
        self.release = (ROOT / ".github/workflows/release.yml").read_text(
            encoding="utf-8"
        )

    def test_publication_verifies_the_lifecycle_result(self):
        self.assertIn("lifecycle_result.py verify", self.release)
        self.assertIn("--revision", self.release)

    def test_the_gate_runs_before_anything_is_published(self):
        gate = self.release.index("lifecycle_result.py verify")
        for later in ("docker/build-push-action@", "name: Build and push Docker image"):
            if later in self.release:
                self.assertLess(gate, self.release.index(later), later)

    def test_the_gate_waits_for_the_run_it_is_gating_on(self):
        # Both workflows start on the same push, so a single sample is always
        # too early — the release would be permanently red and the gate would
        # become something operators re-run past rather than read.
        self.assertIn("head_sha=${RELEASE_SHA}", self.release)
        self.assertIn("still running for", self.release)
        self.assertIn("sleep 30", self.release)

    def test_the_gate_distinguishes_not_yet_run_from_did_not_pass(self):
        # A finished run that did not certify is a different thing from one
        # that has not happened, and only one of them is fixed by waiting.
        self.assertIn("ran for ${RELEASE_SHA} and did not pass", self.release)
        self.assertIn("has not started for ${RELEASE_SHA} yet", self.release)
        self.assertIn("Fix the scenarios it reported, not the gate", self.release)

    def test_the_gate_does_not_stop_at_the_newest_successful_run(self):
        # A newer push-triggered run skips the GitHub-repository scenarios; it
        # must not hide an older dispatched run that carries the attestation.
        self.assertNotIn("sort_by(.updated_at) | last", self.release)
        self.assertIn("sort_by(.updated_at) | reverse", self.release)
        loop = self.release.index("for run_id in $run_ids; do")
        self.assertLess(loop, self.release.index("lifecycle_result.py verify"))
        self.assertIn("published a result that certifies it", self.release)

    def test_the_lifecycle_workflow_seals_and_publishes_its_result(self):
        workflow = (ROOT / ".github/workflows/lifecycle.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("tests/lifecycle/run.sh", workflow)
        self.assertIn("actions/upload-artifact@", workflow)
        # `!cancelled()` rather than `always()`: a cancelled run must leave an
        # unsealed record, which the gate reads as "did not finish".
        self.assertIn("!cancelled()", workflow)


STUB_GH = """#!/usr/bin/env bash
set -eu
case "$1" in
  api) cat "$STUB_RUNS" ;;
  run)
    id=$3
    dir=
    while [ $# -gt 0 ]; do
      if [ "$1" = --dir ]; then dir=$2; fi
      shift
    done
    [ -f "$STUB_RESULTS/$id.json" ] || exit 1
    mkdir -p "$dir"
    cp "$STUB_RESULTS/$id.json" "$dir/lifecycle-result.json"
    ;;
  *) exit 2 ;;
esac
"""


def release_gate_script() -> str:
    """The shell the release runs to pick and verify a lifecycle result."""
    lines = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8").splitlines()
    start = next(
        index
        for index, line in enumerate(lines)
        if "name: Require a lifecycle acceptance result for this revision" in line
    )
    run = next(index for index in range(start, len(lines)) if lines[index].strip() == "run: |")
    indent = len(lines[run + 1]) - len(lines[run + 1].lstrip())
    body = []
    for line in lines[run + 1 :]:
        if line.strip() and len(line) - len(line.lstrip()) < indent:
            break
        body.append(line[indent:])
    return "\n".join(body) + "\n"


@unittest.skipUnless(
    shutil.which("jq") and shutil.which("bash"),
    "jq and bash are required to exercise the release gate's run selection",
)
class ReleaseGateRunSelectionTests(unittest.TestCase):
    """The gate picks the newest successful run whose result certifies."""

    def _gate(self, runs, results):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scripts = root / ".github/scripts"
            scripts.mkdir(parents=True)
            shutil.copyfile(SCRIPT, scripts / "lifecycle_result.py")
            (root / ".github/ferrum-edge-checksums.txt").write_text(
                f"{GATEWAY}  ferrum-edge\n", encoding="utf-8"
            )
            bin_dir = root / "bin"
            bin_dir.mkdir()
            (bin_dir / "gh").write_text(STUB_GH, encoding="utf-8")
            (bin_dir / "gh").chmod(0o755)
            stub_results = root / "stub-results"
            stub_results.mkdir()
            for run_id, result in results.items():
                lifecycle_result.save(stub_results / f"{run_id}.json", result)
            runs_path = root / "runs.json"
            runs_path.write_text(
                json.dumps({"total_count": len(runs), "workflow_runs": runs}),
                encoding="utf-8",
            )
            summary = root / "summary.md"
            completed = subprocess.run(
                ["bash", "-c", release_gate_script()],
                cwd=root,
                env={
                    "PATH": f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}",
                    "REPO": "acme/template-copy",
                    "RELEASE_SHA": REVISION,
                    "GH_TOKEN": "unused",
                    "GITHUB_STEP_SUMMARY": str(summary),
                    "STUB_RUNS": str(runs_path),
                    "STUB_RESULTS": str(stub_results),
                },
                check=False,
                capture_output=True,
                text=True,
                timeout=60,
            )
            return completed

    @staticmethod
    def _run(run_id, updated_at, conclusion="success"):
        return {
            "id": run_id,
            "status": "completed",
            "conclusion": conclusion,
            "updated_at": updated_at,
        }

    @staticmethod
    def _fresh(result):
        lifecycle_result.seal(result, REVISION, GATEWAY, datetime.now(timezone.utc))
        return result

    def _attested(self):
        result = ci_result()
        attest(result, operator_attestation())
        return self._fresh(result)

    def test_an_older_attested_run_is_not_hidden_by_a_newer_skipped_one(self):
        completed = self._gate(
            [
                self._run(101, "2026-09-21T10:00:00Z"),
                self._run(202, "2026-09-21T11:00:00Z"),
            ],
            {101: self._attested(), 202: self._fresh(ci_result())},
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertIn("Lifecycle run 202 does not certify", completed.stdout)
        self.assertIn("Lifecycle run 101 certifies", completed.stdout)

    def test_the_newest_certifying_run_is_used_first(self):
        completed = self._gate(
            [
                self._run(101, "2026-09-21T10:00:00Z"),
                self._run(202, "2026-09-21T11:00:00Z"),
            ],
            {101: self._fresh(ci_result()), 202: self._attested()},
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertIn("Lifecycle run 202 certifies", completed.stdout)
        self.assertNotIn("Lifecycle run 101", completed.stdout)

    def test_a_run_without_an_artifact_moves_to_the_next_older_run(self):
        completed = self._gate(
            [
                self._run(101, "2026-09-21T10:00:00Z"),
                self._run(202, "2026-09-21T11:00:00Z"),
            ],
            {101: self._attested()},
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertIn("Lifecycle run 202 published no result artifact", completed.stdout)
        self.assertIn("Lifecycle run 101 certifies", completed.stdout)

    def test_no_certifying_run_fails_closed(self):
        completed = self._gate(
            [
                self._run(101, "2026-09-21T10:00:00Z"),
                self._run(202, "2026-09-21T11:00:00Z"),
                self._run(303, "2026-09-21T12:00:00Z", conclusion="failure"),
            ],
            {
                101: self._fresh(ci_result()),
                202: self._fresh(ci_result()),
                # A failed run is never a candidate, whatever it uploaded.
                303: self._attested(),
            },
        )
        self.assertEqual(completed.returncode, 1, completed.stdout)
        self.assertIn("published a result that certifies it", completed.stdout)
        self.assertNotIn("certifies " + REVISION + ".", completed.stdout)
        self.assertNotIn("Lifecycle run 303", completed.stdout)


if __name__ == "__main__":
    unittest.main()
