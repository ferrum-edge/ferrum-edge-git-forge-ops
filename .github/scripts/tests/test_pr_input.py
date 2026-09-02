import importlib.util
import io
import json
import os
import re
import tarfile
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "pr_input.py"
SPEC = importlib.util.spec_from_file_location("pr_input", SCRIPT)
assert SPEC and SPEC.loader
pr_input = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pr_input)
HEAD_SHA = "a" * 40


def add_file(bundle, name, data, mode=0o644):
    payload = data.encode()
    member = tarfile.TarInfo(name)
    member.size = len(payload)
    member.mode = mode
    bundle.addfile(member, io.BytesIO(payload))


def make_archive(path, extra=None):
    with tarfile.open(path, "w:gz") as bundle:
        root = tarfile.TarInfo("repo-root/")
        root.type = tarfile.DIRTYPE
        bundle.addfile(root)
        add_file(
            bundle,
            "repo-root/resources/team/proxies/api.yaml",
            "kind: Proxy\nspec:\n  id: api\n",
        )
        # Canary executable content is present in the PR archive but must not
        # cross the data boundary into the privileged artifact.
        add_file(
            bundle,
            "repo-root/build.rs",
            'fn main() { println!("{}", std::env::var("FERRUM_ADMIN_JWT_SECRET").unwrap()); }',
            mode=0o755,
        )
        # These are valid inputs to the secretless static workflow, but live
        # review must replace routing and policy with protected-branch files.
        add_file(
            bundle,
            "repo-root/.gitforgeops/config.yaml",
            "version: 1\nenvironments:\n  production: {}\n",
        )
        add_file(
            bundle,
            "repo-root/.gitforgeops/policies.yaml",
            "version: 1\npolicies: {}\n",
        )
        if extra:
            extra(bundle)


class PrInputTests(unittest.TestCase):
    def test_prepare_excludes_executable_canary_and_verifies_manifest(self):
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            archive = temp / "pr.tar.gz"
            output = temp / "output"
            make_archive(archive)
            manifest = pr_input.prepare(archive, output, HEAD_SHA)
            self.assertEqual(len(manifest["files"]), 1)
            self.assertFalse((output / "build.rs").exists())
            self.assertFalse((output / ".gitforgeops/config.yaml").exists())
            self.assertFalse((output / ".gitforgeops/policies.yaml").exists())
            pr_input.verify(output, HEAD_SHA)

    def test_prepare_rejects_symlinks_in_declarative_tree(self):
        def extra(bundle):
            member = tarfile.TarInfo("repo-root/resources/team/proxies/escape.yaml")
            member.type = tarfile.SYMTYPE
            member.linkname = "../../../../build.rs"
            bundle.addfile(member)

        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            archive = temp / "pr.tar.gz"
            make_archive(archive, extra)
            with self.assertRaisesRegex(pr_input.InputError, "links are forbidden"):
                pr_input.prepare(archive, temp / "output", HEAD_SHA)

    def test_prepare_rejects_traversal_and_executable_yaml(self):
        for name, mode, expected in [
            ("repo-root/resources/../escape.yaml", 0o644, "unsafe archive path"),
            (
                "repo-root/resources/team/proxies/executable.yaml",
                0o755,
                "executable declarative file",
            ),
        ]:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temp:
                temp = Path(temp)
                archive = temp / "pr.tar.gz"

                def extra(bundle):
                    add_file(bundle, name, "kind: Proxy\nspec: {}\n", mode)

                make_archive(archive, extra)
                with self.assertRaisesRegex(pr_input.InputError, expected):
                    pr_input.prepare(archive, temp / "output", HEAD_SHA)

    def test_prepare_rejects_unsupported_declarative_file_extensions(self):
        for name in [
            "resources/team/proxies/api.YAML",
            "resources/team/proxies/api.yam",
            "resources/team/proxies/api.yaml.bak",
            "overlays/prod/team/proxies/api.json",
        ]:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temp:
                temp = Path(temp)
                archive = temp / "pr.tar.gz"

                def extra(bundle):
                    add_file(bundle, f"repo-root/{name}", "kind: Proxy\nspec: {}\n")

                make_archive(archive, extra)
                with self.assertRaisesRegex(pr_input.InputError, "unsupported file"):
                    pr_input.prepare(archive, temp / "output", HEAD_SHA)

    def test_prepare_allows_documentation_and_intentionally_disabled_files(self):
        def extra(bundle):
            add_file(bundle, "repo-root/resources/team/proxies/README.md", "docs")
            add_file(bundle, "repo-root/resources/team/proxies/.gitkeep", "")
            add_file(
                bundle,
                "repo-root/resources/.gitforgeops-import.json",
                '{"schema_version": 1}',
            )
            add_file(
                bundle,
                "repo-root/resources/team/proxies/_api.yaml.bak",
                "disabled",
            )

        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            archive = temp / "pr.tar.gz"
            output = temp / "output"
            make_archive(archive, extra)
            manifest = pr_input.prepare(archive, output, HEAD_SHA)
            self.assertEqual(
                [entry["path"] for entry in manifest["files"]],
                ["resources/team/proxies/api.yaml"],
            )

    def test_prepare_silently_skips_os_artifacts(self):
        # Finder and Explorer drop these into any directory they display.
        # There is nothing for an author to commit that removes them for good,
        # so the trusted-input gate skips them exactly like the Rust loader.
        def extra(bundle):
            for artifact in sorted(pr_input.OS_ARTIFACT_FILES):
                add_file(
                    bundle, f"repo-root/resources/team/proxies/{artifact}", "junk"
                )
                add_file(bundle, f"repo-root/overlays/prod/team/{artifact}", "junk")

        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            archive = temp / "pr.tar.gz"
            output = temp / "output"
            make_archive(archive, extra)
            manifest = pr_input.prepare(archive, output, HEAD_SHA)
            self.assertEqual(
                [entry["path"] for entry in manifest["files"]],
                ["resources/team/proxies/api.yaml"],
            )

    def test_prepare_still_rejects_config_shaped_lookalikes(self):
        # The skip list matches exact names. Anything that could be a resource
        # document stays fatal: a file that looks like configuration and is
        # silently not loaded is how a typo becomes a prune.
        for name in [
            "resources/team/proxies/thumbs.db",
            "resources/team/proxies/Desktop.ini",
            "resources/team/proxies/ds_store.yaml.bak",
        ]:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temp:
                temp = Path(temp)
                archive = temp / "pr.tar.gz"

                def extra(bundle, name=name):
                    add_file(bundle, f"repo-root/{name}", "junk")

                make_archive(archive, extra)
                with self.assertRaisesRegex(pr_input.InputError, "unsupported file"):
                    pr_input.prepare(archive, temp / "output", HEAD_SHA)

    def test_prepare_preserves_misplaced_lowercase_yaml_for_strict_validation(self):
        def extra(bundle):
            add_file(bundle, "repo-root/resources/api.yaml", "kind: Proxy\nspec: {}\n")

        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            archive = temp / "pr.tar.gz"
            output = temp / "output"
            make_archive(archive, extra)
            manifest = pr_input.prepare(archive, output, HEAD_SHA)
            self.assertIn(
                "resources/api.yaml",
                [entry["path"] for entry in manifest["files"]],
            )
            pr_input.verify(output, HEAD_SHA)

    def test_verify_rejects_unexpected_and_tampered_files(self):
        for mutation, expected in [
            ("unexpected", "path set differs"),
            ("tamper", "integrity mismatch"),
        ]:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temp:
                temp = Path(temp)
                archive = temp / "pr.tar.gz"
                output = temp / "output"
                make_archive(archive)
                pr_input.prepare(archive, output, HEAD_SHA)
                if mutation == "unexpected":
                    (output / "unexpected.txt").write_text("nope")
                else:
                    target = output / "resources/team/proxies/api.yaml"
                    target.write_text("tampered")
                with self.assertRaisesRegex(pr_input.InputError, expected):
                    pr_input.verify(output, HEAD_SHA)

    def test_verify_rejects_head_sha_mismatch(self):
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            archive = temp / "pr.tar.gz"
            output = temp / "output"
            make_archive(archive)
            pr_input.prepare(archive, output, HEAD_SHA)
            with self.assertRaisesRegex(pr_input.InputError, "head SHA"):
                pr_input.verify(output, "b" * 40)

    def test_trusted_targets_are_a_protected_environment_namespace_product(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "resources/ferrum").mkdir(parents=True)
            (root / "resources/team-a").mkdir()
            targets = pr_input.trusted_targets(
                root,
                json.dumps(
                    [
                        {"environment": "staging", "namespaces": None},
                        {
                            "environment": "production",
                            "namespaces": ["team-a"],
                        },
                    ]
                ),
            )
            self.assertEqual(
                targets,
                [
                    {"environment": "production", "namespace": "team-a"},
                    {"environment": "staging", "namespace": "ferrum"},
                    {"environment": "staging", "namespace": "team-a"},
                ],
            )

    def test_trusted_targets_reject_unsafe_or_symlinked_namespace_paths(self):
        for name, symlink, expected in [
            ("unsafe namespace", False, "unsafe trusted namespace"),
            ("linked", True, "may not be a symlink"),
        ]:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                resources = root / "resources"
                resources.mkdir()
                target = resources / name
                if symlink:
                    target.symlink_to(root, target_is_directory=True)
                else:
                    target.mkdir()
                with self.assertRaisesRegex(pr_input.InputError, expected):
                    pr_input.trusted_targets(
                        root,
                        '[{"environment":"production","namespaces":null}]',
                    )

    def test_trusted_targets_reject_malformed_or_duplicate_scope(self):
        cases = [
            '["production"]',
            '[{"environment":"production","namespaces":["unsafe namespace"]}]',
            '[{"environment":"production","namespaces":null},'
            '{"environment":"production","namespaces":null}]',
            '[{"environment":"production","namespaces":null,"extra":true}]',
        ]
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "resources/team").mkdir(parents=True)
            for payload in cases:
                with self.subTest(payload=payload), self.assertRaises(
                    pr_input.InputError
                ):
                    pr_input.trusted_targets(root, payload)


class AllowlistParityTests(unittest.TestCase):
    """The Rust loader and this gate guard the same `resources/` and
    `overlays/` trees on either side of the trusted-review boundary. A file one
    of them skips and the other rejects (or vice versa) means a PR that passes
    static validation and then fails live review, or worse, an artifact that
    silently omits a resource. Rather than hope the two lists stay in step,
    read the Rust ones and compare."""

    REPO_ROOT = Path(__file__).resolve().parents[3]

    def _rust_array(self, source: str, name: str) -> list[str]:
        start = source.index(f"const {name}:")
        body = source[start : source.index("];", start)]
        return re.findall(r'"([^"]*)"', body[body.index("=") :])

    def test_non_config_allowlist_matches_the_rust_loader(self):
        strict = (self.REPO_ROOT / "src/config/strict.rs").read_text()
        # `NON_CONFIG_FILES` names the import manifest through a constant, so
        # the literal comes from `import::IMPORT_MANIFEST_FILENAME`.
        expected = set(self._rust_array(strict, "NON_CONFIG_FILES"))
        expected.add(self._import_manifest_filename())
        self.assertEqual(expected, pr_input.NON_CONFIG_FILES)

    def test_os_artifact_allowlist_matches_the_rust_loader(self):
        strict = (self.REPO_ROOT / "src/config/strict.rs").read_text()
        self.assertEqual(
            set(self._rust_array(strict, "OS_ARTIFACT_FILES")),
            pr_input.OS_ARTIFACT_FILES,
        )

    def test_import_manifest_filename_matches_the_rust_constant(self):
        # `.gitforgeops-import.json` is spelled out here but derived from
        # `import::IMPORT_MANIFEST_FILENAME` in Rust; a rename on one side
        # would otherwise make the manifest fatal input to live review.
        self.assertIn(self._import_manifest_filename(), pr_input.NON_CONFIG_FILES)

    def _import_manifest_filename(self) -> str:
        source = (self.REPO_ROOT / "src/import/mod.rs").read_text()
        match = re.search(
            r'pub const IMPORT_MANIFEST_FILENAME: &str = "([^"]+)";', source
        )
        assert match, "IMPORT_MANIFEST_FILENAME not found in src/import/mod.rs"
        return match.group(1)


if __name__ == "__main__":
    unittest.main()
