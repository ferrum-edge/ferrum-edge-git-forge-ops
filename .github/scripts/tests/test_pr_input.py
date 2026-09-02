import importlib.util
import io
import json
import os
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


def write_changed_paths(root, paths):
    changed_paths = root / "changed-paths.json"
    changed_paths.write_text(json.dumps(paths))
    return changed_paths


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
                        {
                            "environment": "staging",
                            "live_review": True,
                            "namespaces": None,
                        },
                        {
                            "environment": "production",
                            "live_review": True,
                            "namespaces": ["team-a"],
                        },
                        {
                            "environment": "file-output",
                            "live_review": False,
                            "namespaces": None,
                        },
                    ]
                ),
                write_changed_paths(
                    root,
                    [
                        "resources/team-a/proxies/api.yaml",
                        "overlays/staging/ferrum/proxies/api.yaml",
                    ],
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

    def test_trusted_targets_reject_symlinked_namespace_paths(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            resources = root / "resources"
            resources.mkdir()
            (resources / "linked").symlink_to(root, target_is_directory=True)
            with self.assertRaisesRegex(pr_input.InputError, "may not be a symlink"):
                pr_input.trusted_targets(
                    root,
                    '[{"environment":"production","live_review":true,"namespaces":null}]',
                    write_changed_paths(root, ["resources/linked/proxies/api.yaml"]),
                )

    def test_trusted_targets_reject_malformed_or_duplicate_scope(self):
        cases = [
            '["production"]',
            '[{"environment":"production","live_review":true,"namespaces":["unsafe namespace"]}]',
            '[{"environment":"production","live_review":true,"namespaces":null},'
            '{"environment":"production","live_review":true,"namespaces":null}]',
            '[{"environment":"production","live_review":true,"namespaces":null,"extra":true}]',
            '[{"environment":"production","live_review":"yes","namespaces":null}]',
        ]
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "resources/team").mkdir(parents=True)
            for payload in cases:
                with self.subTest(payload=payload), self.assertRaises(
                    pr_input.InputError
                ):
                    pr_input.trusted_targets(
                        root,
                        payload,
                        write_changed_paths(
                            root, ["resources/team/proxies/api.yaml"]
                        ),
                    )

    def test_trusted_targets_exclude_untouched_and_new_namespaces(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "resources/touched").mkdir(parents=True)
            (root / "resources/untouched").mkdir()
            targets = pr_input.trusted_targets(
                root,
                '[{"environment":"production","live_review":true,"namespaces":null}]',
                write_changed_paths(
                    root,
                    [
                        "resources/touched/proxies/api.yaml",
                        "resources/new/proxies/api.yaml",
                    ],
                ),
            )
            self.assertEqual(
                targets,
                [{"environment": "production", "namespace": "touched"}],
            )

    def test_trusted_targets_config_only_change_has_no_live_target(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "resources/team").mkdir(parents=True)
            targets = pr_input.trusted_targets(
                root,
                '[{"environment":"production","live_review":true,"namespaces":null}]',
                write_changed_paths(root, [".gitforgeops/policies.yaml"]),
            )
            self.assertEqual(targets, [])

    def test_trusted_targets_ignore_non_resource_files_under_declarative_roots(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "resources/team").mkdir(parents=True)
            targets = pr_input.trusted_targets(
                root,
                '[{"environment":"production","live_review":true,"namespaces":null}]',
                write_changed_paths(
                    root,
                    ["overlays/README.md", "resources/README.md", "resources/team/.gitkeep"],
                ),
            )
            self.assertEqual(targets, [])

    def test_trusted_targets_ignore_non_targetable_namespace_names(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "resources/team").mkdir(parents=True)
            (root / "resources/_shared").mkdir()
            targets = pr_input.trusted_targets(
                root,
                '[{"environment":"production","live_review":true,"namespaces":null}]',
                write_changed_paths(
                    root,
                    [
                        "resources/_shared/proxies/api.yaml",
                        "overlays/My Overlay/team/proxies/api.yaml",
                        "resources/team/proxies/api.yaml",
                    ],
                ),
            )
            self.assertEqual(
                targets, [{"environment": "production", "namespace": "team"}]
            )

    def test_trusted_targets_reject_matrix_larger_than_github_limit(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            changed = []
            for index in range(pr_input.MAX_LIVE_REVIEW_TARGETS + 1):
                namespace = f"team-{index}"
                (root / "resources" / namespace).mkdir(parents=True)
                changed.append(f"resources/{namespace}/proxies/api.yaml")
            with self.assertRaisesRegex(pr_input.InputError, "256-job matrix limit"):
                pr_input.trusted_targets(
                    root,
                    '[{"environment":"production","live_review":true,"namespaces":null}]',
                    write_changed_paths(root, changed),
                )

    def test_trusted_targets_reject_unsafe_changed_paths(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "resources/team").mkdir(parents=True)
            scopes = '[{"environment":"production","live_review":true,"namespaces":null}]'
            for path in ("resources/../escape.yaml", "/resources/team/api.yaml", 7):
                with self.subTest(path=path), self.assertRaises(pr_input.InputError):
                    pr_input.trusted_targets(
                        root, scopes, write_changed_paths(root, [path])
                    )


if __name__ == "__main__":
    unittest.main()
