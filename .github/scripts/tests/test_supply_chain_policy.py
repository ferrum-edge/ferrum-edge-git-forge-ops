import importlib.util
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[3]
SCRIPT = Path(__file__).parents[1] / "check_supply_chain.py"
SPEC = importlib.util.spec_from_file_location("check_supply_chain", SCRIPT)
check_supply_chain = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = check_supply_chain
SPEC.loader.exec_module(check_supply_chain)

CARGO_AUDIT_ACTION_PINS = (
    "taiki-e/install-action@83ac0ad63c0167e6f06796fab0fce28db1bf3db0",
)
REJECTED_CARGO_AUDIT_ACTION_PINS = (
    "taiki-e/install-action@9983c65e42da123ff25d1f78505eb6de315aa172",  # retired v2.87.20
    "taiki-e/install-action@9534c84618278caac52cb373bb164ed464dbd8af",
    "taiki-e/install-action@" + "1" * 40,
    "taiki-e/install-action@" + "0" * 40,
    "taiki-e/install-action@v2",
    "taiki-e/install-action@v2.87.22",
    "taiki-e/install-action@main",
)

# The trigger-pinned classifier as each freshness guard of apply-on-merge.yml
# runs it, and the retired temp-file spelling it replaced (#357).
TEMPFILE_CLASSIFIER = (
    '          trusted_classifier=$(mktemp "${RUNNER_TEMP}/deployment_scope.XXXXXX")\n'
    "          trap 'rm -f \"${trusted_classifier:-}\"; git config --local --unset-all "
    "http.https://github.com/.extraheader || true' EXIT\n"
    '          git show "${TRIGGER_SHA}:.github/scripts/deployment_scope.py" > "$trusted_classifier"\n'
    '          python3 "$trusted_classifier" classify \\\n'
    '            "$TRIGGER_SHA" "$fresh_head" --branch "$DEFAULT_BRANCH"\n'
    '          rm -f "$trusted_classifier"\n'
)
STDIN_CLASSIFIER = (
    '          git show "${TRIGGER_SHA}:.github/scripts/deployment_scope.py" | \\\n'
    "            python3 -I - classify \\\n"
    '            "$TRIGGER_SHA" "$fresh_head" --branch "$DEFAULT_BRANCH"\n'
)

NESTED_ARITHMETIC_PATH_WRITE = """echo "$(
: $(( (1 + (2)) + 3 ))
: '
"
# '; echo "PATH=$PWD/inject:$PATH" >> "$GITHUB_ENV"; : '
'
)"
"""


class SupplyChainPolicyTests(unittest.TestCase):
    def _probe_document(self, workflow):
        text = (ROOT / workflow).read_text(encoding="utf-8")
        return check_supply_chain.parse_workflow(text)

    def _step(self, document, job, name):
        return next(step for step in document["jobs"][job]["steps"] if step.get("name") == name)

    def _guarded_bindings(self, workflow, document):
        if workflow == ".github/workflows/drift-check.yml":
            return check_supply_chain.monitoring_jwt_binding_violations(workflow, document)
        if workflow not in check_supply_chain.PROBE_WORKFLOW_STEPS:
            return check_supply_chain.github_context_access_violations(workflow, document)
        return check_supply_chain.probe_consumer_binding_violations(workflow, document)

    def _env_alias_fixture(self, workflow, source, script, scope):
        document = self._probe_document(workflow)
        job = next(iter(document["jobs"].values()))
        step = {"name": "Render static alias", "run": script}
        job["steps"].insert(0, step)
        owner = {"workflow": document, "job": job, "step": step}[scope]
        owner.setdefault("env", {})["INJECT"] = source
        return document, owner["env"]

    def test_run_env_alias_sources_are_checked_before_shell_filtering(self):
        workflows = (
            *check_supply_chain.PROBE_WORKFLOW_STEPS,
            ".github/workflows/drift-check.yml",
            ".github/workflows/rotate.yml",
            ".github/workflows/materialize-file.yml",
        )
        sources = (
            '\necho FERRUM_NAMESPACE=other >> "$GITHUB_ENV"',
            '\r\necho BASH_ENV=inject.sh >> "$GITHUB_ENV"',
            'EOF\necho FERRUM_NAMESPACE=other >> "$GITHUB_ENV"\ncat <<EOF',
            "$(echo injected)", "`echo injected`", "';echo injected;#",
            r'''${{ fromJSON('"\necho FERRUM_\u004eAMESPACE=other >> \"$GITHUB_\u0045NV\""') }}''',
            r'''${{ fromJSON('"\u000aecho BASH_\u0045NV=inject.sh >> \"$GITHUB_\u0045NV\""') }}''',
            r'''${{ fromJSON('"\u000aEOF\u000aecho injected\u000acat <<EOF"') }}''',
            r'''${{ format('{0}{1}', fromJSON('"\n"'), 'echo injected') }}''',
            "${{ vars.INJECT }}", "${{ steps.payload.outputs.code }}", "${{ env.OTHER }}",
        )
        scripts = (
            "# ${{ env.INJECT }}\ntrue",
            "true # ${{ env.INJECT }}\ntrue",
            "echo '${{ env.INJECT }}'",
            "cat <<'EOF'\n${{ env.INJECT }}\nEOF",
            "${{ env.INJECT }}\ntrue",
        )
        for workflow in workflows:
            for scope in ("workflow", "job", "step"):
                for source in sources:
                    for script in scripts:
                        with self.subTest(
                            workflow=workflow, scope=scope, source=source, script=script
                        ):
                            document, environment = self._env_alias_fixture(
                                workflow, source, script, scope
                            )
                            violations = self._guarded_bindings(workflow, document)
                            self.assertTrue(
                                any("run env alias" in item for item in violations), violations
                            )
                            # Same real operational workflow and insertion
                            # context; only the alias source becomes literal.
                            environment["INJECT"] = "echo static-mode-v1"
                            self.assertEqual(self._guarded_bindings(workflow, document), [])

    def test_legitimate_static_env_aliases_remain_accepted(self):
        workflow = ".github/workflows/apply-on-merge.yml"
        for scope in ("workflow", "job", "step"):
            for source in (
                "", "release v1.2", "out/static.yaml", "https://static.invalid/v1",
                "mode=api", "user@example.invalid", "--format=json",
            ):
                with self.subTest(scope=scope, source=source):
                    document, _ = self._env_alias_fixture(
                        workflow, source, "echo '${{ env.INJECT }}'", scope
                    )
                    self.assertEqual(self._guarded_bindings(workflow, document), [])

    def test_static_env_aliases_follow_workflow_job_step_precedence(self):
        workflow = ".github/workflows/apply-on-merge.yml"
        unsafe = r'''${{ fromJSON('"\u000aecho injected"') }}'''
        document, environment = self._env_alias_fixture(
            workflow, unsafe, "echo '${{ ENV . INJECT }}'", "workflow"
        )
        job = next(iter(document["jobs"].values()))
        step = job["steps"][0]
        job["env"] = {"INJECT": "job-value"}
        self.assertEqual(self._guarded_bindings(workflow, document), [])
        context = check_supply_chain._run_env_contexts(workflow, document)[id(step)]
        self.assertEqual(
            check_supply_chain._expand_static_run_env(step["run"], context),
            ("echo 'job-value'", []),
        )
        job["env"]["INJECT"] = unsafe
        step["env"] = {"INJECT": "step-value"}
        self.assertEqual(self._guarded_bindings(workflow, document), [])
        context = check_supply_chain._run_env_contexts(workflow, document)[id(step)]
        self.assertEqual(
            check_supply_chain._expand_static_run_env(step["run"], context),
            ("echo 'step-value'", []),
        )
        environment["INJECT"] = "workflow-value"
        job["env"]["INJECT"] = "job-value"
        step["env"]["INJECT"] = unsafe
        self.assertTrue(any(
            "run env alias" in item for item in self._guarded_bindings(workflow, document)
        ))
        step["env"]["INJECT"] = "step-value"
        self.assertEqual(self._guarded_bindings(workflow, document), [])

    def test_unknown_dynamic_or_ambiguous_env_alias_sources_fail_closed(self):
        workflow = ".github/workflows/apply-on-merge.yml"
        for scope in ("workflow", "job", "step"):
            for source in (1, {"value": "literal"}, ["literal"]):
                with self.subTest(scope=scope, source=source):
                    document, _ = self._env_alias_fixture(
                        workflow, source, "# ${{ env.INJECT }}\ntrue", scope
                    )
                    self.assertTrue(any(
                        "run env alias" in item
                        for item in self._guarded_bindings(workflow, document)
                    ))
            for environment in ({}, {"INJECT": "safe", "inject": "unsafe"}, "${{ vars.ENV }}"):
                with self.subTest(scope=scope, environment=environment):
                    document, _ = self._env_alias_fixture(
                        workflow, "safe", "echo '${{ env.INJECT }}'", scope
                    )
                    job = next(iter(document["jobs"].values()))
                    owner = {"workflow": document, "job": job, "step": job["steps"][0]}[scope]
                    owner["env"] = environment
                    self.assertTrue(any(
                        "run env alias" in item
                        for item in self._guarded_bindings(workflow, document)
                    ))
        for expression in ("env.INJECT.property", "env['INJECT']", "env.UNKNOWN"):
            with self.subTest(expression=expression):
                document, _ = self._env_alias_fixture(
                    workflow, "safe", "# ${{ " + expression + " }}\ntrue", "step"
                )
                self.assertTrue(any(
                    "run env alias" in item
                    for item in self._guarded_bindings(workflow, document)
                ))

    def test_null_env_aliases_render_empty_and_expose_guarded_file_writes(self):
        workflow = ".github/workflows/apply-on-merge.yml"
        for scope in ("workflow", "job", "step"):
            for script, expected, malicious in (
                ("# ${{ env.INJECT }}\ntrue", "# \ntrue", False),
                ('echo BASH_ENV=inject.sh >> "$GITHUB_${{ env.INJECT }}ENV"',
                 'echo BASH_ENV=inject.sh >> "$GITHUB_ENV"', True),
            ):
                with self.subTest(scope=scope, malicious=malicious):
                    document, _ = self._env_alias_fixture(workflow, None, script, scope)
                    step = next(iter(document["jobs"].values()))["steps"][0]
                    context = check_supply_chain._run_env_contexts(workflow, document)[id(step)]
                    rendered, invalid = check_supply_chain._render_run_expressions(script, context)
                    self.assertEqual(invalid, [])
                    self.assertEqual(rendered, (expected,))
                    self._assert_bash_file_effects(
                        expected, "BASH_ENV=inject.sh\n" if malicious else ""
                    )
                    violations = self._guarded_bindings(workflow, document)
                    if malicious:
                        self.assertTrue(any("GITHUB_ENV/" in item for item in violations), violations)
                    else:
                        self.assertEqual(violations, [])

    def test_static_alias_substitution_cannot_hide_guarded_identifiers(self):
        for workflow in (*check_supply_chain.PROBE_WORKFLOW_STEPS, ".github/workflows/drift-check.yml"):
            protected_suffix = (
                "ADMIN_JWT_SECRET" if workflow.endswith("drift-check.yml")
                else "VERIFY_PROBE_CONSUMERS"
            )
            for value, script, diagnostic in (
                ("ENV", 'echo BASH_ENV=inject.sh >> "$GITHUB_${{ env.INJECT }}"', "GITHUB_ENV/"),
                ("ENV", 'echo injected >> "$GITHUB_${{ env.INJECT }}"', "GITHUB_ENV/"),
                (protected_suffix, "export FERRUM_${{ env.INJECT }}=other", "protected variable"),
            ):
                with self.subTest(workflow=workflow, value=value, script=script):
                    document, _ = self._env_alias_fixture(workflow, value, script, "step")
                    violations = self._guarded_bindings(workflow, document)
                    self.assertTrue(any(diagnostic in item for item in violations), violations)
                    job = next(iter(document["jobs"].values()))
                    job["steps"][0]["run"] = "# " + script + "\ntrue"
                    self.assertEqual(self._guarded_bindings(workflow, document), [])
        workflow = ".github/workflows/apply-on-merge.yml"
        for value in ("ENV", "NAMESPACE"):
            for script in (
                "export FERRUM_${{ env.INJECT }}=other",
                "cat <<'EOF'\nFERRUM_${{ env.INJECT }}=other\nEOF",
            ):
                with self.subTest(value=value, script=script):
                    document, _ = self._env_alias_fixture(workflow, value, script, "step")
                    self.assertTrue(any(
                        "protected variable references/rebinding" in item
                        for item in self._guarded_bindings(workflow, document)
                    ))
        for script in (
            "gitforgeops ${{ env.INJECT }} --auto-approve",
            "${{ env.INJECT }} --auto-approve",
        ):
            with self.subTest(script=script):
                source = "gitforgeops apply" if script.startswith("${{") else "apply"
                document, environment = self._env_alias_fixture(workflow, source, script, "step")
                self.assertTrue(any(
                    "mutations may only run in the guarded Apply steps" in item
                    for item in self._guarded_bindings(workflow, document)
                ))
                environment["INJECT"] = "echo" if script.startswith("${{") else "version"
                if not script.startswith("${{"):
                    # Keep the positive an actual supported read-only call;
                    # version has no apply-only --auto-approve flag.
                    next(iter(document["jobs"].values()))["steps"][0]["run"] = script.replace(
                        "--auto-approve", "--format json"
                    )
                self.assertEqual(self._guarded_bindings(workflow, document), [])
        workflow = ".github/workflows/trusted-pr-review.yml"
        document = self._probe_document(workflow)
        review = self._step(document, "live-review", "Post trusted live review")
        review["run"] += '\necho "${{ env.FERRUM_VERIFY_PROBE_CONSUMERS_BOUND }}"'
        self.assertTrue(any(
            "protected variable references/rebinding" in item
            for item in self._guarded_bindings(workflow, document)
        ))

    def test_inherited_aliases_are_unknown_after_visible_env_file_writes(self):
        workflow = ".github/workflows/rotate.yml"
        document, _ = self._env_alias_fixture(
            workflow, "inherited-value", "echo '${{ env.INJECT }}'", "job"
        )
        job = next(iter(document["jobs"].values()))
        job["steps"].insert(0, {"run": 'echo "INJECT=changed" >> "$GITHUB_ENV"'})
        self.assertTrue(any(
            "run env alias" in item
            for item in check_supply_chain.github_context_access_violations(workflow, document)
        ))
        job["steps"][1]["env"] = {"INJECT": "step-value"}
        self.assertEqual(check_supply_chain.github_context_access_violations(workflow, document), [])

        workflow = ".github/workflows/apply-on-merge.yml"
        document = self._probe_document(workflow)
        job = document["jobs"]["apply"]
        loader = self._step(document, "apply", check_supply_chain.BUNDLE_LOADER_STEP)
        alias = {"run": "echo '${{ env.INJECT }}'"}
        job["env"] = {"INJECT": "static-mode-v1", "FERRUM_CREDS_JSON_FILE": "not-runtime"}
        job["steps"].insert(job["steps"].index(loader) + 1, alias)
        self.assertEqual(check_supply_chain.github_context_access_violations(workflow, document), [])
        alias["run"] = "echo '${{ env.FERRUM_CREDS_JSON_FILE }}'"
        self.assertTrue(any(
            "run env alias" in item
            for item in check_supply_chain.github_context_access_violations(workflow, document)
        ))

    def _assert_rendered_comment_writes_env(self, script, expression, payload):
        # This runs only in the hosted test suite. Decode/render first, exactly
        # the ordering that lets GitHub turn a Bash comment into a command.
        rendered = script.replace("${{ " + expression + " }}", payload)
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "github-env"
            result = subprocess.run(
                ["bash", "--noprofile", "--norc", "-e", "-c", rendered],
                env={"GITHUB_ENV": str(destination)},
                check=False, text=True, capture_output=True,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(destination.read_text(), "BASH_ENV=inject.sh\n")

    def test_encoded_matrix_and_step_outputs_cannot_render_env_writes_from_comments(self):
        workflows = (
            *check_supply_chain.PROBE_WORKFLOW_STEPS,
            ".github/workflows/drift-check.yml",
            ".github/workflows/rotate.yml",
            ".github/workflows/materialize-file.yml",
        )
        payload = '\necho BASH_ENV=inject.sh >> "$GITHUB_ENV"'
        for workflow in workflows:
            for source in ("matrix", "step-output"):
                for prefix in ("# ", "true # ", ""):
                    with self.subTest(workflow=workflow, source=source, prefix=prefix):
                        document = self._probe_document(workflow)
                        job = next(iter(document["jobs"].values()))
                        expression = "matrix.INJECT" if source == "matrix" else "steps.payload.outputs.code"
                        consumer = {"run": prefix + "${{ " + expression + " }}\ntrue"}
                        encoded = json.dumps([payload] if source == "matrix" else payload)
                        encoded = encoded.replace("BASH_ENV", r"BASH_\u0045NV").replace(
                            "GITHUB_ENV", r"GITHUB_\u0045NV"
                        )
                        decoded = json.loads(encoded)
                        self.assertEqual(decoded[0] if source == "matrix" else decoded, payload)
                        if source == "matrix":
                            matrix = job.setdefault("strategy", {}).setdefault("matrix", {})
                            matrix["INJECT"] = "${{ fromJSON('" + encoded + "') }}"
                            job["steps"].insert(0, consumer)
                        else:
                            producer = {
                                "id": "payload",
                                "env": {"INJECT": "${{ fromJSON('" + encoded + "') }}"},
                                "run": 'echo "code<<EOF" >> "$GITHUB_OUTPUT"\n'
                                       'printf "%s\\n" "$INJECT" >> "$GITHUB_OUTPUT"\n'
                                       'echo EOF >> "$GITHUB_OUTPUT"',
                            }
                            job["steps"][0:0] = [producer, consumer]
                            # Exercise the multiline output channel too, so
                            # the consumer payload comes from its real bytes.
                            with tempfile.TemporaryDirectory() as directory:
                                output = Path(directory) / "github-output"
                                result = subprocess.run(
                                    ["bash", "--noprofile", "--norc", "-e", "-c", producer["run"]],
                                    env={"GITHUB_OUTPUT": str(output), "INJECT": decoded},
                                    check=False, text=True, capture_output=True,
                                )
                                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                                contents = output.read_text()
                                self.assertTrue(contents.startswith("code<<EOF\n"), contents)
                                self.assertTrue(contents.endswith("\nEOF\n"), contents)
                                decoded = contents[len("code<<EOF\n"):-len("\nEOF\n")]
                                self.assertEqual(decoded, payload)
                        self._assert_rendered_comment_writes_env(
                            consumer["run"], expression, payload
                        )
                        violations = self._guarded_bindings(workflow, document)
                        self.assertTrue(any("run value" in item for item in violations), violations)
                        if source == "matrix":
                            matrix["INJECT"] = ["static-mode-v1", "static-mode-v2"]
                        else:
                            producer["run"] = 'echo "code=static-mode-v1" >> "$GITHUB_OUTPUT"'
                        self.assertEqual(self._guarded_bindings(workflow, document), [])

    def test_generated_named_sources_cannot_hide_mutations_or_guarded_references(self):
        workflow = ".github/workflows/apply-on-merge.yml"
        for payload in (
            "\ngitforgeops apply --auto-approve",
            "\ngitforgeops rotate --consumer probe --credential jwt.secret",
            "\nexport FERRUM_VERIFY_PROBE_CONSUMERS=other",
        ):
            for source in ("matrix", "step-output"):
                with self.subTest(payload=payload, source=source):
                    document = self._probe_document(workflow)
                    job = document["jobs"]["list-envs"]
                    encoded = json.dumps([payload] if source == "matrix" else payload).replace(
                        "FERRUM_VERIFY_PROBE_CONSUMERS", r"FERRUM_VERIFY_PROBE_\u0043ONSUMERS"
                    )
                    decoded = json.loads(encoded)
                    self.assertEqual(decoded[0] if source == "matrix" else decoded, payload)
                    expression = "matrix.INJECT" if source == "matrix" else "steps.payload.outputs.code"
                    consumer = {"run": "# ${{ " + expression + " }}\ntrue"}
                    if source == "matrix":
                        job["strategy"] = {"matrix": {"INJECT": "${{ fromJSON('" + encoded + "') }}"}}
                        job["steps"].insert(0, consumer)
                    else:
                        job["steps"][0:0] = [{
                            "id": "payload", "env": {"INJECT": "${{ fromJSON('" + encoded + "') }}"},
                            "run": 'echo "code<<EOF" >> "$GITHUB_OUTPUT"\n'
                                   'printf "%s\\n" "$INJECT" >> "$GITHUB_OUTPUT"\n'
                                   'echo EOF >> "$GITHUB_OUTPUT"',
                        }, consumer]
                    rendered = consumer["run"].replace("${{ " + expression + " }}", payload)
                    self.assertIn(payload.lstrip("\n"), check_supply_chain._shell_operation_lines(rendered))
                    self.assertTrue(any(
                        "computed or unknown shell text" in item
                        for item in check_supply_chain.probe_validation_gate_violations(workflow, document)
                    ))

    def test_protected_checker_judges_encoded_named_sources_outside_candidate_tree(self):
        payload = '\necho BASH_ENV=inject.sh >> "$GITHUB_ENV"'
        encoded = json.dumps(payload).replace("BASH_ENV", r"BASH_\u0045NV").replace(
            "GITHUB_ENV", r"GITHUB_\u0045NV"
        )
        for workflow in (
            *check_supply_chain.PROBE_WORKFLOW_STEPS,
            ".github/workflows/drift-check.yml",
            ".github/workflows/rotate.yml",
            ".github/workflows/materialize-file.yml",
        ):
            for source in ("matrix", "step-output"):
                with self.subTest(workflow=workflow, source=source), tempfile.TemporaryDirectory() as directory:
                    root = self._mirror_repo(Path(directory))
                    path = root / workflow
                    original = path.read_text(encoding="utf-8")
                    (root / ".github/scripts/check_supply_chain.py").write_text(
                        "raise SystemExit(0)\n", encoding="utf-8"
                    )

                    def fixture(safe):
                        if source == "matrix":
                            expression = "matrix.INJECT"
                            value = (
                                "            - static-mode-v1\n" if safe else
                                "          INJECT: " + json.dumps(
                                    "${{ fromJSON('[" + encoded + "]') }}"
                                ) + "\n"
                            )
                            matrix = (
                                "    strategy:\n      matrix:\n"
                                + ("          INJECT:\n" if safe else "") + value
                            )
                            producer = ""
                        else:
                            matrix = ""
                            expression = "steps.payload.outputs.code"
                            script = (
                                'echo "code=static-mode-v1" >> "$GITHUB_OUTPUT"' if safe else
                                'echo "code<<EOF" >> "$GITHUB_OUTPUT"\n'
                                'printf "%s\\n" "$INJECT" >> "$GITHUB_OUTPUT"\n'
                                'echo EOF >> "$GITHUB_OUTPUT"'
                            )
                            producer = (
                                "      - name: Generate text\n        id: payload\n        env:\n"
                                "          INJECT: " + json.dumps("${{ fromJSON('" + encoded + "') }}")
                                + "\n        run: " + json.dumps(script) + "\n"
                            )
                        consumer = (
                            "      - name: Render named source\n        run: "
                            + json.dumps("# ${{ " + expression + " }}\ntrue") + "\n"
                        )
                        return original.replace(
                            "    steps:\n", matrix + "    steps:\n" + producer + consumer, 1
                        )

                    path.write_text(fixture(False), encoding="utf-8")
                    violations = self._violations(root)
                    self.assertTrue(any("run value" in item for item in violations), violations)
                    path.write_text(fixture(True), encoding="utf-8")
                    result = subprocess.run(
                        [sys.executable, str(SCRIPT), "--root", str(root)],
                        check=False, text=True, capture_output=True,
                    )
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_fully_proven_named_contexts_preserve_real_operational_workflows(self):
        for workflow in (
            *check_supply_chain.PROBE_WORKFLOW_STEPS,
            ".github/workflows/drift-check.yml",
            ".github/workflows/rotate.yml",
            ".github/workflows/materialize-file.yml",
        ):
            with self.subTest(workflow=workflow):
                document = self._probe_document(workflow)
                job = next(iter(document["jobs"].values()))
                job["needs"] = ["safe"]
                document["jobs"]["safe"] = {
                    "runs-on": "ubuntu-24.04",
                    "outputs": {"code": "trusted-data"}, "steps": [{"run": "true"}],
                }
                job["strategy"] = {"matrix": {
                    "INJECT": ["static-v1", "static-v2"],
                    "nested": [{"label": "static-nested"}],
                    "alias": ["${{ needs.safe.outputs.code }}"],
                }}
                producer = {"id": "literal", "run": 'echo "code=static-output" >> "$GITHUB_OUTPUT"'}
                expressions = (
                    "MATRIX . INJECT", "matrix.nested.label", "matrix.alias",
                    "steps.literal.outputs.code", "steps.literal.outcome", "steps.literal.conclusion",
                    "needs.safe.outputs.code", "needs.safe.result", "github.run_id", "github.sha",
                    "runner.os", "runner.arch", "runner.debug",
                )
                job["steps"][0:0] = [producer, {"run": "\n".join(
                    "# ${{ " + expression + " }}\necho '${{ " + expression + " }}'"
                    for expression in expressions[:3]
                )}]
                # Keep the bounded cross-product in each independently
                # executable step rather than exceeding the render limit.
                job["steps"][2:2] = [
                    {"run": "# ${{ " + expression + " }}\necho '${{ " + expression + " }}'"}
                    for expression in expressions[3:]
                ]
                self.assertEqual(self._guarded_bindings(workflow, document), [])

    def test_unbounded_named_contexts_and_unknown_producers_fail_closed(self):
        workflow = ".github/workflows/apply-on-merge.yml"
        for expression in (
            "github.event.head_commit.message", "github.ref", "github.workflow", "github.actor",
            "runner.name", "runner.temp", "vars.INJECT", "inputs.INJECT", "secrets.INJECT",
            "steps.payload.outputs.code", "needs.dynamic.outputs.code",
        ):
            with self.subTest(expression=expression):
                document = self._probe_document(workflow)
                document["jobs"]["dynamic"] = {
                    "runs-on": "ubuntu-24.04",
                    "outputs": {"code": "${{ vars.INJECT }}"}, "steps": [{"run": "true"}],
                }
                job = document["jobs"]["list-envs"]
                job["needs"] = ["dynamic"]
                job["steps"][0:0] = [
                    {"id": "payload", "uses": "actions/checkout@" + "a" * 40},
                    {"run": "# ${{ " + expression + " }}\ntrue"},
                ]
                violations = self._guarded_bindings(workflow, document)
                self.assertTrue(any("run value" in item for item in violations), violations)

    def test_all_static_matrix_values_and_includes_are_scanned_after_rendering(self):
        workflow = ".github/workflows/apply-on-merge.yml"
        for matrix in (
            {"INJECT": ["OS", "ENV"]},
            {"INJECT": ["OS"], "include": [{"INJECT": "ENV"}]},
            {"INJECT": ["OS"], "include": "${{ fromJSON(vars.INCLUDE) }}"},
            {"INJECT": ["OS"], "inject": ["ENV"]},
        ):
            with self.subTest(matrix=matrix):
                document = self._probe_document(workflow)
                job = document["jobs"]["list-envs"]
                job["strategy"] = {"matrix": matrix}
                job["steps"].insert(0, {"run": 'echo injected >> "$GITHUB_${{ matrix.INJECT }}"'})
                self.assertTrue(self._guarded_bindings(workflow, document))
        for expression, producer in (
            ("matrix.INJECT", None),
            ("steps.payload.outputs.code", {"id": "payload", "run": 'echo "code=apply" >> "$GITHUB_OUTPUT"'}),
        ):
            document = self._probe_document(workflow)
            job = document["jobs"]["list-envs"]
            job["strategy"] = {"matrix": {"INJECT": ["version", "apply"]}}
            job["steps"][0:0] = ([producer] if producer else []) + [{
                "run": "gitforgeops ${{ " + expression + " }}",
            }]
            self.assertTrue(any(
                "mutations may only run" in item for item in self._guarded_bindings(workflow, document)
            ))
            if producer:
                producer["run"] = 'echo "code=version" >> "$GITHUB_OUTPUT"'
            else:
                job["strategy"]["matrix"]["INJECT"] = ["version"]
            self.assertEqual(self._guarded_bindings(workflow, document), [])
        document = self._probe_document(workflow)
        job = document["jobs"]["list-envs"]
        job["strategy"] = {"matrix": {"nested": [{"suffix": "OS"}, {"other": "safe"}]}}
        job["steps"].insert(0, {
            "run": 'echo injected >> "$GITHUB_${{ matrix.nested.suffix }}ENV"',
        })
        # The missing nested property renders empty, assembling GITHUB_ENV.
        self.assertTrue(any("GITHUB_ENV/" in item for item in self._guarded_bindings(workflow, document)))
        document = self._probe_document(workflow)
        job = document["jobs"]["list-envs"]
        job["steps"][0:0] = [{
            "id": "payload",
            "run": 'echo "code=VERIFY_PROBE_CONSUMERS" >> "$GITHUB_OUTPUT"',
        }, {"run": "export FERRUM_${{ steps.payload.outputs.code }}=other"}]
        self.assertTrue(any(
            "protected variable references/rebinding" in item
            for item in self._guarded_bindings(workflow, document)
        ))

    def test_repeated_proven_aliases_keep_one_value_and_large_products_fail_closed(self):
        workflow = ".github/workflows/apply-on-merge.yml"
        document = self._probe_document(workflow)
        job = document["jobs"]["list-envs"]
        job["strategy"] = {"matrix": {"INJECT": ["static-v1", "static-v2"]}}
        consumer = {"run": "\n".join("echo '${{ matrix.INJECT }}'" for _ in range(20))}
        job["steps"].insert(0, consumer)
        context = check_supply_chain._run_env_contexts(workflow, document)[id(consumer)]
        rendered, invalid = check_supply_chain._render_run_expressions(consumer["run"], context)
        self.assertEqual(invalid, [])
        self.assertEqual(len(rendered), 2)
        self.assertEqual(self._guarded_bindings(workflow, document), [])
        job["strategy"]["matrix"]["INJECT"] = [
            "static-" + str(index) for index in range(check_supply_chain._RUN_RENDER_LIMIT + 1)
        ]
        self.assertTrue(any("run value" in item for item in self._guarded_bindings(workflow, document)))

    def test_dynamic_shipped_interpolations_require_complete_source_and_consumer_shapes(self):
        workflow = ".github/workflows/trusted-pr-review.yml"
        for mutation in ("append-output", "remove-sha-guard", "env", "duplicate-id", "shell", "defaults"):
            with self.subTest(workflow=workflow, mutation=mutation):
                document = self._probe_document(workflow)
                metadata = self._step(document, "prepare", "Validate workflow-run metadata")
                if mutation == "append-output":
                    metadata["run"] += '\necho "head_sha=$PAYLOAD" >> "$GITHUB_OUTPUT"'
                elif mutation == "remove-sha-guard":
                    metadata["run"] = metadata["run"].replace(
                        check_supply_chain.REVIEW_METADATA_RUN[1], "true"
                    )
                elif mutation == "env":
                    metadata["env"]["EXPECTED_WORKFLOW_PATH"] = "candidate.yml"
                elif mutation == "duplicate-id":
                    document["jobs"]["prepare"]["steps"].append({"id": "METADATA", "run": "true"})
                elif mutation == "shell":
                    metadata["shell"] = "bash {0}"
                else:
                    document["jobs"]["prepare"]["defaults"] = {"run": {"shell": "bash {0}"}}
                self.assertTrue(any(
                    "run value" in item for item in self._guarded_bindings(workflow, document)
                ))
        workflow = ".github/workflows/apply-on-merge.yml"
        for mutation in ("producer", "matrix", "consumer", "producer-defaults"):
            with self.subTest(workflow=workflow, mutation=mutation):
                document = self._probe_document(workflow)
                if mutation == "producer":
                    enumerator = self._step(document, "list-envs", "Enumerate environments")
                    enumerator["run"] += '\necho "envs=$PAYLOAD" >> "$GITHUB_OUTPUT"'
                elif mutation == "matrix":
                    document["jobs"]["apply"]["strategy"]["matrix"]["include"] = [
                        {"environment": "${{ vars.INJECT }}"},
                    ]
                elif mutation == "consumer":
                    commit = next(step for step in document["jobs"]["apply"]["steps"]
                                  if "git commit -m" in step.get("run", ""))
                    commit["run"] += '\necho "${{ matrix.environment }}"'
                else:
                    document["jobs"]["list-envs"]["defaults"] = {"run": {"shell": "bash {0}"}}
                self.assertTrue(any(
                    "run value" in item for item in self._guarded_bindings(workflow, document)
                ))

    def test_runtime_env_tracking_preserves_physical_boundaries_and_step_overrides(self):
        workflow = ".github/workflows/rotate.yml"
        for script in (
            'echo "INJECT=runtime" >> "$GITHUB_ENV"\napplied_file=next',
            'echo "INJECT=runtime" >> "$GITHUB_ENV"\necho next',
            'echo "INJECT=runtime" >> "$GITHUB_""ENV"\necho next',
            'echo "INJECT=runtime" >> "$GITHUB_E\\\nNV"\necho next',
        ):
            with self.subTest(script=script):
                document, _ = self._env_alias_fixture(
                    workflow, "inherited", "echo '${{ env.INJECT }}'", "job"
                )
                job = next(iter(document["jobs"].values()))
                alias = job["steps"][0]
                job["steps"].insert(0, {"run": script})
                self.assertTrue(any(
                    "run env alias" in item
                    for item in check_supply_chain.github_context_access_violations(workflow, document)
                ))
                alias["env"] = {"INJECT": "step-override"}
                self.assertEqual(check_supply_chain.github_context_access_violations(workflow, document), [])

    def test_credential_handoff_proof_requires_exact_execution_shape_and_safe_drivers(self):
        workflow = ".github/workflows/apply-on-merge.yml"
        for mutation in ("shell", "id", "driver", "unknown-write"):
            with self.subTest(mutation=mutation):
                document = self._probe_document(workflow)
                job = document["jobs"]["apply"]
                loader = self._step(document, "apply", check_supply_chain.BUNDLE_LOADER_STEP)
                if mutation == "shell":
                    loader["shell"] = "bash {0}"
                elif mutation == "id":
                    loader["id"] = "untrusted-loader"
                elif mutation == "driver":
                    job["env"] = {"RUNNER_TEMP": "\nBASH_ENV=inject.sh"}
                else:
                    job["steps"].insert(0, {"run": 'echo "OTHER=x" >> "$GITHUB_ENV"'})
                violations = self._guarded_bindings(workflow, document)
                self.assertTrue(any("outside the credential hand-off" in item for item in violations), violations)

    def test_read_only_cli_classification_keeps_list_envs_and_refuses_other_writes(self):
        workflow = ".github/workflows/apply-on-merge.yml"
        document = self._probe_document(workflow)
        self.assertEqual(check_supply_chain.probe_validation_gate_violations(workflow, document), [])
        for script in (
            'scopes=$(gitforgeops envs --format json --include-scopes | jq -c .)\necho apply rotate',
            'gitforgeops envs --format=json --include-scopes | jq -c . # apply rotate',
            'gitforgeops --env apply envs --format json\necho rotate',
            'gitforgeops envs --env rotate --format text\necho apply',
            'gitforgeops version\necho apply rotate',
        ):
            with self.subTest(read_only=script):
                document = self._probe_document(workflow)
                document["jobs"]["list-envs"]["steps"].insert(0, {"run": script})
                self.assertEqual(check_supply_chain.probe_validation_gate_violations(workflow, document), [])
        for script in (
            'gitforgeops envs --format json\ngitforgeops apply --auto-approve',
            'gitforgeops envs --format json; gitforgeops rotate --consumer x --credential jwt.secret',
            'gitforgeops envs --format json | gitforgeops apply --auto-approve',
            'echo "$(gitforgeops apply --auto-approve)"',
            'gitforgeops --env staging ap""ply --auto-approve',
            'gitforgeops envs --materialize', 'gitforgeops envs apply',
            'gitforgeops export --materialize', 'gitforgeops import --from-api --output-dir out',
            'gitforgeops diff --write-fingerprint-baseline baseline.json',
            'gitforgeops${IFS}apply --auto-approve',
        ):
            with self.subTest(write=script):
                document = self._probe_document(workflow)
                document["jobs"]["list-envs"]["steps"].insert(0, {"run": script})
                self.assertTrue(any(
                    "mutations may only run" in item
                    for item in check_supply_chain.probe_validation_gate_violations(workflow, document)
                ))

    def _assert_bash_file_effects(self, script, expected_env, expected_literal=""):
        # Execution belongs to the hosted workflow-script test gate. No
        # candidate tools, gateway, network, or inherited startup env are used.
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "github-env"
            literal_destination = Path(directory) / "literal-null-env"
            result = subprocess.run(
                ["bash", "--noprofile", "--norc", "-e", "-c", script],
                env={
                    "GITHUB_ENV": str(destination),
                    "GITHUB_nullENV": str(literal_destination),
                },
                check=False, text=True, capture_output=True,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(destination.read_text() if destination.exists() else "", expected_env)
            self.assertEqual(
                literal_destination.read_text() if literal_destination.exists() else "",
                expected_literal,
            )

    def test_multiline_quotes_cannot_hide_active_hash_lines(self):
        write = 'echo BASH_ENV=inject.sh >> "$GITHUB_ENV"'
        scripts = (
            ": '\n# '; " + write + "; : '\n'",
            ': "\n# "; ' + write + '; : "\n"',
            ": $'\n# '; " + write + "; : $'\n'",
            ": escaped\\\n#; " + write,
            'echo "$(\n: \'\n# \'; ' + write + "; : '\n'\n)\"",
        )
        for script in scripts:
            with self.subTest(script=script):
                self._assert_bash_file_effects(script, "BASH_ENV=inject.sh\n")
                self.assertIn(write, "\n".join(check_supply_chain._shell_operation_lines(script)))
                for workflow in (
                    *check_supply_chain.PROBE_WORKFLOW_STEPS,
                    ".github/workflows/drift-check.yml",
                ):
                    document = self._probe_document(workflow)
                    job = next(iter(document["jobs"].values()))
                    job["steps"].insert(0, {"run": script})
                    violations = self._guarded_bindings(workflow, document)
                    self.assertTrue(any("GITHUB_ENV/" in item for item in violations), violations)
                workflow = ".github/workflows/rotate.yml"
                document, _ = self._env_alias_fixture(
                    workflow, "inherited", "echo '${{ env.INJECT }}'", "job"
                )
                next(iter(document["jobs"].values()))["steps"].insert(0, {"run": script})
                self.assertTrue(any(
                    "run env alias" in item
                    for item in check_supply_chain.github_context_access_violations(workflow, document)
                ))

    def test_nested_arithmetic_cannot_hide_real_path_writes(self):
        # Run the exact review11 bypass and deeper/multiline variants only in
        # hosted CI, with builtins and a private working directory/env file.
        arithmetic = "$(( (1 + (2)) + 3 ))"
        scripts = [NESTED_ARITHMETIC_PATH_WRITE.replace(arithmetic, value) for value in (
            arithmetic,
            "$(((1 + ((2))) + 3))",
            "$((\n(1 + (2))\n+ 3\n))",
            "$(( (1 << 2) + (3 * (4 - 1)) ))",
        )]
        scripts.append('echo "$(\n' + NESTED_ARITHMETIC_PATH_WRITE + ')"')
        write = 'echo "PATH=$PWD/inject:$PATH" >> "$GITHUB_ENV"'
        for script in scripts:
            with self.subTest(script=script), tempfile.TemporaryDirectory() as directory:
                destination = Path(directory) / "github-env"
                result = subprocess.run(
                    ["bash", "--noprofile", "--norc", "-e", "-c", script],
                    cwd=directory,
                    env={"PATH": "/usr/bin:/bin", "GITHUB_ENV": str(destination)},
                    check=False, text=True, capture_output=True,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(
                    destination.read_text(), "PATH=" + directory + "/inject:/usr/bin:/bin\n"
                )
                self.assertIn(write, "\n".join(check_supply_chain._shell_operation_lines(script)))
                # The same projection must refuse a producer proof that would
                # match only if the active hash line were discarded.
                hidden_line_shape = tuple(
                    line.strip(" \t") for line in script.splitlines()
                    if line and not line.startswith("#")
                )
                self.assertFalse(check_supply_chain._has_run_shape(
                    {"run": script}, hidden_line_shape, {}
                ))
                for workflow in (
                    *check_supply_chain.PROBE_WORKFLOW_STEPS,
                    ".github/workflows/drift-check.yml",
                ):
                    document = self._probe_document(workflow)
                    next(iter(document["jobs"].values()))["steps"].insert(0, {"run": script})
                    violations = self._guarded_bindings(workflow, document)
                    self.assertTrue(any("GITHUB_ENV/" in item for item in violations), violations)

                workflow = ".github/workflows/rotate.yml"
                document, _ = self._env_alias_fixture(
                    workflow, "inherited", "echo '${{ env.INJECT }}'", "job"
                )
                job = next(iter(document["jobs"].values()))
                consumer = job["steps"][0]
                job["steps"].insert(0, {"run": script})
                context = check_supply_chain._run_env_contexts(workflow, document)[id(consumer)]
                self.assertIsNone(context[1])
                self.assertTrue(any(
                    "run env alias" in item
                    for item in check_supply_chain.github_context_access_violations(workflow, document)
                ))
                consumer["env"] = {"INJECT": "step-override"}
                self.assertEqual(check_supply_chain.github_context_access_violations(workflow, document), [])

    def test_balanced_arithmetic_keeps_real_comments_and_literal_quotes_benign(self):
        comment = '# \'; echo BASH_ENV=inject.sh >> "$GITHUB_ENV"; : \' "'
        for script in (
            ': "$(( (1 + (2)) + 3 ))"\n' + comment + "\ntrue",
            'echo "$(\n: $(((1 + ((2))) + 3))\n' + comment + '\n: safe\n)"',
            'echo "$(\n: $((\n(1 + (2))\n+ 3\n))\n' + comment + '\n: safe\n)"',
            'echo "$(\n: $(( (1 + (2)) + 3 ))\n: \'literal\n'
            '# harmless " $(( unmatched literal text\n\'\n' + comment + '\n)"',
        ):
            with self.subTest(script=script):
                self._assert_bash_file_effects(script, "")
                projection = check_supply_chain._shell_operation_lines(script)
                expected = tuple(
                    line.strip(" \t") for line in script.splitlines()
                    if line and line != comment
                )
                self.assertEqual(projection, expected)
                self.assertNotIn("BASH_ENV", "\n".join(projection))
                self.assertTrue(check_supply_chain._has_run_shape({"run": script}, expected, {}))
                for workflow in (
                    *check_supply_chain.PROBE_WORKFLOW_STEPS,
                    ".github/workflows/drift-check.yml",
                ):
                    document = self._probe_document(workflow)
                    next(iter(document["jobs"].values()))["steps"].insert(0, {"run": script})
                    self.assertEqual(self._guarded_bindings(workflow, document), [])

    def test_unsupported_nested_arithmetic_retains_context_escape_writes(self):
        arithmetic = "$(( (1 + (2)) + 3 ))"
        write = 'echo BASH_ENV=inject.sh >> "$GITHUB_ENV"'
        for value in (
            "$(( (1 + (2)) + $(printf 3) ))",
            "$(( (1 + (2)) + ${VALUE:-3} ))",
            "$(( (1 + (2)) + $((3 + 4)) ))",
            "$(( (1 + (2)) + (3 ? 4 : 5) ))",
            "$(( (1 + (2)) + (3, 4) ))",
            "$(( (1 + (2)) + values[0] ))",
            '$(( "1" + (2) ))',
            "$(( (1 + (2)) + 3 \\\n))",
        ):
            script = NESTED_ARITHMETIC_PATH_WRITE.replace(arithmetic, value).replace(
                'echo "PATH=$PWD/inject:$PATH" >> "$GITHUB_ENV"', write
            )
            with self.subTest(arithmetic=value):
                self._assert_bash_file_effects(script, "BASH_ENV=inject.sh\n")
                self.assertIsNone(check_supply_chain._shell_arithmetic_end(value, 0))
                projection = check_supply_chain._shell_operation_lines(script)
                self.assertIn(write, "\n".join(projection))
                workflow = ".github/workflows/drift-check.yml"
                document = self._probe_document(workflow)
                document["jobs"]["drift"]["steps"].insert(0, {"run": script})
                violations = self._guarded_bindings(workflow, document)
                self.assertTrue(any("GITHUB_ENV/" in item for item in violations), violations)

    def test_malformed_arithmetic_never_discards_remaining_hash_lines(self):
        # Deliberately malformed boundaries are projection tests, not Bash
        # execution evidence. No close/quote state is inferred after refusal.
        write = 'echo BASH_ENV=inject.sh >> "$GITHUB_ENV"'
        for arithmetic in (
            "$(( (1 + (2)) + 3 )",
            "$(( (1 + (2)) + 3",
            "$(( (1 + (2)) + 3 ) )",
            "$(( 1 + (2)",
            "$((1) + 2 )",
        ):
            script = 'echo "$(\n: ' + arithmetic + "\n# '; " + write + "; : '\n'\n)\""
            with self.subTest(arithmetic=arithmetic):
                self.assertIsNone(check_supply_chain._shell_arithmetic_end(arithmetic, 0))
                self.assertIn(write, "\n".join(check_supply_chain._shell_operation_lines(script)))
                self.assertFalse(check_supply_chain._has_run_shape({"run": script}, ("true",), {}))

    def test_trusted_checker_rejects_nested_arithmetic_path_bypass_before_drift(self):
        workflow = ".github/workflows/drift-check.yml"
        with tempfile.TemporaryDirectory() as directory:
            root = self._mirror_repo(Path(directory))
            path = root / workflow
            original = path.read_text(encoding="utf-8")
            (root / ".github/scripts/check_supply_chain.py").write_text(
                "raise SystemExit(0)\n", encoding="utf-8"
            )
            for malicious in (True, False):
                script = (
                    NESTED_ARITHMETIC_PATH_WRITE if malicious else
                    ': "$(( (1 + (2)) + 3 ))"\n'
                    '# \'; echo "PATH=$PWD/inject:$PATH" >> "$GITHUB_ENV"; : \'\ntrue'
                )
                text = original.replace(
                    "      - name: Check drift\n",
                    "      - name: Arithmetic regression fixture\n        run: " + json.dumps(script)
                    + "\n      - name: Check drift\n", 1
                )
                self.assertNotEqual(text, original)
                path.write_text(text, encoding="utf-8")
                if malicious:
                    violations = self._violations(root)
                    self.assertTrue(any("GITHUB_ENV/" in item for item in violations), violations)
                else:
                    result = subprocess.run(
                        [sys.executable, "-I", str(SCRIPT), "--root", str(root)],
                        check=False, text=True, capture_output=True,
                    )
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_real_comments_do_not_supply_quote_state_or_guarded_operations(self):
        comment = '# \'; echo BASH_ENV=inject.sh >> "$GITHUB_ENV"; gitforgeops apply; : \' "'
        for script in (
            comment + "\ntrue",
            "true " + comment + "\ntrue",
            'echo "$(\n' + comment + '\n: safe\n)"\ntrue',
            ": 'literal\n# harmless literal text\n'\n" + comment + "\ntrue",
        ):
            with self.subTest(script=script):
                self._assert_bash_file_effects(script, "")
                self.assertNotIn("BASH_ENV", "\n".join(check_supply_chain._shell_operation_lines(script)))
                for workflow in (
                    *check_supply_chain.PROBE_WORKFLOW_STEPS,
                    ".github/workflows/drift-check.yml",
                ):
                    document = self._probe_document(workflow)
                    next(iter(document["jobs"].values()))["steps"].insert(0, {"run": script})
                    self.assertEqual(self._guarded_bindings(workflow, document), [])

    def test_multiline_quote_scans_preserve_mutations_and_producer_proofs(self):
        workflow = ".github/workflows/apply-on-merge.yml"
        document = self._probe_document(workflow)
        job = document["jobs"]["list-envs"]
        job["steps"].insert(0, {"run": ": '\n# '; gitforgeops apply --auto-approve; : '\n'"})
        self.assertTrue(any(
            "mutations may only run" in item
            for item in check_supply_chain.probe_validation_gate_violations(workflow, document)
        ))
        document = self._probe_document(workflow)
        enumerator = self._step(document, "list-envs", "Enumerate environments")
        self.assertTrue(check_supply_chain._has_run_shape(
            enumerator, check_supply_chain.APPLY_ENVIRONMENT_LIST_RUN, {}
        ))
        injection = '# \'; echo "envs=$PAYLOAD" >> "$GITHUB_OUTPUT"; : \'\n'
        enumerator["run"] = enumerator["run"].replace("jq -e '\n", "jq -e '\n" + injection, 1)
        self.assertFalse(check_supply_chain._has_run_shape(
            enumerator, check_supply_chain.APPLY_ENVIRONMENT_LIST_RUN, {}
        ))
        self.assertTrue(any("run value" in item for item in self._guarded_bindings(workflow, document)))

        workflow = ".github/workflows/trusted-pr-review.yml"
        document = self._probe_document(workflow)
        metadata = self._step(document, "prepare", "Validate workflow-run metadata")
        self.assertTrue(check_supply_chain._has_run_shape(
            metadata, check_supply_chain.REVIEW_METADATA_RUN, metadata["env"]
        ))
        injection = '# \'; echo "head_sha=$PAYLOAD" >> "$GITHUB_OUTPUT"; : \'\n'
        metadata["run"] = metadata["run"].replace(
            '--arg base "$DEFAULT_BRANCH" \'\n',
            '--arg base "$DEFAULT_BRANCH" \'\n' + injection, 1
        )
        self.assertFalse(check_supply_chain._has_run_shape(
            metadata, check_supply_chain.REVIEW_METADATA_RUN, metadata["env"]
        ))
        self.assertTrue(any("run value" in item for item in self._guarded_bindings(workflow, document)))

    def test_unsupported_shell_contexts_never_hide_hash_lines(self):
        write = 'echo BASH_ENV=inject.sh >> "$GITHUB_ENV"'
        for script in (
            "cat <<'EOF'\nliteral\nEOF\n" + write,
            ': "`printf safe`"\n' + write,
            ': "${VALUE:-\'quoted\'}"\n' + write,
            'echo "$(case safe in safe) : safe;; esac)"\n' + write,
            ': "$((1 # ambiguous))"\n' + write,
        ):
            with self.subTest(script=script):
                self.assertIn(write, "\n".join(check_supply_chain._shell_operation_lines(script)))
                self.assertFalse(check_supply_chain._has_run_shape(
                    {"run": script}, ("true",), {}
                ))

    def test_comment_projection_preserves_continuation_boundaries(self):
        for script, expected in (
            ("echo safe\\\n\ntrue", ("echo safe\\", "", "true")),
            ("echo safe \\\n# a real comment\ntrue", ("echo safe \\", "", "true")),
            ("echo safe\\ \ntrue", ("echo safe\\ ", "true")),
        ):
            with self.subTest(script=script):
                self.assertEqual(check_supply_chain._shell_operation_lines(script), expected)
                self.assertEqual(
                    check_supply_chain._shell_operation_lines("\n".join(expected)), expected
                )

    def test_plain_yaml_scalar_provenance_controls_shell_conversion(self):
        # Preserve ordinary textual workflow comparisons, but distinguish
        # plain implicit types from quoted strings before shell interpolation.
        for scalar, rendered in (
            ("null", ""), ("Null", ""), ("NULL", ""), ("~", ""),
            ("true", "true"), ("True", "true"), ("TRUE", "true"),
            ("false", "false"), ("False", "false"), ("FALSE", "false"),
            ("on", "on"), ("yes", "yes"), ("nUlL", "nUlL"),
        ):
            with self.subTest(scalar=scalar):
                plain = check_supply_chain.parse_workflow("value: " + scalar)["value"]
                quoted = check_supply_chain.parse_workflow("value: " + json.dumps(scalar))["value"]
                single = check_supply_chain.parse_workflow("value: '" + scalar + "'")["value"]
                self.assertIsInstance(plain, check_supply_chain._PlainWorkflowScalar)
                self.assertNotIsInstance(quoted, check_supply_chain._PlainWorkflowScalar)
                self.assertEqual(check_supply_chain._shell_literal_values(plain), (rendered,))
                literal = (scalar,) if check_supply_chain._SHELL_SAFE_LITERAL.fullmatch(scalar) else None
                self.assertEqual(check_supply_chain._shell_literal_values(quoted), literal)
                self.assertEqual(check_supply_chain._shell_literal_values(single), literal)
                self.assertEqual(plain, quoted)
                flow = check_supply_chain.parse_workflow("needs: [" + scalar + ", '" + scalar + "']")
                self.assertEqual(check_supply_chain._shell_literal_values(flow["needs"][0]), (rendered,))
                self.assertEqual(check_supply_chain._shell_literal_values(flow["needs"][1]), literal)
        for scalar in ("null", "True", "01"):
            block = check_supply_chain.parse_workflow("script: |\n  " + scalar)["script"]
            self.assertNotIsInstance(block, check_supply_chain._PlainWorkflowScalar)
            self.assertEqual(check_supply_chain._shell_literal_values(block), (scalar,))

    def test_numeric_yaml_sources_fail_closed_until_quoted(self):
        workflow = ".github/workflows/rotate.yml"
        for scalar in (
            "0", "01", "-0", "+1", "1.0", ".5", "1.", "1e+20", "0x45", "0o105",
            ".inf", "-.Inf", "+.INF", ".nan", ".NaN", "9007199254740993", "1e999",
        ):
            for source in ("env", "matrix", "needs"):
                with self.subTest(scalar=scalar, source=source):
                    expression = {
                        "env": "env.INJECT", "matrix": "matrix.INJECT", "needs": "needs.source.outputs.code",
                    }[source]
                    for quoted in (False, True):
                        document = check_supply_chain.parse_workflow(
                            "jobs:\n  source:\n    outputs:\n      code: "
                            + (json.dumps(scalar) if quoted else scalar)
                            + "\n    steps:\n      - run: true\n  consumer:\n    needs: source\n"
                            "    env:\n      INJECT: " + (json.dumps(scalar) if quoted else scalar)
                            + "\n    strategy:\n      matrix:\n        INJECT:\n          - "
                            + (json.dumps(scalar) if quoted else scalar)
                            + "\n    steps:\n      - run: " + json.dumps("echo '${{ " + expression + " }}'")
                        )
                        violations = check_supply_chain.github_context_access_violations(workflow, document)
                        if quoted:
                            self.assertEqual(violations, [])
                        else:
                            self.assertTrue(any("run value" in item or "run env alias" in item
                                                for item in violations), violations)

    def test_null_matrix_rendering_checks_real_file_write_and_runtime_invalidation(self):
        workflow = ".github/workflows/drift-check.yml"
        script = 'echo BASH_ENV=inject.sh >> "$GITHUB_${{ matrix.suffix }}ENV"'
        original = (ROOT / workflow).read_text(encoding="utf-8")
        for scalar in ("null", "Null", "NULL", "~", '"null"', "'null'"):
            with self.subTest(scalar=scalar):
                text = original.replace(
                    "      matrix:\n", "      matrix:\n        suffix:\n          - " + scalar + "\n", 1
                ).replace(
                    "    environment: ${{ matrix.scope.monitoring_environment }}\n    steps:\n",
                    "    environment: ${{ matrix.scope.monitoring_environment }}\n"
                    "    env:\n      INJECT: inherited\n    steps:\n"
                    "      - name: Null interpolation\n        run: " + json.dumps(script) + "\n"
                    "      - run: " + json.dumps("echo '${{ env.INJECT }}'") + "\n", 1
                )
                document = check_supply_chain.parse_workflow(text)
                consumer = document["jobs"]["drift"]["steps"][0]
                context = check_supply_chain._run_env_contexts(workflow, document)[id(consumer)]
                rendered, invalid = check_supply_chain._render_run_expressions(script, context)
                self.assertEqual(invalid, [])
                plain = scalar[0] not in "'\""
                expected = script.replace("${{ matrix.suffix }}", "" if plain else "null")
                self.assertEqual(rendered, (expected,))
                self._assert_bash_file_effects(
                    expected, "BASH_ENV=inject.sh\n" if plain else "",
                    "" if plain else "BASH_ENV=inject.sh\n",
                )
                violations = self._guarded_bindings(workflow, document)
                if plain:
                    self.assertTrue(any("GITHUB_ENV/" in item for item in violations), violations)
                    self.assertTrue(any("run env alias" in item for item in violations), violations)
                else:
                    self.assertEqual(violations, [])

    def test_trusted_checker_rejects_quote_and_null_bypasses_in_candidate_workflows(self):
        workflow = ".github/workflows/drift-check.yml"
        for bypass in ("quotes", "null"):
            with self.subTest(bypass=bypass), tempfile.TemporaryDirectory() as directory:
                root = self._mirror_repo(Path(directory))
                path = root / workflow
                original = path.read_text(encoding="utf-8")
                (root / ".github/scripts/check_supply_chain.py").write_text(
                    "raise SystemExit(0)\n", encoding="utf-8"
                )
                for malicious in (True, False):
                    text = original
                    if bypass == "quotes":
                        script = (
                            ": '\n# '; echo BASH_ENV=inject.sh >> \"$GITHUB_ENV\"; : '\n'"
                            if malicious else
                            '# \'; echo BASH_ENV=inject.sh >> "$GITHUB_ENV"; : \'\ntrue'
                        )
                    else:
                        text = text.replace(
                            "      matrix:\n", "      matrix:\n        suffix:\n          - "
                            + ("null" if malicious else '"null"') + "\n", 1
                        )
                        script = 'echo BASH_ENV=inject.sh >> "$GITHUB_${{ matrix.suffix }}ENV"'
                    text = text.replace(
                        "    environment: ${{ matrix.scope.monitoring_environment }}\n    steps:\n",
                        "    environment: ${{ matrix.scope.monitoring_environment }}\n    steps:\n"
                        "      - name: Regression fixture\n        run: " + json.dumps(script) + "\n", 1
                    )
                    path.write_text(text, encoding="utf-8")
                    if malicious:
                        violations = self._violations(root)
                        self.assertTrue(any("GITHUB_ENV/" in item for item in violations), violations)
                    else:
                        result = subprocess.run(
                            [sys.executable, "-I", str(SCRIPT), "--root", str(root)],
                            check=False, text=True, capture_output=True,
                        )
                        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_computed_github_file_access_fails_closed_in_every_guarded_workflow(self):
        workflows = (
            *check_supply_chain.PROBE_WORKFLOW_STEPS,
            ".github/workflows/drift-check.yml",
            ".github/workflows/rotate.yml",
            ".github/workflows/materialize-file.yml",
        )
        expressions = (
            "github[format('{0}{1}', 'e', 'nv')]",
            "github[format('{0}{1}', 'pa', 'th')]",
            "github[format('{0}{1}', 'out', 'put')]",
            "GITHUB [ format('{0}{1}', 'E', 'NV') ]",
            "github[join(fromJSON('[\"e\",\"nv\"]'), '')]",
            "github[vars.CHANNEL]",
            "github[env.CHANNEL]",
            "github.event[vars.CHANNEL]",
            "format('{1}', '}}', github[format('{0}{1}', 'e', 'nv')])",
            "fromJSON(format('{1}', '}}', toJSON(github))).env",
            "toJSON(github)",
            "github.*",
            "github.env", "github.path", "github.output",
            "github['env']", "github['path']", "github['output']",
        )
        for workflow in workflows:
            for expression in expressions:
                for source in (
                    "run", "comment", "inline-comment", "env", "with", "sequence", "if",
                ):
                    with self.subTest(workflow=workflow, expression=expression, source=source):
                        document = self._probe_document(workflow)
                        step = {"name": "Inject startup", "run": "true"}
                        destination = "${{ " + expression + " }}"
                        if source == "run":
                            # No protected variable name is in this payload.
                            # The file channel itself must be refused before
                            # Bash can source a later BASH_ENV override.
                            step["run"] = 'echo "BASH_ENV=inject.sh" >> "' + destination + '"'
                        elif source == "comment":
                            step["run"] = "# " + destination + "\ntrue"
                        elif source == "inline-comment":
                            step["run"] = "true # " + destination
                        elif source == "sequence":
                            step["with"] = {"destinations": [destination]}
                        elif source == "if":
                            step["if"] = expression + " != ''"
                        else:
                            step[source] = {"destination": destination}
                        job = next(iter(document["jobs"].values()))
                        job["steps"].insert(0, step)
                        violations = self._guarded_bindings(workflow, document)
                        self.assertTrue(
                            any("GitHub context access is forbidden" in item for item in violations),
                            violations,
                        )

    def test_commented_computed_shell_text_is_refused_before_shell_filtering(self):
        workflows = (
            *check_supply_chain.PROBE_WORKFLOW_STEPS,
            ".github/workflows/drift-check.yml",
            ".github/workflows/rotate.yml",
            ".github/workflows/materialize-file.yml",
        )
        expressions = (
            r'''format('{0}echo "BASH_ENV=inject.sh" >>"{1}"', '''
            r'''fromJSON('"\n"'), github[format('{0}{1}', 'e', 'nv')])''',
            r'''fromJSON('"\u000aecho \"BASH_ENV=inject.sh\" >> \"$GITHUB_\u0045NV\""')''',
            r'''format('{1}', '}}', fromJSON('"\nexport FERRUM_VERIFY_PROBE_CONSUMERS=x"'))''',
            "format('{0}{1}', '\n', 'export FERRUM_VERIFY_PROBE_CONSUMERS=x')",
            "steps[format('{0}{1}', 'load-', 'bundles')].outputs.channel",
            "fromJSON(toJSON(steps)).load-bundles.outputs.channel",
        )
        for workflow in workflows:
            for expression in expressions:
                for prefix in ("# ", "true # ", ""):
                    with self.subTest(workflow=workflow, expression=expression, prefix=prefix):
                        document = self._probe_document(workflow)
                        next(iter(document["jobs"].values()))["steps"].insert(0, {
                            "name": "Inject startup",
                            "run": prefix + "${{ " + expression + " }}\ntrue",
                        })
                        violations = self._guarded_bindings(workflow, document)
                        self.assertTrue(
                            any(
                                "computed shell text is forbidden" in item
                                for item in violations
                            ),
                            violations,
                        )

    def test_comment_expressions_are_read_from_decoded_yaml_scalars(self):
        workflows = (
            *check_supply_chain.PROBE_WORKFLOW_STEPS,
            ".github/workflows/drift-check.yml",
            ".github/workflows/rotate.yml",
            ".github/workflows/materialize-file.yml",
        )
        payload = (
            "# ${{ format('{0}echo BASH_ENV=inject.sh >>{1}', "
            "fromJSON('\"\\n\"'), github[format('{0}{1}', 'e', 'nv')]) }}\ntrue"
        )
        for workflow in workflows:
            for scalar in (
                "|\n          " + payload.replace("\n", "\n          "),
                json.dumps(payload),
                json.dumps(payload).replace("github", r"\u0067ithub"),
                json.dumps(payload).replace("#", r"\u0023"),
                json.dumps(r'''# ${{ fromJSON('"\u000aecho injected"') }}'''),
            ):
                with self.subTest(workflow=workflow, scalar=scalar):
                    text = (ROOT / workflow).read_text(encoding="utf-8").replace(
                        "    steps:\n",
                        "    steps:\n      - name: Inject startup\n        run: " + scalar + "\n",
                        1,
                    )
                    violations = self._guarded_bindings(
                        workflow, check_supply_chain.parse_workflow(text)
                    )
                    self.assertTrue(
                        any("computed shell text is forbidden" in item for item in violations),
                        violations,
                    )

    def test_unrecognized_raw_expressions_fail_closed(self):
        for script in (
            "# ${{ github[vars.CHANNEL] }\ntrue",
            "true # ${{ format('unterminated) }}",
        ):
            with self.subTest(script=script):
                violations = check_supply_chain.github_context_access_violations(
                    "guarded.yml", {"jobs": {"job": {"steps": [{"run": script}]}}}
                )
                self.assertTrue(
                    any("unrecognized GitHub expression syntax" in item for item in violations),
                    violations,
                )

    def test_literal_file_channels_and_decoded_computed_forms_are_refused(self):
        workflows = (*check_supply_chain.PROBE_WORKFLOW_STEPS, ".github/workflows/drift-check.yml")
        for workflow in workflows:
            for destination in (
                "$GITHUB_ENV", "${GITHUB_ENV}", '$GITHUB_""ENV', "$GITHUB_PATH",
                "${{ github.env }}", "${{ GITHUB . ENV }}", "${{ github['env'] }}",
                "${{ github.path }}", "${{ github['path'] }}",
                "${{ github.output }}", "${{ github['output'] }}",
            ):
                with self.subTest(workflow=workflow, destination=destination):
                    document = self._probe_document(workflow)
                    next(iter(document["jobs"].values()))["steps"].insert(0, {
                        "name": "Inject startup",
                        "run": 'echo "BASH_ENV=inject.sh" >> "' + destination + '"',
                    })
                    self.assertTrue(self._guarded_bindings(workflow, document))
            for run in (
                "|\n          echo BASH_ENV=inject.sh >> "
                "${{ github[format('{0}{1}', 'e', 'nv')] }}",
                r'''"echo BASH_ENV=inject.sh >> ${{ \x67ithub[format('{0}{1}', 'e', 'nv')] }}"''',
            ):
                with self.subTest(workflow=workflow, run=run):
                    text = (ROOT / workflow).read_text(encoding="utf-8")
                    text = text.replace(
                        "    steps:\n",
                        "    steps:\n      - name: Inject startup\n        run: " + run + "\n",
                        1,
                    )
                    violations = self._guarded_bindings(
                        workflow, check_supply_chain.parse_workflow(text)
                    )
                    self.assertTrue(
                        any("GitHub context access is forbidden" in item for item in violations),
                        violations,
                    )
            for channel in ("GITHUB_ENV", "GITHUB_PATH", "GITHUB_OUTPUT"):
                with self.subTest(workflow=workflow, rebound_channel=channel):
                    document = self._probe_document(workflow)
                    document["env"] = {channel: "candidate/inject"}
                    self.assertTrue(self._guarded_bindings(workflow, document))

    def test_bound_validate_cannot_be_skipped_or_lose_its_exit_status(self):
        workflow = ".github/workflows/apply-on-merge.yml"
        for job in ("apply", "promote"):
            for key, value in (
                ("if", "false"), ("if", "${{ false }}"),
                ("if", "${{ vars.RUN_VALIDATE }}"),
                ("continue-on-error", "true"), ("continue-on-error", "${{ true }}"),
                ("run", "true"), ("run", "gitforgeops validate || true"),
                ("run", "gitforgeops validate\ntrue"),
                ("shell", "true {0}"), ("working-directory", "empty-resources"),
                ("uses", "acme/skip@" + "a" * 40),
            ):
                with self.subTest(job=job, key=key, value=value):
                    document = self._probe_document(workflow)
                    self._step(document, job, "Validate")[key] = value
                    self.assertEqual(
                        self._step(document, job, "Apply")["run"],
                        "gitforgeops apply --auto-approve",
                    )
                    violations = self._guarded_bindings(workflow, document)
                    self.assertTrue(
                        any("Validate must run gitforgeops validate" in item for item in violations),
                        violations,
                    )

    def test_changed_validate_only_environment_is_refused(self):
        workflow = ".github/workflows/apply-on-merge.yml"
        for job, expected in check_supply_chain.PROBE_RUNTIME_ENVIRONMENTS.items():
            with self.subTest(job=job):
                document = self._probe_document(workflow)
                self._step(document, job, "Validate")["env"]["FERRUM_ENV"] = "staging"
                for name in ("Apply", "Apply (file mode)", "Verify traffic"):
                    self.assertEqual(self._step(document, job, name)["env"]["FERRUM_ENV"], expected)
                violations = self._guarded_bindings(workflow, document)
                self.assertTrue(
                    any("'Validate' must bind exactly FERRUM_ENV" in item for item in violations),
                    violations,
                )

    def test_runtime_environment_is_pinned_across_validate_apply_and_verify(self):
        workflow = ".github/workflows/apply-on-merge.yml"
        replacements = (
            None, "staging", "${{ env.FERRUM_ENV }}", "${{ vars.ENVIRONMENT }}",
            "${{ matrix.other_environment }}", "${{ matrix['environment'] }}",
            "${{ steps.routing.outputs.environment }}",
            "${{ format('{0}', matrix.environment) }}",
            "${{ fromJSON(toJSON(matrix)).environment }}",
        )
        for job in check_supply_chain.PROBE_RUNTIME_ENVIRONMENTS:
            for name in ("Validate", "Apply", "Apply (file mode)", "Verify traffic"):
                for replacement in replacements:
                    with self.subTest(job=job, name=name, replacement=replacement):
                        document = self._probe_document(workflow)
                        environment = self._step(document, job, name)["env"]
                        if replacement is None:
                            environment.pop("FERRUM_ENV")
                        else:
                            environment["FERRUM_ENV"] = replacement
                        violations = self._guarded_bindings(workflow, document)
                        self.assertTrue(
                            any("must bind exactly FERRUM_ENV" in item for item in violations),
                            violations,
                        )
            for replacement in (
                None, "staging", "${{ vars.ENVIRONMENT }}",
                {"name": "${{ matrix.environment }}"},
            ):
                with self.subTest(job=job, github_environment=replacement):
                    document = self._probe_document(workflow)
                    if replacement is None:
                        document["jobs"][job].pop("environment")
                    else:
                        document["jobs"][job]["environment"] = replacement
                    violations = self._guarded_bindings(workflow, document)
                    self.assertTrue(
                        any("GitHub Environment must match" in item for item in violations),
                        violations,
                    )

    def test_runtime_scope_cannot_be_inherited_narrowed_or_rebound(self):
        workflow = ".github/workflows/apply-on-merge.yml"
        for job, expected in check_supply_chain.PROBE_RUNTIME_ENVIRONMENTS.items():
            for variable, value in (("FERRUM_ENV", expected), ("FERRUM_NAMESPACE", "other")):
                for scope in ("workflow", "job", "other-step", "with"):
                    with self.subTest(job=job, variable=variable, scope=scope):
                        document = self._probe_document(workflow)
                        if scope == "workflow":
                            document["env"] = {variable: value}
                        elif scope == "job":
                            document["jobs"][job]["env"] = {variable: value}
                        elif scope == "other-step":
                            document["jobs"][job]["steps"].insert(0, {
                                "run": "true", "env": {variable: value},
                            })
                        else:
                            self._step(document, job, "Validate")["with"] = {variable: value}
                        violations = self._guarded_bindings(workflow, document)
                        self.assertTrue(
                            any(
                                "protected variable may only be bound" in item
                                for item in violations
                            ),
                            violations,
                        )
            for name in ("Validate", "Apply", "Apply (file mode)", "Verify traffic"):
                for namespace in (
                    "other", "${{ matrix.namespace }}", "${{ env.NAMESPACE }}",
                    "${{ format('{0}', 'other') }}", "${{ steps.routing.outputs.namespace }}",
                ):
                    with self.subTest(job=job, name=name, namespace=namespace):
                        document = self._probe_document(workflow)
                        self._step(document, job, name)["env"]["FERRUM_NAMESPACE"] = namespace
                        self.assertTrue(self._guarded_bindings(workflow, document))
            for script in (
                "export FERRUM_ENV=staging", "unset FERRUM_ENV",
                "export FERRUM_NAMESPACE=other", "unset FERRUM_NAMESPACE",
                'export FERRUM_NAM""ESPACE=other',
                "export FERRUM_NAM\\\nESPACE=other",
                "# ${{ env.FERRUM_NAMESPACE }}\ntrue",
                "# ${{ env.FERRUM_ENV }}\ntrue",
            ):
                with self.subTest(job=job, script=script):
                    document = self._probe_document(workflow)
                    document["jobs"][job]["steps"].insert(0, {"run": script})
                    violations = self._guarded_bindings(workflow, document)
                    self.assertTrue(
                        any("protected variable references/rebinding" in item for item in violations),
                        violations,
                    )

    def test_verify_cannot_change_scope_in_its_script_or_execution_context(self):
        workflow = ".github/workflows/apply-on-merge.yml"
        for job in check_supply_chain.PROBE_RUNTIME_ENVIRONMENTS:
            for change in (
                "--env staging", "--env ${{ steps.routing.outputs.environment }}",
                "--env ${{ format('{0}', 'staging') }}", "namespace", "inline-env",
                "shell", "working-directory", "uses",
            ):
                with self.subTest(job=job, change=change):
                    document = self._probe_document(workflow)
                    verify = self._step(document, job, "Verify traffic")
                    if change.startswith("--env"):
                        verify["run"] = verify["run"].replace(
                            "gitforgeops verify", "gitforgeops " + change + " verify"
                        )
                    elif change == "namespace":
                        verify["run"] = "export FERRUM_NAMESPACE=other\n" + verify["run"]
                    elif change == "inline-env":
                        verify["run"] = verify["run"].replace(
                            "gitforgeops verify", "FERRUM_ENV=staging gitforgeops verify"
                        )
                    else:
                        verify[change] = "alternate"
                    violations = self._guarded_bindings(workflow, document)
                    self.assertTrue(
                        any(
                            "Verify traffic must retain the pinned command" in item
                            for item in violations
                        ),
                        violations,
                    )

    def test_validate_apply_flow_cannot_be_bypassed_by_step_or_job_gates(self):
        workflow = ".github/workflows/apply-on-merge.yml"
        for job in ("apply", "promote"):
            for mutation in (
                "reorder", "removed", "job-if", "job-needs", "job-nonblocking",
                "workflow-defaults", "job-defaults", "extra-step", "other-job",
            ):
                with self.subTest(job=job, mutation=mutation):
                    document = self._probe_document(workflow)
                    job_document = document["jobs"][job]
                    steps = job_document["steps"]
                    validate = self._step(document, job, "Validate")
                    if mutation == "reorder":
                        steps.remove(validate)
                        steps.append(validate)
                    elif mutation == "removed":
                        steps.remove(validate)
                    elif mutation == "job-if":
                        job_document["if"] = "${{ always() }}"
                    elif mutation == "job-needs":
                        job_document.pop("needs")
                    elif mutation == "job-nonblocking":
                        job_document["continue-on-error"] = "true"
                    elif mutation == "workflow-defaults":
                        document["defaults"] = {"run": {"shell": "true {0}"}}
                    elif mutation == "job-defaults":
                        job_document["defaults"] = {"run": {"working-directory": "empty"}}
                    elif mutation == "extra-step":
                        steps.insert(0, {
                            "name": "Early mutation", "run": "gitforgeops apply --auto-approve",
                        })
                    else:
                        document["jobs"]["unguarded"] = {"steps": [{
                            "run": 'gitforgeops --env staging ap""ply --auto-approve',
                        }]}
                    self.assertTrue(self._guarded_bindings(workflow, document))
            for name in ("Apply", "Apply (file mode)"):
                for gate in (None, "${{ always() }}", "${{ !cancelled() }}", "failure()"):
                    with self.subTest(job=job, name=name, gate=gate):
                        document = self._probe_document(workflow)
                        step = self._step(document, job, name)
                        if gate is None:
                            step.pop("if")
                        else:
                            step["if"] = gate
                        violations = self._guarded_bindings(workflow, document)
                        self.assertTrue(
                            any("must run after successful Validate" in item for item in violations),
                            violations,
                        )

    def test_equivalent_yaml_gates_are_checked_by_the_protected_checker(self):
        for field in ('if: "${{ false }}"', 'continue-on-error: "true"'):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                root = self._mirror_repo(Path(directory))
                path = root / ".github/workflows/apply-on-merge.yml"
                text = path.read_text(encoding="utf-8").replace(
                    "      - name: Validate\n",
                    "      - name: Validate\n        " + field + "\n",
                    1,
                )
                path.write_text(text, encoding="utf-8")
                (root / ".github/scripts/check_supply_chain.py").write_text(
                    "raise SystemExit(0)\n", encoding="utf-8"
                )
                violations = self._violations(root)
                self.assertTrue(
                    any("Validate must run gitforgeops validate" in item for item in violations),
                    violations,
                )
        with tempfile.TemporaryDirectory() as directory:
            root = self._mirror_repo(Path(directory))
            path = root / ".github/workflows/apply-on-merge.yml"
            text = path.read_text(encoding="utf-8").replace(
                "    steps:\n",
                "    steps:\n      - name: Inject startup\n        run: |\n"
                '          echo "BASH_ENV=inject.sh" >> "'
                "${{ github[format('{0}{1}', 'e', 'nv')] }}\"\n",
                1,
            )
            path.write_text(text, encoding="utf-8")
            (root / ".github/scripts/check_supply_chain.py").write_text(
                "raise SystemExit(0)\n", encoding="utf-8"
            )
            violations = self._violations(root)
            self.assertTrue(
                any("GitHub context access is forbidden" in item for item in violations),
                violations,
            )
        for workflow in ("rotate.yml", "materialize-file.yml"):
            with self.subTest(workflow=workflow), tempfile.TemporaryDirectory() as directory:
                root = self._mirror_repo(Path(directory))
                path = root / ".github/workflows" / workflow
                path.write_text(path.read_text(encoding="utf-8").replace(
                    "    steps:\n",
                    "    steps:\n      - name: Inject startup\n        run: |\n"
                    '          echo "BASH_ENV=inject.sh" >> "'
                    "${{ github[format('{0}{1}', 'e', 'nv')] }}\"\n",
                    1,
                ), encoding="utf-8")
                violations = self._violations(root)
                self.assertTrue(
                    any("GitHub context access is forbidden" in item for item in violations),
                    violations,
                )

    def test_protected_checker_rejects_encoded_alias_injection_with_paired_static_sources(self):
        source = (
            r'''${{ fromJSON('"\necho FERRUM_\u004eAMESPACE=other '''
            r'''>> \"$GITHUB_\u0045NV\""') }}'''
        )
        script = json.dumps("# ${{ env.INJECT }}\ntrue").replace("#", r"\u0023")
        for workflow in (
            *check_supply_chain.PROBE_WORKFLOW_STEPS,
            ".github/workflows/drift-check.yml",
            ".github/workflows/rotate.yml",
            ".github/workflows/materialize-file.yml",
        ):
            for scope in ("workflow", "job", "step"):
                with (
                    self.subTest(workflow=workflow, scope=scope),
                    tempfile.TemporaryDirectory() as directory,
                ):
                    root = self._mirror_repo(Path(directory))
                    path = root / workflow
                    original = path.read_text(encoding="utf-8")

                    def fixture(value):
                        scalar = json.dumps(value)
                        step = "      - name: Render alias\n"
                        if scope == "step":
                            step += "        env:\n          INJECT: " + scalar + "\n"
                        step += "        run: " + script + "\n"
                        text = original.replace("    steps:\n", "    steps:\n" + step, 1)
                        if scope == "workflow":
                            text = text.replace(
                                "jobs:\n", "env:\n  INJECT: " + scalar + "\njobs:\n", 1
                            )
                        elif scope == "job":
                            text = text.replace(
                                "    steps:\n",
                                "    env:\n      INJECT: " + scalar + "\n    steps:\n", 1,
                            )
                        return text

                    path.write_text(fixture(source), encoding="utf-8")
                    # The candidate's own checker cannot approve its alias.
                    (root / ".github/scripts/check_supply_chain.py").write_text(
                        "raise SystemExit(0)\n", encoding="utf-8"
                    )
                    violations = self._violations(root)
                    self.assertTrue(any("run env alias" in item for item in violations), violations)
                    path.write_text(fixture("echo static-mode-v1"), encoding="utf-8")
                    result = subprocess.run(
                        [sys.executable, str(SCRIPT), "--root", str(root)],
                        check=False, text=True, capture_output=True,
                    )
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_protected_checker_rejects_comment_injection_and_validate_env_changes(self):
        payload = (
            "# ${{ format('{0}echo BASH_ENV=inject.sh >>{1}', "
            "fromJSON('\"\\n\"'), github[format('{0}{1}', 'e', 'nv')]) }}"
        )
        for workflow in (
            *check_supply_chain.PROBE_WORKFLOW_STEPS,
            ".github/workflows/drift-check.yml",
            ".github/workflows/rotate.yml",
            ".github/workflows/materialize-file.yml",
        ):
            with self.subTest(workflow=workflow), tempfile.TemporaryDirectory() as directory:
                root = self._mirror_repo(Path(directory))
                path = root / workflow
                path.write_text(path.read_text(encoding="utf-8").replace(
                    "    steps:\n",
                    "    steps:\n      - name: Inject startup\n        run: "
                    + json.dumps(payload).replace("github", r"\u0067ithub") + "\n",
                    1,
                ), encoding="utf-8")
                (root / ".github/scripts/check_supply_chain.py").write_text(
                    "raise SystemExit(0)\n", encoding="utf-8"
                )
                violations = self._violations(root)
                self.assertTrue(
                    any("GitHub context access is forbidden" in item for item in violations),
                    violations,
                )
        for job, expected in check_supply_chain.PROBE_RUNTIME_ENVIRONMENTS.items():
            with self.subTest(job=job), tempfile.TemporaryDirectory() as directory:
                root = self._mirror_repo(Path(directory))
                path = root / ".github/workflows/apply-on-merge.yml"
                binding = "      - name: Validate\n        env:\n          FERRUM_ENV: "
                original = path.read_text(encoding="utf-8")
                self.assertIn(binding + expected, original)
                path.write_text(original.replace(
                    binding + expected, binding + '"\\x73taging"', 1
                ), encoding="utf-8")
                (root / ".github/scripts/check_supply_chain.py").write_text(
                    "raise SystemExit(0)\n", encoding="utf-8"
                )
                violations = self._violations(root)
                self.assertTrue(
                    any("'Validate' must bind exactly FERRUM_ENV" in item for item in violations),
                    violations,
                )

    def test_pinned_operations_accept_equivalent_yaml_and_safe_outputs(self):
        # Keep actual Validate, Apply, Verify and viewer-diff operations in the
        # positive; an empty document or `run: true` would prove no binding.
        with tempfile.TemporaryDirectory() as directory:
            root = self._mirror_repo(Path(directory))
            for workflow in (
                *check_supply_chain.PROBE_WORKFLOW_STEPS,
                ".github/workflows/drift-check.yml",
                ".github/workflows/rotate.yml",
                ".github/workflows/materialize-file.yml",
            ):
                path = root / workflow
                text = path.read_text(encoding="utf-8")
                text = text.replace("run: gitforgeops validate\n", 'run: "gitforgeops validate"\n')
                text = text.replace(
                    "      - name: Validate\n",
                    "      - name: Validate\n        continue-on-error: false\n",
                )
                for condition in check_supply_chain.PROBE_APPLY_STEP_GATES.values():
                    text = text.replace("if: " + condition, "if: ${{ " + condition + " }}")
                for _, condition in check_supply_chain.PROBE_APPLY_JOB_GATES.values():
                    text = text.replace("if: " + condition, "if: ${{ " + condition + " }}")
                for environment in check_supply_chain.PROBE_RUNTIME_ENVIRONMENTS.values():
                    text = text.replace(
                        "FERRUM_ENV: " + environment,
                        "FERRUM_ENV: " + json.dumps(environment).replace("matrix", r"\x6datrix"),
                    )
                text = text.replace(
                    "    steps:\n",
                    "    steps:\n      - name: Read named GitHub property\n        run: |\n"
                    "          # FERRUM_ENV, FERRUM_NAMESPACE, GITHUB_ENV and github['env']\n"
                    "          # ${{ steps.deployment-mode.outputs.mode }}\n"
                    '          echo "mode=${{ steps.deployment-mode.outputs.mode }}"\n'
                    '          echo "run_id=${{ github.run_id }}" >> "$GITHUB_OUTPUT"\n',
                    1,
                )
                path.write_text(text, encoding="utf-8")
                document = check_supply_chain.parse_workflow(text)
                self.assertEqual(self._guarded_bindings(workflow, document), [])
                if workflow.endswith("apply-on-merge.yml"):
                    for job in ("apply", "promote"):
                        self.assertEqual(
                            self._step(document, job, "Validate")["run"], "gitforgeops validate"
                        )
                        self.assertEqual(
                            self._step(document, job, "Apply")["run"],
                            "gitforgeops apply --auto-approve",
                        )
                        self.assertEqual(
                            self._step(document, job, "Apply (file mode)")["run"],
                            "gitforgeops apply --auto-approve",
                        )
                        self.assertIn(
                            'FERRUM_CREDS_JSON_FILE="$APPLIED_CREDS_FILE" gitforgeops verify',
                            self._step(document, job, "Verify traffic")["run"],
                        )
                        for name in ("Validate", "Apply", "Apply (file mode)", "Verify traffic"):
                            self.assertEqual(
                                self._step(document, job, name)["env"]["FERRUM_ENV"],
                                check_supply_chain.PROBE_RUNTIME_ENVIRONMENTS[job],
                            )
                elif workflow.endswith("drift-check.yml"):
                    self.assertIn(
                        "gitforgeops diff --exit-on-drift",
                        self._step(document, "drift", "Check drift")["run"],
                    )
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--root", str(root)],
                check=False, text=True, capture_output=True,
            )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_probe_bindings_are_required_in_every_protected_step(self):
        for workflow, required in check_supply_chain.PROBE_WORKFLOW_STEPS.items():
            self.assertEqual(
                check_supply_chain.probe_consumer_binding_violations(
                    workflow, self._probe_document(workflow)
                ),
                [],
            )
            for job, name, bindings in required:
                for variable in bindings:
                    for replacement in (None, "ferrum/customer", "${{ env.ALLOWLIST }}", "false"):
                        with self.subTest(workflow=workflow, job=job, name=name,
                                          variable=variable, replacement=replacement):
                            document = self._probe_document(workflow)
                            environment = self._step(document, job, name)["env"]
                            if replacement is None:
                                environment.pop(variable)
                            else:
                                environment[variable] = replacement
                            violations = check_supply_chain.probe_consumer_binding_violations(
                                workflow, document
                            )
                            self.assertTrue(
                                any("must bind exactly " + variable in item for item in violations),
                                violations,
                            )

    def test_probe_bindings_cannot_be_inherited_or_rebound_elsewhere(self):
        for workflow, required in check_supply_chain.PROBE_WORKFLOW_STEPS.items():
            job, name, bindings = required[0]
            for variable, expected in bindings.items():
                for scope in ("workflow", "job", "other-step", "with", "dynamic"):
                    with self.subTest(workflow=workflow, variable=variable, scope=scope):
                        document = self._probe_document(workflow)
                        step = self._step(document, job, name)
                        if scope == "workflow":
                            document["env"] = {variable: expected}
                        elif scope == "job":
                            document["jobs"][job]["env"] = {variable: expected}
                        elif scope == "other-step":
                            document["jobs"][job]["steps"].append({
                                "name": "Rebind", "env": {variable: expected}, "run": "true",
                            })
                        elif scope == "with":
                            step["with"] = {variable: step["env"].pop(variable)}
                        else:
                            document["jobs"][job]["env"] = "${{ fromJSON(vars.ENVIRONMENT) }}"
                        self.assertTrue(
                            check_supply_chain.probe_consumer_binding_violations(workflow, document)
                        )
            for mutation in ("missing", "duplicate", "renamed"):
                with self.subTest(workflow=workflow, mutation=mutation):
                    document = self._probe_document(workflow)
                    step = self._step(document, job, name)
                    steps = document["jobs"][job]["steps"]
                    if mutation == "missing":
                        steps.remove(step)
                    elif mutation == "duplicate":
                        steps.append(step)
                    else:
                        step["name"] = "Replacement"
                    self.assertTrue(
                        check_supply_chain.probe_consumer_binding_violations(workflow, document)
                    )

    def test_probe_bindings_refuse_shell_rebinding_and_mutable_env_files(self):
        variable = check_supply_chain.PROBE_CONSUMERS_ENV
        scripts = (
            f'{variable}=ferrum/customer gitforgeops validate',
            f'export {variable}=ferrum/customer',
            f'unset {check_supply_chain.PROBE_BOUND_ENV}',
            f'echo "{variable}=ferrum/customer" >> "$GITHUB_ENV"',
            f'printf "%s\\n" "{variable}=ferrum/customer" >> "${{GITHUB_ENV}}"',
            f'printf "%s\\n" "{variable}<<EOF" ferrum/customer EOF >> "$GITHUB_ENV"',
            'destination="$GITHUB_ENV"\necho "$PAYLOAD" >> "$destination"',
            'cat payload >> "${{ github.env }}"',
            'cat payload >> "${{ github[\'env\'] }}"',
            'echo "$PAYLOAD" >> "$GITHUB_""ENV"',
            'env FERRUM_VERIFY_PROBE_""CONSUMERS=ferrum/customer gitforgeops validate',
            'export FERRUM_VERIFY_PROBE_CONSU\\\nMERS=ferrum/customer',
        )
        for workflow, required in check_supply_chain.PROBE_WORKFLOW_STEPS.items():
            job, name, _ = required[0]
            for script in scripts:
                with self.subTest(workflow=workflow, script=script):
                    document = self._probe_document(workflow)
                    self._step(document, job, name)["run"] = script
                    self.assertTrue(
                        check_supply_chain.probe_consumer_binding_violations(workflow, document)
                    )
            for startup in ("BASH_ENV", "ENV", "GITHUB_ENV"):
                with self.subTest(workflow=workflow, startup=startup):
                    document = self._probe_document(workflow)
                    document["env"] = {startup: "candidate/inject.sh"}
                    self.assertTrue(
                        check_supply_chain.probe_consumer_binding_violations(workflow, document)
                    )
        workflow = ".github/workflows/apply-on-merge.yml"
        for write in (
            'echo "$PAYLOAD" >> "$GITHUB_ENV"',
            'echo "$PAYLOAD" >> "$GITHUB_""ENV"',
            'cat payload >> "${{ github[\'env\'] }}"',
            'creds_file="$PAYLOAD"',
        ):
            with self.subTest(loader_write=write):
                document = self._probe_document(workflow)
                loader = self._step(document, "apply", check_supply_chain.BUNDLE_LOADER_STEP)
                loader["run"] += "\n" + write
                self.assertTrue(
                    check_supply_chain.probe_consumer_binding_violations(workflow, document)
                )

    def test_probe_bindings_read_decoded_yaml_values_and_ignore_decoys(self):
        workflow = ".github/workflows/apply-on-merge.yml"
        text = (ROOT / workflow).read_text(encoding="utf-8")
        binding = check_supply_chain.PROBE_CONSUMERS_ENV + ": " + check_supply_chain.PROBE_CONSUMERS_VALUE
        # Quoting a correct scalar preserves its meaning. An escaped hostile
        # value, a comment or a run string cannot supply the env binding.
        quoted = text.replace(binding, binding.split(": ")[0] + ': "' + check_supply_chain.PROBE_CONSUMERS_VALUE + '"')
        self.assertEqual(
            check_supply_chain.probe_consumer_binding_violations(
                workflow, check_supply_chain.parse_workflow(quoted)
            ),
            [],
        )
        for replacement in (
            binding.split(": ")[0] + ': "\\x66errum/customer"',
            "# " + binding,
        ):
            with self.subTest(replacement=replacement):
                changed = text.replace(binding, replacement, 1)
                self.assertTrue(check_supply_chain.probe_consumer_binding_violations(
                    workflow, check_supply_chain.parse_workflow(changed)
                ))
        for replacement in (
            '"' + binding.split(": ")[0] + '": ferrum/customer',
            binding.split(": ")[0] + ': &source ferrum/customer',
            binding.split(": ")[0] + ': {source: ferrum/customer}',
        ):
            with self.subTest(replacement=replacement):
                with self.assertRaises(check_supply_chain.WorkflowSyntaxError):
                    check_supply_chain.parse_workflow(text.replace(binding, replacement, 1))

    def test_candidate_checker_cannot_approve_its_probe_binding_change(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._mirror_repo(Path(directory))
            (root / ".github/scripts/check_supply_chain.py").write_text(
                "print('candidate approves itself')\n", encoding="utf-8"
            )
            path = root / ".github/workflows/trusted-pr-review.yml"
            path.write_text(path.read_text(encoding="utf-8").replace(
                check_supply_chain.PROBE_CONSUMERS_VALUE, "ferrum/customer", 1
            ), encoding="utf-8")
            violations = self._violations(root)
        self.assertTrue(
            any("must bind exactly FERRUM_VERIFY_PROBE_CONSUMERS" in item for item in violations),
            violations,
        )

    def test_codeowners_must_explicitly_cover_exact_state_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self._mirror_repo(Path(temporary))
            path = root / ".github/CODEOWNERS"
            text = path.read_text(encoding="utf-8")
            path.write_text(
                "\n".join(
                    line
                    for line in text.splitlines()
                    if not line.startswith("/.state ")
                )
                + "\n",
                encoding="utf-8",
            )
            self.assertIn(
                "CODEOWNERS: launch-critical path is not explicitly owned: /.state",
                self._violations(root),
            )

    def test_trusted_policy_checker_has_no_stale_bootstrap_fallback(self):
        # A one-time commit-pinned bootstrap covered the window where `main`
        # did not yet carry this checker. `main` carries it now, so a fallback
        # can only substitute an OLDER policy for the protected one — exactly
        # what happens when a tree legitimately changes something the old
        # policy still demands.
        workflow = (ROOT / ".github/workflows/security.yml").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("bootstrap-supply-chain", workflow)
        self.assertEqual(
            check_supply_chain.trusted_supply_chain_policy_violations(workflow), []
        )

        with_fallback = workflow.replace(
            "CHECKER=trusted-supply-chain/.github/scripts/check_supply_chain.py\n",
            "CHECKER=trusted-supply-chain/.github/scripts/check_supply_chain.py\n"
            "            if [ ! -f \"$CHECKER\" ]; then\n"
            "              CHECKER=bootstrap-supply-chain/.github/scripts/check_supply_chain.py\n"
            "            fi\n",
            1,
        )
        violations = check_supply_chain.trusted_supply_chain_policy_violations(
            with_fallback
        )
        self.assertTrue(
            any("only from the protected default branch" in item for item in violations),
            violations,
        )

    def test_cargo_audit_gate_runs_the_default_branch_checker_and_policy(self):
        workflow = (ROOT / ".github/workflows/security.yml").read_text(
            encoding="utf-8"
        )
        self.assertEqual(
            check_supply_chain.trusted_cargo_audit_policy_violations(workflow), []
        )

        # Deleting the trusted checkout is how a pull request would put its own
        # checker and its own exception list back in charge of the gate.
        without_checkout = workflow.replace(
            "      - name: Check out trusted cargo-audit policy\n", "", 1
        )
        self.assertNotEqual(workflow, without_checkout)
        violations = check_supply_chain.trusted_cargo_audit_policy_violations(
            without_checkout
        )
        self.assertTrue(
            any("protected default branch" in item for item in violations), violations
        )

        # So is pointing the trusted checker at the candidate's exception file.
        self_approving = workflow.replace(
            "--policy trusted-cargo-audit/.github/cargo-audit-policy.json",
            "--policy .github/cargo-audit-policy.json",
            1,
        )
        violations = check_supply_chain.trusted_cargo_audit_policy_violations(
            self_approving
        )
        self.assertTrue(
            any(
                "must not supply its own cargo-audit exception policy" in item
                for item in violations
            ),
            violations,
        )

    def test_cargo_audit_gate_still_measures_the_candidate_dependency_graph(self):
        # Pinning the checker must not pin what it audits: --source-root has to
        # stay on the pull request's own tree or the gate would report on main.
        workflow = (ROOT / ".github/workflows/security.yml").read_text(
            encoding="utf-8"
        )
        detached = workflow.replace('--source-root "$GITHUB_WORKSPACE"', "", 1)
        self.assertNotEqual(workflow, detached)
        violations = check_supply_chain.trusted_cargo_audit_policy_violations(detached)
        self.assertTrue(
            any("--source-root" in item for item in violations), violations
        )

    def test_cargo_audit_gate_pins_its_parsed_job_shape(self):
        workflow = (ROOT / ".github/workflows/security.yml").read_text(
            encoding="utf-8"
        )
        self.assertEqual(check_supply_chain.cargo_audit_job_shape_violations(workflow), [])
        enforce = (
            "      - name: Enforce cargo audit policy\n"
            "        env:\n"
            "          EVENT_NAME: ${{ github.event_name }}\n"
            "        run: |\n"
        )
        trusted_enforce = (
            "            python3 trusted-cargo-audit/.github/scripts/check_cargo_audit.py \\\n"
            "              --policy trusted-cargo-audit/.github/cargo-audit-policy.json \\\n"
            '              --source-root "$GITHUB_WORKSPACE"\n'
        )
        trusted_tests = (
            "            python3 trusted-cargo-audit/.github/scripts/tests/"
            "test_check_cargo_audit.py\n"
        )
        job = "  security-cargo-audit:\n    runs-on: ubuntu-24.04\n"
        for anchor in (enforce, trusted_enforce, trusted_tests, job, "\njobs:\n"):
            self.assertEqual(workflow.count(anchor), 1, anchor)
        commented = "".join(
            "            # " + line.lstrip(" ") + "\n"
            for line in trusted_enforce.splitlines()
        )
        refused = {
            # Every required substring survives in a comment under `true`.
            "commented_enforcement": (trusted_enforce, "            true\n" + commented),
            "commented_tests": (
                trusted_tests, "            true # " + trusted_tests.lstrip(" ")
            ),
            "early_exit": (enforce, enforce + "          exit 0\n"),
            "swallowed_failure": (
                '--source-root "$GITHUB_WORKSPACE"\n',
                '--source-root "$GITHUB_WORKSPACE" || true\n',
            ),
            "skipped_step": (
                enforce, enforce.replace("        env:\n", "        if: false\n        env:\n", 1)
            ),
            "tolerated_step": (
                enforce,
                enforce.replace("        env:\n", "        continue-on-error: true\n        env:\n", 1),
            ),
            "alternate_shell": (
                enforce, enforce.replace("        env:\n", "        shell: 'true {0}'\n        env:\n", 1)
            ),
            "step_startup_file": (
                enforce,
                enforce.replace(
                    "          EVENT_NAME:", "          BASH_ENV: ./startup.sh\n          EVENT_NAME:", 1
                ),
            ),
            "added_step": (
                enforce,
                "      - name: Replace trusted checker\n"
                "        run: cp /dev/null trusted-cargo-audit/.github/scripts/check_cargo_audit.py\n"
                "\n" + enforce,
            ),
            "skipped_job": (job, job + "    if: false\n"),
            "tolerated_job": (job, job + "    continue-on-error: true\n"),
            "renamed_job": (job, job + "    name: cargo-audit\n"),
            "job_startup_file": (job, job + "    env:\n      BASH_ENV: ./startup.sh\n"),
            "job_shell": (job, job + "    defaults:\n      run:\n        shell: 'true {0}'\n"),
            "workflow_startup_file": (
                "\njobs:\n", "\nenv:\n  BASH_ENV: ./startup.sh\n\njobs:\n"
            ),
            "workflow_shell": (
                "\njobs:\n", "\ndefaults:\n  run:\n    shell: 'true {0}'\n\njobs:\n"
            ),
        }
        required = (
            "python3 trusted-cargo-audit/.github/scripts/tests/test_check_cargo_audit.py",
            "python3 trusted-cargo-audit/.github/scripts/check_cargo_audit.py",
            "--policy trusted-cargo-audit/.github/cargo-audit-policy.json",
            '--source-root "$GITHUB_WORKSPACE"',
        )
        for label, (old, new) in refused.items():
            with self.subTest(label=label):
                changed = workflow.replace(old, new, 1)
                self.assertNotEqual(changed, workflow)
                # The substring contract alone accepts each of these.
                for item in required:
                    self.assertIn(item, changed)
                self.assertTrue(check_supply_chain.cargo_audit_job_shape_violations(changed))
                self.assertTrue(
                    check_supply_chain.trusted_cargo_audit_policy_violations(changed)
                )

    def test_cargo_audit_job_shape_leaves_commits_and_toolchain_to_their_own_rules(self):
        workflow = (ROOT / ".github/workflows/security.yml").read_text(
            encoding="utf-8"
        )
        job = check_supply_chain.workflow_job(workflow, "security-cargo-audit")
        self.assertIn("toolchain: 1.98.0", job)
        bumped_job = re.sub(r"@[0-9a-f]{40}", "@" + "a" * 40, job).replace(
            "toolchain: 1.98.0", "toolchain: 1.99.0"
        )
        self.assertNotEqual(bumped_job, job)
        bumped = workflow.replace(job, bumped_job, 1)
        self.assertEqual(check_supply_chain.cargo_audit_job_shape_violations(bumped), [])
        # Each free part still answers to its own rule.
        self.assertTrue(check_supply_chain.cargo_audit_install_violations(bumped))
        self.assertTrue(
            check_supply_chain.rust_toolchain_violations("security.yml", bumped, "1.98.0")
        )

    def test_cargo_audit_comment_bypass_is_refused_by_the_trusted_checker(self):
        trusted = (
            "            python3 trusted-cargo-audit/.github/scripts/check_cargo_audit.py \\\n"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = self._mirror_repo(Path(temporary))
            path = root / ".github/workflows/security.yml"
            workflow = path.read_text(encoding="utf-8")
            self.assertEqual(workflow.count(trusted), 1)
            path.write_text(
                workflow.replace(trusted, "            true\n            # " + trusted.lstrip(" "), 1),
                encoding="utf-8",
            )
            # The candidate's own checker cannot approve the bypass.
            (root / ".github/scripts/check_supply_chain.py").write_text(
                "raise SystemExit(0)\n", encoding="utf-8"
            )
            violations = self._violations(root)
        self.assertTrue(
            any(
                item.startswith(
                    "security.yml: security-cargo-audit must keep its reviewed steps"
                )
                for item in violations
            ),
            violations,
        )

    def test_root_override_checks_the_selected_repository(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.assertEqual(check_supply_chain.action_files(root), [])
            nested = root / ".github" / "workflows"
            nested.mkdir(parents=True)
            action = nested / "sample.yml"
            action.write_text("name: sample\n", encoding="utf-8")
            self.assertEqual(check_supply_chain.action_files(root), [action])

    def test_cargo_audit_install_accepts_only_the_reviewed_v2_87_22_pin(self):
        self.assertEqual(
            check_supply_chain.CARGO_AUDIT_ACTIONS, frozenset(CARGO_AUDIT_ACTION_PINS)
        )
        for pin in CARGO_AUDIT_ACTION_PINS:
            with self.subTest(pin=pin):
                workflow = self._cargo_audit_workflow(pin)
                job = check_supply_chain.workflow_job(workflow, "security-cargo-audit")
                self.assertEqual(
                    check_supply_chain.policy_step(job, "Install cargo-audit"),
                    [
                        "name: Install cargo-audit",
                        f"        uses: {pin}",
                        "        with:",
                        "          tool: cargo-audit@0.22.1",
                        "          checksum: true",
                        "          fallback: none",
                    ],
                )
                self.assertEqual(check_supply_chain.cargo_audit_install_violations(workflow), [])

    def test_cargo_audit_install_rejects_retired_unreviewed_pins_and_mutable_tags(self):
        for pin in CARGO_AUDIT_ACTION_PINS:
            workflow = self._cargo_audit_workflow(pin)
            for replacement in REJECTED_CARGO_AUDIT_ACTION_PINS:
                with self.subTest(pin=pin, replacement=replacement):
                    changed = workflow.replace(f"uses: {pin}", f"uses: {replacement}", 1)
                    self.assertNotEqual(changed, workflow)
                    self.assertTrue(check_supply_chain.cargo_audit_install_violations(changed))

    def test_cargo_audit_install_keeps_strict_shape_for_the_reviewed_pin(self):
        mutations = (
            ("tool: cargo-audit@0.22.1", "tool: cargo-audit@latest"),
            ("tool: cargo-audit@0.22.1", "tool: cargo-audit@0.22.2"),
            ("tool: cargo-audit@0.22.1", "tool: cargo-audit"),
            ("          tool: cargo-audit@0.22.1\n", ""),
            ("checksum: true", "checksum: false"),
            ("          checksum: true\n", ""),
            ("fallback: none", "fallback: cargo-install"),
            ("          fallback: none\n", ""),
            ("          fallback: none\n", "          fallback: none\n          cache: true\n"),
            ("          checksum: true\n          fallback: none\n",
             "          fallback: none\n          checksum: true\n"),
            ("      - name: Install cargo-audit\n",
             "      - name: Install cargo-audit\n        if: false\n"),
            ("      - name: Install cargo-audit\n",
             "      - name: Install cargo-audit\n        continue-on-error: true\n"),
        )
        for pin in CARGO_AUDIT_ACTION_PINS:
            workflow = self._cargo_audit_workflow(pin)
            for old, new in mutations:
                with self.subTest(pin=pin, new=new):
                    changed = workflow.replace(old, new, 1)
                    self.assertNotEqual(changed, workflow)
                    self.assertTrue(check_supply_chain.cargo_audit_install_violations(changed))

    def test_cargo_audit_install_rejects_cache_and_registry_fallback(self):
        extras = (
            "      - uses: actions/cache@" + "a" * 40 + "\n"
            "        with:\n          path: ~/.cargo/bin\n          key: old-auditor\n",
            "      - name: Registry fallback\n"
            "        run: cargo install cargo-audit --version 0.22.1 --locked\n",
            "      - name: Registry fallback\n"
            "        run: cargo binstall cargo-audit --version 0.22.1\n",
        )
        for pin in CARGO_AUDIT_ACTION_PINS:
            workflow = self._cargo_audit_workflow(pin)
            for extra in extras:
                with self.subTest(pin=pin, extra=extra):
                    changed = workflow.replace(
                        "      - name: Install cargo-audit\n",
                        extra + "      - name: Install cargo-audit\n",
                        1,
                    )
                    self.assertNotEqual(changed, workflow)
                    self.assertTrue(check_supply_chain.cargo_audit_install_violations(changed))

    def test_cargo_audit_install_must_precede_enforcement(self):
        for pin in CARGO_AUDIT_ACTION_PINS:
            with self.subTest(pin=pin):
                workflow = self._cargo_audit_workflow(pin)
                start = workflow.index("      - name: Install cargo-audit\n")
                end = workflow.index("      - name: Test audit policy gate\n", start)
                install = workflow[start:end]
                changed = workflow.replace(install, "", 1).replace(
                    "  codeql:\n", install + "  codeql:\n", 1
                )
                job = check_supply_chain.workflow_job(changed, "security-cargo-audit")
                self.assertEqual(
                    len(check_supply_chain.policy_step(job, "Install cargo-audit")), 6
                )
                self.assertIn(
                    "security.yml: install cargo-audit before enforcing its policy",
                    check_supply_chain.cargo_audit_install_violations(changed),
                )

    def test_reviewed_cargo_audit_pin_passes_the_trusted_checker(self):
        for pin in CARGO_AUDIT_ACTION_PINS:
            with self.subTest(pin=pin), tempfile.TemporaryDirectory() as temporary:
                root = self._mirror_repo(Path(temporary))
                (root / ".github/workflows/security.yml").write_text(
                    self._cargo_audit_workflow(pin), encoding="utf-8"
                )
                (root / ".github/scripts/check_supply_chain.py").write_text(
                    "raise SystemExit('candidate checker must not execute')\n", encoding="utf-8"
                )
                result = subprocess.run(
                    [sys.executable, "-I", str(SCRIPT), "--root", str(root)],
                    check=False,
                    text=True,
                    capture_output=True,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_cargo_audit_install_policy_is_enforced_by_the_trusted_checker(self):
        for pin in CARGO_AUDIT_ACTION_PINS:
            with self.subTest(pin=pin), tempfile.TemporaryDirectory() as temporary:
                root = self._mirror_repo(Path(temporary))
                path = root / ".github/workflows/security.yml"
                path.write_text(
                    self._cargo_audit_workflow(pin).replace("checksum: true", "checksum: false", 1),
                    encoding="utf-8",
                )
                (root / ".github/scripts/check_supply_chain.py").write_text(
                    "raise SystemExit(0)\n", encoding="utf-8"
                )
                self.assertTrue(any("with checksums" in item for item in self._violations(root)))

    def test_candidate_cannot_authorize_rejected_cargo_audit_installer_pins(self):
        for rejected_pin in REJECTED_CARGO_AUDIT_ACTION_PINS:
            with self.subTest(pin=rejected_pin), tempfile.TemporaryDirectory() as temporary:
                root = self._mirror_repo(Path(temporary))
                (root / ".github/workflows/security.yml").write_text(
                    self._cargo_audit_workflow(rejected_pin), encoding="utf-8"
                )
                # The candidate can declare its own allowlist and return green;
                # the checker outside that tree still refuses retired and unreviewed pins.
                (root / ".github/scripts/check_supply_chain.py").write_text(
                    f'CARGO_AUDIT_ACTIONS = frozenset({{"{rejected_pin}"}})\n'
                    "raise SystemExit(0)\n",
                    encoding="utf-8",
                )
                self.assertTrue(
                    any("reviewed install-action" in item for item in self._violations(root))
                )

    def test_security_push_filter_covers_each_policy_only_change(self):
        workflow = (ROOT / ".github/workflows/security.yml").read_text()
        self.assertEqual(check_supply_chain.security_push_trigger_violations(workflow), [])
        for path in check_supply_chain.SECURITY_PUSH_POLICY_PATHS:
            with self.subTest(path=path), tempfile.TemporaryDirectory() as temporary:
                root = self._mirror_repo(Path(temporary))
                candidate = root / ".github/workflows/security.yml"
                # A mention in another event or a comment cannot cover a push.
                changed = workflow.replace(f"      - '{path}'\n", "", 1)
                changed = changed.replace(
                    "  pull_request:\n",
                    f"  pull_request:\n    paths:\n      - '{path}'\n",
                    1,
                )
                changed += f"\n# Required push input: {path}\n"
                candidate.write_text(changed)
                self.assertIn(
                    f"security.yml: push paths must explicitly include {path}",
                    self._violations(root),
                )

    def test_security_push_filter_rejects_missing_trigger_and_exclusions(self):
        workflow = (ROOT / ".github/workflows/security.yml").read_text()
        for old, new in (
            ("  push:\n", "  workflow_dispatch:\n"),
            ("  push:\n    branches: [main]", "  push:\n    branches: [develop]"),
            ("    paths:\n", "    paths-ignore:\n"),
            ("      - '.github/CODEOWNERS'\n",
             "      - '.github/CODEOWNERS'\n      - '!.github/**'\n"),
        ):
            with self.subTest(new=new):
                self.assertTrue(
                    check_supply_chain.security_push_trigger_violations(
                        workflow.replace(old, new, 1)
                    )
                )

    def test_security_trigger_list_is_pinned_to_the_reviewed_events(self):
        workflow = (ROOT / ".github/workflows/security.yml").read_text(
            encoding="utf-8"
        )
        self.assertEqual(check_supply_chain.security_trigger_violations(workflow), [])

        # A `workflow_dispatch:` runs the candidate's own copy of this workflow
        # outside `pull_request`, where the pinned jobs take the `else` branch
        # and post a second `security-cargo-audit` result under the required
        # name from a run no rule reviewed.
        dispatched = workflow.replace("on:\n", "on:\n  workflow_dispatch:\n", 1)
        self.assertNotEqual(dispatched, workflow)
        violations = check_supply_chain.security_trigger_violations(dispatched)
        self.assertTrue(
            any("workflow_dispatch" in item for item in violations), violations
        )

        for label, old, new in (
            (
                "pull_request_types",
                "    types: [opened, synchronize, reopened, edited]\n",
                "    types: [opened]\n",
            ),
            ("pull_request_branch", "    branches: [main]\n", "    branches: [develop]\n"),
            ("push_branch", "  push:\n    branches: [main]\n", "  push:\n    branches: [develop]\n"),
            ("dropped_schedule", "  schedule:\n    - cron: '17 9 * * 1'\n", ""),
        ):
            with self.subTest(label=label):
                changed = workflow.replace(old, new, 1)
                self.assertNotEqual(changed, workflow)
                self.assertTrue(check_supply_chain.security_trigger_violations(changed))

        # The rule is wired into the aggregate run, not only callable.
        with tempfile.TemporaryDirectory() as temporary:
            root = self._mirror_repo(Path(temporary))
            (root / ".github/workflows/security.yml").write_text(
                dispatched, encoding="utf-8"
            )
            violations = self._violations(root)
        self.assertTrue(
            any(
                item.startswith("security.yml: the trigger 'workflow_dispatch' is not reviewed")
                for item in violations
            ),
            violations,
        )

    def test_security_policy_must_execute_the_default_branch_checker(self):
        secure = "\n".join(
            [
                "if: github.event_name == 'pull_request'",
                "ref: ${{ github.event.repository.default_branch }}",
                "path: trusted-supply-chain",
                "CANDIDATE_CHECKER=.github/scripts/check_supply_chain.py",
                "Candidate must retain the regular-file supply-chain checker.",
                "CHECKER=trusted-supply-chain/.github/scripts/check_supply_chain.py",
                'python3 -I - "$CHECKER" "$GITHUB_WORKSPACE" <<\'PY\'',
                "module.ROOT = candidate",
                'module.WORKFLOWS = candidate / ".github" / "workflows"',
                "module.ACTION_FILES = sorted(",
                "sys.argv = [str(checker)]",
                "raise SystemExit(module.main())",
            ]
        )
        self.assertEqual(
            check_supply_chain.trusted_supply_chain_policy_violations(secure), []
        )

        insecure = secure.replace(
            "ref: ${{ github.event.repository.default_branch }}",
            "ref: ${{ github.event.pull_request.base.sha }}",
        )
        violations = check_supply_chain.trusted_supply_chain_policy_violations(
            insecure
        )
        self.assertTrue(any("missing" in item for item in violations))
        self.assertTrue(any("unprotected PR base" in item for item in violations))

    def test_security_policy_runner_must_be_isolated_from_the_candidate(self):
        # GHSA-x5m2-4555-q4cr: the runner executes in the candidate checkout,
        # and a plain `python3 -` imports candidate root modules first.
        workflow = (ROOT / ".github/workflows/security.yml").read_text(
            encoding="utf-8"
        )
        self.assertEqual(
            check_supply_chain.TRUSTED_POLICY_RUNNER,
            'python3 -I - "$CHECKER" "$GITHUB_WORKSPACE"',
        )
        self.assertEqual(workflow.count(check_supply_chain.TRUSTED_POLICY_RUNNER), 1)
        self.assertEqual(
            check_supply_chain.trusted_supply_chain_policy_violations(workflow), []
        )

        importable = workflow.replace(
            check_supply_chain.TRUSTED_POLICY_RUNNER,
            'python3 - "$CHECKER" "$GITHUB_WORKSPACE"',
            1,
        )
        self.assertNotEqual(importable, workflow)
        violations = check_supply_chain.trusted_supply_chain_policy_violations(
            importable
        )
        self.assertTrue(
            any(
                "missing" in item and "python3 -I -" in item for item in violations
            ),
            violations,
        )

        # Keeping the isolated line while adding a second, plain run of the
        # same checker reopens the import path.
        doubled = workflow.replace(
            check_supply_chain.TRUSTED_POLICY_RUNNER,
            'python3 - "$CHECKER" "$GITHUB_WORKSPACE" </dev/null || true\n'
            "            " + check_supply_chain.TRUSTED_POLICY_RUNNER,
            1,
        )
        self.assertNotEqual(doubled, workflow)
        violations = check_supply_chain.trusted_supply_chain_policy_violations(
            doubled
        )
        self.assertTrue(
            any("invoked exactly once" in item for item in violations), violations
        )

        anchor = "        env:\n          EVENT_NAME: ${{ github.event_name }}\n"
        self.assertIn(anchor, workflow)
        for variable in ("PYTHONPATH", "PYTHONSTARTUP", "PYTHONHOME"):
            with self.subTest(variable=variable):
                redirected = workflow.replace(
                    anchor, anchor + f"          {variable}: ${{{{ github.workspace }}}}\n", 1
                )
                violations = check_supply_chain.trusted_supply_chain_policy_violations(
                    redirected
                )
                self.assertTrue(
                    any(
                        "must not set" in item and variable in item
                        for item in violations
                    ),
                    violations,
                )

    def test_candidate_root_modules_cannot_preempt_the_trusted_checker(self):
        # Hostile candidate-root modules named after what the runner and the
        # checker import. Without `-I` one of them runs first and exits green;
        # with it the trusted checker runs and still reports a real violation.
        runner = self._trusted_policy_runner_source()
        hostile = (
            "import os\n"
            "print('shadowed', flush=True)\n"
            "os._exit(0)\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            candidate = self._mirror_repo(Path(directory))
            for module in ("pathlib.py", "argparse.py", "json.py", "re.py"):
                (candidate / module).write_text(hostile, encoding="utf-8")
            # A known violation the trusted checker must still find.
            path = candidate / ".github/workflows/rotate.yml"
            text = path.read_text(encoding="utf-8")
            start = text.index(
                "      - name: Refresh protected branch and reject stale deployments"
            )
            end = text.index("      - name: ", start + 20)
            path.write_text(text[:start] + text[end:], encoding="utf-8")

            def run(flags: list[str]) -> subprocess.CompletedProcess:
                return subprocess.run(
                    [sys.executable, *flags, "-", str(SCRIPT), str(candidate)],
                    input=runner,
                    cwd=str(candidate),
                    check=False,
                    text=True,
                    capture_output=True,
                )

            shadowed = run([])
            isolated = run(["-I"])
        # The planted modules really are reachable without isolation...
        self.assertEqual(shadowed.returncode, 0, shadowed.stdout + shadowed.stderr)
        self.assertIn("shadowed", shadowed.stdout)
        # ...and isolated mode runs the trusted checker, which rejects the tree.
        self.assertEqual(isolated.returncode, 1, isolated.stdout + isolated.stderr)
        self.assertNotIn("shadowed", isolated.stdout)
        self.assertIn("must refresh the protected branch", isolated.stderr)

    # -- GHSA-x5m2-4555-q4cr tier 2: the protected-definition policy check --

    def test_trusted_policy_workflow_keeps_its_pinned_shape(self):
        workflow = (ROOT / check_supply_chain.SUPPLY_CHAIN_POLICY_PATH).read_text(
            encoding="utf-8"
        )
        self.assertEqual(
            check_supply_chain.supply_chain_policy_shape_violations(workflow), []
        )
        invocation = f"        run: {check_supply_chain.SUPPLY_CHAIN_POLICY_INVOCATION}\n"
        self.assertEqual(workflow.count(invocation), 1)
        self.assertEqual(
            check_supply_chain.SUPPLY_CHAIN_POLICY_INVOCATION,
            "python3 -I base/.github/scripts/check_supply_chain.py --root candidate",
        )

        candidate_checkout = (
            "          repository: ${{ github.event.pull_request.head.repo.full_name }}\n"
            "          ref: ${{ github.event.pull_request.head.sha }}\n"
            "          path: candidate\n"
            "          persist-credentials: false\n"
        )
        self.assertEqual(workflow.count(candidate_checkout), 1)
        mutants = {
            # Loads the definition from the pull request's own head.
            "head_loaded_trigger": (
                "  pull_request_target:\n",
                "  pull_request:\n",
            ),
            "second_trigger": (
                "permissions:\n",
                "  push:\n    branches: [main]\n\npermissions:\n",
            ),
            "path_filtered": (
                "    branches: [main]\n",
                "    branches: [main]\n    paths: ['.github/**']\n",
            ),
            "write_permission": ("  contents: read\n", "  contents: write\n"),
            "added_permission": (
                "  contents: read\n",
                "  contents: read\n  pull-requests: write\n",
            ),
            "persisted_candidate_credentials": (
                candidate_checkout,
                candidate_checkout.replace("false", "true"),
            ),
            "candidate_in_workspace_root": (
                "          path: candidate\n",
                "          path: .\n",
            ),
            "not_isolated": (
                "run: python3 -I base/",
                "run: python3 base/",
            ),
            "run_from_candidate": (
                "run: python3 -I base/.github/scripts/check_supply_chain.py --root candidate",
                "run: cd candidate && python3 -I ../base/.github/scripts/"
                "check_supply_chain.py --root .",
            ),
            "swallowed_failure": (
                "--root candidate\n",
                "--root candidate || true\n",
            ),
            "candidate_checker": (
                "run: python3 -I base/",
                "run: python3 -I candidate/",
            ),
            "startup_file": (
                "jobs:\n",
                "env:\n  BASH_ENV: candidate/startup.sh\n\njobs:\n",
            ),
            "working_directory": (
                "jobs:\n",
                "defaults:\n  run:\n    working-directory: candidate\n\njobs:\n",
            ),
            "skipped_job": (
                "    runs-on: ubuntu-24.04\n",
                "    if: false\n    runs-on: ubuntu-24.04\n",
            ),
            "environment": (
                "    runs-on: ubuntu-24.04\n",
                "    runs-on: ubuntu-24.04\n    environment: production\n",
            ),
            "secret": (
                "    runs-on: ubuntu-24.04\n",
                "    runs-on: ubuntu-24.04\n    env:\n"
                "      TOKEN: ${{ secrets.FERRUM_GH_PROVISIONER_TOKEN }}\n",
            ),
            "tolerated_failure": (
                "    runs-on: ubuntu-24.04\n",
                "    runs-on: ubuntu-24.04\n    continue-on-error: true\n",
            ),
            "no_timeout": ("    timeout-minutes: 10\n", ""),
            "default_timeout": ("    timeout-minutes: 10\n", "    timeout-minutes: 360\n"),
            "renamed_check": (
                "  trusted-supply-chain-policy:\n    runs-on",
                "  trusted-supply-chain-policy:\n    name: policy\n    runs-on",
            ),
            "mutable_action_ref": (
                "uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
                "uses: actions/checkout@v7",
            ),
            "glued_comment_is_part_of_the_value": (
                "--root candidate\n",
                "--root candidate#x\n",
            ),
            "extra_step": (
                "--root candidate\n",
                "--root candidate\n\n      - name: Build candidate\n"
                "        run: make -C candidate\n",
            ),
        }
        for label, (needle, replacement) in mutants.items():
            with self.subTest(label=label):
                mutated = workflow.replace(needle, replacement, 1)
                self.assertNotEqual(mutated, workflow)
                violations = check_supply_chain.supply_chain_policy_shape_violations(
                    mutated
                )
                self.assertEqual(len(violations), 1, violations)
                self.assertIn("must keep its pinned shape", violations[0])

        # Trailing-comment removal is linear: a long run of blanks with no
        # `#` in candidate input must not backtrack quadratically.
        padded = "x" + " " * 50_000 + "y"
        self.assertEqual(check_supply_chain.policy_workflow_shape(padded), [padded])
        self.assertEqual(
            check_supply_chain.policy_workflow_shape("a: b" + " " * 50_000 + "# c"), ["a: b"]
        )

        # Comments, blank lines and a reviewed commit bump are not shape.
        bumped = workflow.replace(
            "3d3c42e5aac5ba805825da76410c181273ba90b1", "0" * 40
        )
        self.assertNotEqual(bumped, workflow)
        commented = "# A reviewer's note.\n\n" + workflow.replace(
            "    steps:\n", "    steps:\n      # Data only.\n", 1
        )
        for text in (bumped, commented):
            with self.subTest(text=text[:40]):
                self.assertEqual(
                    check_supply_chain.supply_chain_policy_shape_violations(text), []
                )

    def test_trusted_policy_workflow_must_remain_a_regular_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._mirror_repo(Path(directory))
            path = root / check_supply_chain.SUPPLY_CHAIN_POLICY_PATH
            self.assertEqual(
                check_supply_chain.supply_chain_policy_workflow_violations(root), []
            )
            original = path.read_text(encoding="utf-8")
            path.unlink()
            self.assertIn(
                "supply-chain-policy.yml: the trusted supply-chain policy workflow "
                "must remain a regular file",
                self._violations(root),
            )
            target = root / "elsewhere.yml"
            target.write_text(original, encoding="utf-8")
            path.symlink_to(target)
            self.assertEqual(
                len(check_supply_chain.supply_chain_policy_workflow_violations(root)), 1
            )

    # A small workflow in the reader's subset that hostile fixtures mutate.
    SUBSET_WORKFLOW = (
        "name: Fixture\n"
        "on:\n"
        "  pull_request:\n"
        "    types: [opened, synchronize]\n"
        "    branches: [main]\n"
        "permissions:\n"
        "  contents: read\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-24.04\n"
        "    steps:\n"
        "      - run: true\n"
    )

    def _syntax_error(self, text: str) -> str:
        with self.assertRaises(check_supply_chain.WorkflowSyntaxError) as raised:
            check_supply_chain.parse_workflow(text)
        return str(raised.exception)

    def test_every_shipped_workflow_is_in_the_reader_subset(self):
        workflows = sorted((ROOT / ".github/workflows").glob("*.yml"))
        self.assertGreater(len(workflows), 10)
        for path in workflows:
            with self.subTest(workflow=path.name):
                document = check_supply_chain.parse_workflow(
                    path.read_text(encoding="utf-8")
                )
                self.assertIsInstance(document.get("jobs"), dict)
                self.assertIn("on", document)

    def test_the_reader_builds_the_documented_structure(self):
        text = (
            "---\n"
            "# a comment\n"
            "name: Example # trailing comment\n"
            "on:\n"
            "  push:\n"
            "    branches: [main, 'release/*', \"x, y\"]\n"
            "    paths:\n"
            "      - 'src/**'\n"
            "      - docs/x.md\n"
            "  workflow_dispatch:\n"
            "permissions:\n"
            "  contents: read\n"
            "jobs:\n"
            "  build:\n"
            "    name: Build it\n"
            "    needs: []\n"
            "    if: >-\n"
            "      always() &&\n"
            "      success()\n"
            "    steps:\n"
            "      - name: Say ${{ matrix.x }}\n"
            "        uses: actions/checkout@" + "0" * 40 + " # v7\n"
            "        with:\n"
            "          path: out\n"
            "      -\n"
            "        run: |\n"
            "          echo 'a: b' # kept\n"
            "\n"
            "          case \"$x\" in\n"
            "            *) echo \"#!\" ;;\n"
            "          esac\n"
            "      - run: 'it''s'\n"
            "      - run: \"tab\\there \\x41\\u00e9\"\n"
        )
        self.assertEqual(
            check_supply_chain.parse_workflow(text),
            {
                "name": "Example",
                "on": {
                    "push": {
                        "branches": ["main", "release/*", "x, y"],
                        "paths": ["src/**", "docs/x.md"],
                    },
                    "workflow_dispatch": None,
                },
                "permissions": {"contents": "read"},
                "jobs": {
                    "build": {
                        "name": "Build it",
                        "needs": [],
                        "if": "always() && success()",
                        "steps": [
                            {
                                "name": "Say ${{ matrix.x }}",
                                "uses": "actions/checkout@" + "0" * 40,
                                "with": {"path": "out"},
                            },
                            {
                                "run": "echo 'a: b' # kept\n\ncase \"$x\" in\n"
                                "  *) echo \"#!\" ;;\nesac"
                            },
                            {"run": "it's"},
                            {"run": "tab\there Aé"},
                        ],
                    }
                },
            },
        )

    def test_the_reader_refuses_everything_outside_its_subset(self):
        # Every spelling both reviews used to hide a job name or a permission,
        # and every construct the subset leaves out.
        base = self.SUBSET_WORKFLOW
        job = "  build:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: true\n"
        self.assertIn(job, base)
        cases = {
            "indented_root": "".join("  " + line + "\n" for line in base.splitlines()),
            "marker_then_indented_root": "---\n"
            + "".join("  " + line + "\n" for line in base.splitlines()),
            "marker_after_start": base + "---\nname: second\n",
            "end_marker": base + "...\n",
            "directive": "%YAML 1.2\n" + base,
            "byte_order_mark": "﻿" + base,
            "tab_indentation": base.replace("    runs-on", "\truns-on"),
            "tab_in_value": base.replace("ubuntu-24.04", "ubuntu-24.04\t"),
            "vertical_tab": base.replace("# x", "") + "# a\x0bjobs:\n",
            "next_line": base + "# \x85\n",
            "line_separator": base.replace("name: Fixture", "name: Fixture #  x"),
            "paragraph_separator": base + "#  \n",
            "explicit_key": base.replace("  contents: read\n", "  ? checks\n  : write\n"),
            "explicit_flow_key": base.replace(
                "permissions:\n  contents: read\n", "permissions: {? checks : write}\n"
            ),
            "anchored_key": base.replace("  contents: read\n", "  &k checks: write\n"),
            "tagged_key": base.replace("  contents: read\n", "  !!str statuses: write\n"),
            "aliased_key": base.replace("  contents: read\n", "  *k : write\n"),
            "anchored_value": base.replace("ubuntu-24.04", "&os ubuntu-24.04"),
            "aliased_value": base.replace("contents: read", "contents: *level"),
            "tagged_value": base.replace("contents: read", "contents: !!str read"),
            "merge_key": base.replace("    runs-on:", "    <<: *defaults\n    runs-on:"),
            "quoted_key": base.replace("jobs:\n", '"jobs":\n'),
            "single_quoted_key": base.replace("  build:\n", "  'build':\n"),
            "flow_mapping": base.replace(
                "permissions:\n  contents: read\n", "permissions: {contents: read}\n"
            ),
            "flow_job": base.replace(job, "  build: {runs-on: ubuntu-24.04}\n"),
            "flow_top_level": "{jobs: {build: {runs-on: ubuntu-24.04}}}\n",
            "flow_sequence_elsewhere": base.replace(
                "    steps:\n      - run: true\n", "    steps: [{run: 'true'}]\n"
            ),
            "nested_flow_sequence": base.replace("[main]", "[main, [x]]"),
            "flow_mapping_in_sequence": base.replace("[main]", "[{a: b}]"),
            "multi_line_flow_sequence": base.replace("[main]", "[main,\n      dev]"),
            "trailing_flow_comma": base.replace("[main]", "[main, ]"),
            "block_scalar_name": base.replace(
                job, "  build:\n    name: >-\n      trusted-supply-chain-policy\n"
            ),
            "block_scalar_indent_indicator": base.replace(
                "      - run: true\n", "      - run: |2\n          true\n"
            ),
            "block_scalar_item": base.replace("      - run: true\n", "      - |\n        x\n"),
            "next_line_name": base.replace(
                job, "  build:\n    name:\n      trusted-supply-chain-policy\n"
            ),
            "continued_plain": base.replace(
                "    runs-on: ubuntu-24.04\n",
                "    name: build\n      ${{ format('{0}', 'x') }}\n    runs-on: ubuntu-24.04\n",
            ),
            "unterminated_quote": base.replace(
                "    runs-on:", '    name: "build\n      x"\n    runs-on:'
            ),
            "text_after_quote": base.replace("ubuntu-24.04", "'ubuntu'-24.04"),
            "bad_escape": base.replace("ubuntu-24.04", '"ubuntu\\q"'),
            "plain_with_colon": base.replace("ubuntu-24.04", "ubuntu: 24.04"),
            "duplicate_key": base.replace(
                "    runs-on: ubuntu-24.04\n",
                "    runs-on: ubuntu-24.04\n    runs-on: ubuntu-22.04\n",
            ),
            "indentless_sequence": base.replace(
                "    steps:\n      - run: true\n", "    steps:\n    - run: true\n"
            ),
            "nested_compact_sequence": base.replace("      - run: true\n", "      - - true\n"),
            "inconsistent_indentation": base.replace("    steps:", "     steps:"),
            "key_without_space": base.replace("runs-on: ubuntu", "runs-on:ubuntu"),
        }
        for label, text in cases.items():
            with self.subTest(label=label):
                self.assertNotEqual(text, base)
                self._syntax_error(text)
        self.assertIsInstance(check_supply_chain.parse_workflow(base), dict)

    # `echo ok #`, a blank line, then an env-file write. YAML folding keeps the
    # line break around the blank line, so bash runs the write; a reader that
    # joins folded lines with spaces would show the policy one commented line.
    HIDDEN_ENV_WRITE = (
        "      - run: {}\n"
        "          echo ok #\n"
        "\n"
        '          echo "BASH_ENV=/tmp/x" >> "$GITHUB_ENV"\n'
    )

    def test_the_reader_refuses_folded_scalars_except_for_if(self):
        base = self.SUBSET_WORKFLOW
        for header in (">", ">-", ">+", "> # comment"):
            with self.subTest(header=header):
                text = base.replace("      - run: true\n", self.HIDDEN_ENV_WRITE.format(header))
                self.assertNotEqual(text, base)
                self.assertIn("folded block scalar", self._syntax_error(text))
        for key in ("description", "script", "body", "path", "restore-keys", "images", "tags"):
            with self.subTest(key=key):
                text = base.replace(
                    "      - run: true\n",
                    "      - uses: actions/checkout@" + "0" * 40 + "\n"
                    "        with:\n"
                    f"          {key}: >-\n"
                    "            x\n",
                )
                self.assertIn("folded block scalar", self._syntax_error(text))

        # A literal block scalar keeps every line, so the rules read what bash runs.
        literal = base.replace("      - run: true\n", self.HIDDEN_ENV_WRITE.format("|"))
        self.assertEqual(
            check_supply_chain.parse_workflow(literal)["jobs"]["build"]["steps"],
            [{"run": 'echo ok #\n\necho "BASH_ENV=/tmp/x" >> "$GITHUB_ENV"'}],
        )
        # An `if:` expression may still fold: it runs no shell.
        conditional = base.replace(
            "    runs-on: ubuntu-24.04\n",
            "    if: >-\n      always() &&\n      success()\n    runs-on: ubuntu-24.04\n",
        )
        self.assertEqual(
            check_supply_chain.parse_workflow(conditional)["jobs"]["build"]["if"],
            "always() && success()",
        )

    def test_a_folded_run_hiding_an_env_file_write_stops_the_check(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._mirror_repo(Path(directory))
            (root / ".github/workflows/impostor.yml").write_text(
                self.SUBSET_WORKFLOW.replace(
                    "      - run: true\n", self.HIDDEN_ENV_WRITE.format(">")
                ),
                encoding="utf-8",
            )
            violations = self._violations(root)
        self.assertEqual(len(violations), 1, violations)
        self.assertTrue(
            violations[0].startswith(
                ".github/workflows/impostor.yml: workflow is outside the YAML subset"
            ),
            violations,
        )
        self.assertIn("folded block scalar", violations[0])

    def test_workflow_files_must_use_an_exact_yml_or_yaml_extension(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workflows = root / ".github/workflows"
            # A subdirectory holds no workflow GitHub loads.
            (workflows / "nested.YML").mkdir(parents=True)
            for name in ("a.yml", "b.yaml", "c.YML", "d.Yaml", "e.yml.disabled", "README.md"):
                (workflows / name).write_text(self.SUBSET_WORKFLOW, encoding="utf-8")
            self.assertEqual(
                check_supply_chain.workflow_extension_violations(root),
                [
                    f".github/workflows/{name}: a workflow file must end in exactly "
                    "`.yml` or `.yaml`; any other spelling would skip every supply-chain rule"
                    for name in ("README.md", "c.YML", "d.Yaml", "e.yml.disabled")
                ],
            )

    def test_a_case_variant_workflow_extension_stops_the_check(self):
        # The impostor would report the trusted check; under a case-variant
        # extension the case-sensitive glob never hands it to that rule.
        impostor = self.SUBSET_WORKFLOW.replace("  build:\n", "  trusted-supply-chain-policy:\n")
        with tempfile.TemporaryDirectory() as directory:
            root = self._mirror_repo(Path(directory))
            for name in ("impostor.YML", "impostor2.Yaml"):
                (root / ".github/workflows" / name).write_text(impostor, encoding="utf-8")
            violations = self._violations(root)
        self.assertEqual(
            violations,
            [
                f".github/workflows/{name}: a workflow file must end in exactly "
                "`.yml` or `.yaml`; any other spelling would skip every supply-chain rule"
                for name in ("impostor.YML", "impostor2.Yaml")
            ],
        )

    def test_a_workflow_outside_the_subset_stops_the_check(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._mirror_repo(Path(directory))
            (root / ".github/workflows/impostor.yml").write_text(
                "".join(
                    "  " + line + "\n"
                    for line in (
                        "name: x",
                        "on: pull_request",
                        "jobs:",
                        "  a:",
                        "    name: ${{ format('{0}-supply-chain-policy', 'trusted') }}",
                        "    runs-on: ubuntu-24.04",
                    )
                ),
                encoding="utf-8",
            )
            violations = self._violations(root)
        self.assertEqual(len(violations), 1, violations)
        self.assertTrue(
            violations[0].startswith(
                ".github/workflows/impostor.yml: workflow is outside the YAML subset"
            ),
            violations,
        )
        self.assertIn("column 0", violations[0])

    def test_only_the_policy_workflow_may_define_the_trusted_check(self):
        base = self.SUBSET_WORKFLOW
        workflow = ".github/workflows/impostor.yml"

        def rule(text: str, path: str = workflow) -> list[str]:
            return check_supply_chain.policy_check_impersonation_violations(
                path, check_supply_chain.parse_workflow(text)
            )

        self.assertEqual(rule(base), [])
        job = "  build:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: true\n"
        named = "  build:\n    name: {}\n    runs-on: ubuntu-24.04\n"
        computed = "${{ format('{0}-supply-chain-policy', 'trusted') }}"
        defines = "may define the 'trusted-supply-chain-policy' check"
        literal = "a job display name must be a literal"
        cases = {
            "job_key": (base.replace("  build:\n", "  trusted-supply-chain-policy:\n"), defines),
            "upper_case_job_key": (
                base.replace("  build:\n", "  TRUSTED-SUPPLY-CHAIN-POLICY:\n"),
                defines,
            ),
            "job_name": (base.replace(job, named.format("trusted-supply-chain-policy")), defines),
            "quoted_job_name": (
                base.replace(job, named.format("'trusted-supply-chain-policy'")),
                defines,
            ),
            "escaped_job_name": (
                base.replace(job, named.format('"\\x74rusted-supply-chain-policy"')),
                defines,
            ),
            "padded_job_name": (
                base.replace(job, named.format('"  Trusted-Supply-Chain-Policy\\t"')),
                defines,
            ),
            "computed_name": (base.replace(job, named.format(computed)), literal),
            "escaped_expression": (
                base.replace(job, named.format('"\\x24{{ github.event.number }}"')),
                literal,
            ),
            "computed_name_deeper_indent": (
                base.replace(
                    "jobs:\n" + job,
                    "jobs:\n    build:\n"
                    f"        name: {computed}\n"
                    "        runs-on: ubuntu-24.04\n",
                ),
                literal,
            ),
        }
        for label, (text, expected) in cases.items():
            with self.subTest(label=label):
                self.assertNotEqual(text, base)
                violations = rule(text)
                self.assertTrue(any(expected in item for item in violations), violations)

        # Naming the context in a script, a step title or an action input
        # defines no check run.
        allowed = base.replace(
            "      - run: true\n",
            "      - name: Upload ${{ matrix.shard }} trusted-supply-chain-policy\n"
            "        uses: actions/upload-artifact@0000000000000000000000000000000000000000\n"
            "        with:\n"
            "          name: trusted-supply-chain-policy-${{ github.sha }}\n"
            "      - run: |\n"
            "          audit --required-check 'trusted-supply-chain-policy'\n",
        )
        self.assertEqual(rule(allowed), [])
        # The protected workflow itself is the one place the job is defined.
        self.assertEqual(
            rule(cases["job_key"][0], check_supply_chain.SUPPLY_CHAIN_POLICY_PATH), []
        )

    def test_only_a_required_checks_own_job_may_define_it(self):
        base = self.SUBSET_WORKFLOW
        job = "  build:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: true\n"
        named = "  build:\n    name: {}\n    runs-on: ubuntu-24.04\n"
        impostor = ".github/workflows/impostor.yml"

        def rule(text: str, path: str) -> list[str]:
            return check_supply_chain.policy_check_impersonation_violations(
                path, check_supply_chain.parse_workflow(text)
            )

        self.assertEqual(
            check_supply_chain.REQUIRED_CHECK_WORKFLOWS["state-guard-reject-state-edits"],
            ".github/workflows/state-guard.yml",
        )
        for context, home in check_supply_chain.REQUIRED_CHECK_WORKFLOWS.items():
            defines = f"may define the {context!r} check"
            keyed = base.replace("  build:\n", f"  {context}:\n")
            refused = {
                "key_elsewhere": (keyed, impostor),
                "upper_case_key_elsewhere": (
                    base.replace("  build:\n", f"  {context.upper()}:\n"), impostor
                ),
                "upper_case_key_at_home": (
                    base.replace("  build:\n", f"  {context.upper()}:\n"), home
                ),
                "name_elsewhere": (base.replace(job, named.format(context)), impostor),
                # Another job of the home workflow named like the context.
                "name_at_home": (base.replace(job, named.format(context)), home),
                "padded_name_at_home": (
                    base.replace(job, named.format(f"'  {context.upper()} '")), home
                ),
            }
            for label, (text, path) in refused.items():
                with self.subTest(context=context, label=label):
                    self.assertNotEqual(text, base)
                    violations = rule(text, path)
                    self.assertTrue(any(defines in item for item in violations), violations)
            with self.subTest(context=context, label="own_job"):
                self.assertEqual(rule(keyed, home), [])
                self.assertEqual(
                    rule(
                        keyed.replace(
                            f"  {context}:\n", f"  {context}:\n    name: {context}\n", 1
                        ),
                        home,
                    ),
                    [],
                )

    def test_required_check_homes_match_the_ruleset_and_the_shipped_jobs(self):
        # The ruleset contexts the bootstrap writes; the checker cannot import
        # them from the tree it judges, so this keeps the copies equal.
        path = ROOT / ".github/scripts/audit_settings.py"
        spec = importlib.util.spec_from_file_location("audit_settings_required_checks", path)
        audit_settings = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = audit_settings
        spec.loader.exec_module(audit_settings)
        self.assertEqual(
            set(check_supply_chain.REQUIRED_CHECK_WORKFLOWS),
            set(audit_settings.REQUIRED_STATUS_CHECKS),
        )
        for context, home in check_supply_chain.REQUIRED_CHECK_WORKFLOWS.items():
            with self.subTest(context=context):
                document = check_supply_chain.parse_workflow(
                    (ROOT / home).read_text(encoding="utf-8")
                )
                self.assertIn(context, document["jobs"])
                self.assertEqual(
                    check_supply_chain.policy_check_impersonation_violations(home, document),
                    [],
                )

    def test_a_state_guard_impostor_is_refused_by_the_trusted_checker(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._mirror_repo(Path(directory))
            (root / ".github/workflows/impostor.yml").write_text(
                self.SUBSET_WORKFLOW.replace(
                    "  build:\n", "  state-guard-reject-state-edits:\n"
                ),
                encoding="utf-8",
            )
            violations = self._violations(root)
        self.assertIn(
            ".github/workflows/impostor.yml: job 'state-guard-reject-state-edits': only job "
            "'state-guard-reject-state-edits' of state-guard.yml may define the "
            "'state-guard-reject-state-edits' check",
            violations,
        )

    def test_no_workflow_may_write_check_runs_or_commit_statuses(self):
        base = self.SUBSET_WORKFLOW
        workflow = ".github/workflows/w.yml"

        def rule(text: str) -> list[str]:
            return check_supply_chain.status_write_permission_violations(
                workflow, check_supply_chain.parse_workflow(text)
            )

        self.assertEqual(rule(base), [])
        refused = {
            "checks": base.replace("  contents: read\n", "  contents: read\n  checks: write\n"),
            "statuses": base.replace(
                "  contents: read\n", "  contents: read\n  statuses: write\n"
            ),
            "quoted_level": base.replace(
                "  contents: read\n", "  contents: read\n  statuses: 'write'\n"
            ),
            "upper_case": base.replace("  contents: read\n", "  contents: read\n  Checks: WRITE\n"),
            "write_all": base.replace("permissions:\n  contents: read\n", "permissions: write-all\n"),
            "bare_write": base.replace("permissions:\n  contents: read\n", "permissions: write\n"),
            "job_level": base.replace(
                "    runs-on: ubuntu-24.04\n",
                "    permissions:\n      checks: write\n    runs-on: ubuntu-24.04\n",
            ),
            "empty_level": base.replace("  contents: read\n", "  contents: read\n  checks:\n"),
        }
        for label, text in refused.items():
            with self.subTest(label=label):
                self.assertNotEqual(text, base)
                self.assertTrue(rule(text))
        for permission in ("  checks: read\n", "  statuses: none\n"):
            text = base.replace("  contents: read\n", "  contents: read\n" + permission)
            self.assertEqual(rule(text), [])
        self.assertEqual(
            rule(base.replace("permissions:\n  contents: read\n", "permissions: read-all\n")),
            [],
        )
        # The spellings that hid a grant from the round-2 scanner are not in
        # the subset at all, so they never reach this rule.
        for spelling in (
            "  ? checks\n  : write\n",
            "  &k checks: write\n",
            "  !!str statuses: write\n",
            "  *k : write\n",
            "  checks: *grant\n",
            "  statuses: &grant write\n",
        ):
            with self.subTest(spelling=spelling):
                self._syntax_error(base.replace("  contents: read\n", spelling))
        self._syntax_error(
            base.replace("permissions:\n  contents: read\n", "permissions: {checks: write}\n")
        )
        with tempfile.TemporaryDirectory() as directory:
            root = self._mirror_repo(Path(directory))
            path = root / ".github/workflows/rust-ci.yml"
            text = path.read_text(encoding="utf-8")
            self.assertEqual(text.count("permissions:\n  contents: read\n"), 1)
            path.write_text(
                text.replace(
                    "permissions:\n  contents: read\n",
                    "permissions:\n  contents: read\n  statuses: write\n",
                ),
                encoding="utf-8",
            )
            violations = self._violations(root)
        self.assertTrue(
            any(item.startswith(".github/workflows/rust-ci.yml: statuses") for item in violations),
            violations,
        )

    def test_links_out_of_the_tree_and_special_files_stop_the_check(self):
        # The policy job puts the protected checkout at `base/` beside
        # `candidate/`. A link from the candidate into `base/` would show the
        # check protected files while every other workflow, running the tree
        # at the workspace root, reads the pull request's own copy.
        def run(candidate: Path) -> subprocess.CompletedProcess:
            return subprocess.run(
                [sys.executable, str(SCRIPT), "--root", str(candidate)],
                check=False,
                text=True,
                capture_output=True,
                timeout=120,
            )

        layouts = {
            "absolute_scripts_dir": lambda workspace, candidate: (
                shutil.rmtree(candidate / ".github/scripts"),
                (candidate / ".github/scripts").symlink_to(
                    workspace / "base/.github/scripts", target_is_directory=True
                ),
                ".github/scripts: symlink leaves the tree under review",
            )[-1],
            "relative_escape": lambda workspace, candidate: (
                shutil.rmtree(candidate / ".github/scripts"),
                (candidate / ".github/scripts").symlink_to(
                    "../../base/.github/scripts", target_is_directory=True
                ),
                ".github/scripts: symlink leaves the tree under review",
            )[-1],
            "absolute_inside": lambda workspace, candidate: (
                (candidate / "Dockerfile").unlink(),
                (candidate / "Dockerfile").symlink_to(candidate / ".dockerignore"),
                "Dockerfile: symlink leaves the tree under review",
            )[-1],
            "nested_escape": lambda workspace, candidate: (
                (candidate / "src/link").symlink_to("../../base"),
                "src/link: symlink leaves the tree under review",
            )[-1],
            "device": lambda workspace, candidate: (
                (candidate / "rust-toolchain.toml").unlink(),
                (candidate / "rust-toolchain.toml").symlink_to("/dev/zero"),
                "rust-toolchain.toml: symlink leaves the tree under review",
            )[-1],
            "fifo": lambda workspace, candidate: (
                (candidate / "rust-toolchain.toml").unlink(),
                os.mkfifo(candidate / "rust-toolchain.toml"),
                "rust-toolchain.toml: only regular files, directories and in-tree "
                "symlinks may be reviewed",
            )[-1],
            "dangling": lambda workspace, candidate: (
                (candidate / "missing").symlink_to("nowhere"),
                "missing: symlink does not resolve",
            )[-1],
            # Climbs out and comes back in through this layout's directory
            # name. Run at the workspace root, the same text names a path
            # that does not exist, so it is refused by its text.
            "reentry": lambda workspace, candidate: (
                (candidate / "x").write_text(".git\n", encoding="utf-8"),
                (candidate / ".dockerignore").unlink(),
                (candidate / ".dockerignore").symlink_to("../candidate/x"),
                ".dockerignore: symlink leaves the tree under review",
            )[-1],
            # The same re-entry one hop longer: `d` points back at the root,
            # so the kernel takes `d/..` above it while the text reads as
            # `a/b/candidate/di`. A target may not pass through another link.
            "reentry_through_link": lambda workspace, candidate: (
                (candidate / "a/b").mkdir(parents=True),
                (candidate / "a/b/d").symlink_to("../..", target_is_directory=True),
                (candidate / "di").write_text(".git\n", encoding="utf-8"),
                (candidate / ".dockerignore").unlink(),
                (candidate / ".dockerignore").symlink_to("a/b/d/../candidate/di"),
                ".dockerignore: symlink target passes through another symlink (a/b/d)",
            )[-1],
        }
        for label, arrange in layouts.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                workspace = Path(directory)
                self._mirror_repo(workspace / "base")
                candidate = self._mirror_repo(workspace / "candidate")
                expected = arrange(workspace, candidate)
                result = run(candidate)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn(expected, result.stderr)
                # Nothing else is judged once the tree itself is refused.
                self.assertNotIn("must refresh the protected branch", result.stderr)

        # Links that stay inside the tree are fine, and `.git` is not judged.
        with tempfile.TemporaryDirectory() as directory:
            candidate = self._mirror_repo(Path(directory))
            (candidate / "AGENTS.md").symlink_to(".github/CODEOWNERS")
            (candidate / "docs").mkdir()
            (candidate / "docs/workflows").symlink_to(
                "../.github/workflows", target_is_directory=True
            )
            (candidate / ".git").mkdir()
            (candidate / ".git/elsewhere").symlink_to("/dev/null")
            self.assertEqual(check_supply_chain.candidate_tree_violations(candidate), [])
            result = run(candidate)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

        # The root is judged as given: a root that is itself a link is refused.
        with tempfile.TemporaryDirectory() as directory:
            candidate = self._mirror_repo(Path(directory) / "real")
            link = Path(directory) / "candidate"
            link.symlink_to(candidate, target_is_directory=True)
            self.assertEqual(len(check_supply_chain.candidate_tree_violations(link)), 1)
            result = run(link)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("the tree under review must be a real directory", result.stderr)

    def test_an_impostor_policy_job_fails_the_whole_tree(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._mirror_repo(Path(directory))
            (root / ".github/workflows/impostor.yml").write_text(
                "name: GitForgeOps Supply-Chain Policy\n"
                "on:\n"
                "  pull_request:\n"
                "    types: [opened, synchronize, reopened, edited]\n"
                "    branches: [main]\n"
                "permissions:\n"
                "  contents: read\n"
                "jobs:\n"
                "  trusted-supply-chain-policy:\n"
                "    runs-on: ubuntu-24.04\n"
                "    steps:\n"
                "      - run: exit 0\n",
                encoding="utf-8",
            )
            violations = self._violations(root)
        self.assertTrue(
            any(
                item.startswith(
                    ".github/workflows/impostor.yml: job 'trusted-supply-chain-policy': "
                    "only job 'trusted-supply-chain-policy' of supply-chain-policy.yml"
                )
                for item in violations
            ),
            violations,
        )

    def test_shipped_policy_invocation_judges_candidate_data_only(self):
        # Run the workflow's exact command from a workspace holding the
        # protected checker under `base/` and the candidate under
        # `candidate/`, with hostile modules planted wherever a candidate (or
        # a careless runner) could put them. The trusted checker still runs
        # and still rejects a real violation.
        workflow = (ROOT / check_supply_chain.SUPPLY_CHAIN_POLICY_PATH).read_text(
            encoding="utf-8"
        )
        invocation = check_supply_chain.SUPPLY_CHAIN_POLICY_INVOCATION
        self.assertIn(f"        run: {invocation}\n", workflow)
        argv = shlex.split(invocation)
        self.assertEqual(argv[:2], ["python3", "-I"])
        hostile = "import os\nprint('shadowed', flush=True)\nos._exit(0)\n"
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            checker = workspace / "base/.github/scripts/check_supply_chain.py"
            checker.parent.mkdir(parents=True)
            shutil.copy2(SCRIPT, checker)
            candidate = self._mirror_repo(workspace / "candidate")
            for folder in (workspace, candidate, candidate / ".github/scripts"):
                for module in ("pathlib.py", "argparse.py", "json.py", "re.py"):
                    (folder / module).write_text(hostile, encoding="utf-8")

            def run() -> subprocess.CompletedProcess:
                return subprocess.run(
                    [sys.executable, *argv[1:]],
                    cwd=str(workspace),
                    check=False,
                    text=True,
                    capture_output=True,
                )

            clean = run()
            path = candidate / ".github/workflows/rotate.yml"
            text = path.read_text(encoding="utf-8")
            start = text.index(
                "      - name: Refresh protected branch and reject stale deployments"
            )
            end = text.index("      - name: ", start + 20)
            path.write_text(text[:start] + text[end:], encoding="utf-8")
            stale = run()
        self.assertEqual(clean.returncode, 0, clean.stdout + clean.stderr)
        self.assertNotIn("shadowed", clean.stdout)
        self.assertEqual(stale.returncode, 1, stale.stdout + stale.stderr)
        self.assertNotIn("shadowed", stale.stdout)
        self.assertIn("must refresh the protected branch", stale.stderr)

    def test_rotation_guard_tells_the_operator_to_redispatch(self):
        # The trigger-pinned classifier's refusal is worded for apply. A
        # rotation is never rescheduled by an apply, so the guard says so first,
        # without splitting the binding or touching shell options.
        workflow = (ROOT / ".github/workflows/rotate.yml").read_text(encoding="utf-8")
        guard = check_supply_chain.named_step(
            workflow, check_supply_chain.FRESH_HEAD_STEP
        )
        self.assertIsNotNone(guard)
        notice = next(
            line
            for line in guard.splitlines()
            if "::notice::" in line and not line.lstrip().startswith("#")
        )
        self.assertIn("dispatch the rotation again from the current head", notice)
        self.assertIn("README.md#a-superseded-rotation", notice)
        self.assertIsNone(check_supply_chain.SHELL_OPTION_COMMAND.search(notice))
        self.assertLess(guard.index(notice), guard.index(STDIN_CLASSIFIER))
        self.assertEqual(
            check_supply_chain.stale_deployment_guard_violations(
                "rotate.yml", workflow, check_supply_chain.FRESH_HEAD_WORKFLOWS["rotate.yml"]
            ),
            [],
        )

    def test_pr_trigger_must_rerun_on_retarget_and_target_main(self):
        secure = """on:
  pull_request:
    types: [opened, synchronize, reopened, edited]
    branches: [main]
"""
        self.assertEqual(
            check_supply_chain.pull_request_trigger_violations("secure.yml", secure),
            [],
        )
        insecure = """on:
  pull_request:
    types: [opened, synchronize, reopened]
    branches: ['**']
"""
        violations = check_supply_chain.pull_request_trigger_violations(
            "insecure.yml", insecure
        )
        self.assertTrue(any("base-retarget" in item for item in violations))
        self.assertTrue(any("protected main" in item for item in violations))

    def test_workflow_display_names_are_exact_contracts(self):
        self.assertEqual(
            check_supply_chain.workflow_name_violations(
                "validate-pr.yml",
                "name: GitForgeOps PR Static Validation\non: pull_request\n",
                "GitForgeOps PR Static Validation",
            ),
            [],
        )
        violations = check_supply_chain.workflow_name_violations(
            "validate-pr.yml",
            "name: Renamed\non: pull_request\n",
            "GitForgeOps PR Static Validation",
        )
        self.assertTrue(any("must remain exactly" in item for item in violations))

    def test_validator_token_must_be_scoped_to_the_installer_step(self):
        secure = """      - name: Download validator
        env:
          GITHUB_TOKEN: ${{ github.token }}
        run: .github/scripts/install-ferrum-edge.sh
      - name: Post review
        env:
          GITHUB_TOKEN: ${{ github.token }}
"""
        self.assertEqual(
            check_supply_chain.installer_step_auth_violations(
                "trusted-pr-review.yml", secure
            ),
            [],
        )
        insecure = secure.replace(
            "          GITHUB_TOKEN: ${{ github.token }}\n", "", 1
        )
        violations = check_supply_chain.installer_step_auth_violations(
            "trusted-pr-review.yml", insecure
        )
        self.assertTrue(any("every validator download step" in item for item in violations))

    def test_validate_pr_uses_trusted_installer_with_candidate_allowlist(self):
        workflow = (ROOT / ".github/workflows/validate-pr.yml").read_text(
            encoding="utf-8"
        )
        self.assertEqual(
            check_supply_chain.untrusted_pr_installer_violations(workflow), []
        )

        # Running the candidate's own installer is what hands a PR-authored
        # script the job's GITHUB_TOKEN.
        insecure = workflow.replace(
            "bash trusted-validator/.github/scripts/install-ferrum-edge.sh",
            "bash .github/scripts/install-ferrum-edge.sh",
            1,
        )
        violations = check_supply_chain.untrusted_pr_installer_violations(insecure)
        self.assertTrue(
            any("must not receive the GitHub token" in item for item in violations),
            violations,
        )

        # Dropping the trusted checkout must be caught even if the invocation
        # still names the trusted path.
        without_checkout = workflow.replace(
            "      - name: Check out trusted validator installer\n", "", 1
        )
        violations = check_supply_chain.untrusted_pr_installer_violations(
            without_checkout
        )
        self.assertTrue(
            any("protected default-branch checkout" in item for item in violations),
            violations,
        )

    def test_validate_pr_installer_allowlist_argument_is_the_candidate_copy(self):
        # A pin-refresh PR has to be validated against the allowlist it adds,
        # so the second positional must be the candidate's file. A prose
        # mention of the allowlist in a comment must not satisfy the policy.
        workflow = (ROOT / ".github/workflows/validate-pr.yml").read_text(
            encoding="utf-8"
        )
        for swapped in (
            workflow.replace(
                "            .github/ferrum-edge-checksums.txt\n",
                "            trusted-validator/.github/ferrum-edge-checksums.txt\n",
                1,
            ),
            workflow.replace(
                " \\\n            \"$RUNNER_TEMP/gitforgeops-validator-bin/ferrum-edge\" \\\n"
                "            .github/ferrum-edge-checksums.txt\n",
                "\n",
                1,
            ),
        ):
            self.assertNotEqual(workflow, swapped, "test fixture did not rewrite")
            violations = check_supply_chain.untrusted_pr_installer_violations(swapped)
            self.assertTrue(
                any(
                    "reviewed digest allowlist as its second argument" in item
                    for item in violations
                ),
                violations,
            )

    def test_each_validator_job_requires_the_trusted_probe_and_checkout(self):
        workflow = (ROOT / ".github/workflows/validate-pr.yml").read_text()
        self.assertEqual(check_supply_chain.trusted_validator_probe_violations(workflow), [])
        for job_name in ("validate", "validator-pairing"):
            job = check_supply_chain.workflow_job(workflow, job_name)
            for old, new in (
                ("bash trusted-validator/.github/scripts/check-validator-resource-labels.sh",
                 "bash .github/scripts/check-validator-resource-labels.sh"),
                ("bash trusted-validator/.github/scripts/check-validator-resource-labels.sh",
                 "# bash trusted-validator/.github/scripts/check-validator-resource-labels.sh"),
                ("      - name: Require resource-label compatibility\n",
                 "      - name: Require resource-label compatibility\n        if: false\n"),
                ("      - name: Require resource-label compatibility\n",
                 "      - name: Require resource-label compatibility\n        continue-on-error: true\n"),
                ("      - name: Require resource-label compatibility\n",
                 "      - name: Require resource-label compatibility\n"
                 "        env:\n          GITHUB_TOKEN: ${{ github.token }}\n"),
                ("ref: ${{ github.event.repository.default_branch }}",
                 "ref: ${{ github.event.pull_request.head.sha }}"),
                ("path: trusted-validator", "path: candidate-validator"),
                ("            .github/ferrum-edge-checksums.txt\n",
                 "            trusted-validator/.github/ferrum-edge-checksums.txt\n"),
                ('            "$RUNNER_TEMP/gitforgeops-validator-bin/ferrum-edge"\n',
                 '            "$RUNNER_TEMP/gitforgeops-validator-bin/ferrum-edge" || true\n'),
            ):
                with self.subTest(job=job_name, new=new):
                    changed_job = job.replace(old, new, 1)
                    self.assertNotEqual(changed_job, job)
                    changed = workflow.replace(job, changed_job, 1)
                    violations = check_supply_chain.trusted_validator_probe_violations(changed)
                    self.assertTrue(
                        any(f": {job_name} " in item for item in violations), violations
                    )

    def test_validator_pairing_stays_fast_and_free_of_alloy_qualification(self):
        # The required pairing job installs and probes the validator only.
        # External producer builds belong to the non-required workflow below.
        document = check_supply_chain.parse_workflow(
            (ROOT / ".github/workflows/validate-pr.yml").read_text()
        )
        job = document["jobs"]["validator-pairing"]
        self.assertEqual(job["timeout-minutes"], "10")
        self.assertEqual(
            [step.get("name") for step in job["steps"]],
            [
                None,
                "Check out trusted pairing installer",
                "Download pairing validator",
                "Require resource-label compatibility",
            ],
        )
        self.assertEqual(
            {step["uses"].split("@", 1)[0] for step in job["steps"] if "uses" in step},
            {"actions/checkout"},
        )

    def test_alloy_consumer_qualification_is_isolated_and_not_required(self):
        workflow_path = ".github/workflows/alloy-consumer.yml"
        workflow = (ROOT / workflow_path).read_text()
        document = check_supply_chain.parse_workflow(workflow)
        provenance = json.loads(
            (ROOT / "tests/fixtures/alloy-producer/PROVENANCE.json").read_text()
        )

        # Not a required context, and never spelled like one.
        self.assertEqual(list(document["jobs"]), ["alloy-consumer-qualification"])
        self.assertNotIn(workflow_path, check_supply_chain.REQUIRED_CHECK_WORKFLOWS.values())
        self.assertEqual(
            check_supply_chain.policy_check_impersonation_violations(workflow_path, document), []
        )

        # Runs when the consumer surface changes, weekly and on demand.
        triggers = document["on"]
        self.assertEqual(set(triggers), {"pull_request", "schedule", "workflow_dispatch"})
        self.assertEqual(
            check_supply_chain.pull_request_trigger_violations(workflow_path, workflow), []
        )
        self.assertEqual(triggers["pull_request"]["branches"], ["main"])
        # Everything the consumer test exercises, compared exactly so a path
        # cannot be dropped silently.
        self.assertEqual(
            triggers["pull_request"]["paths"],
            [
                workflow_path,
                ".github/ferrum-edge-checksums.txt",
                "tests/fixtures/alloy-producer/**",
                "tests/unit/companion_schema_tests.rs",
                "tests/unit/mod.rs",
                "tests/unit_tests.rs",
                "src/main.rs",
                "src/cli.rs",
                "src/lib.rs",
                "src/error.rs",
                "src/diagnostics.rs",
                "src/config/**",
                "src/validate/**",
                "src/apply/**",
                "src/secrets/**",
                "build.rs",
                ".cargo/**",
                "Cargo.toml",
                "Cargo.lock",
                "rust-toolchain.toml",
            ],
        )
        self.assertEqual(len(triggers["schedule"]), 1)
        self.assertIn("cron", triggers["schedule"][0])

        # It builds PR code and an external repository: read-only, no
        # Environment, no secrets, no cache, token only for the installer.
        job = document["jobs"]["alloy-consumer-qualification"]
        self.assertEqual(document["permissions"], {"contents": "read"})
        self.assertEqual(job["permissions"], {"contents": "read"})
        for scope in (document, job):
            self.assertNotIn("environment", scope)
            self.assertNotIn("env", scope)
        # The check is not required, so reviewers rely on its color: no
        # condition or error tolerance may let it go green without running.
        self.assertNotIn("if", job)
        self.assertNotIn("continue-on-error", job)
        # No secret reaches the job: no expression reads the secrets context,
        # named or whole, and no key passes secrets on (`secrets: inherit` or
        # a mapping). The word alone is not exposure: `src/secrets/**` is a
        # path filter.
        for expression in check_supply_chain.EXPRESSION.finditer(workflow):
            self.assertIsNone(
                check_supply_chain.WHOLE_SECRETS.search(expression.group(1)),
                expression.group(0),
            )
        self.assertEqual(check_supply_chain.whole_secrets_context_violations(workflow_path, workflow), [])

        def secret_keys(node, path=()):
            if isinstance(node, dict):
                for key, value in node.items():
                    if check_supply_chain.WHOLE_SECRETS.fullmatch(str(key).strip()):
                        yield path + (key,)
                    yield from secret_keys(value, path + (key,))
            elif isinstance(node, list):
                for index, item in enumerate(node):
                    yield from secret_keys(item, path + (index,))

        self.assertEqual(list(secret_keys(document)), [])
        self.assertIsNone(re.search(r"^\s*-?\s*secrets\s*:", workflow, re.MULTILINE | re.IGNORECASE))
        self.assertEqual(check_supply_chain.installer_step_auth_violations(workflow_path, workflow), [])
        self.assertEqual(check_supply_chain.validator_locator_violations([workflow]), [])
        self.assertEqual(check_supply_chain.status_write_permission_violations(workflow_path, document), [])
        self.assertEqual(check_supply_chain.probe_consumer_binding_violations(workflow_path, document), [])
        steps = {step.get("name"): step for step in job["steps"]}
        installer = "Download verified ferrum-edge validator"
        for step in job["steps"]:
            self.assertNotIn("if", step)
            self.assertNotIn("continue-on-error", step)
            self.assertNotEqual(step.get("uses", "").split("@", 1)[0], "actions/cache")
            if step.get("uses", "").startswith("actions/checkout@"):
                self.assertEqual(step["with"]["persist-credentials"], "false")
            if step.get("name") != installer:
                self.assertNotIn("github.token", json.dumps(step))

        # Trusted installer code, candidate allowlist, as in validate-pr.yml.
        trusted = steps["Check out trusted validator installer"]
        self.assertEqual(
            trusted["with"],
            {
                "ref": "${{ github.event.repository.default_branch }}",
                "path": "trusted-validator",
                "persist-credentials": "false",
            },
        )
        install = steps[installer]
        self.assertEqual(install["env"], {"GITHUB_TOKEN": "${{ github.token }}"})
        argv = shlex.split(install["run"].replace("\\\n", " "))
        self.assertEqual(
            argv,
            [
                "bash",
                "trusted-validator/.github/scripts/install-ferrum-edge.sh",
                "$RUNNER_TEMP/gitforgeops-validator-bin/ferrum-edge",
                ".github/ferrum-edge-checksums.txt",
            ],
        )

        # The producer checkout is the full SHA recorded in PROVENANCE.json.
        producer = steps["Check out pinned Alloy producer"]
        self.assertRegex(provenance["commit"], r"^[0-9a-f]{40}$")
        self.assertEqual(
            producer["with"],
            {
                "repository": provenance["repository"],
                "ref": provenance["commit"],
                "path": "alloy-producer",
                "persist-credentials": "false",
            },
        )

        # Every recorded producer input is generated, from the pinned checkout.
        generate = steps["Generate Alloy GitForgeOps fixture trees"]
        loop = re.search(r"^for fixture in ([^;]+); do$", generate["run"], re.MULTILINE)
        self.assertIsNotNone(loop)
        self.assertEqual(
            loop.group(1).split(),
            [Path(path).stem for path in provenance["fixture_inputs"]],
        )
        for path in provenance["fixture_inputs"]:
            directory = Path(path).parent.as_posix()
            self.assertIn(f"alloy-producer/{directory}/${{fixture}}.toml", generate["run"])

        # The qualification binds the generated trees and the installed
        # validator, and runs exactly the selected ignored test.
        qualify = steps["Require generated Alloy consumer qualification"]
        self.assertEqual(
            qualify["env"],
            {
                "GITFORGEOPS_ALLOY_FIXTURE_ROOT": "${{ runner.temp }}/alloy-generated",
                "GITFORGEOPS_ALLOY_VALIDATOR": argv[2].replace(
                    "$RUNNER_TEMP", "${{ runner.temp }}"
                ),
            },
        )
        # Logical shell lines: continuations joined, whitespace collapsed.
        lines = [
            " ".join(line.split())
            for line in qualify["run"].replace("\\\n", " ").splitlines()
        ]
        test_name = next(line for line in lines if line.startswith("test_name="))
        self.assertTrue(
            test_name.endswith("::alloy_generated_resources_load_assemble_and_validate")
        )
        cargo_tests = [
            shlex.split(line.split("=", 1)[-1].strip("$()"))
            for line in lines
            if "cargo test" in line and not line.startswith("#")
        ]
        self.assertEqual(len(cargo_tests), 2)
        for command in cargo_tests:
            self.assertIn("$test_name", command)
            self.assertIn("--ignored", command)
            self.assertIn("--exact", command)
        self.assertIn("--list", cargo_tests[0])
        self.assertNotIn("--list", cargo_tests[1])

        # Disposable TLS material: private umask, claim a fresh directory,
        # clean up every file on exit, and only then write keys.
        tls_files = [
            f"/etc/ferrum/{name}"
            for name in (
                "edge-client.pem",
                "edge-client.key",
                "alloy-ca.pem",
                "alloy-ca.key",
                "edge-client.csr",
            )
        ]
        umask = lines.index("umask 077")
        cleanup = lines.index("cleanup_tls() {")
        self.assertEqual(
            lines[cleanup : cleanup + 4],
            [
                "cleanup_tls() {",
                "sudo rm -f -- " + " ".join(tls_files),
                "sudo rmdir -- /etc/ferrum",
                "}",
            ],
        )
        mkdir = lines.index("sudo mkdir --mode=0700 /etc/ferrum")
        trap = lines.index("trap cleanup_tls EXIT")
        chown = lines.index('sudo chown "$(id -u):$(id -g)" /etc/ferrum')
        openssl = [i for i, line in enumerate(lines) if line.startswith("openssl ")]
        self.assertEqual(len(openssl), 4)
        self.assertTrue(all(lines[i].endswith(">/dev/null 2>&1") for i in openssl))
        self.assertEqual(qualify["run"].count(">/dev/null 2>&1"), 4)
        chmods = [i for i, line in enumerate(lines) if line.startswith("chmod")]
        self.assertEqual(len(chmods), 1)
        chmod = lines[chmods[0]].split()
        self.assertEqual(chmod[:2], ["chmod", "0600"])
        self.assertEqual(sorted(chmod[2:]), sorted(tls_files))
        verify = next(i for i in openssl if lines[i].startswith("openssl verify "))
        self.assertEqual(verify, openssl[-1])
        self.assertLess(umask, cleanup)
        self.assertLess(cleanup, mkdir)
        self.assertLess(mkdir, trap)
        self.assertLess(trap, chown)
        self.assertLess(chown, openssl[0])
        self.assertLess(openssl[-2], chmods[0])
        self.assertLess(chmods[0], verify)
        self.assertLess(verify, lines.index(test_name))
        self.assertFalse(any("mkdir -p" in line for line in lines))

        order = [step.get("name") for step in job["steps"]]
        self.assertLess(order.index(trusted["name"]), order.index(installer))
        self.assertLess(order.index(installer), order.index(producer["name"]))
        self.assertLess(order.index(producer["name"]), order.index(generate["name"]))
        self.assertLess(order.index(generate["name"]), order.index(qualify["name"]))

    def test_validator_probe_cannot_be_missing_duplicated_or_run_before_install(self):
        workflow = (ROOT / ".github/workflows/validate-pr.yml").read_text()
        probe = (
            "      - name: Require resource-label compatibility\n"
            "        run: |\n"
            "          bash trusted-validator/.github/scripts/check-validator-resource-labels.sh \\\n"
            '            "$RUNNER_TEMP/gitforgeops-validator-bin/ferrum-edge"\n'
        )
        for job_name, install_name in (
            ("validate", "Download verified ferrum-edge binary"),
            ("validator-pairing", "Download pairing validator"),
        ):
            job = check_supply_chain.workflow_job(workflow, job_name)
            self.assertIn(probe, job)
            for changed in (
                job.replace(probe, "", 1),
                job.replace(probe, probe + probe, 1),
                job.replace(probe, "", 1).replace(
                    f"      - name: {install_name}\n",
                    probe + f"      - name: {install_name}\n", 1,
                ),
            ):
                with self.subTest(job=job_name, changed=changed):
                    self.assertTrue(check_supply_chain.trusted_validator_probe_violations(
                        workflow.replace(job, changed, 1)
                    ))

    def test_candidate_probe_and_checker_cannot_approve_themselves(self):
        for job_name in ("validate", "validator-pairing"):
            with self.subTest(job=job_name), tempfile.TemporaryDirectory() as temporary:
                root = self._mirror_repo(Path(temporary))
                path = root / ".github/workflows/validate-pr.yml"
                workflow = path.read_text()
                job = check_supply_chain.workflow_job(workflow, job_name)
                changed = job.replace(
                    "bash trusted-validator/.github/scripts/check-validator-resource-labels.sh",
                    "bash .github/scripts/check-validator-resource-labels.sh",
                    1,
                )
                path.write_text(workflow.replace(job, changed, 1))
                (root / ".github/scripts/check-validator-resource-labels.sh").write_text(
                    "#!/bin/sh\nexit 0\n"
                )
                (root / ".github/ferrum-edge-checksums.txt").write_text(
                    "f" * 64 + "  ferrum-edge-linux-x86_64\n"
                )
                (root / ".github/scripts/check_supply_chain.py").write_text(
                    "raise SystemExit(0)\n"
                )
                # _violations executes SCRIPT outside the candidate root, as
                # the protected-branch workflow does. Candidate code is data.
                self.assertIn(
                    f"validate-pr.yml: {job_name} must run the trusted resource-label probe "
                    "without a bypass or token",
                    self._violations(root),
                )

    def test_candidate_branch_classifier_fails_even_when_trusted_text_remains(self):
        text = """
ref: ${{ github.event.repository.default_branch }}
result=$(python3 trusted-scope/.github/scripts/changed_files.py
result=$(python3 .github/scripts/changed_files.py
"""
        violations = check_supply_chain.trusted_classifier_violations(
            "rust-ci.yml",
            text,
            "result=$(python3 trusted-scope/.github/scripts/changed_files.py",
            1,
        )
        self.assertTrue(any("candidate-branch" in item for item in violations))

    def test_missing_default_branch_checkout_fails(self):
        violations = check_supply_chain.trusted_classifier_violations(
            "validate-pr.yml",
            "result=$(python3 trusted-scope/.github/scripts/changed_files.py",
            "result=$(python3 trusted-scope/.github/scripts/changed_files.py",
            1,
        )
        self.assertTrue(any("default branch" in item for item in violations))

    def test_unprotected_pr_base_cannot_supply_trusted_classifier(self):
        text = """
ref: ${{ github.event.repository.default_branch }}
ref: ${{ github.event.pull_request.base.sha }}
result=$(python3 trusted-scope/.github/scripts/changed_files.py
result='{"complete":false,"matches":true}'
"""
        violations = check_supply_chain.trusted_classifier_violations(
            "validate-pr.yml",
            text,
            "result=$(python3 trusted-scope/.github/scripts/changed_files.py",
            1,
        )
        self.assertTrue(any("unprotected PR base" in item for item in violations))

    def test_missing_trusted_helper_must_run_the_gate_fail_safe(self):
        text = """
ref: ${{ github.event.repository.default_branch }}
result=$(python3 trusted-scope/.github/scripts/changed_files.py
"""
        violations = check_supply_chain.trusted_classifier_violations(
            "validate-pr.yml",
            text,
            "result=$(python3 trusted-scope/.github/scripts/changed_files.py",
            1,
        )
        self.assertTrue(any("bootstrap fail-safe" in item for item in violations))

        secure = text + "\nresult='{\"complete\":false,\"matches\":true}'\n"
        self.assertEqual(
            check_supply_chain.trusted_classifier_violations(
                "validate-pr.yml",
                secure,
                "result=$(python3 trusted-scope/.github/scripts/changed_files.py",
                1,
            ),
            [],
        )

    def test_digest_allowlist_accepts_multiple_commented_builds(self):
        text = (
            "# Reviewed SHA-256 allowlist.\n"
            "\n"
            + "a" * 64
            + "  ferrum-edge-linux-x86_64  # 2026-08-01T00:00:00Z release latest\n"
            + "b" * 64
            + "  ferrum-edge-linux-x86_64  # 2026-09-02T03:02:29Z release latest\n"
        )
        self.assertEqual(check_supply_chain.digest_allowlist_violations(text), [])
        self.assertEqual(
            check_supply_chain.allowlisted_validator_digests(text),
            ["a" * 64, "b" * 64],
        )

    def test_digest_allowlist_rejects_locator_pins_and_bad_records(self):
        for malformed in (
            "release-379454492 ferrum-edge-linux-x86_64 537268718 537268721 "
            + "c" * 64
            + "\n",
            "C" * 64 + "  ferrum-edge-linux-x86_64\n",
            "c" * 64 + "  ferrum-edge-macos-x86_64\n",
            "c" * 64 + "\n",
            "c" * 64 + "  ferrum-edge-linux-x86_64  537268718\n",
        ):
            with self.subTest(malformed=malformed.strip()):
                violations = check_supply_chain.digest_allowlist_violations(malformed)
                self.assertTrue(any("entry must be exactly" in item for item in violations))

    def test_digest_allowlist_must_approve_exactly_one_build_per_digest(self):
        empty = check_supply_chain.digest_allowlist_violations("# nothing yet\n")
        self.assertTrue(any("at least one" in item for item in empty))
        duplicated = ("d" * 64 + "  ferrum-edge-linux-x86_64\n") * 2
        self.assertTrue(
            any(
                "must not repeat" in item
                for item in check_supply_chain.digest_allowlist_violations(duplicated)
            )
        )

    def test_validator_may_not_be_repinned_by_a_mutable_locator(self):
        self.assertEqual(
            check_supply_chain.validator_locator_violations(
                ["run: bash .github/scripts/install-ferrum-edge.sh\n"]
            ),
            [],
        )
        digest_variable = check_supply_chain.validator_locator_violations(
            ["env:\n  FERRUM_EDGE_SHA256: ${{ vars.FERRUM_EDGE_SHA256 }}\n"]
        )
        self.assertTrue(any("mutable variable" in item for item in digest_variable))
        release_identity = check_supply_chain.validator_locator_violations(
            ["env:\n  RAW: ${{ vars.FERRUM_EDGE_VERSION || 'release-1' }}\n"]
        )
        self.assertTrue(any("release identity" in item for item in release_identity))

    @staticmethod
    def _privileged_job(name: str, ordered: bool = True) -> str:
        steps = [
            "      - name: Mint narrowly scoped state-writer token",
            "      - name: Commit state update",
        ]
        build = "      - run: cargo install --path . --locked"
        body = [build, *steps] if ordered else [*steps, build]
        return f"  {name}:\n    steps:\n" + "\n".join(body) + "\n"

    AUTH_LINES = "\n".join(
        [
            "        STATE_WRITER_TOKEN: ${{ steps.state-writer.outputs.token }}",
            "        git config --local http.https://github.com/.extraheader",
            "        git config --local --unset-all http.https://github.com/.extraheader",
        ]
    )

    def test_state_writer_token_must_follow_build_and_stay_ephemeral(self):
        secure = (
            "jobs:\n" + self._privileged_job("apply") + self.AUTH_LINES + "\n"
        )
        self.assertEqual(
            check_supply_chain.state_writer_token_violations(
                "rotate.yml", secure, "- name: Commit state update"
            ),
            [],
        )

        insecure = secure.replace(
            "      - name: Mint narrowly scoped state-writer token\n", ""
        ) + "\ntoken: ${{ steps.state-writer.outputs.token }}"
        violations = check_supply_chain.state_writer_token_violations(
            "rotate.yml", insecure, "- name: Commit state update"
        )
        self.assertTrue(any("persisted by checkout" in item for item in violations))
        self.assertTrue(any("never published" in item for item in violations))

    def test_every_privileged_job_is_ordered_independently(self):
        # Measured across a whole file, the rule stops meaning anything the
        # moment a workflow has two privileged jobs: `rfind` picks up the
        # second job's build and `find` the first job's mint, and the ordering
        # test compares steps that never run in the same runner. A second job
        # that mints before it builds must be caught, and must be NAMED.
        text = (
            "jobs:\n"
            + self._privileged_job("apply")
            + self._privileged_job("promote", ordered=False)
            + self.AUTH_LINES
            + "\n"
        )
        violations = check_supply_chain.state_writer_token_violations(
            "apply-on-merge.yml", text, "- name: Commit state update"
        )
        self.assertTrue(
            any("job 'promote'" in item and "minted after" in item for item in violations),
            violations,
        )
        self.assertFalse(
            any("job 'apply'" in item for item in violations), violations
        )

    def test_unrecognized_job_headers_cannot_hide_a_token_mint(self):
        for header in ('  "promote":\n', "  promote: # privileged job\n"):
            with self.subTest(header=header.rstrip()):
                hidden_job = self._privileged_job("promote", ordered=False).replace(
                    "  promote:\n", header, 1
                )
                text = (
                    "jobs:\n"
                    + self._privileged_job("apply")
                    + hidden_job
                    + self.AUTH_LINES
                    + "\n"
                )
                violations = check_supply_chain.state_writer_token_violations(
                    "apply-on-merge.yml", text, "- name: Commit state update"
                )
                self.assertTrue(
                    any("every state-writer token mint" in item for item in violations),
                    violations,
                )

    def test_comments_do_not_fold_an_unrecognized_job_into_its_neighbor(self):
        # Column-zero comments stay inside `jobs:`, but an unrecognized header
        # still ends the preceding job, so its token mint is never attributed
        # to a validated job.
        hidden_job = self._privileged_job("promote", ordered=False).replace(
            "  promote:\n", '  "promote":\n', 1
        )
        text = (
            "jobs:\n"
            + self._privileged_job("apply")
            + "# staged promotion\n"
            + hidden_job
            + self.AUTH_LINES
            + "\n"
        )
        violations = check_supply_chain.state_writer_token_violations(
            "apply-on-merge.yml", text, "- name: Commit state update"
        )
        self.assertTrue(
            any("every state-writer token mint" in item for item in violations),
            violations,
        )

    def test_two_correctly_ordered_privileged_jobs_are_accepted(self):
        text = (
            "jobs:\n"
            + self._privileged_job("apply")
            + self._privileged_job("promote")
            + self.AUTH_LINES
            + "\n"
        )
        self.assertEqual(
            check_supply_chain.state_writer_token_violations(
                "apply-on-merge.yml", text, "- name: Commit state update"
            ),
            [],
        )

    def test_state_push_retry_must_use_the_default_branch(self):
        commit_step = "- name: Commit state update"
        secure = "\n".join(
            [
                commit_step,
                "DEFAULT_BRANCH: ${{ github.event.repository.default_branch }}",
                'git push origin "HEAD:$DEFAULT_BRANCH"',
                'git fetch origin "$DEFAULT_BRANCH"',
                'git rebase "origin/$DEFAULT_BRANCH"',
            ]
        )
        self.assertEqual(
            check_supply_chain.state_push_retry_violations(
                "rotate.yml", secure, commit_step
            ),
            [],
        )

        insecure = secure.replace(
            'git rebase "origin/$DEFAULT_BRANCH"',
            "git rebase origin/main",
        )
        violations = check_supply_chain.state_push_retry_violations(
            "rotate.yml", insecure, commit_step
        )
        self.assertTrue(
            any("must not hardcode 'origin/main'" in item for item in violations),
            violations,
        )
        self.assertTrue(
            any("missing default-branch push retry" in item for item in violations),
            violations,
        )

    def test_every_whole_secrets_context_form_is_rejected(self):
        # `secrets.NAME` and `secrets['NAME']` were caught in validate-pr.yml,
        # but the whole-context forms — which hand over EVERY environment
        # secret at once — were allowed everywhere else, which is where the
        # privileged workflows actually used them.
        pattern = re.compile(r"\$\{\{[^}]*\bsecrets\b")
        for leak in (
            "${{ toJSON(secrets) }}",
            "${{ fromJSON(toJSON(secrets)) }}",
            "${{ secrets }}",
            "${{ secrets.FERRUM_GATEWAY_URL }}",
            "${{ secrets['FERRUM_GATEWAY_URL'] }}",
        ):
            self.assertRegex(leak, pattern, f"{leak} must be treated as a secret leak")
        for benign in (
            "# secrets never reach this job",
            "${{ github.token }}",
            "${{ vars.GITFORGEOPS_STATE_APP_ID }}",
        ):
            self.assertNotRegex(benign, pattern)

    def test_only_named_secret_references_survive_in_any_workflow(self):
        # validate-pr.yml must receive NO secrets; every other workflow may
        # read `secrets.<NAME>` and nothing broader.
        for leak in (
            "        run: echo '${{ toJSON(secrets) }}'",
            "        run: echo '${{ fromJSON(toJSON(secrets)) }}'",
            "        run: echo '${{ secrets }}'",
            "          URL: ${{ secrets['FERRUM_GATEWAY_URL'] }}",
            "          KEY: ${{ toJSON(secrets.FERRUM_GATEWAY_URL) }}${{ secrets }}",
        ):
            with self.subTest(leak=leak):
                self.assertTrue(
                    check_supply_chain.whole_secrets_context_violations(
                        "sample.yml", leak
                    ),
                    leak,
                )
        benign = "\n".join(
            [
                "# the whole secrets context never reaches this job",
                "          URL: ${{ secrets.FERRUM_GATEWAY_URL }}",
                "          KEY: ${{ secrets.FERRUM_ADMIN_JWT_SECRET }}",
                "          APP: ${{ vars.GITFORGEOPS_STATE_APP_ID }}",
                "          TOKEN: ${{ github.token }}",
                "        if: ${{ secrets.FERRUM_GATEWAY_URL != '' }}",
            ]
        )
        self.assertEqual(
            check_supply_chain.whole_secrets_context_violations("sample.yml", benign), []
        )
        self.assertTrue(
            check_supply_chain.whole_secrets_context_violations(
                "sample.yml", "    secrets: inherit\n"
            )
        )

    def test_no_workflow_dumps_the_whole_secrets_context(self):
        # Guard the wiring, not just the helper: a leak in a workflow that is
        # not validate-pr.yml used to pass the whole policy run.
        with tempfile.TemporaryDirectory() as directory:
            root = self._mirror_repo(Path(directory))
            path = root / ".github/workflows/rust-ci.yml"
            path.write_text(
                path.read_text(encoding="utf-8").replace(
                    "    steps:",
                    "    steps:\n      - run: echo '${{ toJSON(secrets) }}'",
                    1,
                ),
                encoding="utf-8",
            )
            violations = self._violations(root)
        self.assertTrue(
            any("only `secrets.<NAME>`" in item for item in violations), violations
        )

    def test_credential_bundle_shards_are_bound_by_name_up_to_the_rust_ceiling(self):
        limit, limit_violations = check_supply_chain.credential_shard_limit(ROOT)
        self.assertEqual(limit_violations, [])
        self.assertIsNotNone(limit)
        step = "\n".join(
            ["      - name: Load credential bundles", "        env:"]
            + [
                f"          {name}: ${{{{ secrets.{name} }}}}"
                for name in ["FERRUM_CREDS_BUNDLE"]
                + [f"FERRUM_CREDS_BUNDLE_{shard}" for shard in range(1, limit)]
            ]
        )
        self.assertEqual(
            check_supply_chain.credential_bundle_binding_violations(
                "sample.yml", step + "\n", limit
            ),
            [],
        )

        dropped = step.replace(
            f"          FERRUM_CREDS_BUNDLE_{limit - 1}: "
            f"${{{{ secrets.FERRUM_CREDS_BUNDLE_{limit - 1} }}}}\n",
            "",
        ).replace(
            f"\n          FERRUM_CREDS_BUNDLE_{limit - 1}: "
            f"${{{{ secrets.FERRUM_CREDS_BUNDLE_{limit - 1} }}}}",
            "",
        )
        violations = check_supply_chain.credential_bundle_binding_violations(
            "sample.yml", dropped + "\n", limit
        )
        self.assertTrue(
            any("missing or mismatched" in item for item in violations), violations
        )

        beyond = (
            step
            + f"\n          FERRUM_CREDS_BUNDLE_{limit}: "
            + f"${{{{ secrets.FERRUM_CREDS_BUNDLE_{limit} }}}}\n"
        )
        violations = check_supply_chain.credential_bundle_binding_violations(
            "sample.yml", beyond, limit
        )
        self.assertTrue(
            any("beyond MAX_BUNDLE_SHARDS" in item for item in violations), violations
        )

        self.assertTrue(
            check_supply_chain.credential_bundle_binding_violations(
                "sample.yml", "      - name: Something else\n", limit
            )
        )

    def test_shard_ceiling_must_agree_between_rust_and_the_loader(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._mirror_repo(Path(directory))
            loader = root / ".github/scripts/credential_bundles.py"
            text = loader.read_text(encoding="utf-8")
            limit = int(
                re.search(r"^MAX_BUNDLE_SHARDS = (\d+)$", text, re.MULTILINE).group(1)
            )
            loader.write_text(
                text.replace(
                    f"MAX_BUNDLE_SHARDS = {limit}",
                    f"MAX_BUNDLE_SHARDS = {limit + 1}",
                    1,
                ),
                encoding="utf-8",
            )
            violations = self._violations(root)
        self.assertTrue(
            any("MAX_BUNDLE_SHARDS disagrees" in item for item in violations), violations
        )

    def test_import_packing_must_use_the_shared_shard_ceiling(self):
        self.assertEqual(check_supply_chain.import_shard_ceiling_violations(ROOT), [])
        for replacement in ("shard >= 100", "shard > MAX_BUNDLE_SHARDS"):
            with self.subTest(replacement=replacement):
                with tempfile.TemporaryDirectory() as directory:
                    root = self._mirror_repo(Path(directory))
                    path = root / "src/import/mod.rs"
                    original = path.read_text(encoding="utf-8")
                    changed = original.replace("shard >= MAX_BUNDLE_SHARDS", replacement)
                    self.assertNotEqual(original, changed)
                    path.write_text(changed, encoding="utf-8")
                    violations = self._violations(root)
                self.assertTrue(
                    any("migration packing must refuse" in item for item in violations),
                    violations,
                )

    def test_privileged_workflows_must_bind_every_declared_shard(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._mirror_repo(Path(directory))
            path = root / ".github/workflows/apply-on-merge.yml"
            path.write_text(
                path.read_text(encoding="utf-8").replace(
                    "          FERRUM_CREDS_BUNDLE_9: ${{ secrets.FERRUM_CREDS_BUNDLE_9 }}\n",
                    "",
                    1,
                ),
                encoding="utf-8",
            )
            violations = self._violations(root)
        self.assertTrue(
            any(
                "must bind every bundle shard secret" in item and "FERRUM_CREDS_BUNDLE_9" in item
                for item in violations
            ),
            violations,
        )

    def test_unattended_monitoring_may_only_read_the_gateway(self):
        # The drift check runs in an environment with no required reviewer, so
        # its reachable authority is the whole fence. Each of these mutations
        # hands it something it must never have.
        workflow = (ROOT / ".github/workflows/drift-check.yml").read_text(
            encoding="utf-8"
        )
        self.assertEqual(
            check_supply_chain.monitoring_workflow_violations(workflow), []
        )
        for old, new, expected in (
            (
                "gitforgeops diff --exit-on-drift",
                "gitforgeops apply --auto-approve",
                "monitoring may only run",
            ),
            (
                "permissions:\n  contents: read",
                "permissions:\n  contents: write",
                "no write permission",
            ),
            (
                "FERRUM_GATEWAY_URL: ${{ secrets.FERRUM_GATEWAY_URL }}",
                "FERRUM_GH_PROVISIONER_TOKEN: ${{ secrets.FERRUM_GH_PROVISIONER_TOKEN }}",
                "may not reach 'FERRUM_GH_PROVISIONER_TOKEN'",
            ),
            (
                "FERRUM_GATEWAY_URL: ${{ secrets.FERRUM_GATEWAY_URL }}",
                "GITFORGEOPS_STATE_APP_PRIVATE_KEY: "
                "${{ secrets.GITFORGEOPS_STATE_APP_PRIVATE_KEY }}",
                "may not reach 'GITFORGEOPS_STATE_APP_PRIVATE_KEY'",
            ),
            (
                "FERRUM_GATEWAY_URL: ${{ secrets.FERRUM_GATEWAY_URL }}",
                "FERRUM_CREDS_BUNDLE: ${{ secrets.FERRUM_CREDS_BUNDLE }}",
                "may not reach 'FERRUM_CREDS_BUNDLE'",
            ),
            (
                ".github/scripts/drift_report.py",
                ".github/scripts/something_else.py",
                "cannot be reported as in sync",
            ),
        ):
            with self.subTest(expected=expected):
                mutated = workflow.replace(old, new)
                self.assertNotEqual(mutated, workflow)
                violations = check_supply_chain.monitoring_workflow_violations(mutated)
                self.assertTrue(
                    any(expected in item for item in violations), violations
                )

    def test_the_monitoring_fence_is_enforced_by_the_trusted_checker(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._mirror_repo(Path(directory))
            path = root / ".github/workflows/drift-check.yml"
            path.write_text(
                path.read_text(encoding="utf-8").replace(
                    "gitforgeops diff --exit-on-drift",
                    "gitforgeops apply --auto-approve",
                    1,
                ),
                encoding="utf-8",
            )
            violations = self._violations(root)
        self.assertTrue(
            any("monitoring may only run" in item for item in violations), violations
        )

    def test_monitoring_is_exempt_from_the_bundle_rules_by_binding_nothing(self):
        # A comparison does not need credential values, so the bundle stays
        # where allocation needs it. The loader rules follow the secret
        # binding, so an unattended monitoring job is exempt by construction
        # rather than by being left off a list — and it is still a privileged
        # workflow for every other rule.
        workflow = (ROOT / ".github/workflows/drift-check.yml").read_text(
            encoding="utf-8"
        )
        self.assertNotIn(check_supply_chain.BUNDLE_SECRET_BINDING, workflow)
        self.assertIn("drift-check.yml", check_supply_chain.PRIVILEGED_WORKFLOWS)

        # Binding the secret again brings every bundle rule back with it.
        with tempfile.TemporaryDirectory() as directory:
            root = self._mirror_repo(Path(directory))
            path = root / ".github/workflows/drift-check.yml"
            path.write_text(
                workflow.replace(
                    "          FERRUM_GATEWAY_URL: ${{ secrets.FERRUM_GATEWAY_URL }}",
                    "          FERRUM_CREDS_BUNDLE: ${{ secrets.FERRUM_CREDS_BUNDLE }}",
                    1,
                ),
                encoding="utf-8",
            )
            violations = self._violations(root)
        self.assertTrue(
            any("fail-closed loader" in item for item in violations), violations
        )

    def test_credential_workflow_cannot_remove_all_bundle_controls(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._mirror_repo(Path(directory))
            path = root / ".github/workflows/apply-on-merge.yml"
            text = path.read_text(encoding="utf-8")
            text = re.sub(
                r"      - name: Load credential bundles\n.*?(?=      - name: )",
                "      - name: Load credential bundles\n        run: ':'\n",
                text,
                flags=re.DOTALL,
            )
            self.assertNotIn(check_supply_chain.BUNDLE_SECRET_BINDING, text)
            path.write_text(text, encoding="utf-8")
            violations = self._violations(root)

        for expected in (
            "fail-closed loader",
            "missing or mismatched: FERRUM_CREDS_BUNDLE",
            "resolved credential file must live under $RUNNER_TEMP",
        ):
            with self.subTest(expected=expected):
                self.assertTrue(
                    any(expected in item for item in violations), violations
                )

    def test_validate_pr_rejects_the_whole_secrets_context(self):
        # Guard the wiring, not just the regex: the real workflow text is run
        # through the same check the policy applies.
        workflow = (ROOT / ".github/workflows/validate-pr.yml").read_text(
            encoding="utf-8"
        )
        self.assertNotRegex(workflow, r"\$\{\{[^}]*\bsecrets\b")
        with tempfile.TemporaryDirectory() as directory:
            root = self._mirror_repo(Path(directory))
            path = root / ".github/workflows/validate-pr.yml"
            path.write_text(
                workflow.replace(
                    "    steps:",
                    "    steps:\n      - run: echo '${{ toJSON(secrets) }}'",
                    1,
                ),
                encoding="utf-8",
            )
            violations = self._violations(root)
        self.assertTrue(
            any("must not receive any secrets" in item for item in violations),
            violations,
        )

    def test_state_guard_must_run_the_default_branch_definition(self):
        secure = """on:
  pull_request_target:
    types: [opened, synchronize, reopened, edited, labeled, unlabeled]
    branches: [main]
      - uses: actions/checkout@0000000000000000000000000000000000000000 # v7
        with:
          ref: ${{ github.event.repository.default_branch }}
"""
        self.assertEqual(check_supply_chain.state_guard_trigger_violations(secure), [])

        head_loaded = secure.replace("  pull_request_target:", "  pull_request:")
        violations = check_supply_chain.state_guard_trigger_violations(head_loaded)
        self.assertTrue(
            any("pull_request_target trigger is missing" in item for item in violations),
            violations,
        )
        self.assertTrue(
            any("head-loaded pull_request trigger" in item for item in violations),
            violations,
        )

    def test_state_guard_must_never_check_out_the_pull_request(self):
        untrusted = """on:
  pull_request_target:
    types: [opened, synchronize, reopened, edited, labeled, unlabeled]
    branches: [main]
      - uses: actions/checkout@0000000000000000000000000000000000000000 # v7
        with:
          ref: ${{ github.event.repository.default_branch }}
      - uses: actions/checkout@0000000000000000000000000000000000000000 # v7
        with:
          ref: ${{ github.event.pull_request.head.sha }}
"""
        violations = check_supply_chain.state_guard_trigger_violations(untrusted)
        self.assertTrue(
            any("never check out" in item for item in violations), violations
        )
        self.assertTrue(
            any("exactly one checkout" in item for item in violations), violations
        )

    def test_state_guard_must_not_share_a_concurrency_group(self):
        secure = """on:
  pull_request_target:
    types: [opened, synchronize, reopened, edited, labeled, unlabeled]
    branches: [main]
      - uses: actions/checkout@0000000000000000000000000000000000000000 # v7
        with:
          ref: ${{ github.event.repository.default_branch }}
"""
        workflow_level = secure.replace(
            "      - uses:",
            "concurrency:\n"
            "  group: state-guard-${{ github.event.pull_request.number }}\n"
            "  cancel-in-progress: true\n"
            "      - uses:",
            1,
        )
        per_head = secure.replace(
            "      - uses:",
            "concurrency:\n"
            "  group: state-guard-${{ github.event.pull_request.number }}-"
            "${{ github.event.pull_request.head.sha }}\n"
            "  cancel-in-progress: false\n"
            "      - uses:",
            1,
        )
        job_level = secure.replace(
            "      - uses:",
            "    concurrency: state-guard-${{ github.event.pull_request.number }}\n"
            "      - uses:",
            1,
        )
        for text in (workflow_level, per_head, job_level):
            with self.subTest(text=text):
                violations = check_supply_chain.state_guard_trigger_violations(text)
                self.assertTrue(
                    any("must not declare a concurrency group" in item for item in violations),
                    violations,
                )

    def test_state_guard_concurrency_detection_covers_every_yaml_key_spelling(self):
        secure = """on:
  pull_request_target:
    types: [opened, synchronize, reopened, edited, labeled, unlabeled]
    branches: [main]
      - uses: actions/checkout@0000000000000000000000000000000000000000 # v7
        with:
          ref: ${{ github.event.repository.default_branch }}
"""
        spellings = {
            "double_quoted": '"concurrency": state-guard\n',
            "single_quoted": "'concurrency': state-guard\n",
            "flow_mapping": "jobs: {guard: {runs-on: ubuntu-24.04, concurrency: g}}\n",
            "flow_mapping_quoted": 'jobs: {guard: {"concurrency": g, runs-on: x}}\n',
            "explicit_key": "? concurrency\n: state-guard\n",
            "explicit_quoted_key": "? 'concurrency'\n: state-guard\n",
            "capitalised": "Concurrency: state-guard\n",
            "upper_case_job": "    CONCURRENCY:\n      group: g\n",
            "tagged": "!!str concurrency: state-guard\n",
            "anchored": "&key concurrency: state-guard\n",
            "hex_escaped": '"\\x63oncurrency": state-guard\n',
            "unicode_escaped": '"\\u0063oncurrency": state-guard\n',
            "escaped_line_break": '"concur\\\n  rency": state-guard\n',
            "trailing_comment_is_not_exempt": "permissions: {} # concurrency: g\n",
        }
        for label, declaration in spellings.items():
            with self.subTest(label=label):
                text = secure + declaration
                violations = check_supply_chain.state_guard_trigger_violations(text)
                self.assertTrue(
                    any("must not declare a concurrency group" in item for item in violations),
                    violations,
                )

        commented = secure + "# Deliberately NO `concurrency:` group.\n    # concurrency: g\n"
        self.assertEqual(check_supply_chain.state_guard_trigger_violations(commented), [])

    def test_shipped_state_guard_declares_no_concurrency_group(self):
        text = (ROOT / ".github/workflows/state-guard.yml").read_text(encoding="utf-8")
        self.assertEqual(check_supply_chain.state_guard_trigger_violations(text), [])
        self.assertFalse(check_supply_chain.declares_concurrency(text))
        self.assertNotRegex(text, re.compile(r"^\s*concurrency\s*:", re.MULTILINE))

    def test_shipped_state_guard_rechecks_before_recording_an_override(self):
        text = (ROOT / ".github/workflows/state-guard.yml").read_text(encoding="utf-8")
        self.assertEqual(
            check_supply_chain.state_guard_override_recheck_violations(text), []
        )
        step = check_supply_chain.named_step(
            text, check_supply_chain.STATE_GUARD_RECORD_STEP
        )
        self.assertIsNotNone(step)
        for binding in (
            "GH_TOKEN: ${{ github.token }}",
            "EXPECTED_HEAD_SHA: ${{ github.event.pull_request.head.sha }}",
            "DEFAULT_BRANCH: ${{ github.event.repository.default_branch }}",
            "OVERRIDE_LABEL: gitforgeops/state-override",
        ):
            self.assertIn(binding, step)

    def test_state_guard_override_recheck_cannot_be_removed_or_moved(self):
        text = (ROOT / ".github/workflows/state-guard.yml").read_text(encoding="utf-8")
        step = check_supply_chain.named_step(
            text, check_supply_chain.STATE_GUARD_RECORD_STEP
        )
        self.assertIsNotNone(step)

        for required in check_supply_chain.STATE_GUARD_FINAL_RECHECK:
            with self.subTest(removed=required):
                weakened = text.replace(step, step.replace(required, "true", 1), 1)
                violations = check_supply_chain.state_guard_override_recheck_violations(
                    weakened
                )
                self.assertTrue(
                    any("must re-read the pull request" in item for item in violations),
                    violations,
                )

        unguarded = text.replace(step, step.replace("set -euo pipefail", "set -e", 1), 1)
        violations = check_supply_chain.state_guard_override_recheck_violations(unguarded)
        self.assertTrue(
            any("set -euo pipefail" in item for item in violations), violations
        )

        recheck_start = step.index(check_supply_chain.STATE_GUARD_FINAL_RECHECK[0])
        report = "          echo \"::warning::reported early\"\n"
        reported_first = text.replace(
            step, step[:recheck_start] + report.lstrip() + "          " + step[recheck_start:], 1
        )
        violations = check_supply_chain.state_guard_override_recheck_violations(
            reported_first
        )
        self.assertTrue(
            any("before reporting the override" in item for item in violations),
            violations,
        )

        missing = text.replace(
            "      - name: Record authorized override\n",
            "      - name: Record override\n",
            1,
        )
        violations = check_supply_chain.state_guard_override_recheck_violations(missing)
        self.assertTrue(any("step is missing" in item for item in violations), violations)

    def test_state_guard_override_recheck_rejects_commented_out_checks(self):
        text = (ROOT / ".github/workflows/state-guard.yml").read_text(encoding="utf-8")
        step = check_supply_chain.named_step(
            text, check_supply_chain.STATE_GUARD_RECORD_STEP
        )
        self.assertIsNotNone(step)
        required = check_supply_chain.STATE_GUARD_FINAL_RECHECK[0]
        weakened = text.replace(step, step.replace(required, "# " + required, 1), 1)
        violations = check_supply_chain.state_guard_override_recheck_violations(weakened)
        self.assertTrue(
            any("must re-read the pull request" in item for item in violations),
            violations,
        )

    def test_state_guard_override_recheck_rejects_continue_on_error(self):
        text = (ROOT / ".github/workflows/state-guard.yml").read_text(encoding="utf-8")
        step = check_supply_chain.named_step(
            text, check_supply_chain.STATE_GUARD_RECORD_STEP
        )
        self.assertIsNotNone(step)
        weakened = text.replace(
            step, step.replace("        env:\n", "        continue-on-error: true\n        env:\n", 1), 1
        )
        violations = check_supply_chain.state_guard_override_recheck_violations(weakened)
        self.assertTrue(
            any("must not use continue-on-error" in item for item in violations),
            violations,
        )

    def test_state_guard_override_recheck_pins_step_condition(self):
        text = (ROOT / ".github/workflows/state-guard.yml").read_text(encoding="utf-8")
        step = check_supply_chain.named_step(
            text, check_supply_chain.STATE_GUARD_RECORD_STEP
        )
        self.assertIsNotNone(step)
        weakened = text.replace(
            step,
            step.replace(
                f"        if: {check_supply_chain.STATE_GUARD_RECORD_IF}\n",
                "        if: always()\n",
                1,
            ),
            1,
        )
        violations = check_supply_chain.state_guard_override_recheck_violations(weakened)
        self.assertTrue(
            any("if: condition pinned" in item for item in violations), violations
        )

    def test_every_rust_toolchain_step_must_pin_the_version(self):
        secure = """      - name: Install Rust toolchain
        uses: dtolnay/rust-toolchain@0000000000000000000000000000000000000000
        with:
          toolchain: 1.98.0
      - name: Install Rust toolchain again
        uses: dtolnay/rust-toolchain@0000000000000000000000000000000000000000
        with:
          toolchain: 1.98.0
"""
        self.assertEqual(
            check_supply_chain.rust_toolchain_violations(
                "rust-ci.yml", secure, "1.98.0"
            ),
            [],
        )

        # One pinned step used to satisfy the whole file.
        insecure = secure.replace(
            """      - name: Install Rust toolchain again
        uses: dtolnay/rust-toolchain@0000000000000000000000000000000000000000
        with:
          toolchain: 1.98.0
""",
            """      - name: Install Rust toolchain again
        uses: dtolnay/rust-toolchain@0000000000000000000000000000000000000000
""",
        )
        violations = check_supply_chain.rust_toolchain_violations(
            "rust-ci.yml", insecure, "1.98.0"
        )
        self.assertTrue(
            any("every dtolnay/rust-toolchain step" in item for item in violations),
            violations,
        )

    def test_rust_toolchain_workflows_follow_the_pinned_channel(self):
        workflow = """      - name: Install Rust toolchain
        uses: dtolnay/rust-toolchain@0000000000000000000000000000000000000000
        with:
          toolchain: 1.99.0
"""
        self.assertEqual(
            check_supply_chain.rust_toolchain_violations(
                "rust-ci.yml", workflow, "1.99.0"
            ),
            [],
        )
        self.assertTrue(
            check_supply_chain.rust_toolchain_violations(
                "rust-ci.yml", workflow, "1.98.0"
            )
        )

    def test_rust_toolchain_channel_requires_one_stable_pin(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "rust-toolchain.toml"
            path.write_text('[toolchain]\nchannel = "1.99.0"\n', encoding="utf-8")
            self.assertEqual(
                check_supply_chain.read_rust_toolchain_channel(path), "1.99.0"
            )
            path.write_text(
                '[toolchain]\nchannel = "stable"\n', encoding="utf-8"
            )
            self.assertIsNone(check_supply_chain.read_rust_toolchain_channel(path))

    def test_rust_ci_runs_the_library_target_unfiltered(self):
        text = (ROOT / ".github/workflows/rust-ci.yml").read_text(encoding="utf-8")
        self.assertEqual(check_supply_chain.rust_ci_test_scope_violations(text), [])

        # A name filter compiled every library test but ran only one.
        filtered = text.replace(
            "          cargo test --lib\n",
            "          cargo test --lib prepared_apply_tests::only_this_one\n",
            1,
        )
        self.assertNotEqual(filtered, text)
        violations = check_supply_chain.rust_ci_test_scope_violations(filtered)
        self.assertTrue(
            any("`cargo test --lib` unfiltered" in item for item in violations),
            violations,
        )

        # A comment naming the command must not stand in for running it.
        commented = text.replace(
            "          cargo test --lib\n", "          # cargo test --lib\n", 1
        )
        self.assertNotEqual(commented, text)
        self.assertTrue(
            any(
                "`cargo test --lib` unfiltered" in item
                for item in check_supply_chain.rust_ci_test_scope_violations(commented)
            )
        )

        suite_only = text.replace(
            "cargo llvm-cov --lib --test unit_tests", "cargo llvm-cov --test unit_tests", 1
        )
        self.assertNotEqual(suite_only, text)
        violations = check_supply_chain.rust_ci_test_scope_violations(suite_only)
        self.assertTrue(
            any("coverage must measure the library target" in item for item in violations),
            violations,
        )

    def test_unconfigured_repository_skips_instead_of_failing_the_merge(self):
        secure = "\n".join(
            [
                "if [[ ! -f .gitforgeops/config.yaml ]]; then",
                'echo "envs=[]" >> "$GITHUB_OUTPUT"',
                "needs.list-envs.outputs.envs != '[]'",
            ]
        )
        self.assertEqual(check_supply_chain.unconfigured_repo_skip_violations(secure), [])

        hard_failing = secure + (
            "\necho \"::error::Repository configuration is required before binding a "
            "deployment environment.\"\n"
        )
        violations = check_supply_chain.unconfigured_repo_skip_violations(hard_failing)
        self.assertTrue(
            any("must not fail the merge" in item for item in violations), violations
        )

        without_skip = "needs.list-envs.outputs.envs != '[]'"
        violations = check_supply_chain.unconfigured_repo_skip_violations(without_skip)
        self.assertTrue(
            any("empty matrix" in item for item in violations), violations
        )

    def test_state_writer_app_must_be_proven_before_the_gateway_mutation(self):
        secure = "\n".join(
            [
                "- name: Require state-writer App credentials",
                "STATE_APP_ID: ${{ vars.GITFORGEOPS_STATE_APP_ID }}",
                "STATE_APP_PRIVATE_KEY: ${{ secrets.GITFORGEOPS_STATE_APP_PRIVATE_KEY }}",
                'if [ -z "$STATE_APP_ID" ] || [ -z "$STATE_APP_PRIVATE_KEY" ]; then',
                "- name: Mint narrowly scoped state-writer token",
                "app-id: ${{ vars.GITFORGEOPS_STATE_APP_ID }}",
            ]
        )
        self.assertEqual(
            check_supply_chain.state_writer_preflight_violations("rotate.yml", secure),
            [],
        )

        missing = secure.replace(
            "- name: Require state-writer App credentials\n", "", 1
        )
        violations = check_supply_chain.state_writer_preflight_violations(
            "rotate.yml", missing
        )
        self.assertTrue(
            any("before any gateway mutation" in item for item in violations),
            violations,
        )

        secret_app_id = secure.replace(
            "app-id: ${{ vars.GITFORGEOPS_STATE_APP_ID }}",
            "app-id: ${{ secrets.GITFORGEOPS_STATE_APP_ID }}",
        )
        violations = check_supply_chain.state_writer_preflight_violations(
            "rotate.yml", secret_app_id
        )
        self.assertTrue(
            any("must be read from vars" in item for item in violations), violations
        )

    def test_admin_jwt_step_must_bind_every_documented_claim_setting(self):
        secure = "\n".join(
            [
                "      - name: Apply",
                "        env:",
                "          FERRUM_ADMIN_JWT_SECRET: ${{ secrets.FERRUM_ADMIN_JWT_SECRET }}",
                "          FERRUM_ADMIN_JWT_ISSUER: ${{ secrets.FERRUM_ADMIN_JWT_ISSUER }}",
                "          FERRUM_ADMIN_JWT_ROLE: ${{ secrets.FERRUM_ADMIN_JWT_ROLE }}",
                "          FERRUM_ADMIN_JWT_AUDIENCE: ${{ secrets.FERRUM_ADMIN_JWT_AUDIENCE }}",
                "          FERRUM_ADMIN_JWT_TTL_SECS: ${{ secrets.FERRUM_ADMIN_JWT_TTL_SECS }}",
                "        run: gitforgeops apply --auto-approve",
            ]
        )
        self.assertEqual(
            check_supply_chain.admin_jwt_binding_violations("apply.yml", secure), []
        )

        for setting in check_supply_chain.ADMIN_JWT_OPTIONAL_SETTINGS:
            with self.subTest(setting=setting):
                dropped = secure.replace(
                    f"          {setting}: ${{{{ secrets.{setting} }}}}\n", "", 1
                )
                violations = check_supply_chain.admin_jwt_binding_violations(
                    "apply.yml", dropped
                )
                self.assertTrue(
                    any(
                        "'Apply'" in item and setting in item for item in violations
                    ),
                    violations,
                )

        # A step that mints no token is not held to the rule.
        unrelated = "      - name: Validate\n        run: gitforgeops validate\n"
        self.assertEqual(
            check_supply_chain.admin_jwt_binding_violations("apply.yml", unrelated), []
        )

    def test_every_api_workflow_binds_the_optional_jwt_settings(self):
        # Source-of-truth check against the real workflows, not a synthetic
        # fixture: this is the finding the issue reported.
        for workflow in check_supply_chain.ADMIN_API_WORKFLOWS:
            with self.subTest(workflow=workflow):
                text = (ROOT / ".github/workflows" / workflow).read_text(
                    encoding="utf-8"
                )
                accepted = check_supply_chain.admin_api_jwt_bindings(workflow)
                self.assertTrue(any(binding in text for binding in accepted), accepted)
                settings = set()
                if check_supply_chain.ADMIN_JWT_SECRET_BINDING in text:
                    settings.update(check_supply_chain.ADMIN_JWT_OPTIONAL_SETTINGS)
                if check_supply_chain.VIEWER_JWT_SECRET_BINDING in text:
                    settings.update(check_supply_chain.VIEWER_JWT_OPTIONAL_SETTINGS)
                for setting in sorted(settings):
                    self.assertIn(f"{setting}: ${{{{ secrets.{setting} }}}}", text)
                self.assertEqual(
                    check_supply_chain.admin_jwt_binding_violations(workflow, text), []
                )

    def test_dropping_a_jwt_setting_from_a_real_workflow_fails_the_policy(self):
        for workflow in ("drift-check.yml", "trusted-pr-review.yml"):
            with self.subTest(workflow=workflow), tempfile.TemporaryDirectory() as directory:
                root = self._mirror_repo(Path(directory))
                path = root / ".github/workflows" / workflow
                path.write_text(
                    path.read_text(encoding="utf-8").replace(
                        "          FERRUM_ADMIN_JWT_AUDIENCE: "
                        "${{ secrets.FERRUM_ADMIN_JWT_AUDIENCE }}\n",
                        "",
                        1,
                    ),
                    encoding="utf-8",
                )
                violations = self._violations(root)
                self.assertTrue(
                    any(
                        "FERRUM_ADMIN_JWT_AUDIENCE" in item for item in violations
                    ),
                    violations,
                )

    def test_an_api_workflow_that_binds_no_jwt_secret_at_all_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._mirror_repo(Path(directory))
            path = root / ".github/workflows/drift-check.yml"
            text = path.read_text(encoding="utf-8")
            for setting in (
                "FERRUM_ADMIN_JWT_VIEWER_SECRET",
                *check_supply_chain.VIEWER_JWT_OPTIONAL_SETTINGS,
            ):
                text = text.replace(
                    f"          {setting}: ${{{{ secrets.{setting} }}}}\n", "", 1
                )
            path.write_text(text, encoding="utf-8")
            violations = self._violations(root)
        self.assertTrue(
            any("must bind" in item and "FERRUM_ADMIN_JWT_VIEWER_SECRET" in item for item in violations),
            violations,
        )
        # Monitoring requires the viewer key; the admin form is retired.
        self.assertTrue(
            any(
                item.startswith("drift-check.yml: an admin-API workflow must bind")
                and repr(check_supply_chain.VIEWER_JWT_SECRET_BINDING) in item
                and repr(check_supply_chain.ADMIN_JWT_SECRET_BINDING) not in item
                for item in violations
            ),
            violations,
        )

    # -- viewer-only monitoring credential (#440) --------------------------

    ADMIN_LINE = (
        "          FERRUM_ADMIN_JWT_SECRET: ${{ secrets.FERRUM_ADMIN_JWT_SECRET }}\n"
    )
    VIEWER_LINE = (
        "          FERRUM_ADMIN_JWT_VIEWER_SECRET: "
        "${{ secrets.FERRUM_ADMIN_JWT_VIEWER_SECRET }}\n"
    )

    def _drift_check(self) -> str:
        return (ROOT / ".github/workflows/drift-check.yml").read_text(encoding="utf-8")

    def test_viewer_secret_is_allowed_in_the_monitoring_workflow(self):
        workflow = self._drift_check()
        self.assertIn(self.VIEWER_LINE, workflow)
        self.assertNotIn(self.ADMIN_LINE, workflow)
        viewer_only = workflow
        self.assertEqual(
            check_supply_chain.viewer_jwt_scope_violations(
                ".github/workflows/drift-check.yml", viewer_only
            ),
            [],
        )
        self.assertEqual(
            check_supply_chain.monitoring_workflow_violations(viewer_only), []
        )
        self.assertEqual(
            check_supply_chain.admin_jwt_binding_violations("drift-check.yml", viewer_only),
            [],
        )

        # The shipped viewer-only shape passes the whole trusted checker.
        with tempfile.TemporaryDirectory() as directory:
            root = self._mirror_repo(Path(directory))
            path = root / ".github/workflows/drift-check.yml"
            path.write_text(viewer_only, encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--root", str(root)],
                check=False,
                text=True,
                capture_output=True,
            )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("::warning::", result.stdout)

    def test_viewer_secret_is_refused_outside_the_monitoring_workflow(self):
        step = (
            "      - name: Apply\n"
            "        env:\n" + self.VIEWER_LINE + "        run: gitforgeops apply\n"
        )
        for path in (
            ".github/workflows/apply-on-merge.yml",
            ".github/workflows/rotate.yml",
            ".github/workflows/trusted-pr-review.yml",
            ".github/workflows/materialize-file.yml",
            ".github/workflows/validate-pr.yml",
            ".github/workflows/nested/drift-check.yml",
            ".github/actions/gateway/action.yml",
        ):
            with self.subTest(path=path):
                violations = check_supply_chain.viewer_jwt_scope_violations(path, step)
                self.assertTrue(
                    any("only drift-check.yml may bind" in item for item in violations),
                    violations,
                )
        # A file that never names the key is not held to the rule.
        self.assertEqual(
            check_supply_chain.viewer_jwt_scope_violations(
                ".github/workflows/rotate.yml", "run: gitforgeops plan\n"
            ),
            [],
        )

        with tempfile.TemporaryDirectory() as directory:
            root = self._mirror_repo(Path(directory))
            path = root / ".github/workflows/apply-on-merge.yml"
            text = path.read_text(encoding="utf-8")
            self.assertIn(self.ADMIN_LINE, text)
            path.write_text(
                text.replace(self.ADMIN_LINE, self.ADMIN_LINE + self.VIEWER_LINE, 1),
                encoding="utf-8",
            )
            violations = self._violations(root)
        self.assertTrue(
            any(
                item.startswith(".github/workflows/apply-on-merge.yml:")
                and "only drift-check.yml may bind" in item
                for item in violations
            ),
            violations,
        )

    def test_monitoring_admin_key_is_refused_alone_or_with_the_viewer(self):
        workflow = self._drift_check()
        for binding in (self.ADMIN_LINE, self.VIEWER_LINE + self.ADMIN_LINE):
            with self.subTest(binding=binding):
                mutated = workflow.replace(self.VIEWER_LINE, binding, 1)
                violations = check_supply_chain.monitoring_workflow_violations(mutated)
                self.assertTrue(
                    any("may not reach 'FERRUM_ADMIN_JWT_SECRET'" in item for item in violations),
                    violations,
                )
                with tempfile.TemporaryDirectory() as directory:
                    root = self._mirror_repo(Path(directory))
                    path = root / ".github/workflows/drift-check.yml"
                    path.write_text(mutated, encoding="utf-8")
                    violations = self._violations(root)
                self.assertTrue(
                    any("FERRUM_ADMIN_JWT_SECRET" in item for item in violations), violations
                )

    def test_viewer_step_must_bind_issuer_audience_and_ttl(self):
        secure = "\n".join(
            [
                "      - name: Check drift",
                "        env:",
                self.VIEWER_LINE.rstrip("\n"),
                "          FERRUM_ADMIN_JWT_ISSUER: ${{ secrets.FERRUM_ADMIN_JWT_ISSUER }}",
                "          FERRUM_ADMIN_JWT_AUDIENCE: ${{ secrets.FERRUM_ADMIN_JWT_AUDIENCE }}",
                "          FERRUM_ADMIN_JWT_TTL_SECS: ${{ secrets.FERRUM_ADMIN_JWT_TTL_SECS }}",
                "        run: gitforgeops diff --exit-on-drift",
            ]
        )
        # The viewer key's role claim is fixed, so the role setting is not required.
        self.assertEqual(
            check_supply_chain.admin_jwt_binding_violations("drift-check.yml", secure), []
        )
        for setting in check_supply_chain.VIEWER_JWT_OPTIONAL_SETTINGS:
            with self.subTest(setting=setting):
                dropped = secure.replace(
                    f"          {setting}: ${{{{ secrets.{setting} }}}}\n", "", 1
                )
                self.assertNotEqual(dropped, secure)
                violations = check_supply_chain.admin_jwt_binding_violations(
                    "drift-check.yml", dropped
                )
                self.assertTrue(
                    any(
                        "binds FERRUM_ADMIN_JWT_VIEWER_SECRET" in item and setting in item
                        for item in violations
                    ),
                    violations,
                )

    def test_monitoring_requires_only_the_viewer_binding(self):
        self.assertEqual(
            check_supply_chain.admin_api_jwt_bindings("drift-check.yml"),
            (
                check_supply_chain.VIEWER_JWT_SECRET_BINDING,
            ),
        )
        for workflow in ("apply-on-merge.yml", "rotate.yml", "trusted-pr-review.yml"):
            with self.subTest(workflow=workflow):
                self.assertEqual(
                    check_supply_chain.admin_api_jwt_bindings(workflow),
                    (check_supply_chain.ADMIN_JWT_SECRET_BINDING,),
                )

    def test_monitoring_key_binding_is_structural_and_cannot_be_rebound(self):
        workflow = ".github/workflows/drift-check.yml"
        text = self._drift_check()
        document = check_supply_chain.parse_workflow(text)
        self.assertEqual(
            check_supply_chain.monitoring_jwt_binding_violations(workflow, document), []
        )
        # No implicit acceptance of secrets is added with the viewer switch.
        self.assertIn("gitforgeops diff --exit-on-drift || status=$?", text)
        self.assertNotIn("--accept-unverified-secrets", text)
        self.assertNotIn("--fingerprint-baseline", text)
        for replacement in (
            self.VIEWER_LINE.replace("${{ secrets.FERRUM_ADMIN_JWT_VIEWER_SECRET }}", "literal-key"),
            self.VIEWER_LINE.replace("${{ secrets.FERRUM_ADMIN_JWT_VIEWER_SECRET }}", "${{ vars.KEY }}"),
            "          # " + self.VIEWER_LINE.strip() + "\n",
            '          ALIAS: "${{ secrets.FERRUM_ADMIN_JWT_\\x53ECRET }}"\n',
            '          FERRUM_ADMIN_JWT_SECRET: "unused-but-held"\n' + self.VIEWER_LINE,
        ):
            with self.subTest(replacement=replacement):
                changed = text.replace(self.VIEWER_LINE, replacement, 1)
                self.assertTrue(check_supply_chain.monitoring_jwt_binding_violations(
                    workflow, check_supply_chain.parse_workflow(changed)
                ))
        for scope in ("workflow", "job", "other-step", "shell", "env-file"):
            with self.subTest(scope=scope):
                document = check_supply_chain.parse_workflow(text)
                admin = {"FERRUM_ADMIN_JWT_SECRET": "${{ secrets.FERRUM_ADMIN_JWT_SECRET }}"}
                if scope == "workflow":
                    document["env"] = admin
                elif scope == "job":
                    document["jobs"]["drift"]["env"] = admin
                elif scope == "other-step":
                    document["jobs"]["drift"]["steps"].append({"name": "Rebind", "env": admin})
                elif scope == "shell":
                    self._step(document, "drift", "Check drift")["run"] = (
                        "FERRUM_ADMIN_JWT_SECRET=key gitforgeops diff --exit-on-drift"
                    )
                else:
                    document["jobs"]["drift"]["steps"].append({
                        "name": "Rebind", "run": 'cat payload >> "$GITHUB_ENV"',
                    })
                self.assertTrue(check_supply_chain.monitoring_jwt_binding_violations(workflow, document))

    def test_candidate_checker_cannot_approve_an_admin_monitoring_binding(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._mirror_repo(Path(directory))
            (root / ".github/scripts/check_supply_chain.py").write_text(
                "print('candidate approves itself')\n", encoding="utf-8"
            )
            path = root / ".github/workflows/drift-check.yml"
            path.write_text(self._drift_check().replace(
                self.VIEWER_LINE, self.VIEWER_LINE + self.ADMIN_LINE, 1
            ), encoding="utf-8")
            violations = self._violations(root)
        self.assertTrue(
            any("FERRUM_ADMIN_JWT_SECRET" in item for item in violations), violations
        )

    # -- secret names are case-insensitive at GitHub ------------------------

    def test_secret_references_must_use_the_canonical_upper_case_name(self):
        for reference in (
            "${{ secrets.ferrum_admin_jwt_viewer_secret }}",
            "${{ secrets.Ferrum_Gateway_Url }}",
            "${{ SECRETS.FERRUM_GATEWAY_URL }}",
            "${{ Secrets.FERRUM_GATEWAY_URL }}",
        ):
            with self.subTest(reference=reference):
                violations = check_supply_chain.secret_name_case_violations(
                    "sample.yml", f"          KEY: {reference}\n"
                )
                self.assertEqual(len(violations), 1, violations)
                self.assertIn("sample.yml:", violations[0])
                self.assertIn("secrets.<UPPER_CASE_NAME>", violations[0])
        self.assertEqual(
            check_supply_chain.secret_name_case_violations(
                "sample.yml",
                "          URL: ${{ secrets.FERRUM_GATEWAY_URL }}\n"
                "          SHARD: ${{ secrets.FERRUM_CREDS_BUNDLE_2 }}\n"
                "# GitHub Environment Secrets are not process environment variables.\n",
            ),
            [],
        )
        # A whole-context read cannot hide behind upper case either.
        self.assertTrue(
            check_supply_chain.whole_secrets_context_violations(
                "sample.yml", "        run: echo '${{ toJSON(SECRETS) }}'"
            )
        )

    def test_lower_case_viewer_key_outside_monitoring_is_refused(self):
        lower = (
            "          FERRUM_ADMIN_JWT_VIEWER_SECRET: "
            "${{ secrets.ferrum_admin_jwt_viewer_secret }}\n"
        )
        self.assertTrue(
            check_supply_chain.viewer_jwt_scope_violations(
                ".github/workflows/apply-on-merge.yml", lower
            )
        )
        with tempfile.TemporaryDirectory() as directory:
            root = self._mirror_repo(Path(directory))
            path = root / ".github/workflows/apply-on-merge.yml"
            path.write_text(
                path.read_text(encoding="utf-8").replace(
                    self.ADMIN_LINE, self.ADMIN_LINE + lower, 1
                ),
                encoding="utf-8",
            )
            violations = self._violations(root)
        for expected in (
            "only drift-check.yml may bind",
            "found 'secrets.ferrum_admin_jwt_viewer_secret'",
        ):
            with self.subTest(expected=expected):
                self.assertTrue(
                    any(
                        item.startswith(".github/workflows/apply-on-merge.yml:")
                        and expected in item
                        for item in violations
                    ),
                    violations,
                )

    def test_lower_case_forbidden_secrets_are_refused_in_monitoring(self):
        workflow = self._drift_check()
        for secret in check_supply_chain.MONITORING_FORBIDDEN_SECRETS:
            with self.subTest(secret=secret):
                mutated = workflow.replace(
                    "FERRUM_GATEWAY_URL: ${{ secrets.FERRUM_GATEWAY_URL }}",
                    f"{secret}: ${{{{ secrets.{secret.lower()} }}}}",
                    1,
                )
                self.assertNotEqual(mutated, workflow)
                violations = check_supply_chain.monitoring_workflow_violations(mutated)
                self.assertTrue(
                    any(f"may not reach {secret!r}" in item for item in violations),
                    violations,
                )
        # A lower-case shard name still reaches the credential bundle.
        shard = workflow.replace(
            "FERRUM_GATEWAY_URL: ${{ secrets.FERRUM_GATEWAY_URL }}",
            "FERRUM_CREDS_BUNDLE_2: ${{ secrets.ferrum_creds_bundle_2 }}",
            1,
        )
        self.assertTrue(
            any(
                "may not reach 'FERRUM_CREDS_BUNDLE'" in item
                for item in check_supply_chain.monitoring_workflow_violations(shard)
            )
        )

    def test_lower_case_admin_key_is_still_held_to_the_admin_rules(self):
        lower_admin = (
            "          FERRUM_ADMIN_JWT_SECRET: ${{ secrets.ferrum_admin_jwt_secret }}\n"
        )
        # The claim-settings rule still fires for the lower-case binding.
        step = "      - name: Apply\n        env:\n" + lower_admin + "        run: x\n"
        violations = check_supply_chain.admin_jwt_binding_violations("apply.yml", step)
        self.assertTrue(
            any("binds FERRUM_ADMIN_JWT_SECRET but not" in item for item in violations),
            violations,
        )
        # Both keys in monitoring, one spelled in lower case, still refuse.
        both = self._drift_check().replace(
            self.VIEWER_LINE, lower_admin + self.VIEWER_LINE, 1
        )
        self.assertTrue(check_supply_chain.monitoring_workflow_violations(both))
        # And the audit token stays fenced to the settings audit.
        with tempfile.TemporaryDirectory() as directory:
            root = self._mirror_repo(Path(directory))
            path = root / ".github/workflows/rust-ci.yml"
            path.write_text(
                path.read_text(encoding="utf-8").replace(
                    "    steps:",
                    "    steps:\n      - run: echo '${{ secrets.settings_audit_token }}'",
                    1,
                ),
                encoding="utf-8",
            )
            violations = self._violations(root)
        self.assertTrue(
            any(
                item.startswith(".github/workflows/rust-ci.yml:")
                and "administration-read audit token" in item
                for item in violations
            ),
            violations,
        )

    def test_apply_steps_bind_the_allocation_revision_to_the_trigger(self):
        text = (ROOT / ".github/workflows/apply-on-merge.yml").read_text(
            encoding="utf-8"
        )
        self.assertEqual(
            text.count(check_supply_chain.ALLOCATION_REVISION_BINDING),
            text.count(check_supply_chain.APPLY_COMMAND),
        )
        self.assertEqual(
            check_supply_chain.allocation_revision_binding_violations(
                "apply-on-merge.yml", text
            ),
            [],
        )

        # Bound to the applied head instead, a retry would miss its own slots.
        head_bound = text.replace(
            check_supply_chain.ALLOCATION_REVISION_BINDING,
            "GITFORGEOPS_ALLOCATION_REVISION: ${{ steps.freshness.outputs.applied_sha }}",
            1,
        )
        violations = check_supply_chain.allocation_revision_binding_violations(
            "apply-on-merge.yml", head_bound
        )
        self.assertEqual(len(violations), 1, violations)
        self.assertIn("'Apply'", violations[0])

        unrelated = "      - name: Validate\n        run: gitforgeops validate\n"
        self.assertEqual(
            check_supply_chain.allocation_revision_binding_violations(
                "apply-on-merge.yml", unrelated
            ),
            [],
        )

    def test_dropping_the_allocation_revision_fails_the_policy(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._mirror_repo(Path(directory))
            path = root / ".github/workflows/apply-on-merge.yml"
            path.write_text(
                path.read_text(encoding="utf-8").replace(
                    f"          {check_supply_chain.ALLOCATION_REVISION_BINDING}\n", ""
                ),
                encoding="utf-8",
            )
            violations = self._violations(root)
        self.assertTrue(
            any("GITFORGEOPS_ALLOCATION_REVISION" in item for item in violations),
            violations,
        )

    def test_privileged_reconcile_must_refresh_the_protected_head(self):
        # The concurrency group serializes per environment; it does not move
        # the checkout. Dropping the freshness guard is exactly the bug: the
        # queued run reconciles from a ledger the run ahead of it has already
        # superseded.
        for workflow in ("apply-on-merge.yml", "rotate.yml"):
            with self.subTest(workflow=workflow), tempfile.TemporaryDirectory() as directory:
                root = self._mirror_repo(Path(directory))
                path = root / ".github/workflows" / workflow
                text = path.read_text(encoding="utf-8")
                start = text.index(
                    "      - name: Refresh protected branch and reject stale deployments"
                )
                end = text.index("      - name: ", start + 20)
                path.write_text(text[:start] + text[end:], encoding="utf-8")
                violations = self._violations(root)
                self.assertTrue(
                    any(
                        "must refresh the protected branch" in item
                        for item in violations
                    ),
                    violations,
                )

    def test_freshness_guard_must_precede_every_gateway_step(self):
        # A guard that runs after the binary is built and the bundles are
        # loaded proves nothing: the build already came from the stale tree.
        with tempfile.TemporaryDirectory() as directory:
            root = self._mirror_repo(Path(directory))
            path = root / ".github/workflows/rotate.yml"
            text = path.read_text(encoding="utf-8")
            start = text.index(
                "      - name: Refresh protected branch and reject stale deployments"
            )
            end = text.index("      - name: ", start + 20)
            guard = text[start:end]
            moved = text[:start] + text[end:]
            anchor = moved.index("      - name: Rotate\n")
            path.write_text(moved[:anchor] + guard + moved[anchor:], encoding="utf-8")
            violations = self._violations(root)
        self.assertTrue(
            any(
                "must not run before the freshness guard" in item
                for item in violations
            ),
            violations,
        )

    def test_privileged_checkout_must_name_the_branch_with_full_history(self):
        # `actions/checkout` with no `ref:` selects the triggering commit, and
        # a shallow clone cannot answer the ancestry question at all. The
        # checkout under test is whichever one precedes the guard in that job,
        # not a step with a particular title — a workflow with two privileged
        # jobs legitimately labels them differently.
        for workflow in ("apply-on-merge.yml", "rotate.yml"):
            with self.subTest(workflow=workflow), tempfile.TemporaryDirectory() as directory:
                root = self._mirror_repo(Path(directory))
                path = root / ".github/workflows" / workflow
                text = path.read_text(encoding="utf-8")
                path.write_text(
                    text.replace(
                        "          ref: ${{ github.event.repository.default_branch }}\n",
                        "",
                    ).replace("          fetch-depth: 0\n", ""),
                    encoding="utf-8",
                )
                violations = self._violations(root)
                self.assertTrue(
                    any(
                        "protected branch with enough history" in item
                        for item in violations
                    ),
                    violations,
                )

    def test_every_guarded_job_is_checked_independently(self):
        # Measured across a whole file, `named_step` checks the FIRST guard and
        # leaves a second privileged job's unchecked. A staged promotion needs
        # a second such job, and it needs its own guard.
        contract = check_supply_chain.FRESH_HEAD_WORKFLOWS["apply-on-merge.yml"]
        text = (ROOT / ".github/workflows/apply-on-merge.yml").read_text(
            encoding="utf-8"
        )
        self.assertEqual(
            check_supply_chain.stale_deployment_guard_violations(
                "apply-on-merge.yml", text, contract
            ),
            [],
        )

        # Duplicate the privileged job, then break the copy's guard.
        start = text.index("  apply:\n")
        job = text[start:]
        broken = job.replace("  apply:\n", "  promote:\n", 1).replace(
            '          git merge-base --is-ancestor "$TRIGGER_SHA" "$fresh_head" || {\n',
            "          true || {\n",
            1,
        )
        # A column-zero comment is still inside the YAML `jobs:` mapping; it
        # must not hide the following job from the trusted textual checker.
        violations = check_supply_chain.stale_deployment_guard_violations(
            "apply-on-merge.yml", text + "# staged promotion\n" + broken, contract
        )
        self.assertTrue(
            any("job 'promote'" in item and "is missing" in item for item in violations),
            violations,
        )
        self.assertFalse(
            any("job 'apply'" in item for item in violations), violations
        )

    def test_workflow_jobs_reads_jobs_not_trigger_keys(self):
        # A bare two-space indentation match also collects `on:`'s triggers as
        # "jobs". A per-job security rule silently running against a trigger
        # block is a rule nobody can reason about.
        text = (ROOT / ".github/workflows/apply-on-merge.yml").read_text(
            encoding="utf-8"
        )
        names = [name for name, _ in check_supply_chain.workflow_jobs(text)]
        self.assertIn("apply", names)
        self.assertIn("list-envs", names)
        for trigger in ("push", "schedule", "workflow_dispatch"):
            self.assertNotIn(trigger, names)

    def test_a_gateway_step_deleted_outright_is_still_a_violation(self):
        # "After the guard" alone would let the step be removed entirely. A
        # reconciling job that never loads the credential bundle is not a
        # safer job; it is a differently broken one.
        contract = check_supply_chain.FRESH_HEAD_WORKFLOWS["apply-on-merge.yml"]
        text = (ROOT / ".github/workflows/apply-on-merge.yml").read_text(
            encoding="utf-8"
        )
        for marker in contract["gateway"]:
            with self.subTest(marker=marker):
                stripped = text.replace(marker, "removed-marker")
                self.assertNotEqual(stripped, text)
                violations = check_supply_chain.stale_deployment_guard_violations(
                    "apply-on-merge.yml", stripped, contract
                )
                self.assertTrue(
                    any("must be present" in item for item in violations), violations
                )

    def test_a_reconciling_job_is_identified_by_the_lock_it_holds(self):
        # Identifying the set by "jobs that already carry a guard" cannot
        # report a job for *not* carrying one. The lock is the definition: a
        # job that binds an Environment and serializes on ferrum-apply-<env>
        # reconciles, and must be guarded.
        contract = check_supply_chain.FRESH_HEAD_WORKFLOWS["apply-on-merge.yml"]
        text = (ROOT / ".github/workflows/apply-on-merge.yml").read_text(
            encoding="utf-8"
        )
        self.assertEqual(
            check_supply_chain.stale_deployment_guard_violations(
                "apply-on-merge.yml", text, contract
            ),
            [],
        )

        # Remove the guard entirely: the job is still identified by its lock,
        # so the absence is reported.
        start = text.index(
            "      - name: Refresh protected branch and reject stale deployments"
        )
        end = text.index("      - name: ", start + 20)
        violations = check_supply_chain.stale_deployment_guard_violations(
            "apply-on-merge.yml", text[:start] + text[end:], contract
        )
        self.assertTrue(
            any("must refresh the protected branch" in item for item in violations),
            violations,
        )

        # And a file where NO job holds the lock reconciles nothing. Stripping
        # every occurrence, because the workflow has more than one privileged
        # job and each of them holding the lock is the point.
        for pattern in (
            check_supply_chain.ENVIRONMENT_BINDING,
            check_supply_chain.APPLY_CONCURRENCY_GROUP,
        ):
            with self.subTest(pattern=pattern.pattern):
                mutated = pattern.sub("", text)
                self.assertNotEqual(mutated, text)
                violations = check_supply_chain.stale_deployment_guard_violations(
                    "apply-on-merge.yml", mutated, contract
                )
                self.assertTrue(
                    any("reconciles under the lock" in item for item in violations),
                    violations,
                )

    def test_freshness_guard_must_keep_its_ancestry_test(self):
        # Refreshing the checkout without the ancestry test still lets a re-run
        # of an old workflow deploy — it would simply deploy the new head under
        # the old run's attribution, with no signal that it is stale.
        with tempfile.TemporaryDirectory() as directory:
            root = self._mirror_repo(Path(directory))
            path = root / ".github/workflows/apply-on-merge.yml"
            text = path.read_text(encoding="utf-8")
            start = text.index(
                '          git merge-base --is-ancestor "$TRIGGER_SHA" "$fresh_head" || {'
            )
            end = text.index('          echo "applied_sha=$fresh_head"', start)
            path.write_text(text[:start] + text[end:], encoding="utf-8")
            violations = self._violations(root)
        self.assertTrue(
            any("merge-base --is-ancestor" in item for item in violations), violations
        )

    def test_freshness_guard_must_bind_authorization_to_revision(self):
        # A queued old run may consume newer state-writer output, but it must
        # not apply a later PR's resources or policy under the old PR's label
        # and credential recipient — nor rotate with a later merge's binary,
        # helpers or resources under the dispatched run's environment approval
        # (GHSA-xwxm-vjgq-mxhj).
        self.assertEqual(
            sorted(check_supply_chain.FRESH_HEAD_WORKFLOWS),
            ["apply-on-merge.yml", "rotate.yml"],
        )
        for workflow in check_supply_chain.FRESH_HEAD_WORKFLOWS:
            with self.subTest(workflow=workflow), tempfile.TemporaryDirectory() as directory:
                root = self._mirror_repo(Path(directory))
                path = root / ".github/workflows" / workflow
                text = path.read_text(encoding="utf-8")
                self.assertIn(STDIN_CLASSIFIER, text)
                text = text.replace(STDIN_CLASSIFIER, "          true\n", 1)
                path.write_text(text, encoding="utf-8")
                violations = self._violations(root)
                self.assertTrue(
                    any(
                        workflow in item and "must bind PR attribution" in item
                        for item in violations
                    ),
                    violations,
                )

    def test_rotation_guard_accepts_only_the_trigger_pinned_classifier(self):
        contract = check_supply_chain.FRESH_HEAD_WORKFLOWS["rotate.yml"]
        workflow = (ROOT / ".github/workflows/rotate.yml").read_text(encoding="utf-8")
        self.assertEqual(workflow.count(STDIN_CLASSIFIER), 1)
        self.assertEqual(
            check_supply_chain.stale_deployment_guard_violations(
                "rotate.yml", workflow, contract
            ),
            [],
        )

        def rejected(candidate: str, needle: str) -> None:
            self.assertNotEqual(candidate, workflow)
            violations = check_supply_chain.stale_deployment_guard_violations(
                "rotate.yml", candidate, contract
            )
            self.assertTrue(any(needle in item for item in violations), violations)

        incomplete = "no recognized implementation is complete"
        # Ancestry alone — the shape this replaces.
        rejected(workflow.replace(STDIN_CLASSIFIER, "", 1), incomplete)
        # Strict equality is not a recognized binding either: it would refuse
        # every rotation queued behind an apply's own ledger commit.
        rejected(
            workflow.replace(
                STDIN_CLASSIFIER,
                '          [ "$fresh_head" = "$TRIGGER_SHA" ] || exit 1\n',
                1,
            ),
            incomplete,
        )
        # Not isolated: the refreshed checkout could shadow a classifier import.
        rejected(
            workflow.replace(
                "            python3 -I - classify \\\n",
                "            python3 - classify \\\n",
                1,
            ),
            incomplete,
        )
        # Run from the refreshed checkout it is judging.
        rejected(
            workflow.replace(
                "            python3 -I - classify \\\n",
                "            python3 -I .github/scripts/deployment_scope.py classify \\\n",
                1,
            ),
            incomplete,
        )
        # Without pipefail a failed extraction approves the revision.
        opening = "        run: |\n          set -euo pipefail\n          [[ \"$TRIGGER_SHA\""
        self.assertEqual(workflow.count(opening), 1)
        rejected(
            workflow.replace(opening, opening.replace("set -euo pipefail", "set -eu"), 1),
            "must open with 'set -euo pipefail'",
        )

    def test_the_classifier_is_the_only_recognized_attribution_binding(self):
        # The literal-pathspec binding this replaces was the bug: it rejected
        # every difference, including a merge that schedules no apply of its
        # own, so a queued deployment could be cancelled with nothing left to
        # reconcile it. Accepting it alongside the classifier would let a
        # repository regress to it silently.
        contract = check_supply_chain.FRESH_HEAD_WORKFLOWS["apply-on-merge.yml"]
        workflow = (ROOT / ".github/workflows/apply-on-merge.yml").read_text(
            encoding="utf-8"
        )
        self.assertEqual(
            check_supply_chain.stale_deployment_guard_violations(
                "apply-on-merge.yml", workflow, contract
            ),
            [],
        )
        legacy = workflow.replace(
            STDIN_CLASSIFIER,
            '          git diff --quiet "$TRIGGER_SHA" "$fresh_head" -- . \\\n'
            "            ':(exclude).state/**' ':(exclude)assembled/**'\n",
            1,
        )
        self.assertNotEqual(legacy, workflow, "the classifier binding moved")
        violations = check_supply_chain.stale_deployment_guard_violations(
            "apply-on-merge.yml", legacy, contract
        )
        self.assertTrue(
            any(
                "no recognized implementation is complete" in item
                for item in violations
            ),
            violations,
        )

    def test_the_trigger_pinned_classifier_is_the_recognized_binding(self):
        # Running the classifier extracted from the triggering commit keeps a
        # refreshed head from replacing the program that judges it.
        contract = check_supply_chain.FRESH_HEAD_WORKFLOWS["apply-on-merge.yml"]
        workflow = (ROOT / ".github/workflows/apply-on-merge.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("            python3 -I - classify \\\n", workflow)
        self.assertEqual(
            check_supply_chain.stale_deployment_guard_violations(
                "apply-on-merge.yml", workflow, contract
            ),
            [],
        )
        # Extracting the trusted copy without running it is not a binding.
        unused = workflow.replace(
            "            python3 -I - classify \\\n",
            "            true \\\n",
        )
        self.assertTrue(
            any(
                "no recognized implementation is complete" in item
                for item in check_supply_chain.stale_deployment_guard_violations(
                    "apply-on-merge.yml", unused, contract
                )
            )
        )
        # The retired checkout-executed form lets the refreshed head run its
        # own classifier, so it is no longer a recognized binding — even with
        # the trusted copy still piped in and ignored.
        checkout_executed = workflow.replace(
            "            python3 -I - classify \\\n",
            "            python3 -I .github/scripts/deployment_scope.py classify \\\n",
        )
        self.assertTrue(
            any(
                "no recognized implementation is complete" in item
                for item in check_supply_chain.stale_deployment_guard_violations(
                    "apply-on-merge.yml", checkout_executed, contract
                )
            )
        )

    def test_the_retired_tempfile_classifier_is_no_longer_a_binding(self):
        # The temp-file form ran whatever the destination variable named. With
        # `trusted_classifier=/dev/null` slipped in before the extraction,
        # `python3 /dev/null` is an empty program that approves every revision.
        # The stdin form leaves nothing to redirect, so the temp-file form is
        # retired outright rather than policed line by line (#357).
        contract = check_supply_chain.FRESH_HEAD_WORKFLOWS["apply-on-merge.yml"]
        workflow = (ROOT / ".github/workflows/apply-on-merge.yml").read_text(
            encoding="utf-8"
        )
        self.assertEqual(workflow.count(STDIN_CLASSIFIER), 2)
        self.assertNotIn("trusted_classifier", workflow)
        retired = workflow.replace(STDIN_CLASSIFIER, TEMPFILE_CLASSIFIER)
        extraction = (
            '          git show "${TRIGGER_SHA}:.github/scripts/deployment_scope.py"'
            ' > "$trusted_classifier"\n'
        )
        self.assertEqual(retired.count(extraction), 2)
        redirected = retired.replace(
            extraction, "          trusted_classifier=/dev/null\n" + extraction
        )
        for name, candidate in (("retired", retired), ("redirected", redirected)):
            with self.subTest(form=name):
                violations = check_supply_chain.stale_deployment_guard_violations(
                    "apply-on-merge.yml", candidate, contract
                )
                self.assertEqual(
                    sum(
                        "no recognized implementation is complete" in item
                        for item in violations
                    ),
                    2,
                    violations,
                )

    def test_the_stdin_pinned_classifier_is_the_only_recognized_binding(self):
        # Piping the triggering commit's classifier into the interpreter leaves
        # no destination a candidate could redirect.
        contract = check_supply_chain.FRESH_HEAD_WORKFLOWS["apply-on-merge.yml"]
        workflow = (ROOT / ".github/workflows/apply-on-merge.yml").read_text(
            encoding="utf-8"
        )
        self.assertEqual(workflow.count(STDIN_CLASSIFIER), 2)
        self.assertEqual(
            check_supply_chain.APPLY_REVISION_BINDINGS,
            (check_supply_chain.TRIGGER_CLASSIFIER_STDIN,),
        )
        self.assertEqual(
            check_supply_chain.stale_deployment_guard_violations(
                "apply-on-merge.yml", workflow, contract
            ),
            [],
        )
        # Without `-I` the interpreter searches the working directory — the
        # refreshed checkout under judgement — before the standard library.
        importable = workflow.replace(
            "            python3 -I - classify \\\n",
            "            python3 - classify \\\n",
            1,
        )
        self.assertNotEqual(importable, workflow)
        self.assertTrue(
            any(
                "no recognized implementation is complete" in item
                for item in check_supply_chain.stale_deployment_guard_violations(
                    "apply-on-merge.yml", importable, contract
                )
            )
        )
        # A filter spliced into the pipe hands the interpreter an empty program.
        truncated = workflow.replace(
            '          git show "${TRIGGER_SHA}:.github/scripts/deployment_scope.py" | \\\n',
            '          git show "${TRIGGER_SHA}:.github/scripts/deployment_scope.py" | \\\n'
            "            head -c 0 | \\\n",
            1,
        )
        self.assertNotEqual(truncated, workflow)
        self.assertTrue(
            any(
                "no recognized implementation is complete" in item
                for item in check_supply_chain.stale_deployment_guard_violations(
                    "apply-on-merge.yml", truncated, contract
                )
            )
        )

    def test_the_stdin_pinned_classifier_requires_pipefail(self):
        # Without pipefail a failed extraction feeds `python3 -` an empty
        # program, which exits 0 and approves the revision.
        contract = check_supply_chain.FRESH_HEAD_WORKFLOWS["apply-on-merge.yml"]
        workflow = (ROOT / ".github/workflows/apply-on-merge.yml").read_text(
            encoding="utf-8"
        )
        guard_opening = (
            "        run: |\n"
            "          set -euo pipefail\n"
            '          [[ "$TRIGGER_SHA" =~ ^[0-9a-f]{40}$ ]] || {\n'
        )
        self.assertEqual(workflow.count(guard_opening), 2)
        unset = workflow.replace(
            guard_opening,
            guard_opening.replace("set -euo pipefail", "set -eu"),
            1,
        )
        self.assertTrue(
            any(
                "must open with 'set -euo pipefail'" in item
                for item in check_supply_chain.stale_deployment_guard_violations(
                    "apply-on-merge.yml", unset, contract
                )
            ),
        )
        fetch = "          git fetch --no-tags --force origin \\\n"
        self.assertIn(fetch, workflow)
        reverted = workflow.replace(fetch, "          set +o pipefail\n" + fetch, 1)
        self.assertTrue(
            any(
                "must not change shell options" in item
                for item in check_supply_chain.stale_deployment_guard_violations(
                    "apply-on-merge.yml", reverted, contract
                )
            ),
        )

    def test_a_half_present_attribution_binding_is_still_rejected(self):
        # Dropping the branch argument silently changes what the guard refuses
        # and what its message tells the operator to do.
        contract = check_supply_chain.FRESH_HEAD_WORKFLOWS["apply-on-merge.yml"]
        workflow = (ROOT / ".github/workflows/apply-on-merge.yml").read_text(
            encoding="utf-8"
        )
        half = workflow.replace(' --branch "$DEFAULT_BRANCH"', "", 1)
        self.assertNotEqual(half, workflow)
        violations = check_supply_chain.stale_deployment_guard_violations(
            "apply-on-merge.yml", half, contract
        )
        self.assertTrue(
            any(
                "no recognized implementation is complete" in item
                for item in violations
            ),
            violations,
        )

    def test_apply_trigger_and_supersession_scope_must_be_one_list(self):
        # Dropping a path from the trigger while the classifier still treats it
        # as a deployment input recreates the stranded-apply bug: the merge
        # supersedes a queued run and schedules nothing to replace it.
        with tempfile.TemporaryDirectory() as directory:
            root = self._mirror_repo(Path(directory))
            path = root / ".github/workflows/apply-on-merge.yml"
            path.write_text(
                path.read_text(encoding="utf-8").replace(
                    "      - 'overlays/**'\n", "", 1
                ),
                encoding="utf-8",
            )
            violations = self._violations(root)
        self.assertTrue(
            any(
                "push trigger is missing 'overlays/**'" in item
                for item in violations
            ),
            violations,
        )

    def test_apply_trigger_may_not_schedule_paths_the_classifier_ignores(self):
        # The mirror image: a trigger path the guard calls inert starts an apply
        # for a change that provably cannot affect one.
        with tempfile.TemporaryDirectory() as directory:
            root = self._mirror_repo(Path(directory))
            path = root / ".github/workflows/apply-on-merge.yml"
            path.write_text(
                path.read_text(encoding="utf-8").replace(
                    "      - 'resources/**'\n",
                    "      - 'resources/**'\n      - 'README.md'\n",
                    1,
                ),
                encoding="utf-8",
            )
            violations = self._violations(root)
        self.assertTrue(
            any(
                "schedules applies for 'README.md'" in item for item in violations
            ),
            violations,
        )

    def test_generated_output_may_be_neither_trigger_nor_deployment_input(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._mirror_repo(Path(directory))
            script = root / ".github/scripts/deployment_scope.py"
            script.write_text(
                script.read_text(encoding="utf-8").replace(
                    '    "src/**",\n)', '    "src/**",\n    ".state/**",\n)', 1
                ),
                encoding="utf-8",
            )
            violations = self._violations(root)
        self.assertTrue(
            any(
                "is written by the apply itself and must not be a deployment input"
                in item
                for item in violations
            ),
            violations,
        )
        self.assertTrue(
            any("push trigger is missing '.state/**'" in item for item in violations),
            violations,
        )

    def test_apply_push_trigger_must_stay_path_filtered(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._mirror_repo(Path(directory))
            path = root / ".github/workflows/apply-on-merge.yml"
            text = path.read_text(encoding="utf-8")
            start = text.index("  push:\n")
            end = text.index("\n# `apply` commits state updates")
            path.write_text(
                text[:start] + "  push:\n    branches: [main]\n" + text[end:],
                encoding="utf-8",
            )
            violations = self._violations(root)
        self.assertTrue(
            any(
                "explicit paths filter is required" in item for item in violations
            ),
            violations,
        )

    def test_state_commits_must_not_suppress_required_checks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._mirror_repo(Path(directory))
            path = root / ".github/workflows/rotate.yml"
            path.write_text(
                path.read_text(encoding="utf-8").replace(
                    'in ${INPUT_ENVIRONMENT}"', 'in ${INPUT_ENVIRONMENT} [skip ci]"'
                ),
                encoding="utf-8",
            )
            violations = self._violations(root)
        self.assertTrue(
            any("[skip ci]" in item for item in violations), violations
        )

    def test_resolved_credential_file_must_live_under_runner_temp(self):
        # A bare `mktemp` lands in a /tmp that self-hosted runners share
        # between jobs and never clean.
        with tempfile.TemporaryDirectory() as directory:
            root = self._mirror_repo(Path(directory))
            path = root / ".github/workflows/rotate.yml"
            path.write_text(
                path.read_text(encoding="utf-8").replace(
                    'creds_file="${RUNNER_TEMP:-/tmp}/ferrum-creds-',
                    'creds_file="/tmp/ferrum-creds-',
                ),
                encoding="utf-8",
            )
            violations = self._violations(root)
        self.assertTrue(
            any("under $RUNNER_TEMP" in item for item in violations), violations
        )

    def test_release_must_attest_every_published_image_name(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._mirror_repo(Path(directory))
            path = root / ".github/workflows/release.yml"
            text = path.read_text(encoding="utf-8")
            start = text.index("      - name: Publish signed Docker Hub build provenance")
            end = text.index("      - name: Bind image digest into build-input record")
            path.write_text(text[:start] + text[end:], encoding="utf-8")
            violations = self._violations(root)
        self.assertTrue(
            any("every published image name" in item for item in violations), violations
        )
        self.assertTrue(
            any("missing subject" in item for item in violations), violations
        )

    def test_release_push_trigger_ignores_ledger_commits_and_keeps_tags(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._mirror_repo(Path(directory))
            path = root / ".github/workflows/release.yml"
            path.write_text(
                path.read_text(encoding="utf-8").replace("      - '.state/**'\n", ""),
                encoding="utf-8",
            )
            violations = self._violations(root)
        self.assertTrue(
            any("ignore ledger-only commits" in item for item in violations), violations
        )

    def test_release_gate_must_name_upstream_rather_than_test_for_a_fork(self):
        # A "Use this template" copy is not a fork, so a fork test would let
        # every customer repository try to publish the upstream image.
        with tempfile.TemporaryDirectory() as directory:
            root = self._mirror_repo(Path(directory))
            path = root / ".github/workflows/release.yml"
            path.write_text(
                path.read_text(encoding="utf-8").replace(
                    "if: github.repository == 'ferrum-edge/ferrum-edge-git-forge-ops'"
                    " || vars.GITFORGEOPS_RELEASE_ENABLED == 'true'",
                    "if: github.event.repository.fork == false"
                    " || vars.GITFORGEOPS_RELEASE_ENABLED == 'true'",
                ),
                encoding="utf-8",
            )
            violations = self._violations(root)
        self.assertTrue(
            any("never publishes" in item for item in violations), violations
        )
        self.assertTrue(
            any("does not distinguish a template copy" in item for item in violations),
            violations,
        )

    def test_release_gate_must_cover_both_jobs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._mirror_repo(Path(directory))
            path = root / ".github/workflows/release.yml"
            text = path.read_text(encoding="utf-8")
            gate = (
                "    if: github.repository == 'ferrum-edge/ferrum-edge-git-forge-ops'"
                " || vars.GITFORGEOPS_RELEASE_ENABLED == 'true'\n"
            )
            path.write_text(text.replace(gate, "", 1), encoding="utf-8")
            violations = self._violations(root)
        self.assertTrue(
            any("never publishes" in item for item in violations), violations
        )

    def test_settings_audit_is_dispatchable_behind_a_ref_preflight(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._mirror_repo(Path(directory))
            path = root / ".github/workflows/settings-audit.yml"
            path.write_text(
                path.read_text(encoding="utf-8").replace(
                    "  workflow_dispatch:\n", ""
                ),
                encoding="utf-8",
            )
            violations = self._violations(root)
        self.assertTrue(
            any("dispatchable audit is missing" in item for item in violations),
            violations,
        )

        with tempfile.TemporaryDirectory() as directory:
            root = self._mirror_repo(Path(directory))
            path = root / ".github/workflows/settings-audit.yml"
            text = path.read_text(encoding="utf-8")
            start = text.index("      - name: Require protected default branch")
            end = text.index("      - name: Check out protected default branch")
            path.write_text(text[:start] + text[end:] + text[start:end], encoding="utf-8")
            violations = self._violations(root)
        self.assertTrue(
            any("before the audit token is bound" in item for item in violations),
            violations,
        )

    def test_audit_token_is_fenced_by_its_own_environment(self):
        # As a repository secret the administration-read token was released to
        # whatever definition a dispatched ref carried, so any branch a
        # collaborator can push was a path to it.
        with tempfile.TemporaryDirectory() as directory:
            root = self._mirror_repo(Path(directory))
            path = root / ".github/workflows/settings-audit.yml"
            path.write_text(
                path.read_text(encoding="utf-8").replace(
                    "    environment: settings-audit\n", "", 1
                ),
                encoding="utf-8",
            )
            violations = self._violations(root)
        self.assertTrue(
            any("environment: settings-audit" in item for item in violations),
            violations,
        )

    def test_no_other_workflow_may_read_the_audit_token(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._mirror_repo(Path(directory))
            path = root / ".github/workflows/drift-check.yml"
            path.write_text(
                path.read_text(encoding="utf-8").replace(
                    "          FERRUM_GATEWAY_URL: ${{ secrets.FERRUM_GATEWAY_URL }}\n",
                    "          FERRUM_GATEWAY_URL: ${{ secrets.FERRUM_GATEWAY_URL }}\n"
                    "          GH_TOKEN: ${{ secrets.SETTINGS_AUDIT_TOKEN }}\n",
                    1,
                ),
                encoding="utf-8",
            )
            violations = self._violations(root)
        self.assertTrue(
            any(
                "audit token" in item and "drift-check.yml" in item
                for item in violations
            ),
            violations,
        )

    def test_the_audit_environment_binding_precedes_the_token(self):
        # Job-level `environment:` gates the whole job, so the binding must be
        # part of the same job that reads the token — not a later addition
        # somewhere the secret is already in scope.
        workflow = (ROOT / ".github/workflows/settings-audit.yml").read_text(
            encoding="utf-8"
        )
        self.assertLess(
            workflow.index("    environment: settings-audit\n"),
            workflow.index("GH_TOKEN: ${{ secrets.SETTINGS_AUDIT_TOKEN }}"),
        )
        self.assertEqual(workflow.count("secrets.SETTINGS_AUDIT_TOKEN"), 1)

    def test_trusted_review_pins_the_triggering_workflow_definition(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._mirror_repo(Path(directory))
            path = root / ".github/workflows/trusted-pr-review.yml"
            path.write_text(
                path.read_text(encoding="utf-8").replace(
                    "          EXPECTED_WORKFLOW_PATH: .github/workflows/validate-pr.yml\n",
                    "",
                ),
                encoding="utf-8",
            )
            violations = self._violations(root)
        self.assertTrue(
            any("EXPECTED_WORKFLOW_PATH" in item for item in violations), violations
        )

    def test_trusted_review_serializes_runs_for_one_reviewed_commit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._mirror_repo(Path(directory))
            path = root / ".github/workflows/trusted-pr-review.yml"
            path.write_text(
                path.read_text(encoding="utf-8").replace(
                    "  group: trusted-pr-review-${{ github.event.workflow_run.head_sha }}\n",
                    "  group: trusted-pr-review\n",
                ),
                encoding="utf-8",
            )
            violations = self._violations(root)
        self.assertTrue(
            any("trusted-pr-review-" in item for item in violations), violations
        )

    def test_mirrored_repository_is_a_clean_baseline(self):
        # Every mutation test above asserts the checker FAILS. That only proves
        # something if the unmutated mirror passes — otherwise a broken helper
        # would make them all green for the wrong reason.
        with tempfile.TemporaryDirectory() as directory:
            root = self._mirror_repo(Path(directory))
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--root", str(root)],
                check=False,
                text=True,
                capture_output=True,
            )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    # -- helpers ------------------------------------------------------------

    def _cargo_audit_workflow(self, pin: str) -> str:
        workflow = (ROOT / ".github/workflows/security.yml").read_text(encoding="utf-8")
        for current_pin in CARGO_AUDIT_ACTION_PINS:
            if f"uses: {current_pin}" in workflow:
                return workflow.replace(f"uses: {current_pin}", f"uses: {pin}", 1)
        self.fail("security.yml must use the reviewed cargo-audit installer pin")

    def _trusted_policy_runner_source(self) -> str:
        """The inline runner `security.yml` feeds the trusted checker."""
        workflow = (ROOT / ".github/workflows/security.yml").read_text(
            encoding="utf-8"
        )
        start = workflow.index(check_supply_chain.TRUSTED_POLICY_RUNNER + " <<'PY'\n")
        body = workflow.index("\n", start) + 1
        end = workflow.index("\n          PY\n", body)
        return textwrap.dedent(workflow[body:end]) + "\n"

    def _mirror_repo(self, root: Path) -> Path:
        """Copy the policy-relevant tree so a test can mutate one file.

        The checker reads workflows, the Dockerfile, CODEOWNERS, the toolchain
        pin, and the validator checksum policy, so all of them come along.
        """
        for relative in (
            ".github/workflows",
            ".github/scripts/check_supply_chain.py",
            ".github/scripts/credential_bundles.py",
            ".github/scripts/deployment_scope.py",
            ".github/scripts/install-ferrum-edge.sh",
            ".github/scripts/refresh-ferrum-edge-pin.sh",
            ".github/ferrum-edge-checksums.txt",
            ".github/CODEOWNERS",
            "Dockerfile",
            ".dockerignore",
            "rust-toolchain.toml",
            "src/secrets/bundle.rs",
            "src/import/mod.rs",
        ):
            source = ROOT / relative
            destination = root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            if source.is_dir():
                shutil.copytree(source, destination)
            else:
                shutil.copy2(source, destination)
        return root

    def _violations(self, root: Path) -> list[str]:
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--root", str(root)],
            check=False,
            text=True,
            capture_output=True,
        )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        return [
            line.strip().lstrip("- ")
            for line in result.stderr.splitlines()
            if line.startswith("  - ")
        ]


if __name__ == "__main__":
    unittest.main()
