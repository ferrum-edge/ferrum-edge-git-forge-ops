import copy
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


class SupplyChainPolicyTests(unittest.TestCase):
    ENVIRONMENT_BOUND_WORKFLOWS = (
        ".github/workflows/apply-on-merge.yml",
        ".github/workflows/trusted-pr-review.yml",
        ".github/workflows/drift-check.yml",
        ".github/workflows/rotate.yml",
        ".github/workflows/materialize-file.yml",
    )
    HANDOFF_FENCE = "outside the pinned credential hand-off"

    _PARSED = {}

    def _probe_document(self, workflow):
        # Parse each shipped workflow once; every test mutates its own copy.
        if workflow not in self._PARSED:
            text = (ROOT / workflow).read_text(encoding="utf-8")
            self._PARSED[workflow] = check_supply_chain.parse_workflow(text)
        return copy.deepcopy(self._PARSED[workflow])

    def _step(self, document, job, name):
        return next(step for step in document["jobs"][job]["steps"] if step.get("name") == name)

    def _first_steps(self, document):
        return next(
            job["steps"] for job in document["jobs"].values()
            if isinstance(job, dict) and isinstance(job.get("steps"), list)
        )

    def _guarded_bindings(self, workflow, document):
        violations = check_supply_chain.workflow_channel_violations(workflow, document)
        violations += check_supply_chain.run_expression_violations(workflow, document)
        violations += check_supply_chain.run_expression_source_violations(workflow, document)
        if workflow == ".github/workflows/drift-check.yml":
            return violations + check_supply_chain.monitoring_jwt_binding_violations(
                workflow, document
            )
        return violations + check_supply_chain.probe_consumer_binding_violations(
            workflow, document
        )

    def _shipped_workflows(self):
        return sorted(
            path.relative_to(ROOT).as_posix()
            for path in (ROOT / ".github/workflows").iterdir()
            if path.suffix in check_supply_chain.WORKFLOW_SUFFIXES
        )

    def test_shipped_workflows_pass_the_text_fences(self):
        for workflow in self._shipped_workflows():
            with self.subTest(workflow=workflow):
                self.assertEqual(self._guarded_bindings(workflow, self._probe_document(workflow)), [])

    def test_env_file_writes_are_refused_in_every_workflow(self):
        scripts = (
            'echo "FERRUM_NAMESPACE=other" >> "$GITHUB_ENV"',
            'echo x >> "${GITHUB_ENV}"',
            "echo x >>$GITHUB_ENV",
            'echo x >> "$GITHUB_""ENV"',
            "echo x >> \"$GITHUB_E\\NV\"",
            'echo x >> "$GITHUB_E\\\nNV"',
            "echo x >> $'GITHUB_ENV'",
            # Outside quotes Bash reads `\\U` as `U`; plain stripping does too,
            # with or without a `$'` elsewhere in the scalar.
            'echo x >> "$(printenv GITH\\UB_ENV)"',
            "# $'\necho X >> \"$(printenv GITH\\UB_ENV)\"",
            'echo x >> "$(printenv GITH\\UB_ENV)"; : $\'x\'',
            'echo "$PWD/bin" >> "$(printenv GITH\\UB_PATH)"',
            "# $'\necho X >> \"$(printenv GITH\\UB_PATH)\"",
            'p=$(printenv GITH\\UB_OUTPUT); echo X=1 >> "${p/output/env}"',
            "# $'\np=$(printenv GITH\\UB_OUTPUT); echo X=1 >> \"${p/output/env}\"",
            'echo x >> "$(printenv GITH\\UB_STATE)"',
            "# $'\necho x >> \"$GITH\\UB_STATE\"",
            'echo x >> "$RUNNER_TEMP"/_runner_file_\\commands/x',
            "echo x | tee -a $GITHUB_ENV",
            'echo x | tee -a "$GITHUB_PATH"',
            "printf '%s\\n' \"$PWD/bin\" > \"$GITHUB_PATH\"",
            'cat <<< "BASH_ENV=inject.sh" >> "$GITHUB_ENV"',
            'tee -a "$GITHUB_ENV" <<< "FERRUM_ENV=other"',
            "cat >> \"$GITHUB_ENV\" <<'EOF'\nX=1\nEOF",
            'echo x >> "${{ env.GITHUB_ENV }}"',
            'echo x >> "${{ github.env }}"',
            'echo x >> "${{ GITHUB . PATH }}"',
            "echo x >> \"${{ github['env'] }}\"",
            "export BASH_ENV=./startup.sh",
            'destination="$GITHUB_ENV"\necho x >> "$destination"',
            '# echo x >> "$GITHUB_ENV"\ntrue',
            "true # >> $GITHUB_ENV",
            'echo x >> "$GITHUB_STATE"',
            "echo x > ${GITHUB_STATE}",
            "echo x >| $GITHUB_STATE",
            # The runner's file-command files share one directory and suffix,
            # so the output and summary paths derive the env and path files.
            'echo "X=1" >> "${GITHUB_OUTPUT/set_output_/set_env_}"',
            'echo "$PWD/bin" >> "${GITHUB_STEP_SUMMARY/step_summary_/add_path_}"',
            'echo "X=1" >> ${GITHUB_OUTPUT%/*}/set_env_*',
            'echo "X=1" >> "$(dirname "$GITHUB_OUTPUT")"/set_env_*',
            'echo "X=1" >> "$RUNNER_TEMP/_runner_file_commands/set_env_$suffix"',
            'echo "X=1" >> "$RUNNER_TEMP"/_RUNNER_FILE_COMMANDS/"$name"',
            'name=save_state_x; echo x >> "$name"',
            'echo x >> "${GITHUB_OUTPUT#*/}"',
            'echo x >> "${GITHUB_OUTPUT:-/dev/null}"',
            'echo x >> "${!GITHUB_OUTPUT}"',
            'directory=$(dirname "$GITHUB_STEP_SUMMARY")',
            'destination="$GITHUB_OUTPUT"\necho x >> "$destination"',
            'cp payload "$GITHUB_OUTPUT"',
            'echo x > "$GITHUB_OUTPUT"',
            'echo x | tee "$GITHUB_OUTPUT"',
            'report --summary "$GITHUB_OUTPUT"',
        )
        for workflow in self._shipped_workflows():
            for script in scripts:
                with self.subTest(workflow=workflow, script=script):
                    document = self._probe_document(workflow)
                    self._first_steps(document).insert(0, {"name": "Bypass", "run": script})
                    violations = check_supply_chain.workflow_channel_violations(
                        workflow, document
                    )
                    self.assertTrue(
                        any(self.HANDOFF_FENCE in item for item in violations), violations
                    )
        for script in (
            'echo "result=passed" >> "$GITHUB_OUTPUT"',
            "{\n  echo a=1\n  echo b=2\n} >>\"$GITHUB_OUTPUT\"",
            'echo "## Report" >> "$GITHUB_STEP_SUMMARY"',
            'tee -a "$GITHUB_STEP_SUMMARY" <<< "done"',
            'echo x | tee -a "$GITHUB_OUTPUT"',
            "echo x >> ${GITHUB_OUTPUT}",
            "cat >> \"$GITHUB_STEP_SUMMARY\" <<'MSG'\ndone\nMSG",
            'python3 report.py --summary "$GITHUB_STEP_SUMMARY" || true',
            'cd "$GITHUB_WORKSPACE" && echo "$GITHUB_RUN_ID" > /dev/null',
        ):
            with self.subTest(allowed=script):
                workflow = ".github/workflows/rust-ci.yml"
                document = self._probe_document(workflow)
                self._first_steps(document).insert(0, {"name": "Output", "run": script})
                self.assertEqual(
                    check_supply_chain.workflow_channel_violations(workflow, document), []
                )

    def test_env_file_channel_keys_and_dynamic_env_are_refused(self):
        for workflow in self._shipped_workflows():
            for scope in ("workflow", "job", "step"):
                for key in (
                    "BASH_ENV", "bash_env", "ENV", "GITHUB_ENV", "GITHUB_PATH",
                    "GITHUB_OUTPUT", "github_step_summary", "GITHUB_STATE",
                ):
                    with self.subTest(workflow=workflow, scope=scope, key=key):
                        document = self._probe_document(workflow)
                        steps = self._first_steps(document)
                        step = {"name": "Startup", "run": "true", "env": {key: "inject"}}
                        if scope == "workflow":
                            document["env"] = {key: "inject"}
                        elif scope == "job":
                            job = next(
                                job for job in document["jobs"].values()
                                if isinstance(job, dict) and job.get("steps") is steps
                            )
                            job["env"] = {key: "inject"}
                        else:
                            steps.insert(0, step)
                        self.assertTrue(
                            check_supply_chain.workflow_channel_violations(workflow, document)
                        )
                with self.subTest(workflow=workflow, scope=scope, dynamic=True):
                    document = self._probe_document(workflow)
                    steps = self._first_steps(document)
                    dynamic = "${{ fromJSON(vars.ENVIRONMENT) }}"
                    if scope == "workflow":
                        document["env"] = dynamic
                    elif scope == "job":
                        next(
                            job for job in document["jobs"].values()
                            if isinstance(job, dict) and job.get("steps") is steps
                        )["env"] = dynamic
                    else:
                        steps.insert(0, {"name": "Startup", "run": "true", "env": dynamic})
                    violations = check_supply_chain.workflow_channel_violations(
                        workflow, document
                    )
                    self.assertTrue(
                        any("dynamic env sources are forbidden" in item for item in violations),
                        violations,
                    )

    def test_shell_startup_and_loader_env_keys_are_refused(self):
        refused = "shell startup or loader variable"
        keys = (
            "ENV", "env", "BASH_ENV", "BASH_FUNC_gitforgeops", "bash_func_x", "SHELLOPTS",
            "shellopts", "BASHOPTS", "BashOpts", "PS4", "ps4", "LD_PRELOAD", "ld_preload",
            "LD_LIBRARY_PATH", "Ld_Library_Path", "LD_AUDIT", "ld_audit", "LD_BIND_NOW",
            "LD_PRELOADED", "Ld_",
        )
        for workflow in self._shipped_workflows():
            for scope in ("workflow", "job", "step"):
                for key in keys:
                    with self.subTest(workflow=workflow, scope=scope, key=key):
                        document = self._probe_document(workflow)
                        steps = self._first_steps(document)
                        if scope == "workflow":
                            document["env"] = {key: "x"}
                        elif scope == "job":
                            next(
                                job for job in document["jobs"].values()
                                if isinstance(job, dict) and job.get("steps") is steps
                            )["env"] = {key: "x"}
                        else:
                            steps.insert(0, {"name": "Startup", "run": "true", "env": {key: "x"}})
                        violations = check_supply_chain.workflow_channel_violations(
                            workflow, document
                        )
                        self.assertTrue(any(refused in item for item in violations), violations)
        workflow = ".github/workflows/rust-ci.yml"
        for key in (
            "PS3", "FERRUM_PS4", "FERRUM_LD_PRELOAD", "OLD_PRELOAD", "LDAP_URL",
            "BASH_FUNCTIONS", "SHELL_OPTIONS",
        ):
            with self.subTest(allowed=key):
                document = self._probe_document(workflow)
                self._first_steps(document).insert(
                    0, {"name": "Near miss", "run": "true", "env": {key: "x"}}
                )
                self.assertEqual(
                    check_supply_chain.workflow_channel_violations(workflow, document), []
                )

    def test_run_interpolations_may_not_splice_a_name(self):
        for workflow in self._shipped_workflows():
            for script in (
                'echo x >> "$GITHUB_${{ matrix.suffix }}"',
                "echo x >> \"$GITHUB_E${{ '' }}NV\"",
                'echo x >> "$${{ matrix.name }}"',
                'echo x >> "${{ matrix.prefix }}${{ matrix.suffix }}"',
                "export FERRUM_${{ matrix.suffix }}=other",
                'echo x >> "${${{ matrix.name }}}"',
                # Bash joins adjacent quoted words, so quotes do not separate.
                'export "${{ env.A }}""${{ env.B }}"=x',
                'export FERRUM_"${{ matrix.suffix }}"=other',
                "echo x >> \"$GITHUB_\"'${{ matrix.suffix }}'",
                'echo x >> "$GITHUB_"\\\n"${{ matrix.suffix }}"',
                "echo x >> $GITHUB_\\${{ matrix.suffix }}",
            ):
                with self.subTest(workflow=workflow, script=script):
                    document = self._probe_document(workflow)
                    self._first_steps(document).insert(0, {
                        "name": "Splice", "env": {"A": "FERRUM_", "B": "NAMESPACE"},
                        "run": script,
                    })
                    violations = check_supply_chain.workflow_channel_violations(
                        workflow, document
                    )
                    self.assertTrue(
                        any("may not adjoin a name character" in item for item in violations),
                        violations,
                    )
        workflow = ".github/workflows/rust-ci.yml"
        document = self._probe_document(workflow)
        self._first_steps(document).insert(0, {
            "name": "Quoted interpolation",
            "run": 'echo "${{ matrix.os }}" ".state/${{ matrix.os }}.json" '
                   '"assembled/${{ matrix.os }}-mesh.yaml"',
        })
        self.assertEqual(check_supply_chain.workflow_channel_violations(workflow, document), [])

    def test_computed_github_context_access_is_refused_in_every_workflow(self):
        expressions = (
            "github[format('{0}{1}', 'e', 'nv')]",
            "github[format('{0}{1}', 'pa', 'th')]",
            "GITHUB [ format('{0}{1}', 'E', 'NV') ]",
            "github[join(fromJSON('[\"e\",\"nv\"]'), '')]",
            "github[vars.CHANNEL]",
            "github.event[vars.CHANNEL]",
            "format('{1}', '}}', github[format('{0}{1}', 'e', 'nv')])",
            "fromJSON(format('{1}', '}}', toJSON(github))).env",
            "toJSON(github)",
            "github.*",
            "github.env", "github.path", "github.output",
            "github['env']", "github['path']",
        )
        for workflow in self._shipped_workflows():
            for expression in expressions:
                for source in ("run", "comment", "inline-comment", "env", "with", "sequence", "if"):
                    with self.subTest(workflow=workflow, expression=expression, source=source):
                        document = self._probe_document(workflow)
                        step = {"name": "Inject startup", "run": "true"}
                        destination = "${{ " + expression + " }}"
                        if source == "run":
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
                        self._first_steps(document).insert(0, step)
                        violations = check_supply_chain.workflow_channel_violations(
                            workflow, document
                        )
                        self.assertTrue(
                            any(
                                "GitHub context access is forbidden" in item
                                or self.HANDOFF_FENCE in item
                                for item in violations
                            ),
                            violations,
                        )

    def test_unrecognized_raw_expressions_fail_closed(self):
        for script in (
            "# ${{ github[vars.CHANNEL] }\ntrue",
            "true # ${{ format('unterminated) }}",
        ):
            with self.subTest(script=script):
                violations = check_supply_chain.workflow_channel_violations(
                    "guarded.yml", {"jobs": {"job": {"steps": [{"run": script}]}}}
                )
                self.assertTrue(
                    any("unrecognized GitHub expression syntax" in item for item in violations),
                    violations,
                )

    def test_scan_text_reads_split_names_as_bash_does(self):
        for text in (
            "GITHUB_ENV", 'GITHUB_""ENV', "GITHUB_''ENV", "GITHUB_E\\NV", "GITHUB_E\\\nNV",
            "$'GITHUB_ENV'", 'GITHUB_E$""NV', "github_env", "Github_Env",
            "GITH\\UB_ENV", "# $'\nGITH\\UB_ENV", "$'' GITH\\UB_ENV",
        ):
            with self.subTest(text=text):
                self.assertIn("github_env", check_supply_chain._scan_text(text))

    def test_scan_text_strips_escapes_without_decoding(self):
        scan = check_supply_chain._scan_text
        # Escapes are stripped, never decoded, whether or not `$'` appears.
        self.assertEqual(scan("$'\\x67'itforgeops"), "x67itforgeops")
        self.assertEqual(scan("# $'\nprintenv GITH\\UB_ENV"), "# \nprintenv github_env")
        self.assertEqual(scan("_runner_file_\\commands"), "_runner_file_commands")

    def test_ansi_c_quoting_is_refused_in_every_workflow(self):
        refused = "ANSI-C quoting (`$'...'`) is not supported"
        scripts = (
            "echo x >> $'GITHUB_\\x45NV'",
            "echo x >> $'GITHUB_\\105NV'",
            "echo x >> $'GITHUB_\\u0045NV'",
            "echo x >> $'GIT\\x48'\\UB_ENV",
            "echo x >> \"$RUNNER_TEMP\"/$'_runner_file_\\x63ommands'/x",
            "$'\\x67'itforgeops apply --auto-approve",
            "# $'\necho X >> \"$(printenv GITH\\UB_ENV)\"",
            # Fail closed without a lexer: a plain quoted `$` before a quote
            # and a `$` continued onto a quote are refused too.
            "echo '$''x'",
            "echo $\\\n'x'",
        )
        for workflow in self._shipped_workflows():
            for script in scripts:
                with self.subTest(workflow=workflow, script=script):
                    document = self._probe_document(workflow)
                    self._first_steps(document).insert(0, {"name": "Quoted", "run": script})
                    violations = check_supply_chain.workflow_channel_violations(
                        workflow, document
                    )
                    self.assertTrue(any(refused in item for item in violations), violations)
            with self.subTest(workflow=workflow, key="env"):
                document = self._probe_document(workflow)
                self._first_steps(document).insert(
                    0, {"name": "Quoted", "env": {"VALUE": "$'\\x41'"}, "run": "true"}
                )
                violations = check_supply_chain.workflow_channel_violations(workflow, document)
                self.assertTrue(any(refused in item for item in violations), violations)
        for script in ('echo "$x"', "echo '$x'", 'echo $"x"', "echo \"it's $HOME\""):
            with self.subTest(allowed=script):
                workflow = ".github/workflows/rust-ci.yml"
                document = self._probe_document(workflow)
                self._first_steps(document).insert(0, {"name": "Quoted", "run": script})
                violations = check_supply_chain.workflow_channel_violations(workflow, document)
                self.assertFalse(any(refused in item for item in violations), violations)

    def test_program_level_writes_are_out_of_scope(self):
        # The fence reads workflow text. A command that computes the channel
        # name at run time writes $GITHUB_ENV without spelling it; that is
        # program behavior, left to review of every workflow change (#476).
        workflow = ".github/workflows/rust-ci.yml"
        for script in (
            'name=GITHUB_E; eval "echo x >> \\$${name}NV"',
            "echo ZWNobyB4ID4+ICRHSVRIVUJfRU5WCg== | base64 -d | bash",
            "python3 -c 'import os; open(os.environ[\"GITHUB_\" + \"E\" + \"NV\"], \"a\")'",
            # A sibling file-command path found on the filesystem, not
            # derived from a spelled name.
            'for f in "$RUNNER_TEMP"/*/set_e*; do echo X=1 >> "$f"; done',
            '{ p=$(readlink /proc/$$/fd/1); echo X=1 >> "${p/output/env}"; } >> "$GITHUB_OUTPUT"',
            "p=$(env | sed -n 's/^GITHUB_OUT[P]UT=//p'); echo X=1 >> \"${p/output/env}\"",
        ):
            with self.subTest(script=script):
                document = self._probe_document(workflow)
                self._first_steps(document).insert(0, {"name": "Program", "run": script})
                self.assertEqual(
                    check_supply_chain.workflow_channel_violations(workflow, document), []
                )

    def test_indirect_expansion_is_refused_in_every_workflow(self):
        for workflow in self._shipped_workflows():
            for script in (
                'name=GITHUB_E; name=${name}NV; echo x >> "${!name}"',
                'echo "${!prefix@}"',
            ):
                with self.subTest(workflow=workflow, script=script):
                    document = self._probe_document(workflow)
                    self._first_steps(document).insert(0, {"name": "Indirect", "run": script})
                    violations = check_supply_chain.workflow_channel_violations(
                        workflow, document
                    )
                    self.assertTrue(
                        any("indirect expansion" in item for item in violations), violations
                    )

    def _closes_its_quotes(self, line):
        quote, escaped = "", False
        for character in line:
            if escaped:
                escaped = False
            elif character == "\\" and quote != "'":
                escaped = True
            elif quote:
                if character == quote:
                    quote = ""
            elif character in "'\"":
                quote = character
        return not quote and not escaped

    def test_pinned_shapes_are_complete_lines(self):
        # `pinned_run_matches` may drop `#` lines between entries only because
        # no entry leaves a quote, here-document or continuation open.
        shapes = (
            check_supply_chain.PROBE_VERIFY_RUN,
            check_supply_chain.APPLY_ENVIRONMENT_LIST_RUN,
            *check_supply_chain.CREDENTIAL_HANDOFF_SHAPES.values(),
        )
        for shape in shapes:
            for entry in shape:
                with self.subTest(entry=entry):
                    self.assertTrue(self._closes_its_quotes(entry))
                    self.assertFalse(entry.endswith("\\"))
                    self.assertIsNone(re.search(r"(?<!<)<<(?!<)", entry))
                    for line in entry.split("\n"):
                        self.assertEqual(line, line.strip(" \t"))
                        self.assertNotEqual(line, "")
                        self.assertFalse(line.startswith("#"))

    def test_pinned_run_matches_ignores_only_comment_lines(self):
        shape = check_supply_chain.CREDENTIAL_HANDOFF_RUN
        script = "\n".join(shape)
        self.assertTrue(check_supply_chain.pinned_run_matches(script, shape))
        self.assertTrue(check_supply_chain.pinned_run_matches(
            "# A note that names $GITHUB_ENV.\n\n" + "\n".join(
                "\t  " + line + "  " for line in shape
            ) + "\n# trailing note\n", shape,
        ))
        for changed in (
            "# ${{ vars.NOTE }}\n" + script,
            script + "\n# ${{ github.sha }}",
            script + "\necho OTHER=x >> \"$GITHUB_ENV\"",
            script.replace("set -euo pipefail", "set -euo pipefail # strict"),
            script.replace(shape[1], 'creds_file="$PAYLOAD"'),
            ": '\n# '; echo x >> \"$GITHUB_ENV\"; : '\n'\n" + script,
            "\n".join(shape[:-1]),
            "\n".join(check_supply_chain.APPLY_CREDENTIAL_HANDOFF_RUN),
        ):
            with self.subTest(changed=changed):
                self.assertFalse(check_supply_chain.pinned_run_matches(changed, shape))
        # A multi-line entry matches its lines consecutively: a `#` line inside
        # a quoted jq program is jq text, and jq continues a comment ending in
        # a backslash onto the next line.
        shape = check_supply_chain.APPLY_ENVIRONMENT_LIST_RUN
        script = "\n".join(shape)
        guard = next(entry for entry in shape if entry.startswith("jq -e '\n"))
        lines = guard.split("\n")
        self.assertTrue(check_supply_chain.pinned_run_matches(script, shape))
        self.assertTrue(check_supply_chain.pinned_run_matches(
            script.replace(guard, "# The guard.\n\n" + guard), shape
        ))
        for changed in (
            script.replace(guard, "\n".join([lines[0], "# skip \\", *lines[1:]])),
            script.replace(guard, "\n".join([*lines[:2], "", *lines[2:]])),
            script.replace(guard, "\n".join([lines[0], *lines[2:]])),
            script.replace(guard + "\n", ""),
        ):
            with self.subTest(changed=changed):
                self.assertNotEqual(changed, script)
                self.assertFalse(check_supply_chain.pinned_run_matches(changed, shape))

    def test_credential_handoff_is_the_only_env_file_write(self):
        for workflow in check_supply_chain.CREDENTIAL_HANDOFF_SHAPES:
            document = self._probe_document(workflow)
            self.assertEqual(
                check_supply_chain.workflow_channel_violations(workflow, document), []
            )
            for mutation in (
                "appended-write", "rebound-file", "comment-expression", "shell",
                "working-directory", "uses", "job-defaults", "workflow-defaults",
                "step-env", "job-driver", "workflow-driver", "renamed",
            ):
                with self.subTest(workflow=workflow, mutation=mutation):
                    document = self._probe_document(workflow)
                    job = next(
                        job for job in document["jobs"].values()
                        if isinstance(job, dict) and any(
                            step.get("name") == check_supply_chain.BUNDLE_LOADER_STEP
                            for step in job.get("steps", [])
                        )
                    )
                    loader = next(
                        step for step in job["steps"]
                        if step.get("name") == check_supply_chain.BUNDLE_LOADER_STEP
                    )
                    if mutation == "appended-write":
                        loader["run"] += '\necho "OTHER=x" >> "$GITHUB_ENV"'
                    elif mutation == "rebound-file":
                        loader["run"] += '\ncreds_file="$PAYLOAD"'
                    elif mutation == "comment-expression":
                        loader["run"] = "# ${{ vars.NOTE }}\n" + loader["run"]
                    elif mutation in ("shell", "working-directory", "uses"):
                        loader[mutation] = "alternate"
                    elif mutation == "job-defaults":
                        job["defaults"] = {"run": {"shell": "sh {0}"}}
                    elif mutation == "workflow-defaults":
                        document["defaults"] = {"run": {"shell": "sh {0}"}}
                    elif mutation == "step-env":
                        loader["env"]["RUNNER_TEMP"] = "/tmp"
                    elif mutation == "job-driver":
                        job["env"] = {"RUNNER_TEMP": "\nBASH_ENV=inject.sh"}
                    elif mutation == "workflow-driver":
                        document["env"] = {"github_run_id": "1"}
                    else:
                        loader["name"] = "Load bundles"
                    violations = check_supply_chain.workflow_channel_violations(
                        workflow, document
                    )
                    self.assertTrue(
                        any(self.HANDOFF_FENCE in item for item in violations), violations
                    )
            with self.subTest(workflow=workflow, mutation="annotated"):
                document = self._probe_document(workflow)
                for job in document["jobs"].values():
                    for step in job.get("steps", []) if isinstance(job, dict) else []:
                        if step.get("name") == check_supply_chain.BUNDLE_LOADER_STEP:
                            step["run"] = "# Hands off $GITHUB_ENV once.\n\n" + step["run"]
                self.assertEqual(
                    check_supply_chain.workflow_channel_violations(workflow, document), []
                )
        workflow = ".github/workflows/drift-check.yml"
        document = self._probe_document(workflow)
        document["jobs"]["drift"]["steps"].insert(0, {
            "name": check_supply_chain.BUNDLE_LOADER_STEP,
            "env": {"FERRUM_CREDS_BUNDLE": "${{ secrets.FERRUM_CREDS_BUNDLE }}"},
            "run": "\n".join(check_supply_chain.CREDENTIAL_HANDOFF_RUN),
        })
        violations = check_supply_chain.workflow_channel_violations(workflow, document)
        self.assertTrue(
            any("this workflow has no credential hand-off" in item for item in violations),
            violations,
        )

    def test_run_interpolations_are_pinned_per_environment_bound_job(self):
        for workflow in self.ENVIRONMENT_BOUND_WORKFLOWS:
            document = self._probe_document(workflow)
            self.assertEqual(check_supply_chain.run_expression_violations(workflow, document), [])
            pinned = check_supply_chain.RUN_EXPRESSIONS[workflow]
            for job_name, job in document["jobs"].items():
                if not isinstance(job.get("steps"), list):
                    continue
                for expression in (
                    "vars.NOTE", "inputs.environment", "github.event.head_commit.message",
                    "github.sha", "steps.metadata.outputs.pr_number", "env.FERRUM_ENV",
                    "matrix.environment", "needs.prepare.outputs.head_sha",
                ):
                    if expression in pinned.get(job_name, ()):
                        continue
                    for script in (
                        'echo "' + "${{ " + expression + " }}" + '"',
                        "# ${{ " + expression + " }}\ntrue",
                    ):
                        with self.subTest(workflow=workflow, job=job_name, script=script):
                            document = self._probe_document(workflow)
                            document["jobs"][job_name]["steps"].insert(0, {"run": script})
                            violations = check_supply_chain.run_expression_violations(
                                workflow, document
                            )
                            self.assertTrue(
                                any("is not pinned for this job" in item for item in violations),
                                violations,
                            )
        workflow = ".github/workflows/apply-on-merge.yml"
        document = self._probe_document(workflow)
        document["jobs"]["apply"]["steps"].insert(0, {
            "run": 'echo "Deploying ${{ matrix.environment }}"',
        })
        document["jobs"]["promote"]["steps"].insert(0, {
            "run": 'echo ".state/${{ matrix.scope.environment }}.json"',
        })
        self.assertEqual(check_supply_chain.run_expression_violations(workflow, document), [])

    # Values whose text is computed or chosen elsewhere: env, matrix, input,
    # output and event values, literals and string functions. None may reach
    # `run:` outside an Environment-bound job's pins.
    UNTRUSTED_RUN_EXPRESSIONS = (
        "env.A",
        "matrix.c",
        "needs.build.outputs.script",
        "steps.compute.outputs.script",
        "inputs.cmd",
        "vars.SCRIPT",
        "secrets.TOKEN",
        "github.event.pull_request.title",
        "github.event.comment.body",
        "github.head_ref",
        "github.ref_name",
        "github.workflow",
        "fromJSON(vars.SCRIPT)",
        "format('{0}', vars.SCRIPT)",
        "join(matrix.parts, '')",
        "toJSON(github.event)",
        "'echo injected'",
        "github.sha || 'x; echo injected'",
        "GITHUB.SHA",
        "Github.Event_Name",
    )

    def _run_refusals(self, workflow, document):
        return [
            item for item in check_supply_chain.run_expression_violations(workflow, document)
            if "is not an allowlisted run value" in item
        ]

    def test_run_interpolations_are_allowlisted_in_every_workflow(self):
        unbound = [
            workflow for workflow in self._shipped_workflows()
            if workflow not in check_supply_chain.RUN_EXPRESSIONS
        ]
        self.assertIn(".github/workflows/rust-ci.yml", unbound)
        self.assertIn(".github/workflows/lifecycle.yml", unbound)
        for workflow in unbound:
            document = self._probe_document(workflow)
            steps = self._first_steps(document)
            for expression in self.UNTRUSTED_RUN_EXPRESSIONS:
                for script in (
                    "echo ${{ " + expression + " }} done",
                    'echo "${{ ' + expression + ' }}"',
                    "echo '${{ " + expression + " }}'",
                    "echo safe\n${{ " + expression + " }}",
                    "# ${{ " + expression + " }}\ntrue",
                ):
                    with self.subTest(workflow=workflow, script=script):
                        steps.insert(0, {"run": script})
                        self.assertTrue(self._run_refusals(workflow, document), script)
                        steps.pop(0)
        for workflow in unbound:
            for expression in check_supply_chain.RUN_TRUSTED_EXPRESSIONS:
                with self.subTest(workflow=workflow, allowed=expression):
                    document = self._probe_document(workflow)
                    self._first_steps(document).insert(0, {
                        "run": 'echo "${{ ' + expression + ' }}"\n'
                               'if [[ "${{ ' + expression + ' }}" == x ]]; then true; fi',
                    })
                    self.assertEqual(
                        check_supply_chain.run_expression_violations(workflow, document), []
                    )

    def test_computed_values_cannot_reach_run_through_indirection(self):
        # The run allowlist refuses each interpolation whatever its value. This
        # `fromJSON` literal also names GITHUB_ENV, which the channel fence
        # refuses where it is written, but nothing here relies on that: a value
        # computed or chosen elsewhere (a variable, a title) never passes that
        # fence, and only the allowlist stops it rendering as shell source.
        workflow = ".github/workflows/rust-ci.yml"
        computed = "${{ fromJSON('\"x; echo X=1 >> $GITHUB_ENV\"') }}"
        cases = (
            ("env", {"env": {"A": computed}, "run": "echo ${{ env.A }} done"}, None),
            ("quoted env", {"env": {"A": computed}, "run": 'echo "${{ env.A }}"'}, None),
            ("matrix", {"run": "echo ${{ matrix.c }} ."}, {"strategy": {"matrix": {
                "c": ["${{ format('{0}', vars.SCRIPT) }}"],
            }}}),
            ("job output", {"run": "echo ${{ needs.build.outputs.script }} ."}, {
                "needs": "build",
            }),
            ("step output", {"run": "echo ${{ steps.compute.outputs.script }} ."}, None),
            ("event", {"run": "echo ${{ github.event.pull_request.title }} ."}, None),
        )
        for name, step, job_fields in cases:
            with self.subTest(case=name):
                document = self._probe_document(workflow)
                job = document["jobs"]["rust-ci-check"]
                job.update(job_fields or {})
                job["steps"].insert(0, step)
                if name == "job output":
                    document["jobs"]["build"] = {
                        "runs-on": "ubuntu-24.04",
                        "outputs": {"script": "${{ format('{0}', vars.SCRIPT) }}"},
                        "steps": [{"run": "true"}],
                    }
                self.assertTrue(self._run_refusals(workflow, document), step)
        # The same value through env, read by the shell, is data.
        document = self._probe_document(workflow)
        document["jobs"]["rust-ci-check"]["steps"].insert(0, {
            "env": {"TITLE": "${{ github.event.pull_request.title }}"},
            "run": 'echo "$TITLE"',
        })
        self.assertEqual(check_supply_chain.run_expression_violations(workflow, document), [])
        # The checker run refuses it, not only the helper.
        with tempfile.TemporaryDirectory() as directory:
            root = self._mirror_repo(Path(directory))
            path = root / workflow
            original = path.read_text(encoding="utf-8")
            changed = original.replace(
                "    steps:\n",
                "    steps:\n      - name: Indirect\n        env:\n"
                "          A: ${{ vars.SCRIPT }}\n"
                '        run: echo "${{ env.A }}"\n',
                1,
            )
            self.assertNotEqual(changed, original)
            path.write_text(changed, encoding="utf-8")
            violations = self._violations(root)
        self.assertTrue(
            any(
                item.startswith(f"{workflow}: jobs.")
                and "'env.A' is not an allowlisted run value" in item
                for item in violations
            ),
            violations,
        )

    def test_local_actions_interpolate_only_allowlisted_run_values(self):
        rust = ".github/workflows/rust-ci.yml"
        label = f".github/actions/local/action.yml (run by {rust})"
        for expression in self.UNTRUSTED_RUN_EXPRESSIONS:
            for run in (
                "echo ${{ " + expression + " }} x",
                '"${{ ' + expression + ' }}"',
                "${{ " + expression + " }}",
            ):
                with self.subTest(run=run), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    document = self._probe_document(rust)
                    reference = self._local_action(
                        root, "local",
                        "    - shell: bash\n      run: |\n        " + run + "\n",
                    )
                    self._first_steps(document).insert(0, {"name": "Local", "uses": reference})
                    violations = check_supply_chain.local_action_violations(root, rust, document)
                    self.assertTrue(
                        any(
                            item.startswith(f"{label}: runs.steps[0].run:")
                            and "is not an allowlisted run value" in item
                            for item in violations
                        ),
                        violations,
                    )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            # Reached through another local action, with an input from `with:`.
            outer = self._local_action(
                root, "outer",
                "    - uses: ./.github/actions/inner\n      with:\n"
                "        cmd: ${{ inputs.cmd }}\n",
            )
            self._local_action(
                root, "inner", "    - shell: bash\n      run: echo ${{ inputs.cmd }} x\n"
            )
            document = self._probe_document(rust)
            self._first_steps(document).insert(
                0, {"name": "Local", "uses": outer, "with": {"cmd": "${{ vars.SCRIPT }}"}}
            )
            violations = check_supply_chain.local_action_violations(root, rust, document)
            self.assertTrue(any(
                item.startswith(f".github/actions/inner/action.yml (run by {rust})")
                and "'inputs.cmd' is not an allowlisted run value" in item
                for item in violations
            ), violations)
            # An allowlisted value is accepted in a local action too.
            allowed = self._local_action(
                root, "allowed",
                "    - shell: bash\n      run: |\n"
                + "".join(
                    '        echo "${{ ' + expression + ' }}"\n'
                    for expression in check_supply_chain.RUN_TRUSTED_EXPRESSIONS
                ),
            )
            document = self._probe_document(rust)
            self._first_steps(document).insert(0, {"name": "Local", "uses": allowed})
            self.assertEqual(
                check_supply_chain.local_action_violations(root, rust, document), []
            )
            # An Environment-bound workflow's local action interpolates nothing.
            review = ".github/workflows/trusted-pr-review.yml"
            document = self._probe_document(review)
            self._first_steps(document).insert(0, {"name": "Local", "uses": allowed})
            violations = check_supply_chain.local_action_violations(root, review, document)
            self.assertTrue(any(
                "may not interpolate into run:" in item for item in violations
            ), violations)
        # The checker run reaches the local action through `uses: ./...`.
        with tempfile.TemporaryDirectory() as directory:
            root = self._mirror_repo(Path(directory))
            self._local_action(
                root, "local", "    - shell: bash\n      run: echo ${{ inputs.cmd }} x\n"
            )
            path = root / rust
            original = path.read_text(encoding="utf-8")
            changed = original.replace(
                "    steps:\n",
                "    steps:\n      - name: Local\n        uses: ./.github/actions/local\n",
                1,
            )
            self.assertNotEqual(changed, original)
            path.write_text(changed, encoding="utf-8")
            violations = self._violations(root)
        self.assertTrue(
            any(
                item.startswith(f"{label}: runs.steps[0].run:")
                and "is not an allowlisted run value" in item
                for item in violations
            ),
            violations,
        )

    def test_run_values_keep_their_pinned_producers(self):
        for workflow in self._shipped_workflows():
            with self.subTest(workflow=workflow):
                self.assertEqual(
                    check_supply_chain.run_expression_source_violations(
                        workflow, self._probe_document(workflow)
                    ),
                    [],
                )

        def assign(*path, value):
            def mutate(document):
                node = document
                for key in path[:-1]:
                    node = node[key]
                node[path[-1]] = value
            return mutate

        def producer(document, job, step_id):
            return next(
                step for step in document["jobs"][job]["steps"] if step.get("id") == step_id
            )

        def edit_run(job, step_id, old, new):
            def mutate(document):
                step = producer(document, job, step_id)
                self.assertIn(old, step["run"])
                step["run"] = step["run"].replace(old, new)
            return mutate

        def edit_step(job, step_id, key, value):
            def mutate(document):
                step = producer(document, job, step_id)
                if isinstance(step.get(key), dict):
                    step[key].update(value)
                else:
                    step[key] = value
            return mutate

        def edit_job(job, key, value):
            def mutate(document):
                document["jobs"][job][key] = value
            return mutate

        def edit_workflow(key, value):
            def mutate(document):
                document[key] = value
            return mutate

        def move_assignment_after_publish(job, step_id):
            def mutate(document):
                step = producer(document, job, step_id)
                self.assertIn(assignment, step["run"])
                self.assertIn(echo, step["run"])
                step["run"] = step["run"].replace(assignment, "", 1)
                step["run"] = step["run"].replace(echo, echo + "\n" + assignment, 1)
            return mutate

        guard = check_supply_chain.REVIEW_METADATA_PREAMBLE[1]
        assignment = check_supply_chain.REVIEW_TRUSTED_SHA_ASSIGNMENT
        echo = check_supply_chain.REVIEW_METADATA_LINES["trusted_sha"][0]
        branch = "${{ github.event.workflow_run.head_branch }}"
        message = "${{ github.event.head_commit.message }}"
        cases = {
            ".github/workflows/trusted-pr-review.yml": (
                # The pushed branch name, spliced into live review's run.
                assign("jobs", "prepare", "outputs", "head_sha", value=branch),
                assign("jobs", "prepare", "outputs", "trusted_sha",
                       value="${{ github.event.workflow_run.display_title }}"),
                assign("jobs", "prepare", "outputs", "HEAD_SHA", value=branch),
                # The hex check removed, or a SHA output taken from API data.
                edit_run("prepare", "metadata", guard + "\n", ""),
                edit_run("prepare", "metadata", guard, "true\n" + guard),
                edit_run(
                    "prepare", "metadata", 'echo "head_sha=$EVENT_HEAD_SHA"',
                    'echo "head_sha=$(jq -r .head.ref <<< "$current")"',
                ),
                edit_run(
                    "prepare", "metadata", guard,
                    guard + '\nEVENT_HEAD_SHA=$(gh api "repos/${REPO}/pulls/1" --jq .head.ref)',
                ),
                edit_run(
                    "prepare", "metadata", assignment,
                    'trusted_sha=$(gh api "repos/${REPO}" --jq .description)',
                ),
                edit_run(
                    "prepare", "metadata", assignment,
                    assignment + '\nread -r trusted_sha <<< "$TITLE"',
                ),
                edit_run("prepare", "metadata", assignment, assignment + "\n" + assignment),
                edit_step("prepare", "metadata", "env", {"EVENT_HEAD_SHA": branch}),
                edit_run(
                    "prepare", "metadata", assignment,
                    assignment.replace("trusted_sha", "TRUSTED_SHA", 1),
                ),
                edit_step(
                    "prepare", "metadata", "env",
                    {"trusted_sha": "${{ github.event.workflow_run.head_branch }}"},
                ),
                # The same refusal reaches the step's `Env`, the job and the
                # workflow scopes, in either case, and the assignment must
                # precede its echo.
                edit_step("prepare", "metadata", "Env", {"trusted_sha": branch}),
                edit_step("prepare", "metadata", "env", {"Trusted_SHA": branch}),
                edit_job("prepare", "env", {"trusted_sha": branch}),
                edit_job("prepare", "env", {"TRUSTED_SHA": branch}),
                edit_workflow("env", {"trusted_sha": branch}),
                edit_workflow("Env", {"Trusted_SHA": branch}),
                move_assignment_after_publish("prepare", "metadata"),
                edit_step("prepare", "metadata", "id", "workflow-run"),
                edit_step("prepare", "metadata", "shell", "sh {0}"),
            ),
            ".github/workflows/apply-on-merge.yml": (
                # A matrix, job output or enumerator rewired to other data.
                assign("jobs", "apply", "strategy", "matrix",
                       value={"environment": "${{ fromJson(vars.ENVIRONMENTS) }}"}),
                assign("jobs", "apply", "strategy", "matrix", "include",
                       value=[{"environment": message}]),
                assign("jobs", "promote", "strategy", "matrix",
                       value={"scope": "${{ fromJson(github.event.head_commit.message) }}"}),
                assign("jobs", "list-envs", "outputs", "envs", value=message),
                assign("jobs", "list-envs", "outputs", "promotions",
                       value="${{ steps.other.outputs.promotions }}"),
                edit_run(
                    "list-envs", "list", 'test("^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")', "true"
                ),
                edit_run(
                    "list-envs", "list",
                    "envs=$(jq -c '[.[] | select(.promotion_requires == null) | .environment]'",
                    "envs=$(git log -1 --format=%s | jq -R -c '[.]'",
                ),
                edit_run("list-envs", "list", "jq -e '\n", "jq -e '\n# skip \\\n"),
                edit_step("list-envs", "list", "id", "enumerate"),
                edit_step("list-envs", "list", "working-directory", "candidate"),
            ),
        }
        for workflow, mutations in cases.items():
            for index, mutate in enumerate(mutations):
                with self.subTest(workflow=workflow, mutation=index):
                    document = self._probe_document(workflow)
                    mutate(document)
                    self.assertTrue(
                        check_supply_chain.run_expression_source_violations(workflow, document)
                    )

    def test_trusted_checker_refuses_rewired_run_values(self):
        for workflow, old, new, expected in (
            (
                ".github/workflows/trusted-pr-review.yml",
                "head_sha: ${{ steps.metadata.outputs.head_sha }}",
                "head_sha: ${{ github.event.workflow_run.head_branch }}",
                "jobs.prepare.outputs.head_sha must be exactly",
            ),
            (
                ".github/workflows/apply-on-merge.yml",
                "environment: ${{ fromJson(needs.list-envs.outputs.envs) }}",
                "environment: ${{ fromJson(vars.ENVIRONMENTS) }}",
                "jobs.apply.strategy.matrix must be exactly",
            ),
        ):
            with self.subTest(workflow=workflow), tempfile.TemporaryDirectory() as directory:
                root = self._mirror_repo(Path(directory))
                (root / ".github/scripts/check_supply_chain.py").write_text(
                    "raise SystemExit(0)\n", encoding="utf-8"
                )
                path = root / workflow
                original = path.read_text(encoding="utf-8")
                changed = original.replace(old, new, 1)
                self.assertNotEqual(changed, original)
                path.write_text(changed, encoding="utf-8")
                violations = self._violations(root)
                self.assertTrue(any(expected in item for item in violations), violations)

    def test_applied_bundle_path_comes_only_from_the_apply_hand_off(self):
        workflow = ".github/workflows/apply-on-merge.yml"
        for job in ("apply", "promote"):
            for identifier in (None, "bundles"):
                with self.subTest(job=job, identifier=identifier):
                    document = self._probe_document(workflow)
                    loader = self._step(document, job, check_supply_chain.BUNDLE_LOADER_STEP)
                    if identifier is None:
                        loader.pop("id")
                    else:
                        loader["id"] = identifier
                    violations = check_supply_chain.workflow_channel_violations(
                        workflow, document
                    )
                    self.assertTrue(
                        any("keeps id load-bundles" in item for item in violations), violations
                    )
            for step_name, variable in check_supply_chain.APPLIED_BUNDLE_BINDINGS.items():
                for replacement in (
                    None, "${{ steps.stale.outputs.applied_file }}", "/tmp/ready.json",
                ):
                    with self.subTest(job=job, step=step_name, replacement=replacement):
                        document = self._probe_document(workflow)
                        environment = self._step(document, job, step_name)["env"]
                        self.assertEqual(
                            environment[variable], check_supply_chain.APPLIED_BUNDLE_VALUE
                        )
                        if replacement is None:
                            environment.pop(variable)
                        else:
                            environment[variable] = replacement
                        violations = check_supply_chain.probe_validation_gate_violations(
                            workflow, document
                        )
                        self.assertTrue(
                            any(f"must bind exactly {variable}" in item for item in violations),
                            violations,
                        )

    def test_trusted_checker_refuses_env_file_bypasses_in_candidate_workflows(self):
        for workflow, script in (
            (".github/workflows/rust-ci.yml", 'echo "BASH_ENV=x" >> "${GITHUB_ENV}"'),
            (".github/workflows/drift-check.yml", "printf '%s\\n' \"$PWD/bin\" > \"$GITHUB_PATH\""),
            (".github/workflows/rotate.yml", 'tee -a "$GITHUB_ENV" <<< "FERRUM_ENV=other"'),
            (".github/workflows/trusted-pr-review.yml", 'echo x >> "$GITHUB_${{ matrix.suffix }}"'),
        ):
            with self.subTest(workflow=workflow), tempfile.TemporaryDirectory() as directory:
                root = self._mirror_repo(Path(directory))
                # The candidate's own checker cannot approve its workflow.
                (root / ".github/scripts/check_supply_chain.py").write_text(
                    "raise SystemExit(0)\n", encoding="utf-8"
                )
                path = root / workflow
                original = path.read_text(encoding="utf-8")
                changed = original.replace(
                    "    steps:\n",
                    "    steps:\n      - name: Bypass\n        run: " + json.dumps(script) + "\n",
                    1,
                )
                self.assertNotEqual(changed, original)
                path.write_text(changed, encoding="utf-8")
                violations = self._violations(root)
                self.assertTrue(
                    any(
                        self.HANDOFF_FENCE in item or "may not adjoin a name character" in item
                        for item in violations
                    ),
                    violations,
                )

    def test_protected_names_cannot_be_spliced_quoted_or_commented(self):
        workflow = ".github/workflows/apply-on-merge.yml"
        for script in (
            "export FERRUM_NAMESPACE=other",
            'export FERRUM_NAM""ESPACE=other',
            "export FERRUM_NAM\\\nESPACE=other",
            "export $'FERRUM_ENV'=staging",
            "# FERRUM_NAMESPACE=other\ntrue",
            'cat <<< "FERRUM_ENV=staging"',
            "echo '${{ env.FERRUM_ENV }}'",
            "unset FERRUM_VERIFY_PROBE_CONSUMERS",
        ):
            with self.subTest(script=script):
                document = self._probe_document(workflow)
                document["jobs"]["list-envs"]["steps"].insert(0, {"run": script})
                violations = self._guarded_bindings(workflow, document)
                self.assertTrue(
                    any("protected variable references/rebinding" in item for item in violations),
                    violations,
                )
        # A name spelled by character code is refused by the protected-name
        # fence itself, not decoded.
        document = self._probe_document(workflow)
        document["jobs"]["list-envs"]["steps"].insert(
            0, {"run": "export $'FERRUM_NAMESP\\x41CE'=other"}
        )
        violations = check_supply_chain.guarded_environment_violations(
            workflow, document, (), check_supply_chain.protected_environment_names(workflow)
        )
        self.assertTrue(
            any("ANSI-C quoting (`$'...'`) is not supported" in item for item in violations),
            violations,
        )
        workflow = ".github/workflows/trusted-pr-review.yml"
        document = self._probe_document(workflow)
        review = self._step(document, "live-review", "Post trusted live review")
        review["run"] += '\necho "${{ env.FERRUM_VERIFY_PROBE_CONSUMERS_BOUND }}"'
        self.assertTrue(any(
            "protected variable references/rebinding" in item
            for item in self._guarded_bindings(workflow, document)
        ))
        workflow = ".github/workflows/drift-check.yml"
        document = self._probe_document(workflow)
        document["jobs"]["drift"]["steps"].insert(0, {
            "run": "# FERRUM_ADMIN_JWT_SECRET is not held here\ntrue",
        })
        self.assertTrue(any(
            "protected variable references/rebinding" in item
            for item in self._guarded_bindings(workflow, document)
        ))

    def test_only_pinned_read_only_lines_may_invoke_the_binary(self):
        workflow = ".github/workflows/apply-on-merge.yml"
        document = self._probe_document(workflow)
        self.assertEqual(check_supply_chain.probe_validation_gate_violations(workflow, document), [])
        for script in (
            *check_supply_chain.READ_ONLY_GITFORGEOPS_LINES,
            "  scopes=$(gitforgeops envs --format json --include-scopes | jq -c .)",
            'test -f .gitforgeops/config.yaml',
            'git config user.name "gitforgeops[bot]"',
            'git commit -m "chore(gitforgeops): state update"',
            'echo "$GITFORGEOPS_ACTOR"',
        ):
            with self.subTest(read_only=script):
                document = self._probe_document(workflow)
                document["jobs"]["list-envs"]["steps"].insert(0, {"run": script})
                self.assertEqual(
                    check_supply_chain.probe_validation_gate_violations(workflow, document), []
                )
        for script in (
            "gitforgeops apply --auto-approve",
            "gitforgeops envs --format json; gitforgeops apply --auto-approve",
            "gitforgeops validate && gitforgeops apply --auto-approve",
            'echo "$(gitforgeops apply --auto-approve)"',
            'gitforgeops --env staging ap""ply --auto-approve',
            "gitforgeops${IFS}apply --auto-approve",
            "gitforgeops<input apply --auto-approve",
            "~/.cargo/bin/gitforgeops apply --auto-approve",
            "gitforgeops \\\napply --auto-approve",
            "$(command -v gitforgeops) apply --auto-approve",
            '"$(which gitforgeops)" apply --auto-approve',
            "gitforgeops rotate --consumer x --credential jwt.secret",
            "gitforgeops export --materialize",
            "gitforgeops version",
            "# gitforgeops apply --auto-approve\ntrue",
        ):
            with self.subTest(write=script):
                document = self._probe_document(workflow)
                document["jobs"]["list-envs"]["steps"].insert(0, {"run": script})
                self.assertTrue(any(
                    "mutations may only run" in item
                    for item in check_supply_chain.probe_validation_gate_violations(
                        workflow, document
                    )
                ))
        # Bash ANSI-C quoting spells the name by character code. No rule
        # decodes it, so any `$'` is refused.
        for script in (
            "$'\\x67'itforgeops apply --auto-approve",
            "$'\\147'itforgeops apply --auto-approve",
            "$'\\u0067itforgeops' apply --auto-approve",
            "gitforgeops validate$'\\012'apply --auto-approve",
            "gitforgeops validate$'\\n'apply --auto-approve",
        ):
            with self.subTest(ansi_c=script):
                document = self._probe_document(workflow)
                document["jobs"]["list-envs"]["steps"].insert(0, {"run": script})
                self.assertTrue(any(
                    "ANSI-C quoting (`$'...'`) is not supported" in item
                    for item in check_supply_chain.probe_validation_gate_violations(
                        workflow, document
                    )
                ))

    def test_every_apply_scalar_outside_the_guarded_steps_names_the_binary_only_as_pinned(self):
        workflow = ".github/workflows/apply-on-merge.yml"
        pinned_action = "acme/run@" + "a" * 40
        command = "gitforgeops apply --auto-approve"

        def insert_step(step):
            return lambda document: document["jobs"]["list-envs"]["steps"].insert(0, step)

        def set_defaults(document):
            document["jobs"]["list-envs"]["defaults"] = {"run": {"shell": command + " {0}"}}

        for index, mutate in enumerate((
            insert_step({"name": "Shell", "shell": command + " {0}", "run": "true"}),
            insert_step({"name": "Shell", "shell": "gitforgeops validate", "run": "true"}),
            insert_step({"name": "Shell", "shell": "GitForge\"\"Ops apply {0}", "run": "true"}),
            insert_step({"name": "Input", "uses": pinned_action, "with": {"args": command}}),
            insert_step({"name": "Inputs", "uses": pinned_action, "with": {"args": [command]}}),
            insert_step({"name": "Env", "env": {"COMMAND": command}, "run": "true"}),
            insert_step({"name": "Run gitforgeops apply", "run": "true"}),
            insert_step({"working-directory": "Build gitforgeops", "run": "true"}),
            insert_step({"if": "contains('gitforgeops apply', 'x')", "run": "true"}),
            set_defaults,
            # Only a workflow, job or step `name:` is a display name.
            insert_step({
                "name": "Input", "uses": pinned_action, "with": {"name": "GitForgeOps Apply"},
            }),
            insert_step({"name": "Env", "env": {"name": "Install gitforgeops"}, "run": "true"}),
            insert_step({"name": "Inputs", "uses": pinned_action,
                         "with": {"name": ["Build gitforgeops"]}}),
            insert_step({"name": "Shell", "shell": "Build gitforgeops", "run": "true"}),
        )):
            with self.subTest(mutation=index):
                document = self._probe_document(workflow)
                mutate(document)
                violations = check_supply_chain.probe_validation_gate_violations(
                    workflow, document
                )
                self.assertTrue(
                    any("mutations may only run" in item for item in violations), violations
                )
        for step in (
            {"name": "Install gitforgeops", "run": "true"},
            {"name": "Build gitforgeops", "run": "gitforgeops validate", "shell": "bash"},
            {"if": "hashFiles('.gitforgeops/smoke.yaml') != ''", "run": "true"},
            {"name": "Actor", "env": {"GITFORGEOPS_ACTOR": "x"}, "run": "true"},
            {"name": "Bot", "run": 'git config user.name "gitforgeops[bot]"'},
        ):
            with self.subTest(allowed=step):
                document = self._probe_document(workflow)
                document["jobs"]["list-envs"]["steps"].insert(0, step)
                self.assertEqual(
                    check_supply_chain.probe_validation_gate_violations(workflow, document), []
                )
        with self.subTest(allowed="job name"):
            document = self._probe_document(workflow)
            document["jobs"]["list-envs"]["name"] = "Build gitforgeops"
            self.assertEqual(
                check_supply_chain.probe_validation_gate_violations(workflow, document), []
            )

    def test_producer_step_ids_compare_case_insensitively(self):
        producer = check_supply_chain._producer_step
        loader = {"id": "Load-Bundles", "name": check_supply_chain.BUNDLE_LOADER_STEP}
        self.assertIs(producer({"steps": [loader]}, "load-bundles"), loader)
        self.assertIsNone(producer({"steps": [{"id": "metadata"}, {"id": "Metadata"}]}, "metadata"))
        self.assertIsNone(producer({"steps": [{"id": "metadata-2"}, {"id": 1}]}, "metadata"))
        workflow = ".github/workflows/trusted-pr-review.yml"
        for shadow in ("metadata", "Metadata", "METADATA"):
            with self.subTest(shadow=shadow):
                document = self._probe_document(workflow)
                document["jobs"]["prepare"]["steps"].insert(0, {"id": shadow, "run": "true"})
                violations = check_supply_chain.run_expression_source_violations(
                    workflow, document
                )
                self.assertTrue(
                    any("must exist exactly once" in item for item in violations), violations
                )

    def test_load_bundles_id_belongs_to_the_named_loader(self):
        workflow = ".github/workflows/apply-on-merge.yml"
        expected = f"must be named {check_supply_chain.BUNDLE_LOADER_STEP!r}"
        self.assertEqual(
            check_supply_chain.probe_validation_gate_violations(
                workflow, self._probe_document(workflow)
            ),
            [],
        )
        for job in ("apply", "promote"):
            for mutation in ("renamed", "shadow", "shadow-case", "missing"):
                with self.subTest(job=job, mutation=mutation):
                    document = self._probe_document(workflow)
                    loader = self._step(document, job, check_supply_chain.BUNDLE_LOADER_STEP)
                    if mutation == "renamed":
                        loader["name"] = "Load bundles"
                    elif mutation == "missing":
                        loader.pop("id")
                    else:
                        document["jobs"][job]["steps"].insert(0, {
                            "name": "Shadow",
                            "id": "load-bundles" if mutation == "shadow" else "LOAD-BUNDLES",
                            "run": "true",
                        })
                    violations = check_supply_chain.probe_validation_gate_violations(
                        workflow, document
                    )
                    self.assertTrue(any(expected in item for item in violations), violations)

    def _local_action(self, root: Path, name: str, steps: str) -> str:
        """Write a composite action with `steps` (YAML, indented four spaces)."""
        directory = root / ".github" / "actions" / name
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "action.yml").write_text(
            "name: Local\ndescription: Test action\nruns:\n  using: composite\n  steps:\n"
            + steps,
            encoding="utf-8",
        )
        return f"./.github/actions/{name}"

    def test_local_actions_must_resolve_to_readable_composite_actions(self):
        clean = "    - shell: bash\n      run: echo hello\n"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            actions = root / ".github" / "actions"
            self._local_action(root, "clean", clean)
            self._local_action(root, "both", clean)
            (actions / "both" / "action.yaml").write_text("name: Both\n", encoding="utf-8")
            (actions / "node").mkdir()
            (actions / "node" / "action.yml").write_text(
                "name: Node\nruns:\n  using: node20\n  main: index.js\n", encoding="utf-8"
            )
            (actions / "anchored").mkdir()
            (actions / "anchored" / "action.yml").write_text(
                "name: Anchored\nruns: &shared\n  using: composite\n", encoding="utf-8"
            )
            (actions / "docker").mkdir()
            (actions / "docker" / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
            (actions / "linked").mkdir()
            (actions / "linked" / "action.yml").symlink_to(actions / "clean" / "action.yml")
            (actions / "alias").symlink_to(actions / "clean", target_is_directory=True)
            (root / "tools" / "act").mkdir(parents=True)
            (root / "tools" / "act" / "action.yml").write_text(
                (actions / "clean" / "action.yml").read_text(encoding="utf-8"), encoding="utf-8"
            )
            below = "below ./.github/actions/"
            for reference, expected in (
                ("./", below),
                ("./tools/act", below),
                ("./.github/workflows/rust-ci.yml", below),
                ("./trusted/.github/actions/clean", below),
                ("./.github/actions", below),
                ("./.github/actions/../actions/clean", below),
                ("./.github/actions/./clean", below),
                ("./.github/actions//clean", below),
                ("./.github/actions/clean@v1", below),
                ("./.github/actions/missing", "exactly one action.yml or action.yaml"),
                ("./.github/actions/docker", "exactly one action.yml or action.yaml"),
                ("./.github/actions/both", "exactly one action.yml or action.yaml"),
                ("./.github/actions/linked", "no symbolic link"),
                ("./.github/actions/alias", "no symbolic link"),
                ("./.github/actions/node", "must be a composite action"),
                ("./.github/actions/anchored", "outside the YAML subset"),
            ):
                with self.subTest(reference=reference):
                    _, action, refusal = check_supply_chain.resolve_local_action(root, reference)
                    self.assertIsNone(action)
                    self.assertIn(expected, refusal)
            for reference in ("./.github/actions/clean", "./.github/actions/clean/"):
                with self.subTest(allowed=reference):
                    relative, action, refusal = check_supply_chain.resolve_local_action(
                        root, reference
                    )
                    self.assertIsNone(refusal)
                    self.assertEqual(relative, ".github/actions/clean/action.yml")
                    self.assertEqual(
                        action["runs"]["steps"], [{"shell": "bash", "run": "echo hello"}]
                    )
            # A job-level local reusable workflow carries none of its caller's pins.
            workflow = ".github/workflows/rust-ci.yml"
            document = self._probe_document(workflow)
            document["jobs"]["reuse"] = {"uses": "./.github/workflows/rust-ci.yml"}
            violations = check_supply_chain.local_action_violations(root, workflow, document)
            self.assertTrue(any(below in item for item in violations), violations)

    def test_local_actions_carry_their_callers_text_fences(self):
        apply = ".github/workflows/apply-on-merge.yml"
        review = ".github/workflows/trusted-pr-review.yml"
        rust = ".github/workflows/rust-ci.yml"
        for workflow, steps, expected in (
            (rust, '    - shell: bash\n      run: |\n        echo X=1 >> "$GITHUB_ENV"\n',
             self.HANDOFF_FENCE),
            (rust, "    - shell: bash\n      run: |\n        echo x >> $'GITHUB_\\x45NV'\n",
             "ANSI-C quoting"),
            (rust, "    - shell: bash\n      env:\n        SHELLOPTS: xtrace\n"
                   "      run: echo hello\n", "shell startup or loader variable"),
            (rust, "    - shell: bash\n      env:\n        BASH_FUNC_x: '() { true; }'\n"
                   "      run: echo hello\n", "shell startup or loader variable"),
            (apply, "    - shell: bash\n      run: gitforgeops apply --auto-approve\n",
             "mutations may only run"),
            (apply, "    - shell: gitforgeops apply --auto-approve {0}\n      run: echo hello\n",
             "mutations may only run"),
            (apply, "    - shell: bash\n      env:\n        FERRUM_NAMESPACE: other\n"
                    "      run: echo hello\n", "protected variable"),
            (review, '    - shell: bash\n      run: |\n        echo "${{ inputs.title }}"\n',
             "may not interpolate into run:"),
            (review, "    - shell: bash\n      run: echo $FERRUM_VERIFY_PROBE_CONSUMERS\n",
             "protected variable"),
            (".github/workflows/drift-check.yml",
             "    - shell: bash\n      run: echo $FERRUM_ADMIN_JWT_SECRET\n", "protected variable"),
        ):
            with self.subTest(workflow=workflow, steps=steps), \
                    tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                document = self._probe_document(workflow)
                self._first_steps(document).insert(
                    0, {"name": "Local", "uses": self._local_action(root, "local", steps)}
                )
                violations = check_supply_chain.local_action_violations(root, workflow, document)
                self.assertTrue(
                    any(
                        f".github/actions/local/action.yml (run by {workflow})" in item
                        and expected in item
                        for item in violations
                    ),
                    violations,
                )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            clean = self._local_action(root, "clean", "    - shell: bash\n      run: echo hello\n")
            for workflow in self._shipped_workflows():
                with self.subTest(allowed=workflow):
                    document = self._probe_document(workflow)
                    self.assertEqual(
                        check_supply_chain.local_action_violations(root, workflow, document), []
                    )
                    self._first_steps(document).insert(0, {"name": "Local", "uses": clean})
                    self.assertEqual(
                        check_supply_chain.local_action_violations(root, workflow, document), []
                    )
            # Nested local actions are judged as their caller's, and a cycle ends.
            outer = self._local_action(
                root, "outer",
                "    - uses: ./.github/actions/inner\n    - uses: ./.github/actions/outer\n"
                "    - uses: ./.github/actions/missing\n",
            )
            self._local_action(
                root, "inner", "    - shell: bash\n      run: gitforgeops apply --auto-approve\n"
            )
            document = self._probe_document(apply)
            self._first_steps(document).insert(0, {"name": "Local", "uses": outer})
            violations = check_supply_chain.local_action_violations(root, apply, document)
            self.assertTrue(any(
                f".github/actions/inner/action.yml (run by {apply})" in item
                and "mutations may only run" in item
                for item in violations
            ), violations)
            self.assertTrue(any(
                item.startswith(
                    ".github/actions/outer/action.yml: local action './.github/actions/missing'"
                )
                for item in violations
            ), violations)

    def test_trusted_checker_judges_local_actions_a_workflow_runs(self):
        workflow = ".github/workflows/apply-on-merge.yml"
        for steps, reference, expected in (
            ("    - shell: bash\n      run: echo hello\n", "./.github/actions/deploy", None),
            ("    - shell: bash\n      run: gitforgeops apply --auto-approve\n",
             "./.github/actions/deploy", "mutations may only run"),
            ("    - shell: bash\n      run: echo hello\n", "./.github/actions/missing",
             "must resolve to exactly one action.yml or action.yaml"),
        ):
            with self.subTest(reference=reference, expected=expected), \
                    tempfile.TemporaryDirectory() as directory:
                root = self._mirror_repo(Path(directory))
                self._local_action(root, "deploy", steps)
                path = root / workflow
                original = path.read_text(encoding="utf-8")
                changed = original.replace(
                    "    steps:\n",
                    f"    steps:\n      - name: Local\n        uses: {reference}\n",
                    1,
                )
                self.assertNotEqual(changed, original)
                path.write_text(changed, encoding="utf-8")
                if expected is None:
                    result = subprocess.run(
                        [sys.executable, str(SCRIPT), "--root", str(root)],
                        check=False, text=True, capture_output=True,
                    )
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    continue
                violations = self._violations(root)
                self.assertTrue(any(expected in item for item in violations), violations)

    def test_container_and_service_options_are_refused(self):
        refused = "container options are forbidden"
        computed = "never computed"
        unpinned = "must be pinned by digest"
        digest = "@sha256:" + "0" * 64
        for workflow in self._shipped_workflows():
            with self.subTest(workflow=workflow):
                self.assertEqual(
                    check_supply_chain.container_options_violations(
                        workflow, self._probe_document(workflow)
                    ),
                    [],
                )
            for key, value, expected in (
                ("container", {"image": "alpine", "options": "-e LD_PRELOAD=/tmp/x.so"}, refused),
                ("container", {"image": "alpine", "Options": "--env SHELLOPTS=xtrace"}, refused),
                ("container", {"image": "alpine", "options": "--health-cmd true"}, refused),
                ("services", {"db": {"image": "postgres", "options": "--env-file x"}}, refused),
                ("Services", {"db": {"image": "postgres", "OPTIONS": "-ePS4=x"}}, refused),
                ("container", "${{ fromJSON(vars.CONTAINER) }}", computed),
                ("services", "${{ fromJSON(vars.SERVICES) }}", computed),
                ("services", {"db": "${{ fromJSON(vars.DB) }}"}, computed),
                ("container", ["alpine"], computed),
                ("container", "alpine", unpinned),
                ("container", "alpine:3.20", unpinned),
                ("container", {"image": "alpine", "env": {"A": "b"}}, unpinned),
                ("container", {"env": {"A": "b"}}, unpinned),
                ("container", {"image": "alpine" + digest, "Image": "alpine"}, unpinned),
                ("container", {"image": "alpine@sha256:" + "A" * 64}, unpinned),
                ("container", {"image": "${{ vars.IMAGE }}" + digest}, unpinned),
                ("services", {"cache": "redis"}, unpinned),
                ("services", {"db": {"image": "postgres:16", "ports": ["5432:5432"]}}, unpinned),
            ):
                with self.subTest(workflow=workflow, key=key, value=value):
                    document = self._probe_document(workflow)
                    steps = self._first_steps(document)
                    next(
                        job for job in document["jobs"].values()
                        if isinstance(job, dict) and job.get("steps") is steps
                    )[key] = value
                    violations = check_supply_chain.container_options_violations(
                        workflow, document
                    )
                    self.assertTrue(any(expected in item for item in violations), violations)
        workflow = ".github/workflows/rust-ci.yml"
        for key, value in (
            ("container", "alpine" + digest),
            ("container", {"image": "alpine:3.20" + digest, "env": {"A": "b"}}),
            ("Container", {"Image": "ghcr.io/acme/tool" + digest}),
            ("services", {"db": {"image": "postgres" + digest, "ports": ["5432:5432"]}}),
            ("services", {"cache": "redis" + digest}),
        ):
            with self.subTest(allowed=value):
                document = self._probe_document(workflow)
                steps = self._first_steps(document)
                next(
                    job for job in document["jobs"].values()
                    if isinstance(job, dict) and job.get("steps") is steps
                )[key] = value
                self.assertEqual(
                    check_supply_chain.container_options_violations(workflow, document), []
                )
        with tempfile.TemporaryDirectory() as directory:
            root = self._mirror_repo(Path(directory))
            path = root / workflow
            original = path.read_text(encoding="utf-8")
            changed = original.replace(
                "    runs-on: ubuntu-24.04\n",
                "    runs-on: ubuntu-24.04\n    container:\n      image: alpine\n"
                "      options: '-e LD_PRELOAD=/tmp/x.so'\n",
                1,
            )
            self.assertNotEqual(changed, original)
            path.write_text(changed, encoding="utf-8")
            violations = self._violations(root)
            self.assertTrue(any(refused in item for item in violations), violations)

    def test_local_actions_are_deployment_policy_and_owned_inputs(self):
        apply = (ROOT / ".github/workflows/apply-on-merge.yml").read_text(encoding="utf-8")
        scope = (ROOT / ".github/scripts/deployment_scope.py").read_text(encoding="utf-8")
        security = (ROOT / ".github/workflows/security.yml").read_text(encoding="utf-8")
        codeowners = (ROOT / ".github/CODEOWNERS").read_text(encoding="utf-8")
        self.assertIn("      - '.github/actions/**'\n", apply)
        self.assertIn('    ".github/actions/**",\n', scope)
        self.assertIn(".github/actions/**", check_supply_chain.SECURITY_PUSH_POLICY_PATHS)
        self.assertEqual(check_supply_chain.security_push_trigger_violations(security), [])
        owned = [
            line for line in codeowners.splitlines(keepends=True)
            if line.startswith("/.github/actions/ ")
        ]
        self.assertEqual(len(owned), 1, owned)
        for relative, line, expected in (
            (".github/workflows/apply-on-merge.yml", "      - '.github/actions/**'\n",
             "the push trigger is missing '.github/actions/**'"),
            (".github/scripts/deployment_scope.py", '    ".github/actions/**",\n',
             "does not treat as a deployment input"),
            (".github/CODEOWNERS", owned[0],
             "launch-critical path is not explicitly owned: /.github/actions/"),
        ):
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as directory:
                root = self._mirror_repo(Path(directory))
                path = root / relative
                original = path.read_text(encoding="utf-8")
                self.assertIn(line, original)
                path.write_text(original.replace(line, "", 1), encoding="utf-8")
                violations = self._violations(root)
                self.assertTrue(any(expected in item for item in violations), violations)

    def test_local_action_pins_are_read_from_the_parsed_file(self):
        unpinned = "not pinned to a 40-hex commit"
        pinned = "acme/run@" + "a" * 40
        for steps, expected in (
            (f"    - uses: {pinned}\n", None),
            ("    - uses: acme/run@v1\n", unpinned),
            # The text scan read only a lowercase `uses:` line.
            ("    - Uses: acme/run@v1\n", unpinned),
            ("    - USES: acme/run@main\n", unpinned),
            (f"    - name: Nested\n      uses: {pinned}\n    - uses: acme/run@main\n",
             unpinned),
            ("    - uses: &pin acme/run@v1\n", "outside the YAML subset"),
        ):
            with self.subTest(steps=steps), tempfile.TemporaryDirectory() as directory:
                root = self._mirror_repo(Path(directory))
                # Not reached by any workflow: its pins are still checked.
                self._local_action(root, "unreached", steps)
                if expected is None:
                    result = subprocess.run(
                        [sys.executable, str(SCRIPT), "--root", str(root)],
                        check=False, text=True, capture_output=True,
                    )
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    continue
                violations = self._violations(root)
                self.assertTrue(
                    any(
                        item.startswith(".github/actions/unreached/action.yml")
                        and expected in item
                        for item in violations
                    ),
                    violations,
                )

    def test_no_local_action_runs_after_an_unjudged_root_checkout(self):
        checkout = "actions/checkout@" + "b" * 40
        local = {"name": "Local", "uses": "./.github/actions/deploy"}
        head = "${{ github.event.pull_request.head.sha }}"
        default = "${{ github.event.repository.default_branch }}"
        refused = "checks another revision out over the workspace root"
        for workflow in self._shipped_workflows():
            with self.subTest(workflow=workflow):
                self.assertEqual(
                    check_supply_chain.workspace_checkout_violations(
                        workflow, self._probe_document(workflow)
                    ),
                    [],
                )
        workflow = ".github/workflows/rust-ci.yml"
        for inputs in (
            {"ref": head},
            {"ref": head, "path": "."},
            {"ref": head, "path": ""},
            {"ref": head, "path": "./"},
            {"ref": head, "path": "${{ github.workspace }}"},
            {"ref": head, "path": ".github"},
            {"ref": head, "path": "candidate/../.github"},
            {"ref": head, "path": "/home/runner/work/repo/repo"},
            {"ref": head, "path": ["candidate"]},
            {"Ref": head},
            {"ref": default, "REF": head},
            {"repository": "attacker/fork"},
            {"repository": "${{ github.event.pull_request.head.repo.full_name }}"},
            {"ref": 1},
            "${{ fromJSON(vars.CHECKOUT) }}",
        ):
            with self.subTest(inputs=inputs):
                document = self._probe_document(workflow)
                steps = self._first_steps(document)
                steps.insert(0, {"uses": checkout, "with": inputs})
                steps.insert(2, dict(local))
                violations = check_supply_chain.workspace_checkout_violations(
                    workflow, document
                )
                self.assertTrue(any(refused in item for item in violations), violations)
        for before in (
            {"uses": checkout},
            {"uses": checkout, "with": {"persist-credentials": False}},
            {"uses": checkout, "with": {"ref": default, "fetch-depth": 0}},
            {"uses": checkout, "with": {"repository": "${{ github.repository }}"}},
            {"uses": checkout, "with": {"ref": head, "path": "candidate"}},
            {"uses": checkout, "with": {"ref": head, "path": "trusted/src/"}},
            {"uses": "acme/checkout@" + "c" * 40, "with": {"ref": head}},
        ):
            with self.subTest(allowed=before):
                document = self._probe_document(workflow)
                steps = self._first_steps(document)
                steps.insert(0, before)
                steps.insert(1, dict(local))
                self.assertEqual(
                    check_supply_chain.workspace_checkout_violations(workflow, document), []
                )
        with self.subTest(allowed="checkout after the local action"):
            document = self._probe_document(workflow)
            steps = self._first_steps(document)
            steps.insert(0, dict(local))
            steps.insert(1, {"uses": checkout, "with": {"ref": head}})
            self.assertEqual(
                check_supply_chain.workspace_checkout_violations(workflow, document), []
            )
        # A local action may not replace the workspace for a later one.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            reference = self._local_action(
                root, "fetch",
                f"    - uses: {checkout}\n      with:\n        ref: {head}\n",
            )
            document = self._probe_document(workflow)
            self._first_steps(document).insert(0, {"name": "Local", "uses": reference})
            violations = check_supply_chain.local_action_violations(root, workflow, document)
            self.assertTrue(
                any(
                    ".github/actions/fetch/action.yml" in item
                    and "may not check another revision out" in item
                    for item in violations
                ),
                violations,
            )
            self._local_action(
                root, "subdirectory",
                f"    - uses: {checkout}\n      with:\n        ref: {head}\n"
                "        path: candidate\n",
            )
            document = self._probe_document(workflow)
            self._first_steps(document).insert(
                0, {"name": "Local", "uses": "./.github/actions/subdirectory"}
            )
            self.assertEqual(
                check_supply_chain.local_action_violations(root, workflow, document), []
            )
        with tempfile.TemporaryDirectory() as directory:
            root = self._mirror_repo(Path(directory))
            self._local_action(root, "deploy", "    - shell: bash\n      run: echo hello\n")
            path = root / ".github/workflows/apply-on-merge.yml"
            original = path.read_text(encoding="utf-8")
            changed = original.replace(
                "    steps:\n",
                f"    steps:\n      - uses: {checkout}\n        with:\n"
                f"          ref: {head}\n"
                "      - name: Local\n        uses: ./.github/actions/deploy\n",
                1,
            )
            self.assertNotEqual(changed, original)
            path.write_text(changed, encoding="utf-8")
            violations = self._violations(root)
            self.assertTrue(any(refused in item for item in violations), violations)

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
                    "    steps:\n      - name: Write a step output\n        run: |\n"
                    "          # Step outputs and the job summary are not env files.\n"
                    '          echo "run_id=$GITHUB_RUN_ID" >> "$GITHUB_OUTPUT"\n'
                    '          echo "done" >> "$GITHUB_STEP_SUMMARY"\n',
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
                        self.assertTrue(self._guarded_bindings(workflow, document))
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
                    self.assertTrue(self._guarded_bindings(workflow, document))
            for startup in ("BASH_ENV", "ENV", "GITHUB_ENV"):
                with self.subTest(workflow=workflow, startup=startup):
                    document = self._probe_document(workflow)
                    document["env"] = {startup: "candidate/inject.sh"}
                    self.assertTrue(self._guarded_bindings(workflow, document))
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
                self.assertTrue(self._guarded_bindings(workflow, document))

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
        self.assertIn("toolchain: 1.99.0", job)
        bumped_job = re.sub(r"@[0-9a-f]{40}", "@" + "a" * 40, job).replace(
            "toolchain: 1.99.0", "toolchain: 1.100.0"
        )
        self.assertNotEqual(bumped_job, job)
        bumped = workflow.replace(job, bumped_job, 1)
        self.assertEqual(check_supply_chain.cargo_audit_job_shape_violations(bumped), [])
        # Each free part still answers to its own rule.
        self.assertTrue(check_supply_chain.cargo_audit_install_violations(bumped))
        self.assertTrue(
            check_supply_chain.rust_toolchain_violations("security.yml", bumped, "1.99.0")
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

    def test_explicit_cargo_toolchains_follow_the_pinned_channel(self):
        self.assertEqual(
            check_supply_chain.cargo_toolchain_violations(
                "alloy-consumer.yml", "cargo +1.99.0 build --locked", "1.99.0"
            ),
            [],
        )
        self.assertTrue(
            check_supply_chain.cargo_toolchain_violations(
                "alloy-consumer.yml", "cargo +1.98.0 build --locked", "1.99.0"
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

    def test_docker_builder_toolchain_must_match_the_channel(self):
        digest = "a" * 64
        matching = f"FROM rust:1.99.0-bookworm@sha256:{digest} AS builder\n"
        mismatched = f"FROM rust:1.98.0-bookworm@sha256:{digest} AS builder\n"
        self.assertEqual(
            check_supply_chain.docker_builder_toolchain_violations(matching, "1.99.0"),
            [],
        )
        violations = check_supply_chain.docker_builder_toolchain_violations(
            mismatched, "1.99.0"
        )
        self.assertTrue(
            any("must match rust-toolchain.toml channel" in item for item in violations),
            violations,
        )

    def test_every_rust_from_stage_must_match_and_builder_must_be_unique(self):
        digest = "a" * 64
        dockerfile = (
            f"FROM rust:1.99.0-bookworm@sha256:{digest} AS builder\n"
            f"FROM rust:1.98.0-bookworm@sha256:{digest} AS compile\n"
        )
        violations = check_supply_chain.docker_builder_toolchain_violations(
            dockerfile, "1.99.0"
        )
        self.assertTrue(
            any("every Rust base image" in item for item in violations), violations
        )

        duplicate_builder = (
            f"FROM rust:1.99.0-bookworm@sha256:{digest} AS builder\n"
            f"FROM rust:1.99.0-bookworm@sha256:{digest} AS BUILDER\n"
        )
        violations = check_supply_chain.docker_builder_toolchain_violations(
            duplicate_builder, "1.99.0"
        )
        self.assertTrue(
            any("exactly one stage named builder" in item for item in violations),
            violations,
        )

    def test_docker_physical_from_scan_rejects_decoy_with_wrong_channel(self):
        digest = "a" * 64
        dockerfile = (
            f"FROM rust:1.99.0-bookworm@sha256:{digest} AS builder\n"
            "RUN echo first \\\n"
            f"    FROM rust:1.98.0-bookworm@sha256:{digest} AS decoy\n"
            "FROM debian:stable-slim@sha256:"
            + digest
            + "\n"
        )
        violations = check_supply_chain.docker_builder_toolchain_violations(
            dockerfile, "1.99.0"
        )
        self.assertTrue(
            any("every Rust base image" in item for item in violations), violations
        )

    def test_docker_b1_double_backslash_does_not_hide_physical_from(self):
        digest = "a" * 64
        dockerfile = (
            f"FROM rust:1.99.0-bookworm@sha256:{digest} AS builder\n"
            "RUN echo foo\\\\\n"
            f"FROM rust:1.98.0-bookworm@sha256:{digest} AS compile\n"
        )
        violations = check_supply_chain.docker_builder_toolchain_violations(
            dockerfile, "1.99.0"
        )
        self.assertTrue(violations, violations)

    def test_docker_from_continuations_cannot_hide_rust_channel(self):
        digest = "a" * 64
        continued_froms = (
            "FROM\\\n"
            f" rust:1.98.0-bookworm@sha256:{digest} AS compile\n",
            "from\\\n"
            f" rust:1.98.0-bookworm@sha256:{digest} AS compile\n",
            "FROM\\ \t\n"
            f"\trust:1.98.0-bookworm@sha256:{digest} AS compile\n",
            "FROM\\\n"
            "  # continued FROM comment\n"
            f" rust:1.98.0-bookworm@sha256:{digest} AS compile\n",
        )
        for continued_from in continued_froms:
            with self.subTest(continued_from=continued_from):
                dockerfile = (
                    f"FROM rust:1.99.0-bookworm@sha256:{digest} AS builder\n"
                    + continued_from
                )
                violations = check_supply_chain.docker_builder_toolchain_violations(
                    dockerfile, "1.99.0"
                )
                self.assertTrue(violations, violations)

    def test_docker_from_backslash_fails_closed_when_physical_match_cannot_parse(self):
        hidden_unpinned_stage = "FROM\\\n rust:1.98.0-bookworm AS compile\n"
        self.assertEqual(check_supply_chain.FROM.findall(hidden_unpinned_stage), ["\\"])

        lines = (
            "FROM\\\n rust:1.99.0-bookworm AS builder\n",
            "from\\\n rust:1.99.0-bookworm AS builder\n",
        )
        for line in lines:
            with self.subTest(line=line):
                violations = check_supply_chain.docker_builder_toolchain_violations(
                    line, "1.99.0"
                )
                self.assertTrue(
                    any("could not parse FROM" in item for item in violations),
                    violations,
                )

    def test_docker_b2_rejects_unicode_whitespace_after_escape(self):
        dockerfile = (
            "FROM rust:1.99.0-bookworm AS builder\n"
            "RUN echo hi \\" + "\u00a0\n"
            "FROM rust:1.98.0-bookworm AS compile\n"
        )
        self.assertTrue(
            check_supply_chain.docker_builder_toolchain_violations(dockerfile, "1.99.0")
        )

    def test_docker_b3_rejects_heredoc_marker_in_quoted_label(self):
        dockerfile = (
            "FROM rust:1.99.0-bookworm AS builder\n"
            'LABEL note="a <<END b"\n'
            "FROM rust:1.98.0-bookworm AS compile\n"
        )
        self.assertTrue(
            check_supply_chain.docker_builder_toolchain_violations(dockerfile, "1.99.0")
        )

    def test_docker_b4_rejects_quoted_heredoc_delimiter(self):
        dockerfile = (
            "FROM rust:1.99.0-bookworm AS builder\n"
            "RUN <<E\"O\"F\n"
            "body\n"
            "EOF\n"
            "FROM rust:1.98.0-bookworm AS compile\n"
        )
        self.assertTrue(
            check_supply_chain.docker_builder_toolchain_violations(dockerfile, "1.99.0")
        )

    def test_docker_b5_rejects_heredoc_marker_in_continuation_comment(self):
        dockerfile = (
            "FROM rust:1.99.0-bookworm AS builder\n"
            "RUN echo first \\\n"
            "  # <<END\n"
            f"FROM rust:1.98.0-bookworm@sha256:{'a' * 64} AS compile\n"
        )
        self.assertTrue(
            check_supply_chain.docker_builder_toolchain_violations(dockerfile, "1.99.0")
        )

    def test_docker_b6_rejects_all_parser_directives(self):
        dockerfiles = (
            "FROM rust:1.99.0-bookworm AS builder\n"
            " # escape=`\n"
            "RUN echo x #\\\n"
            "FROM rust:1.98.0-bookworm AS compile\n",
            "# syntax=docker/dockerfile:1\n"
            "FROM rust:1.99.0-bookworm AS builder\n",
            "# syntax=docker/dockerfile:1\n"
            "# escape=`\n"
            "FROM rust:1.99.0-bookworm AS builder\n"
            "RUN echo x #\\\n"
            "FROM rust:1.98.0-bookworm AS compile\n",
        )
        for dockerfile in dockerfiles:
            with self.subTest(dockerfile=dockerfile):
                self.assertTrue(
                    check_supply_chain.docker_builder_toolchain_violations(
                        dockerfile, "1.99.0"
                    )
                )

    def test_docker_b7_rejects_variable_in_from_image(self):
        dockerfile = (
            "FROM rust:1.99.0-bookworm AS builder\n"
            "ARG BASE=rust:1.98.0-bookworm\n"
            "FROM ${BASE}@sha256:"
            + "a" * 64
            + " AS compile\n"
        )
        violations = check_supply_chain.docker_builder_toolchain_violations(
            dockerfile, "1.99.0"
        )
        self.assertTrue(
            any("could not parse FROM" in item for item in violations), violations
        )

    def test_docker_toolchain_check_fails_closed_on_unparseable_input(self):
        self.assertTrue(
            check_supply_chain.docker_builder_toolchain_violations(
                "FROM rust:1.99.0-bookworm AS builder \\", "1.99.0"
            )
        )
        self.assertTrue(
            check_supply_chain.docker_builder_toolchain_violations(
                "FROM rust:1.99.0-bookworm AS builder extra\n", "1.99.0"
            )
        )

    def test_main_rejects_dockerfile_rust_channel_mismatch(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self._mirror_repo(Path(temporary))
            dockerfile = root / "Dockerfile"
            text = dockerfile.read_text(encoding="utf-8")
            changed = text.replace("rust:1.99.0-bookworm", "rust:1.98.0-bookworm", 1)
            self.assertNotEqual(text, changed)
            dockerfile.write_text(changed, encoding="utf-8")
            violations = self._violations(root)
        self.assertTrue(
            any("every Rust base image" in item for item in violations), violations
        )

    def test_main_rejects_invalid_rust_toolchain_files(self):
        invalid_files = {
            "nightly": ('[toolchain]\nchannel = "nightly"\n', None),
            "missing patch": ('[toolchain]\nchannel = "1.99"\n', None),
            "non-string channel": ('[toolchain]\nchannel = 198\n', None),
            "leading zero": ('[toolchain]\nchannel = "01.99.0"\n', None),
            "unicode digits": ('[toolchain]\nchannel = "١.99.0"\n', None),
            "duplicate table": (
                '[toolchain]\nchannel = "1.99.0"\n'
                '[toolchain]\nchannel = "1.99.0"\n',
                None,
            ),
            "decoy table": (
                '[toolchain]\nchannel = "1.99.0"\n'
                '[decoy]\nchannel = "1.98.0"\n',
                None,
            ),
            "path key": (
                '[toolchain]\nchannel = "1.99.0"\npath = "../rust"\n', None
            ),
            "unknown key": (
                '[toolchain]\nchannel = "1.99.0"\ncustom = "value"\n', None
            ),
            "below floor": ('[toolchain]\nchannel = "1.97.9"\n', None),
            "legacy file": ('[toolchain]\nchannel = "1.99.0"\n', "legacy"),
            "missing file": (None, None),
        }
        for label, (contents, legacy) in invalid_files.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                root = self._mirror_repo(Path(temporary))
                toolchain = root / "rust-toolchain.toml"
                if contents is None:
                    toolchain.unlink()
                else:
                    toolchain.write_text(contents, encoding="utf-8")
                if legacy is not None:
                    (root / "rust-toolchain").write_text("1.99.0\n", encoding="utf-8")
                violations = self._violations(root)
                self.assertTrue(
                    any(
                        "rust-toolchain.toml: expected [toolchain].channel" in item
                        for item in violations
                    ),
                    violations,
                )

    def test_rust_toolchain_floor_violation_names_the_configured_minimum(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self._mirror_repo(Path(temporary))
            (root / "rust-toolchain.toml").write_text(
                '[toolchain]\nchannel = "1.98.0"\n', encoding="utf-8"
            )
            violations = self._violations(root)
            self.assertTrue(
                any("channel at or above 1.99.0" in item for item in violations),
                violations,
            )

    def test_main_manifest_records_the_parsed_rust_toolchain_channel(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self._mirror_repo(Path(temporary) / "candidate")
            manifest_path = Path(temporary) / "manifest.json"
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--root",
                    str(root),
                    "--write-manifest",
                    str(manifest_path),
                ],
                check=False,
                text=True,
                capture_output=True,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(
                manifest["rust_toolchain"],
                "1.99.0",
            )
            self.assertTrue(
                any(
                    image.startswith(f"rust:{manifest['rust_toolchain']}-")
                    for image in manifest["docker_bases"]
                ),
                manifest["docker_bases"],
            )

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
                violations = check_supply_chain.monitoring_jwt_binding_violations(workflow, document)
                if scope == "env-file":
                    violations = check_supply_chain.workflow_channel_violations(workflow, document)
                self.assertTrue(violations)

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

    # -- release gate -------------------------------------------------------

    RELEASE = ".github/workflows/release.yml"
    RELEASE_HELPER_STEP = (
        "      - name: Verify the published commit passed every required check\n"
        "        timeout-minutes: 16\n"
        "        env:\n"
        "          GH_TOKEN: ${{ github.token }}\n"
        "          REPO: ${{ github.repository }}\n"
        "          RELEASE_SHA: ${{ github.sha }}\n"
        "          DEFAULT_BRANCH: ${{ github.event.repository.default_branch }}\n"
        "        run: python3 -I .github/scripts/release_gate.py\n"
    )

    def _helper_release(self, step: str | None = None) -> str:
        """The shipped release.yml, optionally with another gate step."""
        text = (ROOT / self.RELEASE).read_text(encoding="utf-8")
        self.assertEqual(text.count(self.RELEASE_HELPER_STEP), 1)
        return text.replace(self.RELEASE_HELPER_STEP, step or self.RELEASE_HELPER_STEP, 1)

    def _release_gate_refusals(self, text: str, root: Path = ROOT) -> list[str]:
        return check_supply_chain.release_gate_violations(
            root, check_supply_chain.parse_workflow(text)
        )

    def _helper_violations(self, source: str) -> list[str]:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / check_supply_chain.RELEASE_GATE_HELPER
            path.parent.mkdir(parents=True)
            path.write_text(source, encoding="utf-8")
            return check_supply_chain.release_gate_helper_violations(root)

    def test_shipped_release_gate_and_helper_pass(self):
        self.assertEqual(self._release_gate_refusals(self._helper_release()), [])
        self.assertEqual(check_supply_chain.release_gate_helper_violations(ROOT), [])

    def test_release_gate_pins_match_the_ruleset_contexts(self):
        # The launch list is REQUIRED_CHECK_WORKFLOWS minus the job being added
        # to the ruleset, which the gate tolerates while absent.
        jobs = [
            context.split(" / ")[-1]
            for context in check_supply_chain.RELEASE_GATE_REQUIRED_CHECKS
            + check_supply_chain.RELEASE_GATE_ACCEPTED_CHECKS
        ]
        self.assertEqual(sorted(jobs), sorted(check_supply_chain.REQUIRED_CHECK_WORKFLOWS))
        self.assertEqual(
            [context.split(" / ")[-1] for context in check_supply_chain.RELEASE_GATE_ACCEPTED_CHECKS],
            [check_supply_chain.SUPPLY_CHAIN_POLICY_JOB],
        )

    def test_helper_invocation_is_pinned(self):
        step = self.RELEASE_HELPER_STEP
        for name, changed in (
            ("no isolation", self._helper_release(step.replace("python3 -I ", "python3 "))),
            ("inline script", self._helper_release(step.replace(
                "        run: python3 -I .github/scripts/release_gate.py\n",
                "        run: |\n          set -euo pipefail\n          echo published\n",
            ))),
            ("extra command", self._helper_release(step.replace(
                "        run: python3 -I .github/scripts/release_gate.py\n",
                "        run: |\n          python3 -I .github/scripts/release_gate.py\n"
                "          echo published\n",
            ))),
            ("other script", self._helper_release(
                step.replace("release_gate.py", "check_release_baseline.py")
            )),
            ("extra env", self._helper_release(step.replace(
                "        run:", "          PATH: /tmp/bin\n        run:"
            ))),
            ("missing env", self._helper_release(
                step.replace("          GH_TOKEN: ${{ github.token }}\n", "")
            )),
            ("shell", self._helper_release(step + "        shell: sh\n")),
            ("condition", self._helper_release(step + "        if: always()\n")),
            ("tolerated", self._helper_release(step + "        continue-on-error: true\n")),
            ("short timeout", self._helper_release(
                step.replace("timeout-minutes: 16", "timeout-minutes: 5")
            )),
            ("checkout ref", self._helper_release().replace(
                "          persist-credentials: false\n\n"
                "      - name: Verify the published commit",
                "          persist-credentials: false\n          ref: main\n\n"
                "      - name: Verify the published commit",
                1,
            )),
            ("job env", self._helper_release().replace(
                "    timeout-minutes: 45\n", "    timeout-minutes: 45\n    env:\n      X: y\n", 1
            )),
        ):
            with self.subTest(case=name):
                self.assertNotEqual(changed, self._helper_release())
                self.assertTrue(self._release_gate_refusals(changed), changed)
        # A step that runs before the checkout-then-helper pair could rewrite
        # the helper the gate then runs.
        text = self._helper_release()
        checkout = text.rindex(
            "      - uses: actions/checkout@", 0, text.index(self.RELEASE_HELPER_STEP)
        )
        early = text[:checkout] + "      - run: echo early\n\n" + text[checkout:]
        self.assertTrue(
            any("second step" in item for item in self._release_gate_refusals(early))
        )

    def test_helper_must_exist_once_release_runs_it(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            refusals = self._release_gate_refusals(self._helper_release(), root)
            self.assertTrue(any("must exist" in item for item in refusals), refusals)

    def test_helper_pins_constants_imports_and_calls(self):
        source = (ROOT / check_supply_chain.RELEASE_GATE_HELPER).read_text(encoding="utf-8")
        self.assertEqual(self._helper_violations(source), [])
        guard = 'if __name__ == "__main__":\n    raise SystemExit(main())\n'
        self.assertTrue(source.endswith(guard))
        body = source[: -len(guard)]
        cases = (
            ("dropped check", source.replace('    "Security / security-cargo-audit",\n', "", 1)),
            ("budget", source.replace("BUDGET_SECONDS = 900", "BUDGET_SECONDS = 9000", 1)),
            ("app", source.replace("ACTIONS_APP_ID = 15368", "ACTIONS_APP_ID = True", 1)),
            ("rebound", body + "REQUIRED_CHECKS = ()\n" + guard),
            ("shadowed", body + "def f(BUDGET_SECONDS=1):\n    return BUDGET_SECONDS\n" + guard),
            ("global", body + "def f():\n    global ACTIONS_APP_ID\n" + guard),
            ("aliased import", body + "import os as o\n" + guard),
            ("other import", body + "import importlib\n" + guard),
            ("from import", body + "from subprocess import Popen\n" + guard),
            ("os call", body + "os.system('true')\n" + guard),
            ("module alias", body + "runner = subprocess\n" + guard),
            ("run reference", body + "runner = subprocess.run\n" + guard),
            ("shell run", body + "subprocess.run('gh', shell=True)\n" + guard),
            ("other command", body + "subprocess.run(['sh', '-c', 'true'])\n" + guard),
            ("dynamic lookup", body + "getattr(time, 'sleep')\n" + guard),
            ("dunder", body + "time.__dict__\n" + guard),
            ("dunder name", body + "loader = __loader__\n" + guard),
            ("generator frame", body + "frame = value.gi_frame\n" + guard),
            ("generator code", body + "code = value.gi_code\n" + guard),
            ("frame globals", body + "globals_ = value.f_globals\n" + guard),
            ("frame locals", body + "locals_ = value.f_locals\n" + guard),
            ("frame back", body + "back = value.f_back\n" + guard),
            ("frame builtins", body + "builtins_ = value.f_builtins\n" + guard),
            ("coroutine frame", body + "frame = value.cr_frame\n" + guard),
            ("async generator frame", body + "frame = value.ag_frame\n" + guard),
            ("traceback frame", body + "frame = value.tb_frame\n" + guard),
            ("coroutine code", body + "code = value.cr_code\n" + guard),
            ("async generator code", body + "code = value.ag_code\n" + guard),
            ("frame code", body + "code = value.f_code\n" + guard),
            ("dunder name outside guard", body + "MODULE = __name__\n" + guard),
            ("traceback next", body + "next_ = value.tb_next\n" + guard),
            ("file write", body + "open('x', 'w')\n" + guard),
            ("env-file name", body + "TARGET = 'GITHUB_ENV'\n" + guard),
            # Reach through an allowed module, or past an allowed reference.
            ("parse traversal", body + "urllib.parse.sys.modules\n" + guard),
            ("re traversal", body + "re.enum.sys\n" + guard),
            ("json traversal", body + "json.codecs.open('x', 'a')\n" + guard),
            ("typing import", body + "import typing\n" + guard),
            ("typing name", body + "from typing import Any\n" + guard),
            ("future name", body + "from __future__ import division\n" + guard),
            ("bare module", body + "print(json)\n" + guard),
            ("stream traversal", body + "sys.stdout.buffer.write(b'x')\n" + guard),
            ("stream method", body + "sys.stderr.reconfigure()\n" + guard),
            ("unlisted attribute", body + "time.perf_counter()\n" + guard),
            ("rebound module", body + "def f(json):\n    return json\n" + guard),
            ("rebound dict", body + "dict = list\n" + guard),
            ("class pattern", body + "match 1:\n    case int(real=x):\n        pass\n" + guard),
            ("pager", body + "help(slurp)\n" + guard),
            # gh may run only `gh api` and `gh pr checks`.
            ("gh alias", body + "subprocess.run(['gh', 'alias', 'set', 'x', 'y'])\n" + guard),
            ("gh extension", body + "subprocess.run(['gh', 'extension', 'install', 'x'])\n" + guard),
            ("gh computed", body + "subprocess.run(['gh', *ARGS])\n" + guard),
            ("gh pr other", body + "subprocess.run(['gh', 'pr', 'checkout', '1'])\n" + guard),
            ("gh kwargs", body + "subprocess.run(['gh', 'api', 'user'], **OPTIONS)\n" + guard),
            (
                "gh environment expression",
                body + "subprocess.run(['gh', 'api', 'user'], env=None)\n" + guard,
            ),
            (
                "gh missing environment",
                body + "subprocess.run(['gh', 'api', 'user'])\n" + guard,
            ),
            # Runner variable and channel names, even split across literals.
            ("split channel", body + "TARGET = 'GITHUB_' + 'ENV'\n" + guard),
            ("f-string channel", body + "TARGET = f\"GIT{'HUB_'}ENV\"\n" + guard),
            ("joined channel", body + "TARGET = ''.join(['GITHUB', '_OUTPUT'])\n" + guard),
            ("runner variable", body + "TARGET = 'GITHUB_' + 'TOKEN'\n" + guard),
            # The process environment is read only as a copy.
            ("environment write", body + "os.environ['GH_HOST'] = 'x'\n" + guard),
            ("environment update", body + "os.environ.update({})\n" + guard),
            ("environment alias", body + "ENVIRONMENT = os.environ\n" + guard),
            ("environment augment", body + "os.environ |= {}\n" + guard),
            ("environment delete", body + "del os.environ\n" + guard),
            ("no guard", body),
            ("marker", source.replace("exactly one merged PR", "one merged PR", 1)),
            ("syntax", source + "def (\n"),
        )
        for name, changed in cases:
            with self.subTest(case=name):
                self.assertNotEqual(changed, source)
                self.assertTrue(self._helper_violations(changed))

    def test_mirrored_repository_running_the_helper_is_a_clean_baseline(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._mirror_repo(Path(directory))
            (root / self.RELEASE).write_text(self._helper_release(), encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--root", str(root)],
                check=False,
                text=True,
                capture_output=True,
            )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    # -- shell values -------------------------------------------------------

    def test_shell_values_and_run_defaults_may_not_be_computed(self):
        workflow = ".github/workflows/rust-ci.yml"
        for name, mutate in (
            ("step shell", lambda document, job: self._first_steps(document).insert(
                0, {"shell": "${{ vars.SHELL }} {0}", "run": "true"}
            )),
            ("job default", lambda document, job: job.update(
                {"defaults": {"run": {"shell": "${{ matrix.shell }}"}}}
            )),
            ("workflow default", lambda document, job: document.update(
                {"defaults": {"run": {"shell": "bash ${{ inputs.flags }} {0}"}}}
            )),
            ("computed defaults", lambda document, job: document.update(
                {"defaults": "${{ fromJSON(vars.DEFAULTS) }}"}
            )),
            ("computed run defaults", lambda document, job: job.update(
                {"defaults": {"run": "${{ fromJSON(vars.RUN) }}"}}
            )),
            ("non-scalar shell", lambda document, job: self._first_steps(document).insert(
                0, {"shell": ["bash"], "run": "true"}
            )),
        ):
            with self.subTest(case=name):
                document = self._probe_document(workflow)
                mutate(document, document["jobs"]["rust-ci-check"])
                self.assertTrue(
                    check_supply_chain.shell_expression_violations(workflow, document)
                )
        document = self._probe_document(workflow)
        document["defaults"] = {"run": {"shell": "bash"}}
        self._first_steps(document).insert(0, {"shell": "bash -eo pipefail {0}", "run": "true"})
        self.assertEqual(check_supply_chain.shell_expression_violations(workflow, document), [])

    def test_shipped_workflows_spell_every_shell_literally(self):
        for workflow in self._shipped_workflows():
            with self.subTest(workflow=workflow):
                self.assertEqual(
                    check_supply_chain.shell_expression_violations(
                        workflow, self._probe_document(workflow)
                    ),
                    [],
                )

    def test_local_action_shell_values_may_not_be_computed(self):
        rust = ".github/workflows/rust-ci.yml"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            reference = self._local_action(
                root, "local", "    - shell: ${{ inputs.shell }}\n      run: echo hello\n"
            )
            document = self._probe_document(rust)
            self._first_steps(document).insert(0, {"name": "Local", "uses": reference})
            violations = check_supply_chain.local_action_violations(root, rust, document)
        self.assertTrue(
            any("a shell may not be computed" in item for item in violations), violations
        )
        with tempfile.TemporaryDirectory() as directory:
            root = self._mirror_repo(Path(directory))
            path = root / rust
            original = path.read_text(encoding="utf-8")
            changed = original.replace(
                "    steps:\n",
                "    steps:\n      - name: Computed shell\n"
                "        shell: ${{ vars.SHELL }}\n"
                "        run: echo hello\n",
                1,
            )
            self.assertNotEqual(changed, original)
            path.write_text(changed, encoding="utf-8")
            violations = self._violations(root)
        self.assertTrue(
            any("a shell may not be computed" in item for item in violations), violations
        )

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
            ".github/scripts/release_gate.py",
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
