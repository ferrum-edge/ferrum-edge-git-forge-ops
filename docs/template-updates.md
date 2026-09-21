# Adopting upstream updates in a template copy

Creating a repository from this template copies **files, not history**. GitHub
gives the new repository a fresh root commit with no ancestor in common with
upstream, so `git merge upstream/main` has nothing to merge. And because
`apply-on-merge.yml` builds the engine from *your* checkout
(`cargo install --path . --locked`), publishing a new container image upstream
does not change what your repository runs either.

That is a deliberate property — your repository runs code you can read and
review — but it means an upstream security or correctness fix reaches you only
when you deliberately adopt it. This page is how.

## The model

One recorded baseline plus a three-way comparison:

```
baseline (B)   the upstream commit your tree was last synced from,
               recorded in .gitforgeops/baseline.json
upstream (U)   the same path at the upstream revision you are adopting
local    (L)   the path as it stands in your repository
```

Per upstream-managed file:

| | Result |
| --- | --- |
| `B == U` | upstream did not change it — skipped, your edits preserved |
| `L == B`, `B != U` | you never touched it — **adopted** |
| `L == U` | already adopted — skipped |
| otherwise | **conflict** — reported, never overwritten |

A conflict is never resolved for you. A machine cannot know whether your edit
to `apply-on-merge.yml` was a deliberate policy or a stale copy, and copying an
upstream tree over customer configuration is precisely the failure this exists
to prevent.

## What is whose

**Upstream-managed** — the engine and the machinery around it:

```
src/  tests/  build.rs  Cargo.toml  Cargo.lock  rust-toolchain.toml
Dockerfile  .dockerignore
.github/workflows/  .github/scripts/
.github/ferrum-edge-checksums.txt  .github/cargo-audit-policy.json
.github/dependabot.yml
.gitforgeops/config.example.yaml  .gitforgeops/policies.example.yaml
docs/  README.md  CLAUDE.md  SECURITY.md  LICENSE.md
```

**Yours, never read from upstream and never written**:

```
resources/  overlays/
.gitforgeops/config.yaml  .gitforgeops/policies.yaml
.state/  assembled/
.github/CODEOWNERS
```

Three of those are worth spelling out:

- **`.state/`** is your ownership ledger. Writing an upstream copy over it — or
  restoring an old one during a rollback — would hand your repository a ledger
  describing a gateway it no longer has. Shared mode reads rows it never saw as
  "never managed" and stops reconciling them.
- **`.github/CODEOWNERS`** ships upstream's maintainers, and the setup guide
  tells you to replace them. Adopting upstream's copy would hand review of your
  launch-critical paths back to people who do not work at your company.
- **`README.md` is upstream-managed**, because it is the engine's documentation
  and it changes with the engine. If you rewrote it for your own team, upstream
  editing it will surface as a conflict on every update — resolve it by keeping
  yours. Consider putting your own description in a separate file so this stops
  being a recurring decision.

**Outside Git entirely, and untouched by construction**: repository settings,
rulesets, GitHub Environments, environment secrets, the credential-broker
bundles, and the state-writer App's identity and private key. No update ever
reads or writes any of them.

The lists live in `.github/scripts/template_update.py` (`UPSTREAM_MANAGED`,
`CUSTOMER_OWNED`) and `.github/scripts/tests/test_template_update.py` asserts
they stay disjoint and that this repository's own tree matches them.

## Finding out an update exists

There is no push notification; you pull. Three ways, in decreasing order of
how much attention they need from you:

1. **Watch the upstream repository** for releases and security advisories
   ([`SECURITY.md`](../SECURITY.md) is where advisories are published).
   Release notes name the supported gateway and validator pairing.
2. **Run `status` on a schedule.** It is read-only and needs no credentials:

   ```bash
   python3 .github/scripts/template_update.py status
   ```

3. **Read the diff yourself** between your baseline and upstream's head. The
   `status` output prints the exact `git diff` invocation for any file you want
   to inspect.

`status` exits 0 whether or not there is anything to adopt — it is a report.
`plan` exits 1 when a conflict exists, so it is the one to wire into a job if
you want a red signal.

## Adopting one

```bash
# 1. Where are we?
python3 .github/scripts/template_update.py identify

# 2. What would change?  (read-only; exits 1 on a conflict)
python3 .github/scripts/template_update.py plan --to v0.2.0

# 3. On a branch, never on main.
git switch -c chore/adopt-upstream-v0.2.0
python3 .github/scripts/template_update.py apply --to v0.2.0
```

`--to` takes any upstream revision: a release tag, a branch, or a commit SHA.
Omit it and the ref recorded in your baseline (`main` by default) is used.

`apply` writes only the clean updates. If any conflict remains it prints them,
**does not advance the baseline**, and exits 1 — a half-adopted update must not
be recorded as a completed one. Resolve each conflicting file deliberately,
commit, and re-run `apply` to record the baseline.

### Review it like the code change it is

An engine or workflow update is not a documentation change. It alters the
program that holds your gateway's admin credentials and the workflow that
decides who is allowed to deploy. Read the diff.

Pay particular attention to changes under `.github/workflows/` and
`.github/scripts/`: those define the authorization boundary, the freshness
guard, and credential delivery. `check_supply_chain.py` enforces a great deal
of that mechanically (see step 4 below), but it enforces the *shape* of the
controls, not your intent.

### Re-run everything before deploying

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --test unit_tests
python3 .github/scripts/check_supply_chain.py
python3 -m unittest discover -s .github/scripts/tests
gitforgeops validate
python3 .github/scripts/bootstrap_repo_settings.py --repo OWNER/REPO
gitforgeops --env ENV plan
```

`apply` prints this list for you. Three of them deserve a note:

- **`check_supply_chain.py`** is the one that catches an update that landed
  half a control — a workflow whose freshness guard, credential-bundle
  bindings, or state-writer ordering no longer match the policy.
- **`bootstrap_repo_settings.py`** without `--apply` is a settings *diff*. An
  update that adds a required status check leaves your ruleset one check short
  until you re-run it with `--apply`.
- **`gitforgeops --env ENV plan` must be a no-op.** An engine update changes
  how desired state is computed, not what it is. If the plan shows resource
  changes you did not make, stop: either the update normalizes something
  differently, or your desired state drifted. Find out which before applying.

### Gateway and validator compatibility stays explicit

An engine update can carry a new validator pin
(`.github/ferrum-edge-checksums.txt`) and can require a newer gateway. Neither
is inferred:

- `identify` prints the installed engine version, template baseline, and the
  allowlisted validator digests.
- The gateway's own version comes from the gateway — `gitforgeops doctor
  --scope gateway` (or a plain `GET /health`) reports its mode and readiness.
- Upstream release notes state the supported pairing.

If an update requires a gateway you have not upgraded yet, upgrade the gateway
first. `validate` failing with an unknown-field diagnostic naming `labels` is
the specific symptom of a validator that predates resource attribution; the
message names the remedy.

## Then merge it like any other change

The update is a pull request on your own repository, which means it goes
through your own controls: required checks, the state guard, the settings
audit, and — once merged — an environment-approved apply.

That last part matters. `.github/scripts/**`, `.github/workflows/apply-on-merge.yml`,
`src/**` and the manifests are **deployment inputs**: merging an update
schedules an apply of its own, and supersedes any apply still queued from an
earlier merge. That is deliberate — a new engine reconciles differently, so it
must not ride an older approval, and it must not leave the earlier merge's
desired state with nothing to reconcile it. See
[Deployment inputs](../README.md#deployment-inputs-one-list-for-scheduling-and-for-supersession).

The first apply after an update runs new code against your live gateway.
Adopt on a non-production environment first if you have one.

## When an update goes wrong

**Revert the adoption commit.** It is an ordinary commit on your branch or on
`main`:

```bash
git revert <adoption-commit>
```

That restores the previous engine, workflows and validator pin, and — because
`.gitforgeops/baseline.json` is part of the same commit — the previous recorded
baseline, so `status` reports the update as available again rather than as
adopted.

**Do not restore an old `.state/<env>.json`.** The ledger is forward-only. It
records what this repository has applied to a live gateway, which reverting
code does not un-apply. Restoring an older snapshot tells shared mode that rows
it does manage were never managed, and it quietly stops reconciling them; in
exclusive mode it can make the next apply look like a large prune. If the
ledger itself is wrong, that is a separate, deliberate repair with the
`gitforgeops/state-override` label and a qualified maintainer — never a side
effect of a rollback.

**Do not roll back unrelated live configuration.** Reverting the adoption
commit reverts upstream-managed files only; your resources and overlays are not
in it, and the next apply reconciles the desired state you actually want.

After the revert, run the same check list. If the gateway was mutated by an
apply that used the bad engine, reconcile with `gitforgeops --env ENV plan`
before anything else and read the diff carefully.

## Publishing images stays opt-in

Adopting an update does not make your repository publish anything. `release.yml`
publishes only from the upstream repository or where repository variable
`GITFORGEOPS_RELEASE_ENABLED=true` opts in; the variable is yours and no update
sets it. If you do publish your own images, point `DOCKERHUB_IMAGE` at a
namespace you control — an adopted update never changes where you push.

## What a supported baseline means

This adoption contract begins at the first supported release. Upstream does not
promise to update a repository copied from an arbitrary pre-release development
revision: the baseline you record has to be a revision upstream still has, and
the further behind you are, the more of the three-way comparison lands in the
conflict column. Adopt regularly and each update is small.
