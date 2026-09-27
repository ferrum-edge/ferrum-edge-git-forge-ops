# Adopting upstream updates in a template copy

Creating a repository from this template copies **files, not history**. The
new repository gets a fresh root commit with no common ancestor, so
`git merge upstream/main` has nothing to merge. And `apply-on-merge.yml`
builds the engine from *your* checkout (`cargo install --path . --locked`), so
a new upstream container image does not change what your repository runs
either.

That is deliberate: your repository runs code you can read and review. It also
means an upstream security or correctness fix reaches you only when you adopt
it. This page shows how, using `.github/scripts/template_update.py`.

## The model

The tool keeps one recorded baseline and does a three-way comparison:

```
baseline (B)   the upstream commit your tree was last synced from,
               recorded in .gitforgeops/baseline.json
upstream (U)   the same path at the upstream revision you are adopting
local    (L)   the path as it stands in your repository
```

For each upstream-managed file:

| | Result |
| --- | --- |
| `B == U` | upstream did not change it: skipped, your edits kept |
| `L == B`, `B != U` | you never touched it: **adopted** |
| `L == U` | already adopted: skipped |
| otherwise | **conflict**: reported, never overwritten |

The tool never resolves a conflict for you. It cannot know whether your edit
to `apply-on-merge.yml` was a deliberate policy or a stale copy, and copying an
upstream tree over your configuration is exactly what this process exists to
prevent.

## What is whose

**Upstream-managed**: the engine and the machinery around it.

```
src/  tests/  build.rs  Cargo.toml  Cargo.lock  rust-toolchain.toml
Dockerfile  .dockerignore
.github/workflows/  .github/scripts/
.github/ferrum-edge-checksums.txt  .github/cargo-audit-policy.json
.github/dependabot.yml
.gitforgeops/config.example.yaml  .gitforgeops/policies.example.yaml
.gitforgeops/smoke.example.yaml
release/  docs/  README.md  CLAUDE.md  SECURITY.md  LICENSE.md
```

**Yours**: never read from upstream and never written.

```
resources/  overlays/
.gitforgeops/config.yaml  .gitforgeops/policies.yaml
.state/  assembled/
.github/CODEOWNERS
```

Three of these deserve a note:

- **`.state/`** is your ownership ledger. Overwriting it with upstream's copy,
  or restoring an old one during a rollback, would describe a gateway you no
  longer have. Shared mode would treat rows missing from it as never managed
  and stop reconciling them.
- **`.github/CODEOWNERS`** ships with upstream's maintainers, and setup tells
  you to replace them. Adopting upstream's copy would hand review of your
  launch-critical paths back to people outside your organization.
- **`README.md` is upstream-managed** because it documents the engine and
  changes with it. If you rewrote it for your team, every upstream edit shows
  up as a conflict; keep yours with `--keep README.md`. Putting your own
  description in a separate file avoids the recurring decision.

**Outside Git, and never touched**: repository settings, rulesets, GitHub
Environments, environment secrets, the credential-broker bundles, and the
state-writer App's identity and private key.

The lists are `UPSTREAM_MANAGED` and `CUSTOMER_OWNED` in
`.github/scripts/template_update.py`.
`.github/scripts/tests/test_template_update.py` checks that they do not overlap
and that this repository's tree matches them.

### Links are refused, not followed

The tool reaches every file one real directory at a time from the repository
root and never follows a symbolic link. If an upstream-managed file, a
directory above it, or `.gitforgeops/baseline.json` is a symbolic link or a
special file, `detect-baseline`, `status`, `plan` and `apply` stop with an
error naming it **before writing anything**, and the baseline is not advanced.
Replace the link with the real file or directory and re-run. The tool also
refuses:

- a path that does not resolve to somewhere under the repository root;
- an upstream revision that records a managed path as a link or a submodule.

Adopted files are written to a temporary file beside the destination and then
renamed into place. A destination that is a hard link is therefore replaced in
your repository, and the other copy is left alone. The tool runs on Linux and
macOS, and refuses to run on a platform that cannot open a file without
following links.

An adopted file gets the mode Git would check it out with: executable or not,
as upstream records it, minus your umask. As in Git, only the owner's execute
bit counts when comparing a local file, and not even that when your repository
sets `core.fileMode=false`.

**Leftover temporary files.** An interrupted `apply` can leave a file named
`.<file>.template-update-<16 hex digits>`. `detect-baseline`, `status`, `plan`
and `apply` look for these beside each upstream-managed file and under each
upstream-managed directory. In the repository root, `.github/` and
`.gitforgeops/` they look only for the temporary of a managed file's own name.
Only `apply` and `detect-baseline --write` delete one, and only once it is at
least ten minutes old, since a younger one may belong to an update still
running. Otherwise it is reported on stderr and left in place. Only a regular
file with exactly that name is ever removed, and a nested clone's `.git`
directory is never searched.

## Finding out an update exists

There is no push notification. Check in one of these ways:

1. **Watch the upstream repository** for releases and security advisories (see
   [`SECURITY.md`](../SECURITY.md)). Release notes name the supported gateway
   and validator pairing.
2. **Run `status` on a schedule.** It is read-only and needs no credentials:

   ```bash
   python3 .github/scripts/template_update.py status
   ```

   For any file, its output includes the `git diff` command to inspect the
   upstream change.

`status` always exits 0; it is a report. `plan` exits 1 when there is a
conflict, so use `plan` if you want a job to go red.

`plan` and `apply` compare only paths present in the recorded baseline tree or
the target tree. A file you added at a path that exists in neither is not part
of the comparison.

## Before your first update: record your real baseline

"Use this template" copies upstream's own `.gitforgeops/baseline.json`, which
names whichever upstream commit last wrote it, not the commit you copied.
Left alone, files upstream changed between those two commits show up as false
conflicts. Record the real baseline once:

```bash
python3 .github/scripts/template_update.py detect-baseline          # report
python3 .github/scripts/template_update.py detect-baseline --write  # record it
```

It searches upstream's history for the commit whose upstream-managed files
match yours exactly, and records only an exact match. If you have already
edited upstream-managed files, it reports the closest commit and how many paths
differ. Confirm that is the revision you copied, then record it with
`--write --accept-closest`. Commit the result.

In a Git work tree, "your files" are the ones Git lists: tracked files
(including uncommitted edits and deletions) plus untracked files your ignore
rules do not exclude. So a leftover `__pycache__/` or `.DS_Store` does not
spoil an exact match, but an uncommitted new source file does count. Outside
Git there are no ignore rules, so every file under an upstream-managed path
counts.

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

`--to` takes any upstream revision: a release tag, a branch or a commit SHA.
Without it, the ref recorded in your baseline (`main` by default) is used.
Branch names resolve the same way whether the upstream (`--upstream`, or the
baseline's `upstream`; the HTTPS URL by default) is a URL or a local clone, so
`main` needs no `origin/` prefix.

`HEAD`-style pseudo-refs (`HEAD`, `FETCH_HEAD`, `ORIG_HEAD`, `origin/HEAD`,
...) are refused, whether passed to `--to` or recorded in the baseline,
because they name whatever a clone last pointed at rather than a revision. A
bare `origin` is refused too, since Git reads it as `origin/HEAD`. The check
ignores case; a branch or tag really named `origin` can be given as
`refs/heads/origin` or `refs/tags/origin`.

A short name is resolved without Git's first-match lookup, so an upstream tag
called `main` cannot stand in for the `main` branch. The tool checks every place
the name could live (`refs/<name>`, `refs/tags/<name>`, `refs/heads/<name>`,
`refs/remotes/<name>` and, for a hexadecimal name, an abbreviated commit ID). If
more than one exists it refuses with `upstream revision '<name>' is ambiguous`
and names each match. This applies to `--to` and the recorded ref alike, in
`status`, `plan`, `apply` and `detect-baseline`. Pass the full name instead
(`refs/heads/main`, `refs/tags/main`, or a full commit SHA); a full `refs/...`
name or a 40- or 64-character SHA is used exactly as given.

An `origin/<branch>` target resolves only under `refs/remotes/origin/`, so an
upstream branch literally named `origin/...` cannot shadow it. Select such a
branch by its full `refs/heads/origin/<branch>` name; the error says so when an
`origin/<branch>` target doesn't resolve but that literal branch exists.

The tool fetches into a temporary copy, with background `git gc` and
`git maintenance` disabled, and deletes it when done.

`apply` writes only the clean updates. If any conflict remains it lists them,
**does not advance the baseline**, and exits 1, so a half-adopted update is
never recorded as complete. Resolve each conflict deliberately:

- **Take upstream's version**: copy it in (the output shows the `git diff` to
  inspect). The next run sees it as already adopted.
- **Merge the two**: edit the file, then keep the result as below.
- **Keep yours**: re-run with `--keep <path>` (repeatable).

`--keep` is never a default. It accepts only a path that is actually in
conflict for this update, so a typo or a decision left over from an older
update is refused. Once every conflict is resolved, re-run `apply` to record
the baseline, and commit.

When upstream turns a file into a directory, the new files under it are
adopted only together with the file's removal. While that file is in conflict,
they are reported as conflicts too. If you keep the file with `--keep`, name
each of them with `--keep` as well, or adopt the removal instead.

### Review it like the code change it is

An engine or workflow update changes the program that holds your gateway's
admin credentials and the workflow that decides who may deploy. Read the diff.

Pay particular attention to `.github/workflows/` and `.github/scripts/`: they
define the authorization boundary, the freshness guard and credential delivery.
`check_supply_chain.py` (below) enforces the *shape* of many of those controls,
not your intent.

### Re-run everything before deploying

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --test unit_tests
cargo test --lib
python3 .github/scripts/check_supply_chain.py
python3 -m unittest discover -s .github/scripts/tests
gitforgeops validate
python3 .github/scripts/bootstrap_repo_settings.py --repo OWNER/REPO
gitforgeops --env ENV plan
```

`apply` prints this list when it finishes. Three of them deserve a note:

- **`check_supply_chain.py`** catches an update that landed only half a
  control, such as a workflow whose freshness guard, credential-bundle
  bindings or state-writer ordering no longer match the policy.
- **`bootstrap_repo_settings.py`** without `--apply` is a settings *diff*. If
  an update adds a required status check, your ruleset stays one check short
  until you re-run it with `--apply`.
- **`gitforgeops --env ENV plan` must be a no-op.** An engine update changes
  how desired state is computed, not what it is. If the plan shows resource
  changes you did not make, stop: either the update normalizes something
  differently, or your desired state drifted. Find out which before applying.

### Gateway and validator compatibility stays explicit

An update can carry a new validator pin (`.github/ferrum-edge-checksums.txt`)
and can require a newer gateway. Neither is inferred:

- `identify` prints the engine version (from `Cargo.toml`), the template
  baseline and the allowlisted validator digests.
- The gateway reports its own mode and readiness through
  `gitforgeops doctor --scope gateway` (or a plain `GET /health`).
- Upstream release notes state the supported pairing.

If an update requires a gateway you have not upgraded yet, upgrade the gateway
first. A `validate` failure tagged `validator-resource-labels` (an unknown
`labels` field) means the validator predates resource labels; the message
names the remedy.

## Then merge it like any other change

The update is a pull request on your own repository, so it goes through your
own controls: required checks, the state guard, the settings audit, and, once
merged, an environment-approved apply.

`.github/scripts/**`, `.github/workflows/apply-on-merge.yml`, `src/**` and the
Cargo manifests are **deployment inputs**. Merging an update schedules its own
apply and supersedes any apply still queued from an earlier merge. That is
deliberate: new engine code must not ride an older approval, and the earlier
merge's desired state still gets reconciled by the new run. See
[Deployment inputs](../README.md#deployment-inputs-one-list-for-scheduling-and-for-supersession).

The first apply after an update runs new code against your live gateway. Adopt
on a non-production environment first if you have one.

## When an update goes wrong

**Revert the adoption commit.** It is an ordinary commit:

```bash
git revert <adoption-commit>
```

That restores the previous engine, workflows and validator pin. Because
`.gitforgeops/baseline.json` is in the same commit, it also restores the
previous baseline, so `status` shows the update as available again.

**Do not restore an old `.state/<env>.json`.** The ledger only moves forward.
It records what this repository has applied to a live gateway, and reverting
code does not un-apply anything. An older snapshot tells shared mode that rows
it manages were never managed, so it quietly stops reconciling them; in
exclusive mode the next apply can look like a large prune. If the ledger itself
is wrong, repair it deliberately with the `gitforgeops/state-override` label
and a qualified maintainer, never as a side effect of a rollback.

**Do not roll back unrelated live configuration.** The adoption commit only
touches upstream-managed files. Your resources and overlays are not in it, and
the next apply reconciles the desired state you actually want.

After the revert, run the same checks. If an apply with the bad engine already
changed the gateway, run `gitforgeops --env ENV plan` first and read the diff
carefully.

## Publishing images stays opt-in

Adopting an update does not make your repository publish anything.
`release.yml` publishes only from the upstream repository, or where repository
variable `GITFORGEOPS_RELEASE_ENABLED=true` opts in. That variable is yours and
no update sets it. If you publish your own images, point `DOCKERHUB_IMAGE` at a
namespace you control; an update never changes where you push.

## What a supported baseline means

This adoption process starts at the first supported release. Upstream does not
promise updates for a copy taken from an arbitrary pre-release revision. The
baseline you record has to be a revision upstream still has, and the further
behind you are, the more of the comparison lands in the conflict column. Adopt
regularly and each update stays small.
