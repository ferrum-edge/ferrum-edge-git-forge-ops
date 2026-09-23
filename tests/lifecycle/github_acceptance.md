# GitHub acceptance path

Five lifecycle scenarios are about GitHub's own controls rather than the
gateway's: environment approvals, state-writer App permissions, protected-branch
ledger writes, scheduling, and attribution. None of them can run inside this
repository's CI, which has no authority to create a repository, an Environment
or a GitHub App — and should not have it.

They run against a **disposable repository** instead, and their outcomes are
recorded into the same acceptance result the release gate reads. Until they
are, they stay `skipped`, and a skipped scenario never certifies anything.

Budget an hour. Most of it is waiting for approvals, which is the point.

---

## 0. Prerequisites

- an account (or org) where you can create a repository, a GitHub App, and
  Environments with required reviewers — see
  [GitHub plan requirements](../../README.md#github-plan-requirements); on a
  private repository, required reviewers need Enterprise
- **a second human**, who will be the environment's required reviewer. The
  baseline sets `prevent_self_review: true`, so the account that merges cannot
  approve the apply its merge triggered. This is not an obstacle to work
  around; it is one of the things under test
- a disposable gateway the repository may mutate freely, reachable over
  `https://` from GitHub Actions
- `gh` authenticated with admin on the new repository

Nothing here may point at a real environment. Several steps deliberately
delete managed resources and reject a ledger write mid-run.

---

## 1. Create and bootstrap

Create the repository from the template — **Use this template**, not a fork —
then:

```bash
export GH_TOKEN=$(gh auth token)
REPO=<you>/gitforgeops-acceptance

python3 .github/scripts/bootstrap_repo_settings.py --repo "$REPO" \
  --state-writer-app-id <app-id> --reviewer <second-maintainer>          # plan
python3 .github/scripts/bootstrap_repo_settings.py --repo "$REPO" \
  --state-writer-app-id <app-id> --reviewer <second-maintainer> --apply  # write
```

Follow [the quickstart](../../docs/quickstart.md) for the App, the repository
configuration and the environment secrets. Finish with:

```bash
python3 .github/scripts/audit_settings.py --repo "$REPO" \
  --state-writer-app-id <app-id>
```

A clean audit is the precondition for everything below. If it is red, the
scenarios would be testing your misconfiguration rather than the product.

---

## 2. `scheduling-and-attribution`

The heart of it, and the one carrying
[#261](https://github.com/ferrum-edge/ferrum-edge-git-forge-ops/issues/261)'s
regression.

1. **A queued apply survives an unrelated merge.** Open a PR adding a proxy;
   merge it. While its apply waits for approval, merge a README-only change.
   Approve the first apply.
   - ✅ It applies. The README merge scheduled no apply of its own, so
     cancelling the queued one would have dropped an authorized change with
     nothing left to reconcile it.
   - ❌ `Superseded deployment` here is the bug.
2. **A later resource merge supersedes safely.** Repeat, but make the second
   merge a resource change. The first apply must refuse with `Superseded
   deployment` **and** the second merge must have its own apply run, which
   reconciles both revisions.
3. **A later engine merge cannot ride an older approval.** Repeat with a
   `src/**` change. Same expectation.
4. **Re-running an older workflow.** Re-run the superseded run from the
   Actions tab. It must refuse, not replay an old desired snapshot.
5. **Credential delivery reaches the PR author.** Add a consumer with
   `alloc=generate` from a *second* account. After the apply, the encrypted
   blob must be commented on that PR, decryptable with that account's SSH key —
   and not with yours.
6. **Policy override attribution.** Enable a blocking policy rule, trip it,
   and confirm the apply refuses. Then add the override label and the
   revision-bound review from an account with `write`, and confirm it proceeds
   and that the audit entry records the PR, the review and the applied
   revision.

```bash
python3 .github/scripts/lifecycle_result.py record \
  --result lifecycle-result.json --scenario scheduling-and-attribution \
  --status passed --detail "runs 1..6: queue, supersession, rerun, delivery, override"
```

---

## 3. `credentials-generate-and-rotate`

1. Merge a consumer with `${gh-env-secret:alloc=generate}`. After the apply,
   decrypt the delivered key and confirm it authenticates through the proxy.
2. Run `rotate.yml` for that slot.
3. Confirm the **new** key authenticates and the **old** one now gets `401`.
4. Search for plaintext, everywhere it could have leaked:
   - the apply and rotate job logs,
   - the PR comment (it must be an age blob, not a value),
   - `git log -p` on the protected branch,
   - every workflow artifact.

The fourth step is the scenario. The first three only set it up.

```bash
python3 .github/scripts/lifecycle_result.py record \
  --result lifecycle-result.json --scenario credentials-generate-and-rotate \
  --status passed --detail "rotated; old key 401; no plaintext in logs, Git, comments or artifacts"
```

---

## 4. `ledger-publication-failure`

The scenario is the *recovery*, not the failure.

1. Temporarily revoke the state-writer App's Contents: write permission.
2. Merge a resource change and approve the apply. The gateway is mutated; the
   ledger push fails and retries are exhausted. The job goes red.
3. Restore the permission. **Do not hand-edit `.state/`.**
4. Re-run the apply in a fresh runner and confirm it converges: the resources
   applied in step 2 are recognized (adoption records the already-matching
   rows), nothing is duplicated, and the ledger is published.
5. Confirm shared mode did not treat the step-2 rows as unmanaged — remove one
   from the repository and check the next apply deletes it.

If step 4 or 5 exposes a gap, that is a finding: fix the runbook or the
recovery mechanism. Do **not** resolve it by adopting unmanaged resources
wholesale or by rolling back unrelated live configuration.

---

## 5. `runner-interruption`

1. Merge a resource change; approve the apply; cancel the job mid-mutation.
2. Inspect the gateway: some rows landed, and the ledger was never published
   — a cancelled run does not commit state.
3. Re-run. Confirm it reconciles without duplicating work, and that the
   pending-create journal's absence (cancellation does not persist it) simply
   leaves the rows for the ordinary diff to pick up.
4. If a repair genuinely needs `.state/` edited, do it through the
   `gitforgeops/state-override` label with a qualified maintainer, and confirm
   `state-guard.yml` rejects the same edit without it.

---

## 6. `staged-promotion`

Needs two environments and `promotion.requires` on the second.

1. Declare `staging` and `production` in `.gitforgeops/config.yaml`, with
   `promotion.requires: staging` on production, and declare at least one
   traffic check for staging in `.gitforgeops/smoke.yaml`.
2. Merge a resource change. Approve staging's apply.
   - ✅ Production's job does not start until staging has applied **and** its
     traffic checks have passed.
3. **Break staging's routing without breaking the write** — point the upstream
   at a port nothing listens on, so the gateway accepts the configuration and
   the route answers 502. Merge and approve staging.
   - ✅ Staging's apply succeeds, its traffic check fails, and production is
     blocked with the reason named in the job summary.
   - ❌ Production starting here is the bug the gate exists for.
4. **Move `main` during verification.** While staging's checks run, merge a
   resource change. Production must refuse the promotion rather than silently
   deploying the newer revision, and the newer merge must run its own
   staging→production cycle.
5. Confirm staging's approval granted nothing in production: production's own
   reviewer is still required.

```bash
python3 .github/scripts/lifecycle_result.py record \
  --result lifecycle-result.json --scenario staged-promotion \
  --status passed --detail "502 staging blocked production; mid-flight merge refused"
```

## 7. `partial-failure-recovery` (optional here)

Runs locally against a fault-injecting proxy — see
[README.md#injecting-failures](README.md#injecting-failures). Record it from
whichever environment you actually exercised.

---

## 8. Seal and publish

Re-seal so the record certifies the revision you actually tested — the
upstream commit (or release tag) whose template you exercised, not the
disposable repository's own commit:

```bash
python3 .github/scripts/lifecycle_result.py seal \
  --result lifecycle-result.json \
  --revision <upstream commit being released> --gateway "<gateway binary sha256>"
```

Then hand it to the release gate. The gate reads the result artifact of a
**GitForgeOps Lifecycle Acceptance** run for the release revision, so dispatch
that workflow on the release ref with your sealed file as its
`github_acceptance` input:

```bash
gh workflow run lifecycle.yml --repo ferrum-edge/ferrum-edge-git-forge-ops \
  --ref <release tag or main> \
  -f github_acceptance="$(cat lifecycle-result.json)"
```

That run executes the local scenarios itself, then merges your outcomes into
**only** the scenarios it recorded as `skipped`, each marked `attested by
@<you>`. It refuses an attestation that is unsealed or sealed for a different
revision, and it can never overwrite a scenario it ran. When it is green,
re-run the `Release` workflow for the same revision; it picks the newest
successful acceptance run for that commit.

`verify` is the same computation the release runs, if you want to check the
merged record yourself:

```bash
python3 .github/scripts/lifecycle_result.py verify \
  --result lifecycle-result.json --revision <upstream commit> \
  --gateway-allowlist .github/ferrum-edge-checksums.txt
```

It exits 0 only when every scenario is `passed`, the revision matches, the
gateway build is one the revision's allowlist trusts, and the record is inside
the freshness window.

---

## 9. Clean up

- delete the repository
- delete its Environments and their secrets
- uninstall and delete the GitHub App
- destroy the disposable gateway
- rotate anything you typed by hand that was not generated for this run

None of it is meant to outlive the run. A half-deleted acceptance repository
with live environment secrets is a worse artifact than no acceptance run at
all.
