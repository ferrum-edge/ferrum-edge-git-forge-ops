# Ownership and the state ledger

How GitForgeOps decides what it may change or delete on a gateway. The
[README](../README.md#ownership-modes) has the short version.

## Resource classes

Every live gateway resource is one of:

1. **Declared** — in the repository's desired config now.
2. **Previously managed** — applied by the repository before, no longer
   declared (an intentional removal).
3. **Unmanaged** — on the gateway, never put there by the repository.
4. **Spec-owned** — carries an `api_spec_id`, meaning the gateway's OpenAPI
   spec importer (`/api-specs`) created it.

"Previously managed" comes from the ownership ledger, `.state/<env>.json`.

## `shared` mode (default)

- Declared resources are added and modified.
- Previously managed resources are deleted.
- Unmanaged resources are **left alone** and reported in PR review.
- `full_replace` is rejected, because it would wipe unmanaged resources.

Use it when people still change the gateway outside the repository, or for
sandbox environments.

### Pending-create journal

Immediately before an API create, GitForgeOps records the key in a
pending-create journal in the ledger. Pending keys do not grant deletion
authority. On the next authoritative backup:

- If the live row exactly matches the declaration, an idempotent `PUT` makes
  the repository its last writer, and only then does the key become managed.
  Equality alone never grants deletion authority, because an administrator
  might have created the same row.
- If the row is absent, it is an ordinary add.
- If the declaration has since disappeared, the entry is dropped with a warning
  naming the row. In `shared` mode the row is then unmanaged and never deleted;
  in `exclusive` mode it is an ordinary prune candidate.

The journal survives a crashed process, because the apply workflow commits
state under `if: !cancelled()`. It does not survive a cancelled workflow or a
lost runner; the next run then sees the created row as unmanaged (shared) or
prunable (exclusive). `full_replace` does not use the journal.

## `exclusive` mode

- The repository is authoritative for the namespaces in
  `ownership.namespaces`, which is required.
- Unmanaged resources in those namespaces are **pruned**.
- `ownership.large_prune_threshold_percent` (default `25`) stops an apply that
  would delete more than that share of the managed set, unless
  `--allow-large-prune` is passed. The comparison uses the exact ratio, so an
  exact match is allowed.

Every command that loads desired resources (`validate`, `plan`, `review`,
`diff`, `export`, `apply`) enforces the namespace list after overlays and
namespace filtering, before validation or any gateway call. Gateway resources
use their effective namespace; `MeshConfig` fragments use their
`resources/<namespace>/mesh/` directory. A fragment from an unowned directory
is refused with its namespace and label (`namespace/mesh/id`). A namespace
filter outside the owned list is refused even when it selects nothing.

Use it for production or regulated environments where Git is the single source
of truth.

## First apply

With no `.state/<env>.json`, `shared` mode treats **every** live resource as
unmanaged. The run prints a loud warning, applies adds and modifies, and
deletes **nothing**. The ledger it commits is what makes later deletions
possible. Adds enter the pending-create journal before the create and the
ledger only after a successful response or a verified ownership `PUT`.

An empty ledger means the repository manages nothing in shared mode. Clearing
it while live resources remain loses the history needed to delete them.

## Adoption of already-matching resources

A declared resource that already matches its live row produces no add or
modify, so nothing would ever record it. Incremental apply therefore adopts
such rows as a final step. A candidate is declared, live, byte-for-byte equal
to the declaration, untouched by this run, missing from the ledger, and not
spec-owned.

| Mode | What adoption does |
|---|---|
| `shared` | Claims the row with an idempotent `PUT`, sent with `If-Match` on a fresh read of the row that must still equal the declaration (with complete preallocation evidence for Consumers). A row that changed since the diff, or changes before the `PUT` lands, is skipped and stays unclaimed, so a concurrent edit is never reverted. |
| `exclusive` | Records the ledger entry without writing. |
| file mode | Nothing extra; the file write records the whole desired set. |
| `full_replace` | Not applicable; a restore rebuilds the namespace's ledger entries. |

`apply` prints `Adopted N already-matching resource(s) into the ledger` plus
one line per resource. `plan`, PR review and the apply preview list pending
adoptions as `ADOPT <Kind> <id>`.

Two rules never relax: nothing is adopted from a cached
(`X-Data-Source: cached`) backup, and spec-owned rows are never adopted. A
failed adoption `PUT` records nothing and is reported as an error.

## State file trust model

`.state/<env>.json` decides two things:

- **What shared mode may delete.** Nothing outside the ledger is removed.
- **What gets reconciled.** Namespaces named by managed and pending entries
  are reconciled along with the namespaces the repository declares, so
  removing the last resource from a namespace still reconciles it.

An authoritative backup also drops ledger keys that are absent from both
desired and live state, so deleted rows do not dilute the large-prune ratio.

The ledger is only safe because CI writes it. `apply-on-merge.yml` and
`rotate.yml` commit it to `main` with the state-writer App token (commit author
`gitforgeops[bot]`). The trust is enforced by:

- **`state-guard.yml`.** It fails any PR that touches `.state` or anything
  under it, including renames. It runs on `pull_request_target`, so the
  guard that runs is always the one on `main`, and it never checks out the PR:
  file lists, labels and permissions come from the GitHub API. A PR with 3,000
  or more changed files is treated as incomplete. The escape hatch is the exact
  `gitforgeops/state-override` label; it authorizes only the `labeled` event
  for the current head, and only when the labeling account currently has
  `write`, `maintain` or `admin`. Any later push or reopen fails until a
  qualified maintainer removes and re-adds the label. The job summary records
  the actor, permission, head and run.
- **Runtime path checks.** `.state` must be a real directory and its state and
  lock files regular files; symlinks and other file types are rejected. No
  label bypasses this. Environment names are single safe path components.
- **Owner routing.** CODEOWNERS covers `/.state` and `/.state/`.
- **Git tracking.** `.state/*.json` is tracked; locks and temp files are
  ignored. Keep the shipped `.gitignore` entries. If `.state/` is ignored, the
  ledger never lands on `main` and shared mode silently stops deleting.
- **Post-merge apply.** A forged ledger must survive review and land on `main`
  before it can act.
- **Required status check.** Make the guard a required check before launch;
  see [GitHub launch controls](github-launch-controls.md).

A forged ledger entry names a live resource as previously managed, and the
next apply deletes it. Namespace scoping cannot catch that, which is why the
ledger itself is protected.

### State format

[`src/state.rs`](../src/state.rs) defines the format. The writer emits version
3: a constant `managed:v1` marker per resource key, credential delivery
metadata, the pending-create journal, override evidence, and the published mesh
path. Version 2 files are still read and rewritten as version 3 on the next
save. There are no migrations to run. The ledger holds no credential-derived
hashes.

## Spec-owned resources

A proxy, upstream or plugin config with `api_spec_id` belongs to the gateway's
OpenAPI importer, which re-creates it on every spec import. In **both** modes,
whatever the ledger says:

- **Never modified.** If the repository declares the same
  `(namespace, kind, id)`, that is a conflict: the whole namespace is taken out
  of the run and listed in the apply errors, so the run exits non-zero. Other
  namespaces reconcile normally.
- **Never deleted**, except in `exclusive` mode with
  `apply --confirm-api-spec-deletion`. Otherwise apply lists each skipped row.
- **Never claimed after the plan.** Every overwrite is sent with `If-Match` on
  a read that must still show the planned owner, so a row an `/api-specs`
  import tags between apply's plan and its write is refused, not modified or
  deleted, and a confirmed spec deletion still requires the owner the plan
  saw. See [Changes made during an apply](apply.md#changes-made-during-an-apply).
- **Always reported** in `plan`, `diff` and the PR comment's
  "Spec-owned Resources" section, regardless of `ownership.drift_report`.
- **Never authored.** An `api_spec_id` in repository YAML is rejected, even
  with the confirmation flag.

### `full_replace` and spec-owned graphs

`/restore` validates API-spec ownership as a unit, so the restore body carries
the repository's rows, the complete live spec-owned graph, and the live
`api_specs` section. All come from the original coherent
`GET /backup?conditional=true` snapshot. The restore carries its namespace
`If-Match`, checked inside the server's replacement transaction. A spec document,
tagged resource, credential, association, trust or namespace metadata change
invalidates the prepared replacement, including ABA changes. A `412` abandons
that body without acquiring a fresh token. Other namespaces retain completed
results and the run exits nonzero. Empty replacement and confirmed spec deletion
require the same original namespace condition.

Two sections are always left out of the body:

- **An empty `api_specs` section.** `items: []` means "wipe", while an absent
  section makes the gateway answer 409 if live specs exist.
- **`gateway_trust_bundles`.** An absent section leaves trust as it is.

`--confirm-api-spec-deletion` is the only way to drop the spec graph. An
incomplete graph (a spec with no tagged rows, a tagged row whose spec is
missing, a cross-namespace row), a cached backup, a repository/spec id
collision, or an unknown top-level backup section fails before any namespace is
changed.
