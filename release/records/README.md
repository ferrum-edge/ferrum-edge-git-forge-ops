# Finalized release records

One file per published GitForgeOps release, named `<tag>.json` (for example
`v1.0.0.json`). Each is the finalized copy of `release/baseline.json` for that
release: `status` `supported`, the exact source SHA, the published image
digest, the validator pin, the tested gateway and the lifecycle run URL. Its
release notes stay committed as `release/notes-<tag>.md`.

A release is supported only when its record is here on upstream `main`.
`release/baseline.json` describes the release being prepared and may be
`pending`; preparing the next release never changes an existing record.

Records are immutable. `check_release_baseline.py` validates every record, and
the protected-branch `check_supply_chain.py` refuses a change that rewrites or
deletes a record already on the default branch. To finalize a release, commit
the filled `release/baseline.json` and an identical `release/records/<tag>.json`
in the same record-only change (see [the release guide](../README.md)).
