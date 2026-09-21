# `quickstart/` — the copyable half of `docs/quickstart.md`

Every file under this directory is the *exact* text
[`docs/quickstart.md`](../../../docs/quickstart.md) tells a new operator to
copy. `tests/unit/quickstart_tests.rs` loads it under the strict loader,
assembles it with the production overlay, and checks the properties the guide
promises about it — one namespace, shared ownership, one declared environment,
no literal credential.

The point is that a guide can go stale silently. This fixture cannot: a schema
or loader change that would break a copy-pasted quickstart breaks the test
instead, in the same pull request that makes the change.

Keep the tree and the guide byte-identical. It is deliberately minimal — one
proxy, one upstream, one consumer, one scoped auth plugin — because the guide's
job is a first successful apply, not a showcase.
