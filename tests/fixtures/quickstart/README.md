# `quickstart/` — the copyable half of `docs/quickstart.md`

Every file under this directory except this README is the *exact* text
[`docs/quickstart.md`](../../../docs/quickstart.md) tells a new operator to
copy. `tests/unit/quickstart_tests.rs` loads it under the strict loader,
assembles it with the production overlay, and checks the properties the guide
promises: one namespace, shared ownership, one declared environment, no
literal credential. It also checks that each file is byte-identical to the
fenced block that follows its `` `path`: `` line in the guide.

A guide can go stale silently; this fixture cannot. A schema or loader change
that would break the copy-paste breaks the test instead, in the same pull
request.

Edit the guide and the fixture together. The tree is deliberately minimal (one
proxy, one upstream, one consumer, one scoped auth plugin) because the guide's
job is a first successful apply, not a showcase.
