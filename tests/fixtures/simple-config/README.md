# simple-config fixture

The smallest loadable GitOps tree used as the local sample: one proxy,
consumer, upstream, and plugin-config under `ferrum/`. Loader, assembler,
and export-determinism tests load it in place.

Consumer credentials are `${gh-env-secret:alloc=require}` broker placeholders.
Fixtures never carry literal secrets — copying this tree into `resources/`
must not recreate the hazard the broker exists to prevent. `alloc=require`
means the slot (`ferrum/consumer-alice/keyauth/key`) must already exist in
`FERRUM_CREDS_BUNDLE`; switch to `alloc=generate` as in
`resources/ferrum/consumers/_example.yaml` for first-apply allocation.

The error-severity refusal for a committed literal lives in
`tests/fixtures/literal-credential/`, not here.
