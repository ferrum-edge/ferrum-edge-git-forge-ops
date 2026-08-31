---
paths:
  - "src/secrets/**"
  - "src/http_client.rs"
  - "src/jwt.rs"
  - "src/config/env.rs"
  - "tests/unit/{http_client,jwt,secrets}_tests.rs"
  - ".env.example"
---

# Credentials, TLS, and secret-broker rules

- Never log, diff, review-comment, export unencrypted, or write back resolved credentials. Secret
  placeholders are replaced only in memory for validation/apply/materialization.
- Consumer credential slots derive from `(namespace, consumer_id, credential path)`. Preserve
  JSON-pointer-style escaping and index-zero elision so normalization cannot orphan an existing
  allocation. Older slot encodings remain read-only lookup candidates.
- The five gateway credential types are arrays. Enforce generation constraints before mutation:
  JWT/HMAC secrets need the documented entropy floor; refuse generated basic-auth values in file
  mode and generated `password_hash` values everywhere; reject `[REDACTED]` bundle values.
- Credential bundles are GitHub Environment Secrets. Parse every shard strictly, reject duplicate
  slots, stay below GitHub's size limit, and keep shard assignment deterministic. Provisioning
  tokens must never enter normal gateway requests or output.
- Delivery encrypts to a verified GitHub user's SSH public key with age. The reviewed RSA exception
  permits public-key encryption only; do not add identity/private-key/decryption APIs or expand age
  features without a new security review.
- Gateway CA, client certificate, and client key inputs are base64-encoded PEM. mTLS requires both
  client cert and key; reject partial configuration. `FERRUM_TLS_NO_VERIFY` is development-only and
  must remain explicit.
- Admin JWT secrets must meet the gateway minimum. Preserve issuer, audience, role, TTL, and
  namespace-claim compatibility; do not emit `aud` unless configured.
- Scrub all `FERRUM_*` variables from the external validator child, pass a private settings file,
  and keep temporary specs mode 0600. Validator diagnostics are sensitive and remain suppressed or
  sanitized where they can echo materialized values.
- HTTP retries are allowed only for demonstrably safe transient outcomes. A request timeout after a
  mutation is ambiguous and must not be retried.

## Verification

Add tests for redaction, slot stability, malformed bundles, certificate pairing, and JWT claims in
the existing flat unit modules. Run the mandatory repository gate and cargo-audit policy.
