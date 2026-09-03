use std::collections::BTreeMap;

use base64::Engine;
use rand::Rng;
use reqwest::Client;

use super::bundle::{
    merge_bundles, reserve_shard, serialize_bundle, shard_secret_name, CredentialBundle,
};
use super::delivery::{deliver_to_author, DeliveryResult};
use super::github_api::{fetch_public_key, put_environment_secret};
use super::placeholder::PlaceholderAlloc;
use super::resolver::{
    check_min_entropy, credential_type_from_slot, ResolveReport, ResolveResult, SlotStatus,
    MAX_CREDENTIAL_VALUE_CHARS, MIN32_CREDENTIAL_TYPES, REDACTED_SENTINEL,
};

#[derive(Debug, Clone)]
pub struct AllocatedSlot {
    pub slot: String,
    pub shard: u32,
    pub value: String,
    pub alloc: PlaceholderAlloc,
    pub delivered: Option<DeliveryResult>,
}

#[derive(Debug, Clone, Default)]
pub struct AllocateOutcome {
    pub allocated: Vec<AllocatedSlot>,
    pub shard_count: u32,
}

/// Failure result from `allocate_and_deliver` that still carries any already-
/// committed slots (their shards were successfully PUT to GitHub before the
/// failure). Callers surface `partial.allocated` so recipients can decrypt
/// their credentials even though later shards failed.
#[derive(Debug)]
pub struct AllocationFailure {
    pub source: Box<crate::error::Error>,
    pub partial: AllocateOutcome,
}

impl AllocationFailure {
    fn with_partial(source: crate::error::Error, partial: AllocateOutcome) -> Self {
        Self {
            source: Box::new(source),
            partial,
        }
    }
}

impl std::fmt::Display for AllocationFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.source.fmt(f)
    }
}

impl std::error::Error for AllocationFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
}

impl From<crate::error::Error> for AllocationFailure {
    fn from(source: crate::error::Error) -> Self {
        Self::with_partial(source, AllocateOutcome::default())
    }
}

/// Generate + publish any slots that need allocation (first-apply
/// `alloc=generate` or first-apply `alloc=rotate`), and deliver new values to
/// the PR author via age encryption.
///
/// Two-phase for partial-failure safety:
///   1. Plan: assign each candidate to a shard, generate its value, and
///      encrypt the delivery ciphertext. No GitHub writes yet. Fails
///      cleanly if delivery fails or shard cap is exceeded — `shards` is
///      left unchanged.
///   2. Commit: for each target shard, PUT the updated bundle to GitHub.
///      Only on a successful PUT do we mutate `shards` and record the
///      slot in `outcome.allocated`. If a shard PUT fails, earlier
///      shards are already committed (their GitHub Env Secret reflects
///      the new values) and their ciphertexts are in the returned
///      `AllocationFailure::partial`. Subsequent shards are dropped —
///      those recipients would have a ciphertext the gateway never saw,
///      which is worse than no ciphertext (next apply reallocates and
///      redelivers).
///
/// Callers must surface `partial.allocated` before propagating the
/// error — otherwise recipients whose shards DID commit lose their
/// decryption material.
#[allow(clippy::too_many_arguments)]
pub async fn allocate_and_deliver(
    client: &Client,
    repo: &str,
    environment: &str,
    provisioner_token: &str,
    pr_author: Option<&str>,
    report: &ResolveReport,
    shards: &mut BTreeMap<u32, CredentialBundle>,
    shard_count: &mut u32,
) -> Result<AllocateOutcome, AllocationFailure> {
    let mut outcome = AllocateOutcome::default();

    let candidates: Vec<&ResolveResult> = report
        .results
        .iter()
        .filter(|r| matches!(r.status, SlotStatus::NeedsAllocation))
        .collect();

    if candidates.is_empty() {
        outcome.shard_count = *shard_count;
        return Ok(outcome);
    }

    let pubkey = fetch_public_key(client, repo, environment, provisioner_token)
        .await
        .map_err(|source| AllocationFailure::with_partial(source, outcome.clone()))?;

    // Phase 1: plan shard assignments, generate values, and encrypt delivery
    // ciphertexts. No GitHub writes and no mutation of `shards` yet.
    //
    // `staged` is a clone of `shards` that we mutate as we plan, so each
    // `pick_shard` call sees the projected size including earlier candidates
    // from this same batch. Without it, a first-apply with `shard_count=1`
    // hashes every new slot to shard 0; each candidate's projected size is
    // computed against the same pre-batch `shards`, so all candidates pass
    // the soft-limit check independently and the resulting serialized shard
    // can blow past GitHub's hard limit at PUT time. The real `shards` is
    // still only mutated in phase 2 on successful PUT.
    struct Planned {
        slot: String,
        value: String,
        shard: u32,
        alloc: PlaceholderAlloc,
        delivered: Option<DeliveryResult>,
    }
    let mut planned: Vec<Planned> = Vec::new();
    let mut staged: BTreeMap<u32, CredentialBundle> = shards.clone();

    for candidate in candidates {
        // Fails before any GitHub write, so a `len=` that violates the
        // gateway's minimum leaves `shards` untouched. The credential type
        // comes from the report, where the resolver captured it as a slot
        // *component*; parsing it back out of the slot string is only the
        // fallback.
        let value = generate_credential_value_typed(
            &candidate.slot,
            candidate.placeholder.length_bytes,
            report.credential_type_for(&candidate.slot),
        )
        .map_err(|source| AllocationFailure::with_partial(source, outcome.clone()))?;

        // `reserve_shard` prefers the shard the slot already lives on. If we
        // ran pick_shard after `shard_count` has grown, the hash-based target
        // could differ from the slot's current shard — we'd write the fresh
        // value to shard N while a stale copy lingers on shard M. Because
        // `merge_bundles` iterates shards in ascending order, whichever copy
        // sits on the higher shard index wins; that can silently revert to a
        // stale value. It also refuses to grow past MAX_BUNDLE_SHARDS, which
        // is the count of bundle secrets the workflows bind by name.
        let shard = reserve_shard(
            &candidate.slot,
            value.len(),
            &staged,
            shard_count,
            "allocating",
        )
        .map_err(|source| AllocationFailure::with_partial(source, outcome.clone()))?;

        // Encrypt delivery BEFORE any GitHub write. If recipient has no
        // compatible SSH key, we abort phase 1 — nothing has been
        // committed yet, so shards/outcome stay empty and the next run can
        // retry once keys are fixed.
        let delivered = if let Some(login) = pr_author {
            match deliver_to_author(client, login, value.as_bytes())
                .await
                .map_err(|source| AllocationFailure::with_partial(source, outcome.clone()))?
            {
                Some(d) => Some(d),
                None => {
                    return Err(AllocationFailure::with_partial(
                        crate::error::Error::Config(format!(
                            "Refusing to allocate credential slot '{}': recipient @{} has no compatible SSH public key on GitHub. \
                             Ask them to add an Ed25519 or RSA key at https://github.com/settings/keys, then retry. \
                             To allocate without delivery, unset the recipient (no GITFORGEOPS_ACTOR).",
                            candidate.slot, login
                        )),
                        outcome.clone(),
                    ));
                }
            }
        } else {
            None
        };

        // Reserve in `staged` so the next `pick_shard` accounts for this
        // candidate's bytes when deciding whether the same target shard
        // still has room.
        staged
            .entry(shard)
            .or_default()
            .insert(candidate.slot.clone(), value.clone());

        planned.push(Planned {
            slot: candidate.slot.clone(),
            value,
            shard,
            alloc: candidate.placeholder.alloc,
            delivered,
        });
    }

    // Group by target shard so we PUT each shard at most once.
    let mut by_shard: BTreeMap<u32, Vec<Planned>> = BTreeMap::new();
    for p in planned {
        by_shard.entry(p.shard).or_default().push(p);
    }

    // Phase 2: per-shard PUT; commit to `shards` and `outcome` only on
    // successful PUT. If a PUT fails, earlier shards are already live on
    // GitHub — their slots and ciphertexts stay in `partial.allocated` so
    // the caller surfaces them. Subsequent shards are dropped (their
    // ciphertexts would reference values the gateway never saw).
    for (shard, batch) in by_shard {
        let mut shard_bundle = shards.get(&shard).cloned().unwrap_or_default();
        for p in &batch {
            shard_bundle.insert(p.slot.clone(), p.value.clone());
        }

        let serialized = match serialize_bundle(&shard_bundle) {
            Ok(s) => s,
            Err(e) => {
                outcome.shard_count = *shard_count;
                return Err(AllocationFailure::with_partial(e, outcome));
            }
        };
        let secret_name = shard_secret_name(shard);

        match put_environment_secret(
            client,
            repo,
            environment,
            &secret_name,
            serialized.as_bytes(),
            &pubkey,
            provisioner_token,
        )
        .await
        {
            Ok(()) => {
                shards.insert(shard, shard_bundle.clone());
                for p in batch {
                    outcome.allocated.push(AllocatedSlot {
                        slot: p.slot,
                        shard,
                        value: p.value,
                        alloc: p.alloc,
                        delivered: p.delivered,
                    });
                }
            }
            Err(e) => {
                outcome.shard_count = *shard_count;
                return Err(AllocationFailure::with_partial(e, outcome));
            }
        }
    }

    outcome.shard_count = *shard_count;
    Ok(outcome)
}

/// Rotate a specific slot: generate a new value, write to GitHub, deliver to
/// the invoking user.
///
/// Ordering matters: encrypt the delivery ciphertext **before** PUT, and fail
/// closed when the caller requested a recipient but `deliver_to_author`
/// returns `None` (recipient has no compatible SSH key). This keeps rotation
/// atomic from the operator's perspective: the GitHub secret is changed only
/// after the new value has a deliverable ciphertext.
#[allow(clippy::too_many_arguments)]
pub async fn rotate_and_deliver(
    client: &Client,
    repo: &str,
    environment: &str,
    provisioner_token: &str,
    recipient_login: Option<&str>,
    slot: &str,
    length_bytes: usize,
    shards: &mut BTreeMap<u32, CredentialBundle>,
    shard_count: &mut u32,
) -> Result<AllocatedSlot, AllocationFailure> {
    let partial = AllocateOutcome::default();

    // Validate the requested length against the credential type BEFORE the
    // GitHub round-trip, so `rotate --credential jwt/secret` with an
    // undersized `len=` fails without touching the environment's secrets.
    let value = generate_credential_value(slot, length_bytes)
        .map_err(|source| AllocationFailure::with_partial(source, partial.clone()))?;

    let pubkey = fetch_public_key(client, repo, environment, provisioner_token)
        .await
        .map_err(|source| AllocationFailure::with_partial(source, partial.clone()))?;

    // Encrypt delivery BEFORE the PUT. If the recipient has no compatible
    // SSH key (or the API fails), we bail with a hard error and the
    // GitHub Environment Secret stays untouched — the caller can retry
    // once the recipient fixes their keys. Mirrors the same invariant
    // allocate_and_deliver already enforces.
    let delivered = if let Some(login) = recipient_login {
        match deliver_to_author(client, login, value.as_bytes())
            .await
            .map_err(|source| AllocationFailure::with_partial(source, partial.clone()))?
        {
            Some(d) => Some(d),
            None => {
                return Err(AllocationFailure::with_partial(
                    crate::error::Error::Config(format!(
                        "Refusing to rotate slot '{slot}': recipient @{login} has no compatible SSH public key on GitHub. \
                         Ask them to add an Ed25519 or RSA key at https://github.com/settings/keys, then retry. \
                         To rotate without delivery, re-run without --recipient."
                    )),
                    partial,
                ));
            }
        }
    } else {
        None
    };

    // Keep the slot on the shard it already occupies, and refuse up front
    // rather than PUTting a FERRUM_CREDS_BUNDLE_<N> that no workflow binds:
    // the write would succeed at the GitHub API and then be invisible to
    // every later run.
    let target_shard = reserve_shard(slot, value.len(), shards, shard_count, "rotating")
        .map_err(|source| AllocationFailure::with_partial(source, partial.clone()))?;

    let bundle = shards.get(&target_shard).cloned().unwrap_or_default();
    let mut staged_bundle = bundle;
    staged_bundle.insert(slot.to_string(), value.clone());
    let serialized = serialize_bundle(&staged_bundle)
        .map_err(|source| AllocationFailure::with_partial(source, partial.clone()))?;
    let secret_name = shard_secret_name(target_shard);
    let allocated = AllocatedSlot {
        slot: slot.to_string(),
        shard: target_shard,
        value,
        alloc: PlaceholderAlloc::Rotate,
        delivered,
    };

    put_environment_secret(
        client,
        repo,
        environment,
        &secret_name,
        serialized.as_bytes(),
        &pubkey,
        provisioner_token,
    )
    .await
    .map_err(|source| AllocationFailure::with_partial(source, partial))?;

    shards.insert(target_shard, staged_bundle);
    Ok(allocated)
}

fn random_value(length_bytes: usize) -> String {
    let mut buf = vec![0u8; length_bytes];
    rand::rng().fill_bytes(&mut buf);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&buf)
}

/// Generate a credential value for `slot`, enforcing ferrum-edge's value
/// constraints at the point of generation.
///
/// The generator emits base64url-no-pad, so `length_bytes` entropy bytes
/// become `ceil(n*4/3)` characters. The `len=` range the placeholder parser
/// accepts is `16..=256`, i.e. 22..=342 characters — always within the
/// 4096-character cap, and always ≥32 characters *except* for the low end of
/// the range, which is why `jwt`/`hmac_auth` need a floor of their own.
///
/// Enforced here:
///
/// * `jwt` / `hmac_auth` secrets must be ≥32 characters, so `len=` must be at
///   least [`super::resolver::MIN_ENTROPY_BYTES_FOR_32_CHARS`] (24). `len=16` is rejected with
///   an actionable error rather than silently clamped — silently growing a
///   credential the operator explicitly sized would be a surprise, and the
///   alternative (emitting a 22-character secret) is a credential the gateway
///   rejects at write time.
/// * No value may exceed [`MAX_CREDENTIAL_VALUE_CHARS`].
/// * The reserved sentinel [`REDACTED_SENTINEL`] is never stored. base64url
///   cannot produce it, so this is a tripwire for a future encoding change.
///
/// The resolver runs the same `len=` check at plan time
/// (`check_generation_constraints`) so `plan`/`diff` fail before any GitHub
/// write; this is the last line of defense for callers that reach the
/// allocator directly (notably `gitforgeops rotate`, whose `--credential`
/// argument never passes through the resolver's placeholder walk).
pub fn generate_credential_value(slot: &str, length_bytes: usize) -> crate::error::Result<String> {
    generate_credential_value_typed(slot, length_bytes, None)
}

/// [`generate_credential_value`] with the credential type supplied
/// structurally.
///
/// The type decides whether the ≥32-character `jwt`/`hmac_auth` floor applies,
/// so getting it wrong silently emits a credential the gateway rejects. The
/// resolver already knows the type as a slot *component* before the slot
/// string is joined ([`ResolveReport::slot_credential_types`]), so
/// `allocate_and_deliver` passes it through instead of parsing it back out.
///
/// `cred_type == None` falls back to splitting the slot
/// ([`credential_type_from_slot`]) — the path `gitforgeops rotate` takes,
/// where the slot is built from CLI arguments and no report exists. If *that*
/// also fails to yield a type, this is a hard error: a slot we cannot classify
/// is a slot whose minimum-length rule we cannot apply, and the previous
/// `.unwrap_or_default()` turned that into an empty type string that quietly
/// skipped the floor.
pub fn generate_credential_value_typed(
    slot: &str,
    length_bytes: usize,
    cred_type: Option<&str>,
) -> crate::error::Result<String> {
    let cred_type = match cred_type {
        Some(t) => t.to_string(),
        None => credential_type_from_slot(slot).ok_or_else(|| {
            crate::error::Error::Config(format!(
                "credential slot '{slot}' has no credential-type component, so the \
                 minimum-length rule for jwt/hmac_auth secrets cannot be applied. Slots are \
                 '<namespace>/<consumer>/<credential-type>/…' — build the slot with \
                 secrets::slot_path rather than by hand."
            ))
        })?,
    };

    // One shared implementation of the floor, also used by the resolver's
    // plan-time check so the two can't drift.
    check_min_entropy(slot, &cred_type, length_bytes)?;

    let value = random_value(length_bytes);
    let chars = value.chars().count();

    if MIN32_CREDENTIAL_TYPES.contains(&cred_type.as_str()) && chars < 32 {
        return Err(crate::error::Error::Config(format!(
            "internal: generated {cred_type} secret for slot '{slot}' is {chars} characters, \
             below ferrum-edge's 32-character minimum"
        )));
    }
    if chars > MAX_CREDENTIAL_VALUE_CHARS {
        return Err(crate::error::Error::Config(format!(
            "internal: generated value for slot '{slot}' is {chars} characters, above \
             ferrum-edge's {MAX_CREDENTIAL_VALUE_CHARS}-character cap"
        )));
    }
    if value == REDACTED_SENTINEL {
        return Err(crate::error::Error::Config(format!(
            "internal: generated value for slot '{slot}' is the reserved sentinel \
             '{REDACTED_SENTINEL}'"
        )));
    }

    Ok(value)
}

/// Utility re-export for consumers who need to flatten shards after allocation.
pub fn merged(shards: &BTreeMap<u32, CredentialBundle>) -> CredentialBundle {
    merge_bundles(shards)
}
