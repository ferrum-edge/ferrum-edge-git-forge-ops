use std::collections::BTreeMap;

use base64::Engine;
use rand::Rng;
use reqwest::Client;

use super::bundle::{
    bundle_hash, merge_bundles, pick_shard, serialize_bundle, shard_secret_name, CredentialBundle,
};
use super::delivery::{deliver_to_author, DeliveryResult};
use super::github_api::{fetch_public_key, put_environment_secret};
use super::placeholder::PlaceholderAlloc;
use super::resolver::{ResolveReport, ResolveResult, SlotStatus};

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
    pub bundle_hashes: BTreeMap<u32, String>,
    pub shard_count: u32,
}

/// Failure result from `allocate_and_deliver` that still carries any already-
/// committed slots (their shards were successfully PUT to GitHub before the
/// failure). Callers surface `partial.allocated` so recipients can decrypt
/// their credentials even though later shards failed.
#[derive(Debug)]
pub struct AllocationFailure {
    pub source: crate::error::Error,
    pub partial: AllocateOutcome,
}

impl std::fmt::Display for AllocationFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.source.fmt(f)
    }
}

impl std::error::Error for AllocationFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

impl From<crate::error::Error> for AllocationFailure {
    fn from(source: crate::error::Error) -> Self {
        Self {
            source,
            partial: AllocateOutcome::default(),
        }
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
        .map_err(|e| AllocationFailure {
            source: e,
            partial: outcome.clone(),
        })?;

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
        let value = random_value(candidate.placeholder.length_bytes);

        // Prefer the shard the slot already lives on. If we ran pick_shard
        // after `shard_count` has grown, the hash-based target could differ
        // from the slot's current shard — we'd write the fresh value to
        // shard N while a stale copy lingers on shard M. Because
        // `merge_bundles` iterates shards in ascending order, whichever copy
        // sits on the higher shard index wins; that can silently revert to
        // the old value.
        let existing_shard = staged
            .iter()
            .find_map(|(s, bundle)| bundle.contains_key(&candidate.slot).then_some(*s));

        let shard = match existing_shard {
            Some(s) => s,
            None => loop {
                if *shard_count == 0 {
                    *shard_count = 1;
                }
                match pick_shard(&candidate.slot, value.len(), &staged, *shard_count) {
                    Some(s) => break s,
                    None => {
                        *shard_count += 1;
                        if *shard_count > 100 {
                            return Err(AllocationFailure {
                                source: crate::error::Error::Config(
                                    "credential bundle shards exceeded 100 (GitHub env secret limit)"
                                        .to_string(),
                                ),
                                partial: outcome.clone(),
                            });
                        }
                    }
                }
            },
        };

        // Encrypt delivery BEFORE any GitHub write. If recipient has no
        // compatible SSH key, we abort phase 1 — nothing has been
        // committed yet, so shards/outcome stay empty and the next run can
        // retry once keys are fixed.
        let delivered = if let Some(login) = pr_author {
            match deliver_to_author(client, login, value.as_bytes())
                .await
                .map_err(|e| AllocationFailure {
                    source: e,
                    partial: outcome.clone(),
                })? {
                Some(d) => Some(d),
                None => {
                    return Err(AllocationFailure {
                        source: crate::error::Error::Config(format!(
                            "Refusing to allocate credential slot '{}': recipient @{} has no compatible SSH public key on GitHub. \
                             Ask them to add an Ed25519 or RSA key at https://github.com/settings/keys, then retry. \
                             To allocate without delivery, unset the recipient (no GITFORGEOPS_ACTOR).",
                            candidate.slot, login
                        )),
                        partial: outcome.clone(),
                    });
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
                return Err(AllocationFailure {
                    source: e,
                    partial: outcome,
                });
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
                let hash = bundle_hash(&shard_bundle);
                for p in batch {
                    outcome.allocated.push(AllocatedSlot {
                        slot: p.slot,
                        shard,
                        value: p.value,
                        alloc: p.alloc,
                        delivered: p.delivered,
                    });
                }
                outcome.bundle_hashes.insert(shard, hash);
            }
            Err(e) => {
                outcome.shard_count = *shard_count;
                return Err(AllocationFailure {
                    source: e,
                    partial: outcome,
                });
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
/// returns `None` (recipient has no compatible SSH key). The prior flow
/// wrote the new secret to GitHub first, attempted delivery after, and
/// treated `Ok(None)` as success — so a recipient with no SSH key (or a
/// transient /users/{login}/keys failure) silently rotated the gateway
/// credential to a value nobody received. That left the deployed consumer
/// credential in a state where the rotator couldn't authenticate again and
/// no re-delivery path existed without another explicit rotate.
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
) -> crate::error::Result<AllocatedSlot> {
    let pubkey = fetch_public_key(client, repo, environment, provisioner_token).await?;
    // Honor the placeholder's `len=...` field. Forcing 32 bytes would
    // silently shrink credentials declared with a larger length and grow
    // ones declared smaller.
    let value = random_value(length_bytes);

    // Encrypt delivery BEFORE the PUT. If the recipient has no compatible
    // SSH key (or the API fails), we bail with a hard error and the
    // GitHub Environment Secret stays untouched — the caller can retry
    // once the recipient fixes their keys. Mirrors the same invariant
    // allocate_and_deliver already enforces.
    let delivered = if let Some(login) = recipient_login {
        match deliver_to_author(client, login, value.as_bytes()).await? {
            Some(d) => Some(d),
            None => {
                return Err(crate::error::Error::Config(format!(
                    "Refusing to rotate slot '{slot}': recipient @{login} has no compatible SSH public key on GitHub. \
                     Ask them to add an Ed25519 or RSA key at https://github.com/settings/keys, then retry. \
                     To rotate without delivery, re-run without --recipient."
                )));
            }
        }
    } else {
        None
    };

    // Find current shard if present.
    let current_shard = shards.iter().find_map(|(s, bundle)| {
        if bundle.contains_key(slot) {
            Some(*s)
        } else {
            None
        }
    });

    let target_shard = match current_shard {
        Some(s) => s,
        None => loop {
            if *shard_count == 0 {
                *shard_count = 1;
            }
            match pick_shard(slot, value.len(), shards, *shard_count) {
                Some(s) => break s,
                None => {
                    // Mirror allocate_and_deliver's cap. Without this, a
                    // deeply sharded env that can't fit another slot would
                    // keep incrementing and eventually try to PUT
                    // FERRUM_CREDS_BUNDLE_100+, failing late at the GitHub
                    // API instead of up front with a clear config error.
                    *shard_count += 1;
                    if *shard_count > 100 {
                        return Err(crate::error::Error::Config(
                            "credential bundle shards exceeded 100 (GitHub env secret limit) during rotate"
                                .to_string(),
                        ));
                    }
                }
            }
        },
    };

    shards
        .entry(target_shard)
        .or_default()
        .insert(slot.to_string(), value.clone());

    let bundle = shards.get(&target_shard).cloned().unwrap_or_default();
    let serialized = serialize_bundle(&bundle)?;
    let secret_name = shard_secret_name(target_shard);

    put_environment_secret(
        client,
        repo,
        environment,
        &secret_name,
        serialized.as_bytes(),
        &pubkey,
        provisioner_token,
    )
    .await?;

    Ok(AllocatedSlot {
        slot: slot.to_string(),
        shard: target_shard,
        value,
        alloc: PlaceholderAlloc::Rotate,
        delivered,
    })
}

fn random_value(length_bytes: usize) -> String {
    let mut buf = vec![0u8; length_bytes];
    rand::rng().fill_bytes(&mut buf);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&buf)
}

/// Utility re-export for consumers who need to flatten shards after allocation.
pub fn merged(shards: &BTreeMap<u32, CredentialBundle>) -> CredentialBundle {
    merge_bundles(shards)
}
