use std::collections::BTreeMap;

use base64::Engine;
use rand::RngCore;
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

/// Generate + publish any slots that need allocation (`generate` with no
/// existing value, or `rotate` regardless), and deliver new values to the PR
/// author via age encryption.
///
/// Modifies `shards` in place to reflect the new values; callers should persist
/// the merged bundle and update state.json with hashes.
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
) -> crate::error::Result<AllocateOutcome> {
    let mut outcome = AllocateOutcome::default();

    let candidates: Vec<&ResolveResult> = report
        .results
        .iter()
        .filter(|r| {
            matches!(
                r.status,
                SlotStatus::NeedsAllocation | SlotStatus::NeedsRotation
            )
        })
        .collect();

    if candidates.is_empty() {
        outcome.shard_count = *shard_count;
        return Ok(outcome);
    }

    let pubkey = fetch_public_key(client, repo, environment, provisioner_token).await?;

    let mut touched_shards: std::collections::BTreeSet<u32> = std::collections::BTreeSet::new();

    for candidate in candidates {
        let value = random_value(candidate.placeholder.length_bytes);

        // Prefer the shard the slot already lives on (for alloc=rotate, and
        // for alloc=generate on a slot that somehow exists). If we ran
        // pick_shard after `shard_count` has grown, the hash-based target
        // could differ from the slot's current shard — we'd write the fresh
        // value to shard N while a stale copy lingers on shard M. Because
        // `merge_bundles` iterates shards in ascending order, whichever copy
        // sits on the higher shard index wins; that can silently revert a
        // rotation to the old value.
        let existing_shard = shards
            .iter()
            .find_map(|(s, bundle)| bundle.contains_key(&candidate.slot).then_some(*s));

        let shard = match existing_shard {
            Some(s) => s,
            None => loop {
                if *shard_count == 0 {
                    *shard_count = 1;
                }
                match pick_shard(&candidate.slot, value.len(), shards, *shard_count) {
                    Some(s) => break s,
                    None => {
                        // Target shard would overflow — expand and redistribute lazily.
                        *shard_count += 1;
                        if *shard_count > 100 {
                            return Err(crate::error::Error::Config(
                                "credential bundle shards exceeded 100 (GitHub env secret limit)"
                                    .to_string(),
                            ));
                        }
                    }
                }
            },
        };

        // Encrypt for delivery BEFORE mutating the local shards map.
        // If delivery fails (recipient has no compatible SSH key),
        // returning Err here means we never touch `shards` for this
        // candidate — the outer PUT loop won't see a shard to write,
        // and no GitHub Env Secret is committed. A dead-letter
        // credential (generated but undeliverable) is worse than no
        // credential; the next run can retry once the recipient adds
        // a key.
        let delivered = if let Some(login) = pr_author {
            match deliver_to_author(client, login, value.as_bytes()).await? {
                Some(d) => Some(d),
                None => {
                    return Err(crate::error::Error::Config(format!(
                        "Refusing to allocate credential slot '{}': recipient @{} has no compatible SSH public key on GitHub. \
                         Ask them to add an Ed25519 or RSA key at https://github.com/settings/keys, then retry. \
                         To allocate without delivery, unset the recipient (no GITFORGEOPS_ACTOR).",
                        candidate.slot, login
                    )));
                }
            }
        } else {
            None
        };

        // Delivery succeeded (or wasn't required) — now safe to mutate
        // local state and mark the shard as one we need to PUT.
        shards
            .entry(shard)
            .or_default()
            .insert(candidate.slot.clone(), value.clone());
        touched_shards.insert(shard);

        outcome.allocated.push(AllocatedSlot {
            slot: candidate.slot.clone(),
            shard,
            value: value.clone(),
            alloc: candidate.placeholder.alloc,
            delivered,
        });
    }

    // Write touched shards to GitHub.
    for shard in touched_shards {
        let bundle = shards.get(&shard).cloned().unwrap_or_default();
        let serialized = serialize_bundle(&bundle)?;
        let secret_name = shard_secret_name(shard);

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

        outcome.bundle_hashes.insert(shard, bundle_hash(&bundle));
    }

    outcome.shard_count = *shard_count;
    Ok(outcome)
}

/// Rotate a specific slot: generate a new value, write to GitHub, deliver to
/// the invoking user.
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

    let delivered = if let Some(login) = recipient_login {
        deliver_to_author(client, login, value.as_bytes()).await?
    } else {
        None
    };

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
    rand::rngs::OsRng.fill_bytes(&mut buf);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&buf)
}

/// Utility re-export for consumers who need to flatten shards after allocation.
pub fn merged(shards: &BTreeMap<u32, CredentialBundle>) -> CredentialBundle {
    merge_bundles(shards)
}
