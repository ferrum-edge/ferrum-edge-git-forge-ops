pub mod allocator;
pub mod bundle;
pub mod delivery;
pub mod github_api;
pub mod placeholder;
pub mod resolver;

pub use allocator::{
    allocate_and_deliver, generate_credential_value, rotate_and_deliver, AllocateOutcome,
    AllocatedSlot, AllocationFailure,
};
pub use bundle::{load_bundles_from_env, merge_bundles, serialize_bundle, CredentialBundle};
pub use delivery::{deliver_to_author, DeliveryResult};
pub use github_api::{fetch_public_key, put_environment_secret, EnvSecretPublicKey};
pub use placeholder::{parse_placeholder, PlaceholderAlloc, SecretPlaceholder};
pub use resolver::{
    report_secrets, report_secrets_with_mode, resolve_secrets, resolve_secrets_with_mode,
    slot_path, ResolveReport, ResolveResult, SlotStatus, KNOWN_CREDENTIAL_TYPES,
    MAX_CREDENTIAL_VALUE_CHARS, MIN32_CREDENTIAL_TYPES, MIN_ENTROPY_BYTES_FOR_32_CHARS,
    REDACTED_SENTINEL,
};
