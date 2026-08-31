pub mod allocator;
pub mod bundle;
pub mod delivery;
pub mod github_api;
pub mod placeholder;
mod plugin_config;
pub mod resolver;

pub use allocator::{
    allocate_and_deliver, generate_credential_value, generate_credential_value_typed,
    rotate_and_deliver, AllocateOutcome, AllocatedSlot, AllocationFailure,
};
pub use bundle::{load_bundles_from_env, merge_bundles, serialize_bundle, CredentialBundle};
pub use delivery::{deliver_to_author, DeliveryResult};
pub use github_api::{fetch_public_key, put_environment_secret, EnvSecretPublicKey};
pub use placeholder::{parse_placeholder, PlaceholderAlloc, SecretPlaceholder};
pub use resolver::{
    capture_and_redact_import_credentials, capture_and_redact_import_plugin_config_secrets,
    report_secrets, report_secrets_lenient, resolve_secrets, resolve_secrets_with_mode, slot_path,
    ResolveReport, ResolveResult, SlotStatus, IMPORT_REQUIRED_PLACEHOLDER,
    MAX_CREDENTIAL_VALUE_CHARS, MIN32_CREDENTIAL_TYPES, MIN_ENTROPY_BYTES_FOR_32_CHARS,
    REDACTED_SENTINEL,
};
