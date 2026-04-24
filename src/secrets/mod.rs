pub mod allocator;
pub mod bundle;
pub mod delivery;
pub mod github_api;
pub mod placeholder;
pub mod resolver;

pub use allocator::{allocate_and_deliver, rotate_and_deliver, AllocateOutcome, AllocatedSlot};
pub use bundle::{load_bundles_from_env, merge_bundles, serialize_bundle, CredentialBundle};
pub use delivery::{deliver_to_author, DeliveryResult};
pub use github_api::{fetch_public_key, put_environment_secret, EnvSecretPublicKey};
pub use placeholder::{parse_placeholder, PlaceholderAlloc, SecretPlaceholder};
pub use resolver::{resolve_secrets, slot_path, ResolveReport, ResolveResult, SlotStatus};
