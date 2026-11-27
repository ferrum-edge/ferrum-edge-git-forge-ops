mod client_key_standin;
mod compatibility;
pub mod pem_standin;
pub mod reporter;
pub mod runner;
pub mod standin;

pub use pem_standin::{validation_private_key_standin, PEM_STANDIN_MARKER};
pub use reporter::{format_result, format_results, workflow_annotation, OutputFormat};
pub use runner::{
    basic_auth_key_standin_env, build_validate_args_for_mode, run_mesh_validation, run_validation,
    run_validation_for_admin_api, run_validation_for_mode, run_validation_with_report,
    scrubbed_env_names, validation_context_env, ValidationResult, BASIC_AUTH_HMAC_SECRET_ENV,
    BASIC_AUTH_HMAC_SECRET_STANDIN, GATEWAY_VALIDATE_MODE, MESH_ALLOW_NO_CA_ENV,
    MESH_VALIDATE_MODE,
};
pub use standin::{
    validation_standin, validation_url_standin, with_admin_api_basicauth_standins,
    with_validation_standins, VALIDATION_STANDIN_HOST, VALIDATION_STANDIN_PREFIX,
};
