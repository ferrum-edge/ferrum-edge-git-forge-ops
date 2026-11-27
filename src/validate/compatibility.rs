//! Capability and version-pairing diagnostics for Ferrum Edge validators.
//!
//! These recognizers inspect already-scrubbed validator streams and prepend an
//! actionable compatibility error while retaining Edge's original diagnostic.
//! They never retry or rewrite the document behind the caller's back:
//!
//! * **`validator-resource-labels`** — an Edge build predating `ferrum-edge#5483`
//!   rejected mandatory `labels` on a gateway resource.
//! * **`validator-pool-max-requests-per-connection`** — an Edge `>= v0.9.21`
//!   build rejected `Proxy.pool_max_requests_per_connection`, which Edge removed
//!   after v0.9.20 (`ferrum-edge#7218`), when the run was explicitly paired with
//!   v0.9.20 or earlier (the default pairing is the pinned v0.9.21).

use crate::diagnostics::safe;

const PROXY_SIGNATURE: &[&str] = &["listen_path", "backend_host", "backend_port"];
const RESOURCE_SIGNATURES: &[&[&str]] = &[
    PROXY_SIGNATURE,
    &["username", "credentials", "acl_groups"],
    &["name", "targets", "algorithm"],
    &["plugin_name", "config", "scope", "proxy_id"],
];

const LABELS_PREFIX: &str =
    "Validation error: Spec validation failed: unknown field `labels`, expected one of ";
const POOL_MAX_PREFIX: &str = "Validation error: Spec validation failed: unknown field \
                               `pool_max_requests_per_connection`, expected one of ";

/// Recognize Edge's serde unknown-field rejection, including the expected-field
/// signature of the matching gateway resource kind(s). A mention of the field,
/// an unrelated unknown field, or a nested plugin/mesh/settings schema must not
/// become a compatibility error.
fn unknown_resource_field_rejection<'a>(
    stream: &'a str,
    prefix: &str,
    field_name: &str,
    signatures: &[&[&str]],
) -> Option<&'a str> {
    stream.lines().find(|line| {
        // Edge prints the diagnostic bare on a TTY and wrapped in its JSON log
        // envelope (`{"timestamp":…,"level":"ERROR","fields":{"message":"…"}}`)
        // when stdout is a pipe, which is how the runner always invokes it. Accept
        // exactly those two shapes; a line that merely echoes the text elsewhere
        // (quoted YAML, a comment, a different key) is not a rejection.
        let trimmed = line.trim();
        let Some(start) = trimmed.find(prefix) else {
            return false;
        };
        let envelope = &trimmed[..start];
        // The runner's own multi-namespace annotation (`[namespace "name"] `)
        // is prepended to every diagnostic line before scrubbing, so the
        // bare form legitimately arrives behind it. Accept exactly that
        // prefix (a debug-quoted namespace in brackets), never arbitrary
        // leading text.
        let is_namespace_annotation =
            envelope.starts_with("[namespace \"") && envelope.ends_with("\"] ");
        if !envelope.is_empty() && !envelope.ends_with("\"message\":\"") && !is_namespace_annotation
        {
            return false;
        }
        let expected = &trimmed[start + prefix.len()..];
        // Serde appends location text after the final field, and the JSON
        // envelope closes the string right after it. Only consume
        // comma-separated, backtick-quoted field names, never arbitrary text
        // elsewhere in the diagnostic or another line of echoed YAML.
        let mut fields = Vec::new();
        let mut remaining = expected;
        loop {
            let Some(quoted) = remaining.strip_prefix('`') else {
                return false;
            };
            let Some((field, tail)) = quoted.split_once('`') else {
                return false;
            };
            fields.push(field);
            let Some(next) = tail.strip_prefix(", ") else {
                let terminated = tail.is_empty()
                    || tail.starts_with(" at line ")
                    || tail.starts_with('"')
                    || tail.starts_with("\\\"");
                if !terminated {
                    return false;
                }
                break;
            };
            remaining = next;
        }
        fields.contains(&"id")
            && fields.contains(&"namespace")
            && !fields.contains(&field_name)
            && signatures
                .iter()
                .any(|signature| signature.iter().all(|field| fields.contains(field)))
    })
}

fn prepend_diagnostic(
    mut header: String,
    stdout_rejection: Option<&str>,
    stderr_rejection: Option<&str>,
    stderr: &str,
) -> String {
    if stderr_rejection.is_none() {
        if let Some(line) = stdout_rejection {
            header.push_str("Original Ferrum Edge diagnostic (stdout): ");
            header.push_str(line);
            header.push('\n');
        }
    }
    header.push_str(stderr);
    header
}

fn resource_labels_diagnostic(stdout: &str, stderr: &str, binary_path: &str) -> Option<String> {
    let stdout_rejection =
        unknown_resource_field_rejection(stdout, LABELS_PREFIX, "labels", RESOURCE_SIGNATURES);
    let stderr_rejection =
        unknown_resource_field_rejection(stderr, LABELS_PREFIX, "labels", RESOURCE_SIGNATURES);
    if stdout_rejection.is_none() && stderr_rejection.is_none() {
        return None;
    }
    let header = format!(
        "gitforgeops error [validator-resource-labels]: Ferrum Edge resource-labels support is \
         required for Proxy, Consumer, Upstream and PluginConfig. Validator binary: {}. \
         Upgrade the gateway and the `ferrum-edge validate` binary to a build including \
         ferrum-edge#5483; otherwise pin Git Forge Ops before #218. Resource labels are always \
         emitted.\n",
        safe(binary_path)
    );
    Some(prepend_diagnostic(
        header,
        stdout_rejection,
        stderr_rejection,
        stderr,
    ))
}

fn pool_max_requests_diagnostic(stdout: &str, stderr: &str, binary_path: &str) -> Option<String> {
    let stdout_rejection = unknown_resource_field_rejection(
        stdout,
        POOL_MAX_PREFIX,
        "pool_max_requests_per_connection",
        &[PROXY_SIGNATURE],
    );
    let stderr_rejection = unknown_resource_field_rejection(
        stderr,
        POOL_MAX_PREFIX,
        "pool_max_requests_per_connection",
        &[PROXY_SIGNATURE],
    );
    if stdout_rejection.is_none() && stderr_rejection.is_none() {
        return None;
    }
    let header = format!(
        "gitforgeops error [validator-pool-max-requests-per-connection]: Ferrum Edge v0.9.21 and \
         later removed the no-op Proxy field `pool_max_requests_per_connection` \
         (ferrum-edge#7218). Validator binary: {}. This environment is paired with an earlier \
         Edge release; set `edge_version: v0.9.21` on it in `.gitforgeops/config.yaml` (or \
         `FERRUM_EDGE_VERSION=v0.9.21`, or leave both unset for the pinned default) to omit \
         the removed field automatically for v0.9.21+ targets; remove \
         `pool_max_requests_per_connection` from proxy YAML if no v0.9.20 gateway \
         uses it (a save omitting it clears the stored field on v0.9.20); or validate with a \
         v0.9.20 `ferrum-edge` binary.\n",
        safe(binary_path)
    );
    Some(prepend_diagnostic(
        header,
        stdout_rejection,
        stderr_rejection,
        stderr,
    ))
}

/// Prepend an actionable compatibility error to already-scrubbed stderr,
/// retaining Edge's original streams for debugging. Copy a stdout rejection
/// into stderr too: plan's failure detail is read from stderr. Never inspect
/// unsanitized secret output here or bypass the scrubber's decision to withhold
/// either stream.
pub(super) fn compatibility_diagnostic(
    stdout: &str,
    stderr: &str,
    binary_path: &str,
) -> Option<String> {
    resource_labels_diagnostic(stdout, stderr, binary_path)
        .or_else(|| pool_max_requests_diagnostic(stdout, stderr, binary_path))
}
