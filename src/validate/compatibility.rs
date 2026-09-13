//! Capability diagnostics for older Ferrum Edge validators. Labels remain
//! mandatory; this only explains a schema rejection, never retries without them.

use crate::diagnostics::safe;

/// Recognize Edge's serde rejection, including the expected-field signature
/// of a gateway resource. A mention of labels, an unrelated unknown field,
/// or a nested plugin/mesh/settings schema must not become an upgrade error.
fn resource_labels_rejection(stream: &str) -> Option<&str> {
    const PREFIX: &str = "Validation error: Spec validation failed: unknown field `labels`, \
                          expected one of ";
    stream.lines().find(|line| {
        // Edge prints the diagnostic bare on a TTY and wrapped in its JSON log
        // envelope (`{"timestamp":…,"level":"ERROR","fields":{"message":"…"}}`)
        // when stdout is a pipe, which is how the runner always invokes it. Accept
        // exactly those two shapes; a line that merely echoes the text elsewhere
        // (quoted YAML, a comment, a different key) is not a rejection.
        let trimmed = line.trim();
        let Some(start) = trimmed.find(PREFIX) else {
            return false;
        };
        let envelope = &trimmed[..start];
        if !envelope.is_empty() && !envelope.ends_with("\"message\":\"") {
            return false;
        }
        let expected = &trimmed[start + PREFIX.len()..];
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
            && !fields.contains(&"labels")
            && [
                &["listen_path", "backend_host", "backend_port"][..],
                &["username", "credentials", "acl_groups"][..],
                &["name", "targets", "algorithm"][..],
                &["plugin_name", "config", "scope", "proxy_id"][..],
            ]
            .iter()
            .any(|signature| signature.iter().all(|field| fields.contains(field)))
    })
}

/// Prepend an actionable error to already-scrubbed stderr, retaining Edge's
/// original streams for debugging. Copy a stdout rejection into stderr too:
/// plan's failure detail is read from stderr. Never inspect unsanitized secret
/// output here or bypass the scrubber's decision to withhold either stream.
pub(super) fn resource_labels_diagnostic(
    stdout: &str,
    stderr: &str,
    binary_path: &str,
) -> Option<String> {
    let stdout_rejection = resource_labels_rejection(stdout);
    let stderr_rejection = resource_labels_rejection(stderr);
    if stdout_rejection.is_none() && stderr_rejection.is_none() {
        return None;
    }
    let mut diagnostic = format!(
        "gitforgeops error [validator-resource-labels]: Ferrum Edge resource-labels support is \
         required for Proxy, Consumer, Upstream and PluginConfig. Validator binary: {}. \
         Upgrade the gateway and the `ferrum-edge validate` binary to a build including \
         ferrum-edge#5483; otherwise pin Git Forge Ops before #218. Resource labels are always \
         emitted.\n",
        safe(binary_path)
    );
    if stderr_rejection.is_none() {
        if let Some(line) = stdout_rejection {
            diagnostic.push_str("Original Ferrum Edge diagnostic (stdout): ");
            diagnostic.push_str(line);
            diagnostic.push('\n');
        }
    }
    diagnostic.push_str(stderr);
    Some(diagnostic)
}
