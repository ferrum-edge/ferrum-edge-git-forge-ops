use crate::error::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlaceholderAlloc {
    Generate,
    Require,
    Rotate,
}

impl PlaceholderAlloc {
    pub fn parse(s: &str) -> crate::error::Result<Self> {
        match s {
            "generate" => Ok(Self::Generate),
            "require" => Ok(Self::Require),
            "rotate" => Ok(Self::Rotate),
            other => Err(Error::Config(format!(
                "unknown secret alloc mode '{other}' (expected: generate | require | rotate)"
            ))),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SecretPlaceholder {
    pub alloc: PlaceholderAlloc,
    pub length_bytes: usize,
}

/// Parse a `${gh-env-secret:alloc=...|len=...}` placeholder.
///
/// Supported keys:
///   - `alloc`: generate | require | rotate (default: `require`)
///   - `len`: integer byte count for generated values (default: 32)
///
/// The slot path is *not* part of the placeholder. Slots are always derived
/// deterministically from the enclosing resource: `<namespace>/<id>/<cred_key>`.
/// This keeps YAML minimal and rename-safe.
pub fn parse_placeholder(raw: &str) -> Option<crate::error::Result<SecretPlaceholder>> {
    let inner = raw.strip_prefix("${gh-env-secret:")?.strip_suffix('}')?;

    let mut alloc = PlaceholderAlloc::Require;
    let mut length_bytes: usize = 32;

    if !inner.is_empty() {
        for piece in inner.split('|') {
            let piece = piece.trim();
            if piece.is_empty() {
                continue;
            }
            let (key, value) = match piece.split_once('=') {
                Some(kv) => kv,
                None => {
                    return Some(Err(Error::Config(format!(
                        "malformed secret placeholder piece '{piece}' (expected key=value)"
                    ))))
                }
            };
            match key.trim() {
                "alloc" => match PlaceholderAlloc::parse(value.trim()) {
                    Ok(a) => alloc = a,
                    Err(e) => return Some(Err(e)),
                },
                "len" => match value.trim().parse::<usize>() {
                    Ok(n) if (16..=256).contains(&n) => length_bytes = n,
                    Ok(n) => {
                        return Some(Err(Error::Config(format!(
                            "secret placeholder 'len={n}' out of range (16..=256)"
                        ))))
                    }
                    Err(_) => {
                        return Some(Err(Error::Config(format!(
                            "secret placeholder 'len={value}' is not an integer"
                        ))))
                    }
                },
                other => {
                    return Some(Err(Error::Config(format!(
                        "unknown secret placeholder key '{other}'"
                    ))))
                }
            }
        }
    }

    Some(Ok(SecretPlaceholder {
        alloc,
        length_bytes,
    }))
}
