//! URL userinfo (`scheme://user[:password]@host`) detection.
//!
//! Ferrum Edge reads URLs with the WHATWG parser (`url::Url::parse`), which
//! accepts far more spellings than `scheme://user@host`: it ignores leading
//! and trailing whitespace and C0 controls, drops embedded tabs and line
//! breaks, and for the special schemes (`http`, `https`, `ws`, `wss`, `ftp`,
//! `file`) accepts any run of `/` and `\` (or none) after `scheme:` and ends
//! the authority at `\` as well as `/`, `?` and `#`. A credential check that
//! only splits on `://` misses every one of those spellings while Edge still
//! sends the credential, so every check that asks "does this string carry URL
//! credentials" goes through this module.

/// Schemes WHATWG parses with the special-scheme authority rules.
const SPECIAL_SCHEMES: [&str; 6] = ["ftp", "file", "http", "https", "ws", "wss"];

/// Whether `value` carries URL userinfo that a URL consumer would read, or
/// looks enough like such a URL that it must be treated as one.
///
/// True when any of these holds:
///
/// * `url::Url::parse` (what Ferrum Edge uses) yields a non-empty username or
///   a password;
/// * after WHATWG preprocessing, a special scheme's authority (any run of `/`
///   and `\` after `scheme:`, ending at `/`, `\`, `?` or `#`) contains `@`.
///   This also covers values Edge's parser would reject, and the empty
///   userinfo of `https://@host`;
/// * after the same preprocessing, the text after the first `://` contains `@`
///   before any `/`, `?` or `#` — the generic authority of every other scheme,
///   kept as broad as the original check so nothing it caught is lost (it
///   still flags `https://host\x@y`, which WHATWG reads as a path).
///
/// A value with no `://` and no special scheme is never a match, so an email
/// address (`ops@example.com`), a `mailto:` URI or free text with a colon in
/// it is not mistaken for URL credentials. For a non-special scheme only the
/// `scheme://` authority counts, as it does for WHATWG: `redis:///u:p@h` has
/// an empty host and `u:p@h` in its path.
pub(crate) fn url_has_userinfo(value: &str) -> bool {
    if url::Url::parse(value)
        .is_ok_and(|parsed| !parsed.username().is_empty() || parsed.password().is_some())
    {
        return true;
    }
    let cleaned = strip_url_noise(value);
    let special_authority = split_scheme(&cleaned)
        .filter(|(scheme, _)| is_special_scheme(scheme))
        .and_then(|(_, rest)| {
            let rest = rest.trim_start_matches(['/', '\\']);
            rest.split(['/', '\\', '?', '#']).next()
        });
    let generic_authority = cleaned
        .split_once("://")
        .and_then(|(_, rest)| rest.split(['/', '?', '#']).next());
    let has_at = |authority: Option<&str>| authority.is_some_and(|text| text.contains('@'));
    has_at(special_authority) || has_at(generic_authority)
}

/// A URL split around its userinfo by [`split_url_userinfo`].
pub(crate) struct UrlUserinfo {
    pub(crate) scheme: Option<String>,
    pub(crate) userinfo: String,
    pub(crate) after: String,
}

/// Find a URL's userinfo the way a lenient (WHATWG-style) parser would, and
/// err towards finding one: surrounding whitespace and control characters
/// and embedded tabs and newlines are ignored, any number of `/` or `\`
/// may follow the scheme (`https:///u:p@h`, `https:u:p@h`), and an `@`
/// anywhere before the first `/`, `\`, `?` or `#` counts, with or without a
/// scheme.
///
/// This is for a field that is always an address (the Consul `address`,
/// which may be a bare `host:port`), so `user@host` without a scheme counts.
/// For an arbitrary string that may or may not be a URL, use
/// [`url_has_userinfo`].
pub(crate) fn split_url_userinfo(text: &str) -> Option<UrlUserinfo> {
    let cleaned = strip_url_noise(text);
    let (scheme, rest) = match split_scheme(&cleaned) {
        Some((scheme, rest)) => (Some(scheme.to_string()), rest),
        None => (None, cleaned.as_str()),
    };
    let rest = rest.trim_start_matches(['/', '\\']);
    let authority_end = rest.find(['/', '\\', '?', '#']).unwrap_or(rest.len());
    let at = rest[..authority_end].rfind('@')?;
    Some(UrlUserinfo {
        scheme,
        userinfo: rest[..at].to_string(),
        after: rest[at + 1..].to_string(),
    })
}

/// WHATWG input preprocessing: strip leading and trailing C0 controls and
/// spaces, and remove every tab, line feed and carriage return.
fn strip_url_noise(text: &str) -> String {
    text.trim_matches(|c: char| c <= ' ')
        .chars()
        .filter(|c| !matches!(c, '\t' | '\n' | '\r'))
        .collect()
}

/// `(scheme, rest after the colon)` when `cleaned` starts with a URL scheme.
fn split_scheme(cleaned: &str) -> Option<(&str, &str)> {
    let colon = cleaned.find(':')?;
    let scheme = &cleaned[..colon];
    is_url_scheme(scheme).then(|| (scheme, &cleaned[colon + 1..]))
}

fn is_url_scheme(candidate: &str) -> bool {
    let mut characters = candidate.chars();
    characters.next().is_some_and(|c| c.is_ascii_alphabetic())
        && characters.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
}

fn is_special_scheme(scheme: &str) -> bool {
    SPECIAL_SCHEMES
        .iter()
        .any(|special| special.eq_ignore_ascii_case(scheme))
}

#[cfg(test)]
mod tests {
    use super::url_has_userinfo;

    #[test]
    fn whatwg_userinfo_spellings_are_detected() {
        for value in [
            "https://user:pass@host.example/path",
            "https:///user:pass@host.example/path",
            "https:////user:pass@host.example",
            "https:/\\user:pass@host.example",
            "https:\\\\user:pass@host.example",
            "https:user:pass@host.example",
            "https:\t//user:pass@host.example",
            "ht\ttps://user:pass@host.example",
            "https://us\ter:pass@host.example",
            "https:\r\n//user:pass@host.example",
            "https:/\n/user:pass@host.example",
            "https://user:pass@host.example\\path",
            " https://user:pass@host.example",
            "\u{1}\u{1f} https://user:pass@host.example \u{0}",
            "HTTPS:///user:pass@host.example",
            "wss:/\\user:pass@host.example",
            "ftp:\\/user@host.example",
            // Empty password, empty username, empty userinfo.
            "https://user@host.example",
            "https://:pass@host.example",
            "https://@host.example",
            "https:///@host.example",
            // Non-special and non-standard schemes keep their `://` authority.
            "redis://user:pass@cache.internal:6379/0",
            "custom+scheme://user:pass@host.example",
            "custom+scheme://user:pass@host.example\\path",
            "ldaps://svc:pw@ldap.internal.example:636",
            // Not a valid URL for Edge, but caught before and still caught.
            "://user:pass@host.example",
            "https://user:pass@bad host.example",
            "https://host.example\\user:pass@path",
        ] {
            assert!(url_has_userinfo(value), "{value:?}");
        }
    }

    #[test]
    fn credential_free_values_are_not_userinfo() {
        for value in [
            "https://host.example/path",
            "https:///host.example/path",
            "https:/\\host.example/path",
            "https:\t//host.example/path",
            "https:\r\n//host.example/path?q=1",
            " https://host.example/path ",
            "https://host.example/user@path",
            "https://host.example?next=user@host",
            "https://host.example#user@host",
            "redis://cache.internal:6379/0",
            // A non-special scheme has an authority only after exactly `//`;
            // Edge reads these as an empty host and a path.
            "redis:///user:pass@cache.internal",
            "redis:/\\user:pass@cache.internal",
            // Not URLs at all.
            "ops@example.com",
            "user:pass@host.example",
            "mailto:ops@example.com",
            "note: contact ops@example.com",
            "strict",
            "",
        ] {
            assert!(!url_has_userinfo(value), "{value:?}");
        }
    }
}
