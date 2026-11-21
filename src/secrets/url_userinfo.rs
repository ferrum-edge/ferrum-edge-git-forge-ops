//! URL userinfo (`scheme://user[:password]@host`) detection.
//!
//! Ferrum Edge reads URLs with the WHATWG parser (`url::Url::parse`), which
//! accepts far more spellings than `scheme://user@host`: it ignores leading
//! and trailing whitespace and C0 controls, drops embedded tabs and line
//! breaks, and for the special schemes other than `file` accepts any run of
//! `/` and `\` (or none) after `scheme:` and ends the authority at `\` as
//! well as `/`, `?` and `#`. A credential check that only splits on `://`
//! misses every one of those spellings while Edge still sends the
//! credential, so every check that asks "does this string carry URL
//! credentials" goes through this module.

/// Whether `value` carries URL userinfo.
///
/// True when either holds:
///
/// * `url::Url::parse(value)` yields a non-empty username or a password:
///   exactly the credentials Ferrum Edge reads (and its own export projection
///   strips), in every spelling its parser accepts;
/// * the raw value, split at its first `://`, has an `@` before the next `/`,
///   `?` or `#`: the original check, kept on the unmodified input so nothing it
///   caught is lost (non-standard schemes, empty userinfo such as
///   `https://@host`, hosts Edge's parser rejects).
///
/// Free text is not normalized or reinterpreted, so an email address, a
/// `mailto:` URI, a `file:` path with `@` in it or prose that merely starts
/// with `https:` is not mistaken for URL credentials unless Edge's own parser
/// would read a username or password from it.
pub(crate) fn url_has_userinfo(value: &str) -> bool {
    if !value.contains('@') {
        return false;
    }
    if url::Url::parse(value)
        .is_ok_and(|parsed| !parsed.username().is_empty() || parsed.password().is_some())
    {
        return true;
    }
    value
        .split_once("://")
        .and_then(|(_, rest)| rest.split(['/', '?', '#']).next())
        .is_some_and(|authority| authority.contains('@'))
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
            // Non-special and non-standard schemes keep their `://` authority.
            "redis://user:pass@cache.internal:6379/0",
            "custom+scheme://user:pass@host.example",
            "custom+scheme://user:pass@host.example\\path",
            "ldaps://svc:pw@ldap.internal.example:636",
            // Not a valid URL for Edge, but caught before and still caught.
            "://user:pass@host.example",
            "https://user:pass@bad host.example",
            "https://host.example\\user:pass@path",
            // An earlier delimiter that only appears once a tab is removed does
            // not hide the literal `://` authority after it.
            "Reference :\t//local then https://alice@example.com",
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
            "https: contact ops@example.com for help",
            // `file` URLs never carry userinfo: `@` there is in a path.
            "file:///app@v2/policy.rego",
            "file:/a@b",
            "file:bundle@2026.yaml",
            "file: contact ops@example.com",
            // An empty userinfo only a lenient reading finds; Edge reads none.
            "https:///@host.example",
            "strict",
            "",
        ] {
            assert!(!url_has_userinfo(value), "{value:?}");
        }
    }
}
