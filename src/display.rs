//! The one sink for user-visible text.
//!
//! Everything this program shows a person goes through here: stdout and
//! stderr (via [`outln!`](crate::outln), [`out!`](crate::out),
//! [`eoutln!`](crate::eoutln) and [`eout!`](crate::eout)), every `--format
//! json` document, the final `Error:` line, panic messages, and the Markdown
//! the review posts to a pull request or writes to `$GITHUB_STEP_SUMMARY`
//! ([`scrub_text`]). A test (`no_direct_output_outside_the_sink`) fails when
//! code writes to stdout or stderr any other way.
//!
//! # Why at the sink
//!
//! A run sends secrets: resolved credentials travel in gateway requests, a
//! rotation publishes a freshly generated value, every admin request carries
//! a minted JWT, GitHub calls carry a token. A peer can reflect any of them
//! in what it sends back — an error message, a namespace name, a `/health`
//! field — and that text reaches output by many routes. Scrubbing each route
//! where a value is parsed changes the values decisions are made on (a
//! scrubbed `/health` `mode` stops being `file`), and misses the next route
//! someone adds. So parsed values stay raw for logic, and the secrets are
//! removed from the final rendered text instead.
//!
//! # What is registered
//!
//! The CLI calls [`enable_display_scrubbing`] at startup. From then on the
//! process registers every snapshot the resolver resolves
//! ([`register_resolved`]), every rotated value it publishes and every token
//! it reads from the environment ([`register_values`]), and every admin JWT
//! it sends ([`register_sent_token`]), for the rest of the run. Every secret
//! admitted from live evidence, a probe, a broker or a token must be at least
//! [`MIN_SCRUB_LENGTH`] bytes. Admission refuses shorter values, and deduplicates
//! all sources under one cumulative budget before building encodings/windows.
//! A refusal withholds further diagnostics and makes the CLI fail even when a
//! reporting command would ordinarily tolerate a live-read failure. Library
//! callers opt in to retention; minimum-length admission still applies. A test
//! opts in its own thread only
//! ([`enable_display_scrubbing_on_this_thread`]), so parallel tests never see
//! each other's canaries.
//!
//! # The policy ([`scrub_text`])
//!
//! 1. Every registered value and its single-line re-encodings (base64 in four
//!    alphabets, percent, JSON escaping with and without `\u` escapes for
//!    non-ASCII, single-quoted YAML, and the forms this crate's sanitizers
//!    give control characters) become [`REDACTION`]. A `Bearer` credential
//!    and a JWT or GitHub token by its shape are redacted too, registered or
//!    not.
//! 2. Any [`FRAGMENT_SCAN_LENGTH`]-byte run of a registered value or of one of
//!    its encodings that survives withholds the whole line (a JSON string
//!    value, in a JSON document) with [`DISPLAY_WITHHELD`]. The scan covers
//!    the text as written and as decoded from backslash escapes (JSON, YAML
//!    double-quoted, Rust; twice, for double encoding), percent-encoding,
//!    HTML character references and doubled single quotes, so a re-encoded
//!    value cannot slip past as a different spelling. A run that also occurs
//!    in public text is not evidence: the scrubbed configuration the value
//!    came from, or the tool's own string literals (`build.rs` collects them),
//!    so an ordinary remedy that shares eight letters with a seeded value is
//!    still printed.
//!
//! Text a peer sent gets the stricter [`peer_text`] at the point it is
//! interpolated, which withholds it while a registered value is not safely
//! scrubbable ([`is_reencoding_hazard`]), the validator-output policy.
//!
//! Ciphertext a run produces for a person (an age-encrypted credential) is
//! written byte for byte: [`Composed`] scrubs the text around it and leaves
//! the ciphertext alone, so a registered value can never corrupt it.
//!
//! # Not routed through here
//!
//! Data a command was asked to write, not text it shows: the `export`
//! document ([`write_data_stdout`], which `--materialize` fills with real
//! credentials on purpose), credential bundles, state files, fingerprint
//! baselines and the files `import` writes. Scrubbing them would corrupt
//! them.

use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet};
use std::io::{IsTerminal, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{LazyLock, Mutex, PoisonError};

use base64::Engine;

use crate::config::GatewayConfig;
use crate::secrets::scrubber::{
    gateway_secret_values, json_escaped, percent_encoded, yaml_single_quoted,
};
use crate::secrets::{
    is_reencoding_hazard, ResolveReport, FRAGMENT_SCAN_LENGTH, MIN_SCRUB_LENGTH, REDACTION,
};

/// Shown in place of a line (or a JSON string, or a peer's text) that could
/// not be shown without risking a secret.
pub const DISPLAY_WITHHELD: &str =
    "[diagnostic withheld: it may carry a secret that could not be redacted]";

/// The string literals of this crate's non-test sources (see `build.rs`).
/// A run of a secret that occurs here is the tool's own prose, not a leak.
static PUBLIC_PROSE: &str = include_str!(concat!(env!("OUT_DIR"), "/display_corpus.txt"));

/// The longest excerpt of peer text [`peer_text`] processes and returns.
const MAX_PEER_TEXT_CHARS: usize = 16 * 1024;

/// Whole-run admission budget. Charge conservatively for spellings, windows,
/// hash buckets and their duplicate indexes *before* allocating them. This is
/// an accounting limit, not a claim about allocator-exact resident memory.
const REGISTRATION_BUDGET: usize = 64 * 1024 * 1024;
const REGISTRATION_BYTES_PER_INPUT_BYTE: usize = 1024;

const BUDGET_REFUSAL: &str = "Secret registration budget exceeded; refusing the run because its credentials cannot all be protected in displayed output.";

type Window = [u8; FRAGMENT_SCAN_LENGTH];

fn window_at(bytes: &[u8], at: usize) -> Option<Window> {
    Window::try_from(bytes.get(at..at + FRAGMENT_SCAN_LENGTH)?).ok()
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack.len() >= needle.len()
        && haystack
            .windows(needle.len())
            .any(|candidate| candidate == needle)
}

/// One unique admitted value, with its spellings and fragment windows.
struct Entry {
    windows: Vec<Window>,
    needles: Vec<String>,
    hazardous: bool,
}

/// Every spelling of `value` the sink looks for: the value, its encodings,
/// and the forms this crate's own sanitizers turn it into (control
/// characters as U+FFFD or as spaces).
fn spellings(value: &str) -> Vec<String> {
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    let bytes = value.as_bytes();
    let mut all = vec![
        value.to_string(),
        STANDARD.encode(bytes),
        STANDARD_NO_PAD.encode(bytes),
        URL_SAFE.encode(bytes),
        URL_SAFE_NO_PAD.encode(bytes),
        percent_encoded(value),
        yaml_single_quoted(value),
        ascii_json_escaped(value),
    ];
    all.extend(json_escaped(value));
    // As `crate::diagnostics` renders it (unsafe characters, including
    // U+2028/U+2029, as U+FFFD; `##[` broken up), and with control
    // characters as spaces (`bounded_error_message`).
    all.push(crate::diagnostics::sanitized_spelling(value));
    if value.chars().any(char::is_control) {
        all.push(
            value
                .chars()
                .map(|c| if c.is_control() { ' ' } else { c })
                .collect(),
        );
    }
    // Use the review formatter itself, so its CRLF collapse, trimming,
    // unsafe-character handling and Markdown escapes cannot drift from us.
    all.extend(crate::review::pr_comment::secret_spellings(value));
    all.retain(|spelling| !spelling.is_empty());
    all.sort();
    all.dedup();
    all
}

/// JSON escaping with every non-ASCII character as `\uXXXX` (what an
/// `ensure_ascii` serializer writes), without the surrounding quotes.
fn ascii_json_escaped(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_ascii() && !c.is_ascii_control() => out.push(c),
            c => {
                let mut units = [0u16; 2];
                for unit in c.encode_utf16(&mut units) {
                    out.push_str(&format!("\\u{unit:04x}"));
                }
            }
        }
    }
    out
}

impl Entry {
    fn new(value: &str) -> Self {
        let mut windows = Vec::new();
        let mut needles = Vec::new();
        let hazardous = is_reencoding_hazard(value);
        for spelling in spellings(value) {
            if spelling.len() < MIN_SCRUB_LENGTH {
                continue;
            }
            windows.extend(
                spelling
                    .as_bytes()
                    .windows(FRAGMENT_SCAN_LENGTH)
                    .filter_map(|w| Window::try_from(w).ok()),
            );
            needles.push(spelling);
        }
        windows.sort_unstable();
        windows.dedup();
        needles.sort();
        needles.dedup();
        Self {
            windows,
            needles,
            hazardous,
        }
    }
}

/// Unique secrets for the whole run, regardless of their source. Repeated
/// snapshots update public-run evidence without retaining duplicate documents.
#[derive(Default)]
struct Registry {
    entries: HashMap<String, Entry>,
    /// A window is private if any registration has no public explanation for it.
    private_windows: HashSet<Window>,
    /// First window of a needle → the needles, longest first.
    needles: HashMap<Window, Vec<String>>,
    hazardous: bool,
    used: usize,
    refusal: Option<String>,
}

impl Registry {
    /// The single admission path for resolutions, live evidence, probes and
    /// tokens. Check the entire registration before building any indexes.
    fn register(
        &mut self,
        source: &str,
        values: &[String],
        document: Option<&GatewayConfig>,
    ) -> crate::error::Result<()> {
        if let Some(reason) = &self.refusal {
            return Err(crate::error::Error::Config(reason.clone()));
        }
        let mut additional = 0usize;
        let mut new_values = HashSet::new();
        for value in values {
            if value.len() < MIN_SCRUB_LENGTH {
                let reason = format!("{source} holds a secret shorter than {MIN_SCRUB_LENGTH} bytes; refusing the run. Use a longer credential so it can be protected in displayed output.");
                self.refusal = Some(reason.clone());
                return Err(crate::error::Error::Config(reason));
            }
            if !self.entries.contains_key(value) && new_values.insert(value.as_str()) {
                additional = value
                    .len()
                    .checked_add(1)
                    .and_then(|bytes| bytes.checked_mul(REGISTRATION_BYTES_PER_INPUT_BYTE))
                    .and_then(|bytes| additional.checked_add(bytes))
                    .unwrap_or(usize::MAX);
            }
        }
        if additional > REGISTRATION_BUDGET.saturating_sub(self.used) {
            self.refusal = Some(BUDGET_REFUSAL.to_string());
            return Err(crate::error::Error::Config(BUDGET_REFUSAL.to_string()));
        }
        // CRLF collapse or trimming can make even an eight-byte raw value
        // too short to protect. Refuse that case rather than registering a
        // short needle that would withhold ordinary prose throughout the run.
        for value in &new_values {
            if crate::review::pr_comment::secret_spellings(value)
                .iter()
                .any(|spelling| spelling.len() < MIN_SCRUB_LENGTH)
            {
                let reason = format!("{source} has a review-formatted spelling shorter than {MIN_SCRUB_LENGTH} bytes; refusing the run. Use a longer credential so it can be protected in displayed output.");
                self.refusal = Some(reason.clone());
                return Err(crate::error::Error::Config(reason));
            }
        }
        self.used += additional;
        for value in new_values {
            let entry = Entry::new(value);
            self.hazardous |= entry.hazardous;
            self.add_needles(&entry.needles);
            self.entries.insert(value.to_string(), entry);
        }
        // Do not retain documents: repeated live reads must not accumulate
        // copies or owners. Only the secret windows' public/private evidence
        // survives. A bare value/token has no public document.
        let public_text =
            document.map(|config| self.redact(&serde_json::to_string(config).unwrap_or_default()));
        let relevant_windows: HashSet<Window> = values
            .iter()
            .filter_map(|value| self.entries.get(value))
            .flat_map(|entry| entry.windows.iter().copied())
            .collect();
        let public_windows: HashSet<Window> = public_text
            .as_deref()
            .unwrap_or_default()
            .as_bytes()
            .windows(FRAGMENT_SCAN_LENGTH)
            .filter_map(|window| {
                let window = Window::try_from(window).ok()?;
                relevant_windows.contains(&window).then_some(window)
            })
            .collect();
        for value in values {
            if let Some(entry) = self.entries.get(value) {
                self.private_windows.extend(
                    entry
                        .windows
                        .iter()
                        .filter(|window| !public_windows.contains(*window))
                        .copied(),
                );
            }
        }
        Ok(())
    }

    fn add_needles(&mut self, needles: &[String]) {
        for needle in needles {
            let Some(prefix) = window_at(needle.as_bytes(), 0) else {
                continue;
            };
            let bucket = self.needles.entry(prefix).or_default();
            if !bucket.iter().any(|known| known == needle) {
                bucket.push(needle.clone());
                bucket.sort_by_key(|known| std::cmp::Reverse(known.len()));
            }
        }
    }

    /// Replace every needle, then every credential-shaped word.
    fn redact(&self, text: &str) -> String {
        if self.needles.is_empty() {
            return redact_credential_shapes(text);
        }
        let bytes = text.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut at = 0;
        'scan: while at < bytes.len() {
            if let Some(bucket) = window_at(bytes, at).and_then(|w| self.needles.get(&w)) {
                for needle in bucket {
                    if bytes[at..].starts_with(needle.as_bytes()) {
                        out.extend_from_slice(REDACTION.as_bytes());
                        at += needle.len();
                        continue 'scan;
                    }
                }
            }
            out.push(bytes[at]);
            at += 1;
        }
        // A needle is whole UTF-8 and starts on a character boundary, so
        // replacing it keeps the text valid.
        let replaced = String::from_utf8(out)
            .unwrap_or_else(|error| String::from_utf8_lossy(error.as_bytes()).into_owned());
        redact_credential_shapes(&replaced)
    }

    /// Is this surviving run evidence of a secret, rather than a run that is
    /// public anyway?
    fn is_leak(&self, window: &Window, cache: &mut HashMap<Window, bool>) -> bool {
        if !self.private_windows.contains(window) {
            return false;
        }
        *cache
            .entry(*window)
            .or_insert_with(|| !contains_bytes(PUBLIC_PROSE.as_bytes(), window))
    }

    /// Does `bytes` hold a surviving run?
    fn has_leak(&self, bytes: &[u8], cache: &mut HashMap<Window, bool>) -> bool {
        bytes.len() >= FRAGMENT_SCAN_LENGTH
            && (0..=bytes.len() - FRAGMENT_SCAN_LENGTH)
                .any(|at| window_at(bytes, at).is_some_and(|w| self.is_leak(&w, cache)))
    }

    /// Byte ranges of every surviving run in `bytes`.
    fn leak_ranges(&self, bytes: &[u8], cache: &mut HashMap<Window, bool>) -> Vec<(usize, usize)> {
        if !self.has_windows() || bytes.len() < FRAGMENT_SCAN_LENGTH {
            return Vec::new();
        }
        (0..=bytes.len() - FRAGMENT_SCAN_LENGTH)
            .filter(|&at| window_at(bytes, at).is_some_and(|w| self.is_leak(&w, cache)))
            .map(|at| (at, at + FRAGMENT_SCAN_LENGTH))
            .collect()
    }

    fn has_windows(&self) -> bool {
        !self.private_windows.is_empty()
    }

    /// Does a decoded spelling of `text` carry a surviving run? It cannot be
    /// replaced in place, so the caller withholds.
    fn leaks_when_decoded(&self, text: &str, cache: &mut HashMap<Window, bool>) -> bool {
        self.has_windows() && any_decoded_view(text.as_bytes(), |view| self.has_leak(view, cache))
    }

    /// The sink's policy for one block of text (see the module docs).
    fn scrub_text(&self, text: &str) -> String {
        if let Some(reason) = &self.refusal {
            return reason.clone();
        }
        let redacted = self.redact(text);
        if !self.has_windows() {
            return redacted;
        }
        let mut cache = HashMap::new();
        let hits = self.leak_ranges(redacted.as_bytes(), &mut cache);
        let mut out = String::with_capacity(redacted.len());
        let mut start = 0;
        for line in redacted.split_inclusive('\n') {
            let end = start + line.len();
            let body = line.trim_end_matches(['\n', '\r']);
            let withheld = hits.iter().any(|&(from, to)| from < end && to > start)
                || self.leaks_when_decoded(body, &mut cache);
            if withheld {
                out.push_str(DISPLAY_WITHHELD);
                out.push_str(&line[body.len()..]);
            } else {
                out.push_str(line);
            }
            start = end;
        }
        out
    }

    /// One JSON string value: redacted, or withheld whole.
    fn scrub_json_string(&self, value: &str) -> String {
        if let Some(reason) = &self.refusal {
            return reason.clone();
        }
        let redacted = self.redact(value);
        let mut cache = HashMap::new();
        if self.has_leak(redacted.as_bytes(), &mut cache)
            || self.leaks_when_decoded(&redacted, &mut cache)
        {
            return DISPLAY_WITHHELD.to_string();
        }
        redacted
    }

    /// The stricter policy for text a peer sent (see [`peer_text`]).
    fn peer_text(&self, text: &str) -> String {
        if let Some(reason) = &self.refusal {
            return reason.clone();
        }
        if self.hazardous {
            return DISPLAY_WITHHELD.to_string();
        }
        // Only a bounded excerpt is ever shown, so only that much is
        // processed: an accepted response field can be tens of megabytes.
        let (text, truncated) = match text.char_indices().nth(MAX_PEER_TEXT_CHARS) {
            Some((end, _)) => (&text[..end], true),
            None => (text, false),
        };
        let mut redacted = self.redact(text);
        let mut cache = HashMap::new();
        if self.has_leak(redacted.as_bytes(), &mut cache)
            || self.leaks_when_decoded(&redacted, &mut cache)
        {
            return DISPLAY_WITHHELD.to_string();
        }
        if truncated {
            redacted.push_str(" [truncated]");
        }
        redacted
    }
}

static ENABLED: AtomicBool = AtomicBool::new(false);
static GLOBAL: LazyLock<Mutex<Registry>> = LazyLock::new(|| Mutex::new(Registry::default()));

thread_local! {
    static THREAD_ENABLED: Cell<bool> = const { Cell::new(false) };
    static LOCAL: RefCell<Registry> = RefCell::new(Registry::default());
}

/// Register, from now on, every secret this process resolves, generates or
/// sends, for the whole process. The CLI calls this first thing.
pub fn enable_display_scrubbing() {
    ENABLED.store(true, Ordering::SeqCst);
}

/// [`enable_display_scrubbing`] for the calling thread only: what it
/// registers applies only to text scrubbed on that thread. For tests, which
/// run in parallel threads of one process.
pub fn enable_display_scrubbing_on_this_thread() {
    THREAD_ENABLED.with(|enabled| enabled.set(true));
}

fn registering() -> bool {
    ENABLED.load(Ordering::SeqCst) || THREAD_ENABLED.with(Cell::get)
}

fn with_registry<T>(f: impl FnOnce(&Registry) -> T) -> T {
    if ENABLED.load(Ordering::SeqCst) {
        f(&GLOBAL.lock().unwrap_or_else(PoisonError::into_inner))
    } else {
        LOCAL.with(|local| f(&local.borrow()))
    }
}

fn with_registry_mut<T>(f: impl FnOnce(&mut Registry) -> T) -> T {
    if ENABLED.load(Ordering::SeqCst) {
        f(&mut GLOBAL.lock().unwrap_or_else(PoisonError::into_inner))
    } else {
        LOCAL.with(|local| f(&mut local.borrow_mut()))
    }
}

/// Admit a live or outgoing document. Placeholder-shaped leaves are real
/// credentials here; unlike repository declarations they get no exemption.
pub fn register_gateway_config(config: &GatewayConfig) -> crate::error::Result<()> {
    let values = gateway_secret_values(config, &ResolveReport::default(), true);
    register(
        "a live gateway credential",
        values.into_iter().collect(),
        Some(config),
    )
}

/// Register a resolved snapshot, retaining the declared-manifest policy:
/// unresolved placeholders and short committed literals remain repository data.
pub fn register_resolved(
    config: &GatewayConfig,
    report: &ResolveReport,
) -> crate::error::Result<()> {
    let values = gateway_secret_values(config, report, false);
    register(
        "a resolved credential",
        values
            .into_iter()
            .filter(|value| value.len() >= MIN_SCRUB_LENGTH)
            .collect(),
        Some(config),
    )
}

/// Admit bare secrets (rotation, probe credentials, environment and sent tokens).
/// Empty environment tokens are absent; live and probe leaves must pass the
/// minimum even when empty. Sources must be trusted descriptions, never values.
pub fn register_values<I, S>(source: &str, values: I) -> crate::error::Result<()>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    register(
        source,
        values
            .into_iter()
            .map(Into::into)
            .filter(|value| !value.is_empty())
            .collect(),
        None,
    )
}

pub(crate) fn register_probe_value(value: &str) -> crate::error::Result<()> {
    register("a traffic probe credential", vec![value.to_string()], None)
}

fn register(
    source: &str,
    values: Vec<String>,
    document: Option<&GatewayConfig>,
) -> crate::error::Result<()> {
    if registering() {
        with_registry_mut(|registry| registry.register(source, &values, document))
    } else if values.iter().any(|value| value.len() < MIN_SCRUB_LENGTH) {
        Err(crate::error::Error::Config(format!("{source} holds a secret shorter than {MIN_SCRUB_LENGTH} bytes; refusing the run. Use a longer credential so it can be protected in displayed output.")))
    } else {
        Ok(())
    }
}

/// Register each sent JWT for the whole run, under the same cumulative budget.
pub fn register_sent_token(token: &str) -> crate::error::Result<()> {
    register_values("an admin JWT", [token])
}

/// A swallowed live-read error must never turn a refused registration into a
/// successful CLI run (e.g. review's ordinary offline fallback).
pub fn registration_result() -> crate::error::Result<()> {
    with_registry(|registry| match &registry.refusal {
        Some(reason) => Err(crate::error::Error::Config(reason.clone())),
        None => Ok(()),
    })
}

/// The sink's policy for text, without writing it: for output that leaves
/// the process another way (a PR comment, the step summary).
pub fn scrub_text(text: &str) -> String {
    with_registry(|registry| registry.scrub_text(text))
}

/// [`scrub_text`] for a JSON document: each string value is redacted or
/// withheld on its own, so the document stays valid JSON.
pub fn scrub_json_text(text: &str) -> String {
    with_registry(|registry| rewrite_json_strings(text, |value| registry.scrub_json_string(value)))
}

/// What the sink does to `text` before writing it: [`scrub_json_text`] for a
/// JSON document, [`scrub_text`] for anything else.
pub fn scrub_output(text: &str) -> String {
    let trimmed = text.trim();
    let json = (trimmed.starts_with('{') || trimmed.starts_with('['))
        && serde_json::from_str::<serde::de::IgnoredAny>(trimmed).is_ok();
    if json {
        scrub_json_text(text)
    } else {
        scrub_text(text)
    }
}

/// Make text a peer sent safe to interpolate into a diagnostic: a gateway
/// `error` or `reason`, GitHub's `message`, a namespace name from
/// `/namespaces`, a `/health` or `/cluster` field, a `/config/export` field.
///
/// Stricter than the sink, because nothing in it is the tool's own prose: it
/// is withheld whole when a registered value is not safely scrubbable
/// ([`is_reencoding_hazard`]: a peer can re-encode it past every needle),
/// or when a run of one survives redaction, and only a bounded excerpt is
/// kept. Use it only on the displayed copy; decisions read the raw value.
pub fn peer_text(text: &str) -> String {
    with_registry(|registry| registry.peer_text(text))
}

/// Write `text` to stdout through the sink. Used by [`out!`](crate::out) and
/// [`outln!`](crate::outln).
pub fn write_stdout(text: &str) {
    if text.is_empty() {
        return;
    }
    let scrubbed = scrub_output(text);
    // display-sink: the one stdout writer.
    let mut stdout = std::io::stdout().lock();
    if let Err(error) = stdout
        .write_all(scrubbed.as_bytes())
        .and_then(|()| stdout.flush())
    {
        // `println!`'s behavior: a closed or failing stdout is fatal.
        panic!("failed printing to stdout: {error}");
    }
}

/// Write `text` to stderr through the sink. Used by [`eout!`](crate::eout)
/// and [`eoutln!`](crate::eoutln).
pub fn write_stderr(text: &str) {
    if text.is_empty() {
        return;
    }
    let scrubbed = scrub_output(text);
    // A failure is ignored: there is nowhere left to report it.
    // display-sink: the one stderr writer.
    let _ = std::io::stderr().lock().write_all(scrubbed.as_bytes());
}

/// Write a data payload to stdout unchanged: the `export` document, which
/// `--materialize` fills with real credentials because that is what was asked
/// for. Not for anything a person reads as diagnostics.
pub fn write_data_stdout(payload: &[u8]) -> std::io::Result<()> {
    // display-sink: data, not display (see the module docs).
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(payload)?;
    stdout.flush()
}

/// Output that mixes text with ciphertext the run produced for a person (an
/// age-encrypted credential). [`Composed::render`] scrubs the text parts and
/// keeps every data part byte for byte, so the recipient can still decrypt
/// whatever values are registered.
#[derive(Debug, Clone, Default)]
pub struct Composed {
    parts: Vec<(bool, String)>,
}

impl Composed {
    pub fn new() -> Self {
        Self::default()
    }

    /// Text that goes through the sink.
    pub fn text(&mut self, text: impl Into<String>) -> &mut Self {
        self.parts.push((false, text.into()));
        self
    }

    /// Ciphertext, written unchanged. Only for data this process produced
    /// (never peer text): it is not scrubbed.
    pub fn data(&mut self, data: impl Into<String>) -> &mut Self {
        self.parts.push((true, data.into()));
        self
    }

    /// The text parts scrubbed, the data parts as given.
    pub fn render(&self) -> String {
        self.parts
            .iter()
            .map(|(data, part)| {
                if *data {
                    part.clone()
                } else {
                    scrub_text(part)
                }
            })
            .collect()
    }
}

/// Write a [`Composed`] message to stdout.
pub fn write_composed_stdout(message: &Composed) {
    if let Err(error) = write_data_stdout(message.render().as_bytes()) {
        panic!("failed printing to stdout: {error}");
    }
}

/// Whether stdout is an interactive terminal.
pub fn stdout_is_terminal() -> bool {
    // display-sink: a query, writes nothing.
    std::io::stdout().is_terminal()
}

/// Route panic messages through the sink: a panic payload can carry any
/// value the code was holding.
pub fn install_panic_hook() {
    // display-sink: installs the hook, which writes only scrubbed text.
    std::panic::set_hook(Box::new(|info| {
        let payload = info
            .payload()
            .downcast_ref::<&str>()
            .map(|message| (*message).to_string())
            .or_else(|| info.payload().downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "Box<dyn Any>".to_string());
        let location = info
            .location()
            .map(|location| format!(" at {location}"))
            .unwrap_or_default();
        let thread = std::thread::current();
        let name = thread.name().unwrap_or("<unnamed>");
        let message = format!("\nthread '{name}' panicked{location}:\n{payload}\n");
        // The panic can come from inside the sink with the registry held;
        // never wait for it.
        let scrubbed = if ENABLED.load(Ordering::SeqCst) {
            match GLOBAL.try_lock() {
                Ok(registry) => Some(registry.scrub_text(&message)),
                Err(std::sync::TryLockError::Poisoned(poisoned)) => {
                    Some(poisoned.into_inner().scrub_text(&message))
                }
                Err(std::sync::TryLockError::WouldBlock) => None,
            }
        } else {
            LOCAL
                .try_with(|local| {
                    local
                        .try_borrow()
                        .ok()
                        .map(|registry| registry.scrub_text(&message))
                })
                .ok()
                .flatten()
        };
        let text = scrubbed.unwrap_or_else(|| format!("\nthread '{name}' panicked{location}\n"));
        // display-sink: the panic hook, already scrubbed above.
        let _ = std::io::stderr().lock().write_all(text.as_bytes());
    }));
}

/// `println!` through the display sink.
#[macro_export]
macro_rules! outln {
    () => {
        $crate::display::write_stdout("\n")
    };
    ($($arg:tt)*) => {
        $crate::display::write_stdout(&::std::format!("{}\n", ::std::format_args!($($arg)*)))
    };
}

/// `print!` through the display sink.
#[macro_export]
macro_rules! out {
    ($($arg:tt)*) => {
        $crate::display::write_stdout(&::std::format!($($arg)*))
    };
}

/// `eprintln!` through the display sink.
#[macro_export]
macro_rules! eoutln {
    () => {
        $crate::display::write_stderr("\n")
    };
    ($($arg:tt)*) => {
        $crate::display::write_stderr(&::std::format!("{}\n", ::std::format_args!($($arg)*)))
    };
}

/// `eprint!` through the display sink.
#[macro_export]
macro_rules! eout {
    ($($arg:tt)*) => {
        $crate::display::write_stderr(&::std::format!($($arg)*))
    };
}

/// Replace credential-shaped words with [`REDACTION`]: the word after a
/// `Bearer` scheme, a JWT (`eyJ…` in three dot-separated parts, which is what
/// the admin client sends), and a GitHub token by its documented prefix.
/// These are caught by shape as a backstop to the registered values.
///
/// One streaming pass: besides the output, it keeps only the bounds of the
/// previous word and whether the gap after it was blank, so memory does not
/// grow with the number of words.
pub fn redact_credential_shapes(text: &str) -> String {
    // Not `=`: it would join `token=<JWT>` into one word that no longer starts
    // with the JWT. Base64url JWTs and GitHub tokens never contain it.
    fn is_word_char(c: char) -> bool {
        c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '~' | '+' | '/')
    }
    fn is_credential_shaped(word: &str) -> bool {
        let jwt =
            word.starts_with("eyJ") && word.split('.').filter(|part| !part.is_empty()).count() == 3;
        let github = ["ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"]
            .iter()
            .any(|prefix| word.starts_with(prefix) && word.len() >= prefix.len() + 16);
        jwt || github
    }
    fn run_end(text: &str, start: usize, word: bool) -> usize {
        text[start..]
            .char_indices()
            .find(|&(_, c)| is_word_char(c) != word)
            .map_or(text.len(), |(offset, _)| start + offset)
    }

    let mut out = String::with_capacity(text.len());
    let mut previous_word: Option<(usize, usize)> = None;
    let mut blank_gap = false;
    let mut position = 0;
    while let Some(c) = text[position..].chars().next() {
        if is_word_char(c) {
            let end = run_end(text, position, true);
            let segment = &text[position..end];
            let after_bearer = blank_gap
                && previous_word
                    .is_some_and(|(start, end)| text[start..end].eq_ignore_ascii_case("bearer"));
            if after_bearer || is_credential_shaped(segment) {
                out.push_str(REDACTION);
            } else {
                out.push_str(segment);
            }
            previous_word = Some((position, end));
            blank_gap = false;
            position = end;
        } else {
            let end = run_end(text, position, false);
            let segment = &text[position..end];
            blank_gap = segment.chars().all(|c| c == ' ' || c == '\t');
            out.push_str(segment);
            position = end;
        }
    }
    out
}

/// Re-encode every string literal of a JSON document through `scrub`,
/// leaving structure, key order and formatting alone. A literal `scrub`
/// returns unchanged is kept byte for byte.
///
/// A property name in this crate's snake_case schema form (`namespace`,
/// `diff_count`) is the report contract and is never rewritten, even when
/// it happens to equal a registered value. Any other property name (a label
/// key, a header name, a resource id used as a map key) is data and is
/// scrubbed like a value.
fn rewrite_json_strings(text: &str, scrub: impl Fn(&str) -> String) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut copied = 0;
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] != b'"' {
            at += 1;
            continue;
        }
        let start = at;
        at += 1;
        while at < bytes.len() && bytes[at] != b'"' {
            at += if bytes[at] == b'\\' { 2 } else { 1 };
        }
        let end = (at + 1).min(bytes.len());
        let literal = &text[start..end];
        out.push_str(&text[copied..start]);
        let is_key = text[end..].trim_start().starts_with(':');
        let schema_key =
            is_key && is_schema_key(&literal[1..literal.len().saturating_sub(1).max(1)]);
        if schema_key {
            out.push_str(literal);
            copied = end;
            at = end;
            continue;
        }
        match serde_json::from_str::<String>(literal) {
            Ok(value) => {
                let scrubbed = scrub(&value);
                if scrubbed == value {
                    out.push_str(literal);
                } else {
                    out.push_str(
                        &serde_json::to_string(&scrubbed)
                            .unwrap_or_else(|_| format!("\"{DISPLAY_WITHHELD}\"")),
                    );
                }
            }
            Err(_) => out.push_str(&format!("\"{DISPLAY_WITHHELD}\"")),
        }
        copied = end;
        at = end;
    }
    out.push_str(&text[copied..]);
    out
}

/// A property name in the crate's own schema form: lowercase ASCII, digits
/// and underscores, starting with a letter.
fn is_schema_key(name: &str) -> bool {
    name.starts_with(|c: char| c.is_ascii_lowercase())
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// Run `check` over each spelling of `bytes` a peer's re-encoding would
/// hide a value behind, decoded: backslash escapes, percent-encoding, HTML
/// character references and doubled single quotes, each alone and each
/// followed by another (a Markdown comment escapes `_` with a backslash and
/// `.` as `&#46;`). Views are built one at a time and dropped, and the walk
/// stops at the first `true`, so memory stays at two copies of `bytes`.
fn any_decoded_view(bytes: &[u8], mut check: impl FnMut(&[u8]) -> bool) -> bool {
    for decode in DECODERS {
        let Some(once) = decode(bytes).filter(|once| once.as_slice() != bytes) else {
            continue;
        };
        if check(&once) {
            return true;
        }
        for decode_again in DECODERS {
            if let Some(twice) = decode_again(&once).filter(|twice| *twice != once) {
                if check(&twice) {
                    return true;
                }
            }
        }
    }
    false
}

type Decoder = fn(&[u8]) -> Option<Vec<u8>>;

/// The decoders [`any_decoded_view`] applies; each returns `None` when the
/// input has nothing for it to decode.
const DECODERS: [Decoder; 5] = [
    |bytes| bytes.contains(&b'\\').then(|| unescape_backslashes(bytes)),
    |bytes| bytes.contains(&b'%').then(|| percent_decode(bytes)),
    |bytes| bytes.contains(&b'&').then(|| html_unescape(bytes)),
    // A sanitizer's U+FFFD, inserted or substituted, dropped: what is left
    // around it must not spell a secret either.
    |bytes| {
        contains_bytes(bytes, "\u{fffd}".as_bytes()).then(|| {
            String::from_utf8_lossy(bytes)
                .replace('\u{fffd}', "")
                .into_bytes()
        })
    },
    |bytes| {
        bytes.windows(2).any(|pair| pair == b"''").then(|| {
            String::from_utf8_lossy(bytes)
                .replace("''", "'")
                .into_bytes()
        })
    },
];

fn hex_value(digits: &[u8]) -> Option<u32> {
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    u32::from_str_radix(std::str::from_utf8(digits).ok()?, 16).ok()
}

fn push_char(out: &mut Vec<u8>, code: u32) -> bool {
    match char::from_u32(code) {
        Some(character) => {
            let mut buffer = [0u8; 4];
            out.extend_from_slice(character.encode_utf8(&mut buffer).as_bytes());
            true
        }
        None => false,
    }
}

/// Decode JSON, YAML double-quoted and Rust escapes. Anything unrecognized is
/// kept as written.
fn unescape_backslashes(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] != b'\\' || at + 1 >= bytes.len() {
            out.push(bytes[at]);
            at += 1;
            continue;
        }
        let kind = bytes[at + 1];
        let simple = match kind {
            b'n' => Some(b'\n'),
            b'r' => Some(b'\r'),
            b't' => Some(b'\t'),
            b'0' => Some(0),
            b'b' => Some(8),
            b'f' => Some(12),
            b'v' => Some(11),
            b'e' => Some(27),
            // Any other escaped ASCII punctuation is the character itself
            // (JSON's `\/`, Markdown's `\_`, a shell's `\#`).
            other if other.is_ascii_punctuation() || other == b' ' => Some(other),
            _ => None,
        };
        if let Some(byte) = simple {
            out.push(byte);
            at += 2;
            continue;
        }
        match kind {
            b'x' => {
                if let Some(byte) = bytes.get(at + 2..at + 4).and_then(hex_value) {
                    out.push(byte as u8);
                    at += 4;
                    continue;
                }
            }
            b'u' if bytes.get(at + 2) == Some(&b'{') => {
                if let Some(close) = bytes[at + 3..].iter().position(|&b| b == b'}') {
                    if let Some(code) = hex_value(&bytes[at + 3..at + 3 + close]) {
                        if push_char(&mut out, code) {
                            at += 4 + close;
                            continue;
                        }
                    }
                }
            }
            b'u' => {
                if let Some(high) = bytes.get(at + 2..at + 6).and_then(hex_value) {
                    if (0xD800..0xDC00).contains(&high)
                        && bytes.get(at + 6) == Some(&b'\\')
                        && bytes.get(at + 7) == Some(&b'u')
                    {
                        if let Some(low) = bytes.get(at + 8..at + 12).and_then(hex_value) {
                            if (0xDC00..0xE000).contains(&low) {
                                let code = 0x10000 + ((high - 0xD800) << 10) + (low - 0xDC00);
                                if push_char(&mut out, code) {
                                    at += 12;
                                    continue;
                                }
                            }
                        }
                    }
                    if push_char(&mut out, high) {
                        at += 6;
                        continue;
                    }
                }
            }
            b'U' => {
                if let Some(code) = bytes.get(at + 2..at + 10).and_then(hex_value) {
                    if push_char(&mut out, code) {
                        at += 10;
                        continue;
                    }
                }
            }
            _ => {}
        }
        out.push(bytes[at]);
        at += 1;
    }
    out
}

fn percent_decode(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] == b'%' {
            if let Some(byte) = bytes.get(at + 1..at + 3).and_then(hex_value) {
                out.push(byte as u8);
                at += 3;
                continue;
            }
        }
        out.push(bytes[at]);
        at += 1;
    }
    out
}

/// HTML named references for the characters [`is_reencoding_hazard`] cares
/// about and the ASCII punctuation an encoder might spell by name.
const HTML_NAMED: &[(&str, char)] = &[
    ("amp", '&'),
    ("lt", '<'),
    ("gt", '>'),
    ("quot", '"'),
    ("apos", '\''),
    ("nbsp", '\u{a0}'),
    ("num", '#'),
    ("colon", ':'),
    ("bsol", '\\'),
    ("sol", '/'),
    ("NewLine", '\n'),
    ("Tab", '\t'),
    ("excl", '!'),
    ("dollar", '$'),
    ("percnt", '%'),
    ("lpar", '('),
    ("rpar", ')'),
    ("ast", '*'),
    ("plus", '+'),
    ("comma", ','),
    ("period", '.'),
    ("semi", ';'),
    ("equals", '='),
    ("quest", '?'),
    ("commat", '@'),
    ("lsqb", '['),
    ("lbrack", '['),
    ("rsqb", ']'),
    ("rbrack", ']'),
    ("Hat", '^'),
    ("lowbar", '_'),
    ("grave", '`'),
    ("lcub", '{'),
    ("lbrace", '{'),
    ("verbar", '|'),
    ("vert", '|'),
    ("rcub", '}'),
    ("rbrace", '}'),
];

fn html_unescape(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] == b'&' {
            if let Some(length) = bytes[at + 1..]
                .iter()
                .take(12)
                .position(|&byte| byte == b';')
            {
                let Ok(reference) = std::str::from_utf8(&bytes[at + 1..at + 1 + length]) else {
                    out.push(bytes[at]);
                    at += 1;
                    continue;
                };
                let code = if let Some(hex) = reference
                    .strip_prefix("#x")
                    .or_else(|| reference.strip_prefix("#X"))
                {
                    hex_value(hex.as_bytes())
                } else if let Some(decimal) = reference.strip_prefix('#') {
                    decimal.parse::<u32>().ok()
                } else {
                    HTML_NAMED
                        .iter()
                        .find(|(name, _)| *name == reference)
                        .map(|(_, character)| *character as u32)
                };
                if let Some(code) = code {
                    if push_char(&mut out, code) {
                        at += length + 2;
                        continue;
                    }
                }
            }
        }
        out.push(bytes[at]);
        at += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enable() {
        enable_display_scrubbing_on_this_thread();
    }

    #[test]
    fn registered_values_and_their_encodings_are_redacted() {
        enable();
        const SECRET: &str = "zq7-sink-canary-value-5d1c";
        register_values("test", [SECRET]).unwrap();
        let encoded = base64::engine::general_purpose::STANDARD.encode(SECRET);
        let text = format!("plain {SECRET}\nbase64 {encoded}\nquoted '{SECRET}'\n");
        assert_eq!(
            scrub_text(&text),
            "plain [REDACTED]\nbase64 [REDACTED]\nquoted '[REDACTED]'\n"
        );
    }

    /// A peer field is processed and shown only up to a bounded excerpt.
    #[test]
    fn peer_text_memory_is_bounded() {
        let field = r"\%&'' ".repeat(10 * 1024 * 1024);
        let (shown, peak) = crate::alloc_meter::peak_bytes(|| peer_text(&field));
        assert!(shown.ends_with("[truncated]"), "{}", shown.len());
        assert!(peak <= 2 * 1024 * 1024, "peer_text peaked at {peak} bytes");
    }

    /// A secret too short to find in output is refused, naming where it
    /// came from and never the value.
    #[test]
    fn short_secrets_are_refused_by_source() {
        enable();
        register_values("GITHUB_TOKEN", [""]).unwrap();
        let error = register_values("GITHUB_TOKEN", ["s3cr3t!"])
            .unwrap_err()
            .to_string();
        assert!(error.contains("GITHUB_TOKEN"), "{error}");
        assert!(error.contains("8 bytes"), "{error}");
        assert!(!error.contains("s3cr3t"), "{error}");
        assert!(register_values("GITHUB_TOKEN", ["long-enough-value"]).is_err());
        assert!(registration_result().is_err());
    }

    fn live_config(secret: &str) -> GatewayConfig {
        serde_json::from_value(serde_json::json!({
            "consumers": [{"id": "consumer", "namespace": "ferrum", "username": "client",
                "credentials": {"keyauth": [{"key": secret}],
                    "basicauth": [{"username": "x", "password": secret}],
                    "mtls_auth": [{"identity": "x"}]}}],
            "plugin_configs": [{"id": "plugin", "namespace": "ferrum", "plugin_name": "otel_tracing", "scope": "global",
                "config": {"headers": {"authorization": secret}}}],
            "upstreams": [{"id": "upstream", "namespace": "ferrum", "targets": [],
                "service_discovery": {"provider": "consul", "consul": {
                    "address": "https://consul.example", "service_name": "service", "token": secret}}}]
        })).unwrap()
    }

    #[test]
    fn live_admission_refuses_short_leaves_without_registering_them() {
        enable();
        for length in 0..MIN_SCRUB_LENGTH {
            for kind in ["consumer", "plugin", "discovery"] {
                LOCAL.with(|local| *local.borrow_mut() = Registry::default());
                let value = "Q7!x9z?"[..length].to_string();
                let mut config = live_config(&value);
                if kind != "consumer" {
                    config.consumers.clear();
                }
                if kind != "plugin" {
                    config.plugin_configs.clear();
                }
                if kind != "discovery" {
                    config.upstreams.clear();
                }
                let error = crate::http_client::BackupSnapshot::from_body(
                    &serde_json::to_string(&config).unwrap(),
                )
                .unwrap_err()
                .to_string();
                assert!(
                    error.contains("live gateway credential holds a secret shorter than 8 bytes"),
                    "{error}"
                );
                if !value.is_empty() {
                    assert!(!error.contains(&value), "{error}");
                }
                LOCAL.with(|local| {
                    let registry = local.borrow();
                    assert!(registry.entries.is_empty());
                    assert!(registry.needles.is_empty());
                });
                assert!(registration_result().is_err());
                assert!(!scrub_text("failed peer response").contains("peer response"));
            }
        }
    }

    #[test]
    fn live_admission_refuses_a_formatter_spelling_too_short_to_protect() {
        enable();
        let value = "Q7\r\nx9yz";
        assert_eq!(value.len(), MIN_SCRUB_LENGTH);
        let result = crate::http_client::BackupSnapshot::from_body(
            &serde_json::to_string(&live_config(value)).unwrap(),
        );
        let error = result.unwrap_err().to_string();
        assert!(
            error.contains("review-formatted spelling shorter than 8 bytes"),
            "{error}"
        );
        assert!(!error.contains("Q7"));
        LOCAL.with(|local| assert!(local.borrow().entries.is_empty()));
    }

    #[test]
    fn live_admission_registers_placeholder_shaped_leaves_and_keeps_identity_exemptions() {
        enable();
        const VALUE: &str = "${gh-env-secret:alloc=require}";
        let config = live_config(VALUE);
        // The manifest collector must retain its placeholder policy.
        assert!(crate::secrets::SecretScrubber::from_gateway_config(&config).is_empty());
        crate::http_client::BackupSnapshot::from_body(&serde_json::to_string(&config).unwrap())
            .unwrap();
        assert_eq!(scrub_text(VALUE), REDACTION);
        assert_eq!(
            scrub_text(&base64::engine::general_purpose::STANDARD.encode(VALUE)),
            REDACTION
        );
        assert_eq!(scrub_text("x"), "x");
    }

    #[test]
    fn repeated_live_reads_and_cross_source_registrations_share_one_budget() {
        enable();
        let config = live_config("Q7-live-deduplicated-key");
        let body = serde_json::to_string(&config).unwrap();
        crate::http_client::BackupSnapshot::from_body(&body).unwrap();
        let used = LOCAL.with(|local| local.borrow().used);
        for _ in 0..32 {
            crate::http_client::BackupSnapshot::from_body(&body).unwrap();
            register_sent_token("Q7-live-deduplicated-key").unwrap();
            crate::secrets::resolve_secrets(&mut config.clone(), &Default::default()).unwrap();
            let headers = std::collections::BTreeMap::from([(
                "X-Key".to_string(),
                crate::verify::HeaderValue::slot("slot"),
            )]);
            crate::verify::resolve_headers(
                &headers,
                &std::collections::BTreeMap::from([(
                    "slot".to_string(),
                    "Q7-live-deduplicated-key".to_string(),
                )]),
            )
            .unwrap();
        }
        LOCAL.with(|local| {
            let registry = local.borrow();
            assert_eq!(registry.entries.len(), 1);
            assert_eq!(registry.used, used);
        });
        assert_eq!(scrub_text("Q7-live-deduplicated-key"), REDACTION);
    }

    #[test]
    fn cumulative_budget_refuses_the_next_source_instead_of_dropping_it() {
        enable();
        // Each unique 8191-byte value costs 8 MiB of the 64 MiB budget.
        for n in 0..8 {
            let value = format!("Q7-budget-{n}-{}", "x".repeat(8179));
            assert_eq!(value.len(), 8191);
            if n % 3 == 0 {
                crate::http_client::BackupSnapshot::from_body(
                    &serde_json::to_string(&live_config(&value)).unwrap(),
                )
                .unwrap();
            } else if n % 3 == 1 {
                crate::secrets::resolve_secrets(&mut live_config(&value), &Default::default())
                    .unwrap();
            } else {
                let headers = std::collections::BTreeMap::from([(
                    "X-Key".to_string(),
                    crate::verify::HeaderValue::slot("slot"),
                )]);
                crate::verify::resolve_headers(
                    &headers,
                    &std::collections::BTreeMap::from([("slot".to_string(), value)]),
                )
                .unwrap();
            }
        }
        let error = register_sent_token("Q7-overflow-token")
            .unwrap_err()
            .to_string();
        assert!(error.contains("registration budget exceeded"), "{error}");
        assert!(!error.contains("overflow-token"));
        assert!(registration_result().is_err());
        assert!(register_values("another source", ["Q7-another-key"]).is_err());
        assert_eq!(scrub_text("unregistered private peer data"), BUDGET_REFUSAL);
        LOCAL.with(|local| {
            let registry = local.borrow();
            assert_eq!(registry.used, REGISTRATION_BUDGET);
            assert_eq!(registry.entries.len(), 8);
        });
    }

    #[test]
    fn oversized_live_value_is_refused_before_encoding_or_window_allocation() {
        enable();
        let body = serde_json::to_string(&live_config(&"Q7-secret".repeat(128 * 1024))).unwrap();
        let (result, peak) =
            crate::alloc_meter::peak_bytes(|| crate::http_client::BackupSnapshot::from_body(&body));
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("registration budget exceeded"));
        assert!(peak < 32 * 1024 * 1024, "admission allocated {peak} bytes");
        LOCAL.with(|local| assert!(local.borrow().entries.is_empty()));
    }

    /// Every sent token stays registered for the whole run, however many
    /// requests follow: a response can be rendered long after it arrived.
    #[test]
    fn sent_tokens_stay_registered_for_the_run() {
        enable();
        let token = |n: usize| format!("zq7-sent-token-{n:04}-signature-part");
        for n in 0..1000 {
            register_sent_token(&token(n)).unwrap();
        }
        assert_eq!(scrub_text(&token(0)), REDACTION);
        // A fragment of the first token is still recognized.
        assert_eq!(
            scrub_text(&format!("id {}", &token(0)[4..20])),
            DISPLAY_WITHHELD
        );
    }

    /// Ciphertext is written byte for byte, whatever is registered; only the
    /// text around it is scrubbed.
    #[test]
    fn composed_output_keeps_ciphertext_intact() {
        enable();
        const ARMOR: &str = "-----BEGIN AGE ENCRYPTED FILE-----";
        let payload = format!("{ARMOR}\nYWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNzaC1lZDI1NTE5\n-----END AGE ENCRYPTED FILE-----\n");
        // Values that occur inside the armor and the base64.
        register_values("test", [ARMOR, "YWdlLWVuY3J5cHRpb24"]).unwrap();
        // Short punctuation values cannot be registered at all; force them
        // into this thread's registry to prove the data path ignores it.
        LOCAL.with(|local| {
            local
                .borrow_mut()
                .add_needles(&["-----".to_string(), "/////////".to_string()])
        });
        let mut message = Composed::new();
        message.text(format!("Encrypted to @octocat, header {ARMOR}:\n"));
        message.data(payload.as_str());
        let rendered = message.render();
        assert!(rendered.ends_with(&payload), "{rendered}");
        assert!(
            rendered.starts_with("Encrypted to @octocat, header [REDACTED]"),
            "{rendered}"
        );
    }

    #[test]
    fn a_surviving_run_withholds_only_its_line() {
        enable();
        const SECRET: &str = "zq7-sink-fragment-canary-77ab";
        register_values("test", [SECRET]).unwrap();
        let partial = &SECRET[..SECRET.len() - 2];
        let text = format!("first line\nreflected {partial}\nlast line\n");
        assert_eq!(
            scrub_text(&text),
            format!("first line\n{DISPLAY_WITHHELD}\nlast line\n")
        );
    }

    /// A run of a secret that is also the tool's own prose is not evidence:
    /// the remedy still prints.
    #[test]
    fn runs_shared_with_the_tools_own_prose_are_public() {
        enable();
        register_values("test", ["seeded-materialized-key"]).unwrap();
        let line = "refusing to materialize: 1 credential slot(s) have no value yet";
        assert!(PUBLIC_PROSE.contains("refusing to materialize"));
        assert_eq!(scrub_text(line), line);
        // A longer run than the prose explains is still withheld.
        assert_eq!(scrub_text("got seeded-materialized"), DISPLAY_WITHHELD);
    }

    /// Re-encoded spellings are decoded before the scan, so a non-ASCII or
    /// multi-line value cannot pass as escapes, percent-encoding or HTML
    /// references.
    #[test]
    fn re_encoded_values_are_caught_when_decoded() {
        enable();
        register_values(
            "test",
            ["p\u{e4}ssw\u{f6}rd-zq7-123", "zq7-line-one\nzq7-line-two"],
        )
        .unwrap();
        for reflected in [
            r"bad password p\u00e4ssw\u00f6rd-zq7-123",
            r"bad password p\xc3\xa4ssw\xc3\xb6rd-zq7-123",
            "bad password p%C3%A4ssw%C3%B6rd-zq7-123",
            "bad password p&#228;ssw&#xf6;rd-zq7-123",
            r"bad value zq7-line-one\\nzq7-line-two",
        ] {
            let scrubbed = scrub_text(reflected);
            assert!(
                scrubbed == DISPLAY_WITHHELD || !scrubbed.contains("zq7"),
                "{reflected} -> {scrubbed}"
            );
        }
        // Peer text is withheld outright while such a value is registered.
        assert_eq!(peer_text("anything at all"), DISPLAY_WITHHELD);
    }

    /// Escaped for Markdown (`_` as `\_`, `.` as `&#46;`, the way the PR
    /// comment writes untrusted text): two encodings in one value.
    #[test]
    fn values_escaped_twice_over_are_caught() {
        enable();
        const SECRET: &str = "zq7_md.ca_ny.va_ue.x9";
        register_values("test", [SECRET]).unwrap();
        let markdown = SECRET.replace('_', "\\_").replace('.', "&#46;");
        assert_eq!(scrub_text(&format!("- {markdown}")), "- [REDACTED]");
    }

    /// Schema keys are the report contract; data keys are scrubbed.
    #[test]
    fn json_schema_keys_survive_matching_a_secret() {
        enable();
        register_values("test", ["namespace", "Zq7-Label-Key-Value"]).unwrap();
        let document = r#"{"namespace":"namespace","labels":{"Zq7-Label-Key-Value":"x"}}"#;
        let parsed: serde_json::Value = serde_json::from_str(&scrub_output(document)).unwrap();
        assert_eq!(parsed["namespace"], "[REDACTED]");
        assert!(
            parsed["labels"].get("Zq7-Label-Key-Value").is_none(),
            "{parsed}"
        );
        assert_eq!(parsed["labels"]["[REDACTED]"], "x");
    }

    /// The forms `crate::diagnostics` gives a value are found too.
    #[test]
    fn sanitized_spellings_are_found() {
        enable();
        register_values("test", ["Q7##[x9!-key", "zq7\u{2028}line-sep-key"]).unwrap();
        for value in ["Q7##[x9!-key", "zq7\u{2028}line-sep-key"] {
            let sanitized = crate::diagnostics::sanitize(value);
            assert_eq!(scrub_text(&format!("id {sanitized}")), "id [REDACTED]");
        }
        // Broken up any other way around a U+FFFD, the run is still caught.
        assert_eq!(
            scrub_text("id Q7##\u{fffd}[x9!-\u{fffd}key"),
            DISPLAY_WITHHELD
        );
    }

    #[test]
    fn json_documents_keep_their_shape() {
        enable();
        const SECRET: &str = "zq7-json-canary-value-0c4e";
        register_values("test", [SECRET]).unwrap();
        let partial = &SECRET[..SECRET.len() - 3];
        // Written by hand: `json!` would sort the keys.
        let document = format!(
            "{{\n  \"zeta\": \"value {SECRET}\",\n  \"alpha\": \"{partial}\",\n  \
             \"nested\": [\"p\\\\{partial}\", \"fine\"]\n}}\n"
        );
        let scrubbed = scrub_output(&document);
        let parsed: serde_json::Value = serde_json::from_str(&scrubbed).unwrap();
        assert_eq!(parsed["zeta"], "value [REDACTED]");
        assert_eq!(parsed["alpha"], DISPLAY_WITHHELD);
        assert_eq!(parsed["nested"][0], DISPLAY_WITHHELD);
        assert_eq!(parsed["nested"][1], "fine");
        // Key order and formatting are the document's own.
        assert!(scrubbed.find("zeta").unwrap() < scrubbed.find("alpha").unwrap());
        assert!(!scrubbed.contains(partial), "{scrubbed}");
    }

    #[test]
    fn credential_shapes_are_redacted_unregistered() {
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ6cTcifQ.c2lnbmF0dXJlLXpxNw";
        assert_eq!(
            scrub_text(&format!("rejected Authorization: Bearer {jwt}")),
            "rejected Authorization: Bearer [REDACTED]"
        );
        assert_eq!(
            scrub_text("token ghs_zq7AAAABBBBCCCCDDDDEEEE lacks scope"),
            "token [REDACTED] lacks scope"
        );
    }

    /// Nothing is registered unless this process or thread opted in.
    #[test]
    fn registration_is_opt_in() {
        register_values("test", ["zq7-unregistered-value-9e0d"]).unwrap();
        assert_eq!(
            scrub_text("zq7-unregistered-value-9e0d"),
            "zq7-unregistered-value-9e0d"
        );
    }

    /// Accepted `/namespaces` names reach the empty-filter warning and the
    /// JSON scope fields as scrubbed copies; the comparison keeps the raw
    /// names.
    #[test]
    fn live_namespace_names_are_scrubbed_where_displayed() {
        enable();
        const TOKEN: &str = "zq7-namespace-token-canary-0b7f";
        register_sent_token(TOKEN).unwrap();
        let partial = &TOKEN[2..TOKEN.len() - 2];
        let scope = crate::config::NamespaceScope {
            filter: Some("team-alpha".to_string()),
            on_disk_namespaces: vec!["team-alpha".to_string()],
            on_disk_count: 1,
            desired_count: 1,
            live_count: Some(0),
            live_namespaces: vec![TOKEN.to_string(), partial.to_string()],
        };
        assert!(scope.live_filter_matched_nothing());
        let warning = scope.live_warning().unwrap();
        let json = scope.json_fields().to_string();
        for rendered in [&warning, &json] {
            assert!(!rendered.contains(partial), "{rendered}");
        }
        assert!(warning.contains(DISPLAY_WITHHELD), "{warning}");
    }

    /// `/config/export` and `/backup` diagnostics quote response fields; a
    /// fragment of a sent token there never survives.
    #[test]
    fn export_and_backup_diagnostics_never_quote_a_reflected_fragment() {
        enable();
        const TOKEN: &str = "zq7-export-token-canary-4a9e";
        register_sent_token(TOKEN).unwrap();
        let fragment = &TOKEN[3..TOKEN.len() - 3];
        let namespace = serde_json::json!({ "namespace": fragment }).to_string();
        let fingerprint = serde_json::json!({
            "namespace": "team-alpha",
            "redaction": { "fingerprint_algorithm": fragment, "fingerprint_prefix": fragment },
        })
        .to_string();
        let backup = serde_json::json!({
            "consumers": [{ "id": fragment, "namespace": "other" }],
        })
        .to_string();
        let errors = [
            crate::config_export::ConfigExport::from_response(&namespace, "team-alpha", false)
                .err()
                .unwrap(),
            crate::config_export::ConfigExport::from_response(&fingerprint, "team-alpha", false)
                .err()
                .unwrap(),
            crate::http_client::BackupSnapshot::from_scoped_body(&backup, "team-alpha")
                .err()
                .unwrap(),
        ];
        for error in errors {
            let rendered = format!("{error} {error:?}");
            assert!(!rendered.contains(fragment), "{rendered}");
            assert!(
                rendered.contains(DISPLAY_WITHHELD)
                    || rendered.contains("response identifiers withheld"),
                "{rendered}"
            );
        }
    }

    /// Every write to stdout or stderr goes through this module. A new
    /// `println!` (or `io::stdout()`, or an inherited child stream) fails
    /// here; an exception needs a `display-sink:` comment on its line or the
    /// line above saying why it is safe.
    #[test]
    fn no_direct_output_outside_the_sink() {
        fn rust_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            for entry in std::fs::read_dir(dir).unwrap().flatten() {
                let path = entry.path();
                if path.is_dir() {
                    rust_files(&path, out);
                } else if path.extension().is_some_and(|ext| ext == "rs") {
                    out.push(path);
                }
            }
        }
        let forbidden = [
            "println!",
            "eprintln!",
            "print!",
            "eprint!",
            "dbg!",
            "io::stdout",
            "io::stderr",
            "stdout()",
            "stderr()",
            "Stdio::inherit",
            "set_hook",
        ];
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        rust_files(&root, &mut files);
        let mut violations = Vec::new();
        for file in files {
            let source = std::fs::read_to_string(&file).unwrap();
            // This module's own tests name the patterns.
            let source = if file.ends_with("display.rs") {
                &source[..source.find("#[cfg(test)]\nmod tests").unwrap()]
            } else {
                &source[..]
            };
            let lines: Vec<&str> = source.lines().collect();
            for (index, line) in lines.iter().enumerate() {
                let code = line.split("//").next().unwrap_or("");
                let hit = forbidden.iter().any(|pattern| {
                    code.match_indices(pattern).any(|(at, _)| {
                        !code[..at]
                            .chars()
                            .next_back()
                            .is_some_and(|c| c.is_alphanumeric() || c == '_' || c == '.')
                    })
                });
                let justified = line.contains("display-sink:")
                    || index
                        .checked_sub(1)
                        .is_some_and(|above| lines[above].contains("display-sink:"));
                if hit && !justified {
                    violations.push(format!("{}:{}: {}", file.display(), index + 1, line.trim()));
                }
            }
        }
        assert!(
            violations.is_empty(),
            "write through crate::display (outln!/eoutln!/out!/eout!) instead:\n{}",
            violations.join("\n")
        );
    }
}
