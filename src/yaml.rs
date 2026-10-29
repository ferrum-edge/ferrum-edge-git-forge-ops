//! The one YAML boundary: every byte of YAML gitforgeops reads or writes goes
//! through this module.
//!
//! Two readers share one safe-Rust parser (`granit-parser`, which
//! `serde-saphyr` is built on):
//!
//! - [`parse_value`] composes a JSON-shaped document from parser events. It is
//!   used for every repository resource and overlay file and for file import,
//!   whose opaque islands (`PluginConfig.config`, credential entries, mesh
//!   items) are carried to the gateway verbatim. Resource limits are enforced
//!   *while* composing: an alias is charged the full size of the node it
//!   copies before the copy is made, so an alias bomb is refused instead of
//!   expanded.
//! - [`from_str`] deserializes repository settings (`.gitforgeops/*.yaml`)
//!   straight into their typed structs through `serde-saphyr`, under a
//!   [`serde_saphyr::Budget`] with the same node and byte limits and a
//!   shallower depth ([`SETTINGS_MAX_DEPTH`]).
//!
//! [`to_string`] renders every YAML document gitforgeops emits, refusing a
//! mapping key too long for the gateway's reader.
//!
//! # Scalar semantics
//!
//! The gateway reads YAML with `serde_yaml` 0.9 (YAML 1.2 core schema), so
//! [`parse_value`] resolves plain scalars exactly as that parser does: `017`
//! and `1_000` stay strings, `yes`/`on` stay strings, `0x1F`/`0o17`/`0b1`
//! are integers, and `~`/`null`/empty are null. `tests/unit/yaml_compat_tests.rs`
//! checks this differentially against `serde_yaml` 0.9 and checks that
//! [`to_string`] output reads back identically under it.
//!
//! Where `serde_yaml` would silently change a value on the way to JSON,
//! [`parse_value`] refuses instead:
//!
//! - a non-string mapping key (`404:`, `true:`, `? [a]`), which JSON would
//!   stringify;
//! - an application tag (`!foo`), the non-specific tag `!`, and core tags
//!   other than `str`/`int`/`float`/`bool`/`null`/`map`/`seq` (for example
//!   `!!binary`), which `serde_yaml` either wraps as `{"!foo": …}` or keeps as
//!   undecoded text;
//! - `.inf`/`.nan`, which become JSON `null`;
//! - an integer outside the `i64`/`u64` range;
//! - more than one document, and a repeated key;
//! - input the two readers would read differently: a raw U+0085, U+2028 or
//!   U+2029 (a line break to YAML 1.1 readers only), any U+FEFF (including a
//!   leading byte-order mark), an anchor name outside `[A-Za-z0-9_-]`, a plain
//!   scalar starting with `?` inside a flow collection (an explicit-key
//!   indicator to libyaml), and a clipped or kept block scalar (`|`, `>`,
//!   `|+`; not `|-`) that runs to the end of a file without a line break.
//!
//! The merge key `<<` is an ordinary string key, as it is for the gateway, so
//! in a typed section it surfaces as the unknown field `<<`.
//!
//! No [`parse_value`] error carries a scalar *value*: a resource file may hold
//! credentials, so messages name the line, the key path, a duplicate or
//! non-string key, and the tag. [`from_str`] errors are `serde`'s and may name
//! an offending settings value (settings hold no credentials). Neither quotes
//! source lines.

use std::collections::HashMap;
use std::fmt;

use granit_parser::{Event, Parser, ScalarStyle, Scanner, Span, StrInput, Tag, TokenType};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::{Map, Number, Value};

/// Deepest collection nesting accepted.
pub const MAX_YAML_DEPTH: usize = 128;

/// Deepest nesting accepted in repository settings, which are a few levels
/// deep. `serde-saphyr` deserializes recursively, so this bound also keeps
/// its stack use small.
pub const SETTINGS_MAX_DEPTH: usize = 32;

/// Resource and overlay files. A per-resource file is small by design; the
/// node bound counts every node an alias or anchor copies.
pub const RESOURCE_LIMITS: Limits = Limits {
    max_depth: MAX_YAML_DEPTH,
    max_nodes: 1_000_000,
    max_scalar_bytes: 64 * 1024 * 1024,
};

/// File import reads a whole gateway backup (up to 64 MiB).
pub const IMPORT_LIMITS: Limits = Limits {
    max_depth: MAX_YAML_DEPTH,
    max_nodes: 16_000_000,
    max_scalar_bytes: 128 * 1024 * 1024,
};

/// Bounds on one composed document, counted with alias and anchor copies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Deepest collection nesting.
    pub max_depth: usize,
    /// Total scalars and collections, each alias and anchor charged for what
    /// it copies.
    pub max_nodes: usize,
    /// Total scalar bytes (keys included), charged likewise.
    pub max_scalar_bytes: usize,
}

/// A YAML read or write failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YamlError {
    message: String,
}

impl YamlError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    fn at(message: impl fmt::Display, span: &Span) -> Self {
        Self::new(format!(
            "{message} at line {} column {}",
            span.start.line(),
            span.start.col() + 1
        ))
    }
}

impl fmt::Display for YamlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for YamlError {}

/// Compose one YAML document into a JSON value under `limits`.
///
/// An empty stream (or one holding only comments) is `null`.
pub fn parse_value(contents: &str, limits: Limits) -> Result<Value, YamlError> {
    refuse_reader_disagreements(contents, limits.max_depth)?;
    let mut composer = Composer {
        limits,
        nodes: 0,
        scalar_bytes: 0,
        stack: Vec::new(),
        anchors: HashMap::new(),
        root: None,
    };
    let mut documents = 0usize;
    for event in Parser::new_from_str_with_options(contents, parser_options(limits.max_depth)) {
        let (event, span) = event.map_err(|error| YamlError::new(error.to_string()))?;
        match event {
            Event::StreamStart | Event::StreamEnd | Event::DocumentEnd => {}
            Event::DocumentStart(..) => {
                documents += 1;
                if documents > 1 {
                    return Err(YamlError::at(
                        "more than one YAML document in the file",
                        &span,
                    ));
                }
            }
            Event::Scalar(text, style, anchor, tag) => {
                composer.scalar(&text, style, anchor, tag.as_deref(), &span)?;
            }
            Event::SequenceStart(_, anchor, tag) => {
                composer.open(Kind::Sequence, anchor, tag.as_deref(), &span)?;
            }
            Event::MappingStart(_, anchor, tag) => {
                composer.open(Kind::Mapping, anchor, tag.as_deref(), &span)?;
            }
            Event::SequenceEnd | Event::MappingEnd => composer.close(&span)?,
            Event::Alias(anchor) => composer.alias(anchor, &span)?,
            // Comments are disabled above; anything else is a parser feature
            // this composer does not understand.
            _ => return Err(YamlError::at("unsupported YAML construct", &span)),
        }
    }
    Ok(composer.root.unwrap_or(Value::Null))
}

/// Deserialize repository settings into `T` with the shared limits.
///
/// For typed settings structs only. Scalars are read through the target
/// field's type, so `'5'` fills an integer field and an empty value cannot
/// fill a string one. A self-describing target such as `serde_json::Value`
/// gets `serde-saphyr`'s own scalar inference, not the gateway's: JSON-shaped
/// data goes through [`parse_value`].
pub fn from_str<T: DeserializeOwned>(contents: &str) -> Result<T, YamlError> {
    refuse_reader_disagreements(contents, SETTINGS_MAX_DEPTH)?;
    let options = serde_saphyr::options! {
        budget: serde_saphyr::budget! {
            max_depth: SETTINGS_MAX_DEPTH,
            flow_nesting_limit: SETTINGS_MAX_DEPTH,
            max_nodes: RESOURCE_LIMITS.max_nodes,
            max_total_scalar_bytes: RESOURCE_LIMITS.max_scalar_bytes,
            max_documents: 1,
        },
        alias_limits: serde_saphyr::alias_limits! {
            max_total_replayed_events: RESOURCE_LIMITS.max_nodes,
        },
        // YAML 1.2, as the gateway reads it: `yes`/`on` are not booleans and
        // `017` is not octal.
        strict_booleans: true,
        legacy_octal_numbers: false,
        merge_keys: serde_saphyr::options::MergeKeyPolicy::AsOrdinary,
        duplicate_keys: serde_saphyr::options::DuplicateKeyPolicy::Error,
        reject_unsupported_tags: true,
        non_finite_float_policy: serde_saphyr::options::NonFiniteFloatPolicy::Reject,
        // A snippet would quote source lines, which may hold credentials.
        with_snippet: false,
    };
    serde_saphyr::from_str_with_options(contents, options)
        .map_err(|error| YamlError::new(error.to_string()))
}

/// Render `value` as one YAML document. `value` must be JSON-shaped (string
/// keys, numbers within 64 bits, finite floats), as every gitforgeops document
/// is: the key check below reads it through `serde_json::to_value`.
///
/// Every string is a single plain or quoted line: no `|`/`>` block scalars,
/// whose folding and chomping rules are where readers disagree, and which
/// split one value across lines for line-oriented tools. Strings a YAML 1.1
/// reader would type differently (`yes`, `on`, `017`) stay quoted.
///
/// A mapping key whose rendering exceeds [`MAX_RENDERED_KEY_BYTES`] is
/// refused: the gateway's reader rejects an implicit key longer than 1024
/// bytes, while `serde-saphyr` switches to the explicit `? key` form only past
/// 1024 *characters*, so a long multibyte key would render a document the
/// gateway cannot load.
pub fn to_string<T: Serialize>(value: &T) -> Result<String, YamlError> {
    let shape = serde_json::to_value(value).map_err(|error| YamlError::new(error.to_string()))?;
    let mut path = String::new();
    refuse_unportable_keys(&shape, &mut path)?;
    render(value)
}

/// Longest rendered mapping key [`to_string`] emits, under the gateway
/// reader's 1024-byte implicit-key limit.
pub const MAX_RENDERED_KEY_BYTES: usize = 1000;

fn render<T: Serialize>(value: &T) -> Result<String, YamlError> {
    let options = serde_saphyr::ser_options! {
        prefer_block_scalars: false,
    };
    serde_saphyr::to_string_with_options(value, options)
        .map_err(|error| YamlError::new(error.to_string()))
}

fn refuse_unportable_keys(value: &Value, path: &mut String) -> Result<(), YamlError> {
    match value {
        Value::Object(entries) => {
            for (key, child) in entries {
                // Quoting at most quadruples a byte (`\x01`) and adds two
                // quotes, so shorter keys cannot reach the limit.
                if key.len() > (MAX_RENDERED_KEY_BYTES - 2) / 4 {
                    let rendered = render(key)?;
                    let rendered = rendered.trim_end_matches('\n').len();
                    if rendered > MAX_RENDERED_KEY_BYTES {
                        let location = if path.is_empty() {
                            "the document root".to_string()
                        } else {
                            format!("`{path}`")
                        };
                        return Err(YamlError::new(format!(
                            "a mapping key in {location} renders to {rendered} bytes, over the \
                             {MAX_RENDERED_KEY_BYTES}-byte limit the gateway's YAML reader \
                             accepts for a key; shorten it"
                        )));
                    }
                }
                let restore = path.len();
                path.push('.');
                path.push_str(key);
                refuse_unportable_keys(child, path)?;
                path.truncate(restore);
            }
        }
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                let restore = path.len();
                path.push_str(&format!("[{index}]"));
                refuse_unportable_keys(item, path)?;
                path.truncate(restore);
            }
        }
        _ => {}
    }
    Ok(())
}

fn parser_options(max_depth: usize) -> granit_parser::Options {
    let mut options = granit_parser::Options::default();
    options.set_emit_comments(false);
    options.block_nesting_limit = max_depth;
    options.flow_nesting_limit = max_depth;
    options
}

/// Refuse input that `granit-parser` and the gateway's libyaml-based reader
/// both accept but read differently, before either reader runs.
///
/// - U+0085, U+2028 and U+2029 are line breaks to a YAML 1.1 reader (and to
///   many editors and diff views) but content to a YAML 1.2 one, so the same
///   bytes would show a reviewer a different document than gitforgeops reads.
///   Inside a quoted string they can be written as `\N`, `\L` and `\P`.
/// - U+FEFF, including a leading byte-order mark. libyaml strips one leading
///   BOM but counts it toward the first line's indentation and keeps a second
///   as part of the first key; granit strips them all and ignores them.
/// - Anchor and alias names are limited to libyaml's `[A-Za-z0-9_-]`. granit
///   also takes `:` and `?` into a name, where libyaml ends the name and
///   reads the rest as content (`&a:b x` is `":b x"` to the gateway).
/// - Inside a flow collection, libyaml takes a leading `?` as an explicit-key
///   indicator even without a following space; granit reads `?x` as a string.
/// - A clipped or kept block scalar (`|`, `>`, `|+`) that runs to the end of a
///   file without a final line break gains a trailing newline under granit but
///   not under libyaml. A comment or `...` after it ends the scalar first. A
///   trailing whitespace-only line is refused too: past the block's indent it
///   is content the readers disagree on, and telling the two apart is not
///   worth the risk when the remedy is a final newline.
fn refuse_reader_disagreements(contents: &str, max_depth: usize) -> Result<(), YamlError> {
    for (index, line) in contents.split('\n').enumerate() {
        if let Some(column) = line.find(['\u{85}', '\u{2028}', '\u{2029}', '\u{feff}']) {
            return Err(YamlError::new(format!(
                "raw U+0085, U+2028, U+2029 or U+FEFF at line {} byte {}; YAML readers \
                 disagree on how to read it — remove a byte-order mark, and write the others \
                 as \\N, \\L, \\P or \\uFEFF inside a double-quoted string",
                index + 1,
                column + 1
            )));
        }
    }
    // Blank trailing lines are not safe either: whitespace past the block's
    // indentation is content, and the readers disagree on it too.
    let unterminated = !contents.is_empty() && !contents.ends_with(['\n', '\r']);
    let length = contents.chars().count();
    let mut flow_depth = 0usize;
    // A scan error is returned here, not left to the reader: serde-saphyr stops
    // at the first `...` and would never see malformed text after it.
    for token in Scanner::with_options(StrInput::new(contents), parser_options(max_depth)) {
        let (span, token) = token
            .map_err(|error| YamlError::new(error.to_string()))?
            .into_parts();
        match token {
            TokenType::FlowSequenceStart | TokenType::FlowMappingStart => flow_depth += 1,
            TokenType::FlowSequenceEnd | TokenType::FlowMappingEnd => {
                flow_depth = flow_depth.saturating_sub(1);
            }
            TokenType::Anchor(name) | TokenType::Alias(name)
                if !name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')) =>
            {
                return Err(YamlError::at(
                    "anchor or alias name outside letters, digits, `_` and `-`; the \
                     gateway's YAML reader ends the name early (reading the rest as content) or \
                     refuses it — rename it",
                    &span,
                ));
            }
            TokenType::Scalar(ScalarStyle::Plain, text)
                if flow_depth > 0 && text.starts_with('?') =>
            {
                return Err(YamlError::at(
                    "plain scalar starting with `?` inside a flow collection; the gateway's \
                     YAML reader takes `?` there as an explicit-key indicator — quote the value",
                    &span,
                ));
            }
            TokenType::Scalar(ScalarStyle::Literal | ScalarStyle::Folded, text)
                if unterminated && span.end.index() == length && text.ends_with('\n') =>
            {
                return Err(YamlError::at(
                    "`|` or `>` block scalar ends the file without a final line break; YAML \
                     readers disagree on whether its value ends in a newline — end the file \
                     with one",
                    &span,
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Sequence,
    Mapping,
}

/// Size of a composed subtree, so an alias can be charged before it copies.
#[derive(Debug, Clone, Copy, Default)]
struct Size {
    nodes: usize,
    scalar_bytes: usize,
    /// Collection nesting inside the node: 0 for a scalar.
    height: usize,
}

impl Size {
    fn add(&mut self, child: Size) {
        self.nodes = self.nodes.saturating_add(child.nodes);
        self.scalar_bytes = self.scalar_bytes.saturating_add(child.scalar_bytes);
        self.height = self.height.max(child.height + 1);
    }
}

enum Body {
    Sequence(Vec<Value>),
    /// `key` holds a key whose value has not arrived yet.
    Mapping {
        entries: Map<String, Value>,
        key: Option<String>,
    },
}

struct Frame {
    body: Body,
    anchor: usize,
    size: Size,
}

struct Composer {
    limits: Limits,
    nodes: usize,
    scalar_bytes: usize,
    stack: Vec<Frame>,
    anchors: HashMap<usize, (Value, Size)>,
    root: Option<Value>,
}

impl Composer {
    fn charge(&mut self, size: Size, span: &Span) -> Result<(), YamlError> {
        self.nodes = self.nodes.saturating_add(size.nodes);
        self.scalar_bytes = self.scalar_bytes.saturating_add(size.scalar_bytes);
        if self.nodes > self.limits.max_nodes
            || self.scalar_bytes > self.limits.max_scalar_bytes
            || self.stack.len() + size.height > self.limits.max_depth
        {
            return Err(YamlError::at(
                format!(
                    "document expands past the accepted shape (over {} nodes, {} scalar bytes \
                     or {} levels deep, counting alias and anchor copies); refusing to compose it",
                    self.limits.max_nodes, self.limits.max_scalar_bytes, self.limits.max_depth
                ),
                span,
            ));
        }
        Ok(())
    }

    fn scalar(
        &mut self,
        text: &str,
        style: ScalarStyle,
        anchor: usize,
        tag: Option<&Tag>,
        span: &Span,
    ) -> Result<(), YamlError> {
        let size = Size {
            nodes: 1,
            scalar_bytes: text.len(),
            height: 0,
        };
        self.charge(size, span)?;
        let value = resolve_scalar(text, style, tag, span)?;
        self.attach(value, size, anchor, span)
    }

    fn open(
        &mut self,
        kind: Kind,
        anchor: usize,
        tag: Option<&Tag>,
        span: &Span,
    ) -> Result<(), YamlError> {
        if let Some(tag) = tag {
            let accepted = match kind {
                Kind::Sequence => "seq",
                Kind::Mapping => "map",
            };
            if tag.core_suffix() != Some(accepted) {
                return Err(unsupported_tag(tag, span));
            }
        }
        if self.awaiting_key() {
            return Err(self.non_string_key(
                match kind {
                    Kind::Sequence => "a sequence",
                    Kind::Mapping => "a mapping",
                },
                span,
            ));
        }
        self.charge(
            Size {
                nodes: 1,
                scalar_bytes: 0,
                height: 1,
            },
            span,
        )?;
        let body = match kind {
            Kind::Sequence => Body::Sequence(Vec::new()),
            Kind::Mapping => Body::Mapping {
                entries: Map::new(),
                key: None,
            },
        };
        self.stack.push(Frame {
            body,
            anchor,
            size: Size {
                nodes: 1,
                scalar_bytes: 0,
                height: 1,
            },
        });
        Ok(())
    }

    fn close(&mut self, span: &Span) -> Result<(), YamlError> {
        let frame = self
            .stack
            .pop()
            .ok_or_else(|| YamlError::at("unbalanced collection end", span))?;
        let value = match frame.body {
            Body::Sequence(items) => Value::Array(items),
            Body::Mapping { entries, key: None } => Value::Object(entries),
            Body::Mapping { key: Some(_), .. } => {
                return Err(YamlError::at("mapping ended before a key's value", span));
            }
        };
        // `frame.size` was charged as the children arrived; attaching must not
        // charge it again.
        self.attach(value, frame.size, frame.anchor, span)
    }

    fn alias(&mut self, anchor: usize, span: &Span) -> Result<(), YamlError> {
        let size = match self.anchors.get(&anchor) {
            Some((_, size)) => *size,
            None => return Err(YamlError::at("alias to an unknown anchor", span)),
        };
        // Charge the whole copy before making it.
        self.charge(size, span)?;
        let value = match self.anchors.get(&anchor) {
            Some((value, _)) => value.clone(),
            None => return Err(YamlError::at("alias to an unknown anchor", span)),
        };
        self.attach(value, size, 0, span)
    }

    /// Place a finished node in its parent. Its size has already been charged.
    fn attach(
        &mut self,
        value: Value,
        size: Size,
        anchor: usize,
        span: &Span,
    ) -> Result<(), YamlError> {
        if anchor != 0 {
            // The anchor table keeps its own copy, which is charged like an
            // alias copy: nested anchors would otherwise retain a subtree once
            // per enclosing anchor without counting it. A redefined anchor
            // replaces the earlier one, as YAML requires.
            self.charge(size, span)?;
            self.anchors.insert(anchor, (value.clone(), size));
        }
        if self.awaiting_key() {
            let Value::String(key) = value else {
                return Err(self.non_string_key(&describe_key(&value), span));
            };
            let Some(Frame {
                body: Body::Mapping { entries, key: slot },
                size: parent,
                ..
            }) = self.stack.last_mut()
            else {
                return Err(YamlError::at("internal composer state", span));
            };
            if entries.contains_key(&key) {
                return Err(YamlError::at(
                    format!(
                        "duplicate mapping key `{}` in {}",
                        key,
                        location(&self.stack)
                    ),
                    span,
                ));
            }
            parent.add(size);
            *slot = Some(key);
            return Ok(());
        }
        match self.stack.last_mut() {
            None => {
                self.root = Some(value);
            }
            Some(frame) => {
                frame.size.add(size);
                match &mut frame.body {
                    Body::Sequence(items) => items.push(value),
                    Body::Mapping { entries, key } => {
                        let Some(key) = key.take() else {
                            return Err(YamlError::at("internal composer state", span));
                        };
                        entries.insert(key, value);
                    }
                }
            }
        }
        Ok(())
    }

    fn awaiting_key(&self) -> bool {
        matches!(
            self.stack.last(),
            Some(Frame {
                body: Body::Mapping { key: None, .. },
                ..
            })
        )
    }

    fn non_string_key(&self, description: &str, span: &Span) -> YamlError {
        YamlError::at(
            format!(
                "non-string mapping key ({description}) in {}; configuration is JSON-shaped and \
                 only string keys survive parsing — quote the key to keep it",
                location(&self.stack)
            ),
            span,
        )
    }
}

/// Key path of the innermost open mapping or sequence, e.g. `` `.spec.config` ``.
fn location(stack: &[Frame]) -> String {
    let mut path = String::new();
    // Every frame but the innermost contributes the segment leading into its
    // child: the pending key of a mapping, the next index of a sequence.
    for frame in stack.iter().take(stack.len().saturating_sub(1)) {
        match &frame.body {
            Body::Sequence(items) => {
                path.push('[');
                path.push_str(&items.len().to_string());
                path.push(']');
            }
            Body::Mapping { key, .. } => {
                path.push('.');
                path.push_str(key.as_deref().unwrap_or_default());
            }
        }
    }
    if path.is_empty() {
        "the document root".to_string()
    } else {
        format!("`{path}`")
    }
}

fn describe_key(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(value) => format!("boolean `{value}`"),
        Value::Number(value) => format!("number `{value}`"),
        Value::String(value) => format!("string `{value}`"),
        Value::Array(_) => "a sequence".to_string(),
        Value::Object(_) => "a mapping".to_string(),
    }
}

fn unsupported_tag(tag: &Tag, span: &Span) -> YamlError {
    YamlError::at(
        format!(
            "unsupported YAML tag `{}`; only !!str, !!int, !!float, !!bool and !!null \
             scalars and !!map/!!seq collections are accepted",
            tag.original()
        ),
        span,
    )
}

fn resolve_scalar(
    text: &str,
    style: ScalarStyle,
    tag: Option<&Tag>,
    span: &Span,
) -> Result<Value, YamlError> {
    let Some(tag) = tag else {
        return if matches!(style, ScalarStyle::Plain) {
            resolve_plain(text, span)
        } else {
            Ok(Value::String(text.to_string()))
        };
    };
    let invalid = |expected: &str| {
        YamlError::at(
            format!("scalar tagged `{}` is not {expected}", tag.original()),
            span,
        )
    };
    match tag.core_suffix() {
        Some("str") => Ok(Value::String(text.to_string())),
        Some("bool") => parse_bool(text)
            .map(Value::Bool)
            .ok_or_else(|| invalid("a boolean")),
        Some("null") if parse_null(text) => Ok(Value::Null),
        Some("null") => Err(invalid("null")),
        Some("int") => match parse_int(text) {
            Int::Fits(number) => Ok(Value::Number(number)),
            Int::OutOfRange => Err(out_of_range(span)),
            Int::NotInteger => Err(invalid("an integer")),
        },
        Some("float") => match parse_float(text) {
            Some(float) => finite(float, span),
            None => Err(invalid("a float")),
        },
        _ => Err(unsupported_tag(tag, span)),
    }
}

/// YAML 1.2 core-schema resolution of an untagged plain scalar, as the
/// gateway's `serde_yaml` 0.9 performs it.
fn resolve_plain(text: &str, span: &Span) -> Result<Value, YamlError> {
    if text.is_empty() || parse_null(text) {
        return Ok(Value::Null);
    }
    if let Some(boolean) = parse_bool(text) {
        return Ok(Value::Bool(boolean));
    }
    match parse_int(text) {
        Int::Fits(number) => return Ok(Value::Number(number)),
        Int::OutOfRange => return Err(out_of_range(span)),
        Int::NotInteger => {}
    }
    if !leading_zero_digits(text) {
        if let Some(float) = parse_float(text) {
            return finite(float, span);
        }
    }
    Ok(Value::String(text.to_string()))
}

fn out_of_range(span: &Span) -> YamlError {
    YamlError::at(
        "integer outside the 64-bit range; quote it to keep it as a string",
        span,
    )
}

fn finite(float: f64, span: &Span) -> Result<Value, YamlError> {
    Number::from_f64(float).map(Value::Number).ok_or_else(|| {
        YamlError::at(
            "non-finite float (.inf or .nan) has no JSON form; quote it to keep it as a string",
            span,
        )
    })
}

fn parse_null(text: &str) -> bool {
    matches!(text, "null" | "Null" | "NULL" | "~")
}

fn parse_bool(text: &str) -> Option<bool> {
    match text {
        "true" | "True" | "TRUE" => Some(true),
        "false" | "False" | "FALSE" => Some(false),
        _ => None,
    }
}

/// `0` followed by more digits is a string in YAML 1.2 (`017`, `-00`).
fn leading_zero_digits(text: &str) -> bool {
    let digits = text.strip_prefix(['-', '+']).unwrap_or(text);
    digits.len() > 1 && digits.starts_with('0') && digits[1..].bytes().all(|b| b.is_ascii_digit())
}

enum Int {
    Fits(Number),
    /// An integer `serde_yaml` would read as 128-bit, which JSON cannot hold.
    OutOfRange,
    NotInteger,
}

fn parse_int(text: &str) -> Int {
    if let Some(value) = parse_unsigned(text, u64::from_str_radix) {
        return Int::Fits(value.into());
    }
    if let Some(value) = parse_negative(text, i64::from_str_radix) {
        return Int::Fits(value.into());
    }
    if parse_unsigned(text, u128::from_str_radix).is_some()
        || parse_negative(text, i128::from_str_radix).is_some()
    {
        return Int::OutOfRange;
    }
    Int::NotInteger
}

type FromStrRadix<T> = fn(&str, u32) -> Result<T, std::num::ParseIntError>;

/// An optionally `+`-signed decimal, `0x`, `0o` or `0b` integer.
fn parse_unsigned<T>(text: &str, from_str_radix: FromStrRadix<T>) -> Option<T> {
    let unsigned = text.strip_prefix('+').unwrap_or(text);
    for (prefix, radix) in [("0x", 16), ("0o", 8), ("0b", 2)] {
        if let Some(digits) = unsigned.strip_prefix(prefix) {
            if digits.starts_with(['+', '-']) {
                return None;
            }
            if let Ok(value) = from_str_radix(digits, radix) {
                return Some(value);
            }
        }
    }
    if unsigned.starts_with(['+', '-']) || leading_zero_digits(text) {
        return None;
    }
    from_str_radix(unsigned, 10).ok()
}

/// A `-`-signed decimal, `-0x`, `-0o` or `-0b` integer.
fn parse_negative<T>(text: &str, from_str_radix: FromStrRadix<T>) -> Option<T> {
    for (prefix, radix) in [("-0x", 16), ("-0o", 8), ("-0b", 2)] {
        if let Some(digits) = text.strip_prefix(prefix) {
            if let Ok(value) = from_str_radix(&format!("-{digits}"), radix) {
                return Some(value);
            }
        }
    }
    if leading_zero_digits(text) {
        return None;
    }
    from_str_radix(text, 10).ok()
}

/// A float, including the YAML spellings of infinity and NaN. Rust's own
/// `inf`/`nan` spellings and overflowing literals (`1e999`) are not floats.
fn parse_float(text: &str) -> Option<f64> {
    let unsigned = match text.strip_prefix('+') {
        Some(rest) if rest.starts_with(['+', '-']) => return None,
        Some(rest) => rest,
        None => text,
    };
    if matches!(unsigned, ".inf" | ".Inf" | ".INF") {
        return Some(f64::INFINITY);
    }
    if matches!(text, "-.inf" | "-.Inf" | "-.INF") {
        return Some(f64::NEG_INFINITY);
    }
    if matches!(text, ".nan" | ".NaN" | ".NAN") {
        return Some(f64::NAN);
    }
    unsigned
        .parse::<f64>()
        .ok()
        .filter(|float| float.is_finite())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(contents: &str) -> Result<Value, YamlError> {
        parse_value(contents, RESOURCE_LIMITS)
    }

    #[test]
    fn plain_scalars_resolve_as_yaml_1_2_core() {
        let value = parse(
            "a: 017\nb: 1_000\nc: yes\nd: 0x1F\ne: -0o17\nf: ~\ng:\nh: 1e3\ni: TRUE\nj: '7'\n",
        )
        .unwrap();
        assert_eq!(
            value,
            serde_json::json!({
                "a": "017", "b": "1_000", "c": "yes", "d": 31, "e": -15,
                "f": null, "g": null, "h": 1000.0, "i": true, "j": "7",
            })
        );
    }

    #[test]
    fn alias_is_charged_before_it_is_copied() {
        let limits = Limits {
            max_depth: MAX_YAML_DEPTH,
            max_nodes: 50,
            max_scalar_bytes: 1024,
        };
        let base = "x,".repeat(10);
        let doc = format!("a: &b [{base}]\nc: [*b, *b, *b, *b]\n");
        let error = parse_value(&doc, limits).unwrap_err().to_string();
        assert!(error.contains("expands past the accepted shape"), "{error}");
    }

    #[test]
    fn alias_bytes_are_bounded() {
        let limits = Limits {
            max_depth: MAX_YAML_DEPTH,
            max_nodes: 1_000,
            max_scalar_bytes: 100,
        };
        let doc = format!("a: &b '{}'\nc: [*b, *b]\n", "s".repeat(40));
        assert!(parse_value(&doc, limits).is_err());
    }

    #[test]
    fn alias_depth_is_bounded() {
        let limits = Limits {
            max_depth: 3,
            max_nodes: 1_000,
            max_scalar_bytes: 1_000,
        };
        assert!(parse_value("a: &b [[1]]\nc: *b\n", limits).is_ok());
        assert!(parse_value("a: &b [[1]]\nc: [*b]\n", limits).is_err());
    }

    /// Billion laughs: ten levels of ten-fold aliases name 10^10 nodes in
    /// under a kilobyte. It is refused within the node bound, and memory stays
    /// near what the bound allows rather than growing with the expansion.
    #[test]
    fn alias_bomb_is_refused_with_bounded_memory() {
        let mut doc = String::from("a0: &a0 [x, x, x, x, x, x, x, x, x, x]\n");
        for level in 1..10 {
            let previous = format!("*a{}", level - 1);
            let refs = [previous.as_str(); 10].join(", ");
            doc.push_str(&format!("a{level}: &a{level} [{refs}]\n"));
        }
        let (result, peak) =
            crate::alloc_meter::peak_bytes(|| parse_value(&doc, RESOURCE_LIMITS).map(|_| ()));
        let error = result.unwrap_err().to_string();
        assert!(error.contains("expands past the accepted shape"), "{error}");
        // A million JSON values fit in a few hundred MiB; unbounded expansion
        // would need terabytes.
        assert!(peak < 512 << 20, "peak {peak} bytes");
        assert!(from_str::<serde_json::Value>(&doc).is_err());
    }

    /// Anchors nested around a large subtree: each enclosing anchor keeps its
    /// own copy, and those copies are charged, so no alias is needed to be
    /// refused within the bound.
    #[test]
    fn nested_anchor_copies_are_charged() {
        let nest = |levels: usize, leaf: &str| {
            format!(
                "{}{leaf}{}",
                (0..levels).map(|i| format!("&a{i} [")).collect::<String>(),
                "]".repeat(levels)
            )
        };
        let big = format!("'{}'", "s".repeat(1 << 20));
        let (result, peak) = crate::alloc_meter::peak_bytes(|| {
            parse_value(&nest(120, &big), RESOURCE_LIMITS).map(|_| ())
        });
        let error = result.unwrap_err().to_string();
        assert!(error.contains("expands past the accepted shape"), "{error}");
        assert!(peak < 192 << 20, "peak {peak} bytes");

        let ones = vec!["1"; 20_000].join(", ");
        let (result, peak) = crate::alloc_meter::peak_bytes(|| {
            parse_value(&nest(120, &ones), RESOURCE_LIMITS).map(|_| ())
        });
        assert!(result.is_err());
        assert!(peak < 512 << 20, "peak {peak} bytes");

        // A few nested anchors are still fine.
        assert!(parse(&format!("k: {}\n", nest(3, "[1, 2]"))).is_ok());
    }

    /// One long scalar copied by many aliases is bounded by scalar bytes,
    /// not node count.
    #[test]
    fn alias_scalar_amplification_is_refused_with_bounded_memory() {
        let doc = format!(
            "a: &s '{}'\nb: [{}]\n",
            "s".repeat(1 << 20),
            ["*s"; 200].join(", ")
        );
        let (result, peak) =
            crate::alloc_meter::peak_bytes(|| parse_value(&doc, RESOURCE_LIMITS).map(|_| ()));
        assert!(result.is_err());
        assert!(peak < 256 << 20, "peak {peak} bytes");
        assert!(from_str::<serde_json::Value>(&doc).is_err());
    }

    #[test]
    fn nesting_past_the_depth_bound_is_refused_without_recursion() {
        for open in ["[", "{a: ", "- "] {
            let deep = if open == "- " {
                (0..300)
                    .map(|level| format!("{}- \n", " ".repeat(level * 2)))
                    .collect::<String>()
            } else {
                open.repeat(100_000)
            };
            assert!(parse(&deep).is_err(), "{open}");
            assert!(from_str::<serde_json::Value>(&deep).is_err(), "{open}");
        }
        let nested = |depth: usize| format!("{}{}", "[".repeat(depth), "]".repeat(depth));
        assert!(parse(&nested(MAX_YAML_DEPTH)).is_ok());
        assert!(parse(&nested(MAX_YAML_DEPTH + 1)).is_err());
        assert!(from_str::<serde_json::Value>(&nested(SETTINGS_MAX_DEPTH)).is_ok());
        assert!(from_str::<serde_json::Value>(&nested(SETTINGS_MAX_DEPTH + 1)).is_err());
    }

    #[test]
    fn duplicate_and_non_string_keys_name_the_mapping() {
        let error = parse("spec:\n  config:\n    a: 1\n    a: 2\n")
            .unwrap_err()
            .to_string();
        assert!(error.contains("duplicate mapping key `a`"), "{error}");
        assert!(error.contains("`.spec.config`"), "{error}");
        let error = parse("items:\n  - {1: x}\n").unwrap_err().to_string();
        assert!(error.contains("number `1`"), "{error}");
        assert!(error.contains("`.items[0]`"), "{error}");
        let error = parse("? {a: b}\n: c\n").unwrap_err().to_string();
        assert!(error.contains("a mapping"), "{error}");
        assert!(error.contains("the document root"), "{error}");
    }

    #[test]
    fn raw_line_separators_are_refused() {
        for separator in ['\u{85}', '\u{2028}', '\u{2029}'] {
            for doc in [
                format!("# note{separator}enabled: false\n"),
                format!("k: \"a{separator}b\"\n"),
            ] {
                assert!(parse(&doc).is_err(), "{doc:?}");
                assert!(from_str::<serde_json::Value>(&doc).is_err(), "{doc:?}");
            }
        }
        assert_eq!(
            parse("k: \"a\\Lb\"\n").unwrap(),
            serde_json::json!({"k": "a\u{2028}b"})
        );
    }

    #[test]
    fn errors_do_not_echo_scalar_values() {
        for doc in [
            "a: !!int sekret-value\n",
            "a: !!bool sekret-value\n",
            "a: !foo sekret-value\n",
        ] {
            let error = parse(doc).unwrap_err().to_string();
            assert!(!error.contains("sekret"), "{error}");
        }
    }
}
