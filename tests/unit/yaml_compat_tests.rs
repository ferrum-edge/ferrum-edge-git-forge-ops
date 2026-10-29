//! Differential checks of `gitforgeops::yaml` against `serde_yaml` 0.9, the
//! parser the gateway reads YAML with (issue #561).
//!
//! `parse_value` must give the gateway's reading of a document, or refuse it
//! when that reading cannot reach JSON unchanged. `to_string` output must read
//! back identically under both parsers.

use gitforgeops::yaml::{self, RESOURCE_LIMITS};
use serde_json::{json, Value};

/// How the gateway reads `document`.
enum Gateway {
    Reads(Value),
    /// Read, but not as JSON: a tag, a non-string key, a non-finite float.
    Lossy,
    /// Refused outright.
    Refuses,
}

fn gateway_reading(document: &str) -> Gateway {
    match serde_yaml::from_str::<serde_yaml::Value>(document) {
        Err(_) => Gateway::Refuses,
        Ok(value) if !json_shaped(&value) => Gateway::Lossy,
        Ok(value) => Gateway::Reads(serde_json::to_value(value).unwrap()),
    }
}

fn json_shaped(value: &serde_yaml::Value) -> bool {
    match value {
        serde_yaml::Value::Tagged(_) => false,
        serde_yaml::Value::Number(number) => number.as_f64().is_none_or(f64::is_finite),
        serde_yaml::Value::Sequence(items) => items.iter().all(json_shaped),
        serde_yaml::Value::Mapping(mapping) => mapping
            .iter()
            .all(|(key, value)| key.is_string() && json_shaped(value)),
        _ => true,
    }
}

/// Documents the gateway reads that gitforgeops refuses on purpose.
const REFUSED_ON_PURPOSE: [&str; 4] = [
    // YAML 1.2 forbids a plain `-` before a flow indicator; libyaml allows it.
    "[-]\n",
    // Raw line separators (see `yaml::parse_value`).
    "k: \"\u{85}\u{2028}\"\n",
    // serde_yaml keeps the undecoded text; other readers decode it.
    "k: !!binary aGk=\n",
    // serde_yaml reads a global tag as a bare string, turning `1` into "1".
    "%TAG !e! tag:example.com,2000:\n---\nk: !e!x 1\n",
];

/// The contract: where both accept a document they read the same value;
/// gitforgeops never accepts what the gateway reads lossily; and it refuses
/// what the gateway reads only where listed above. It may accept YAML 1.2
/// syntax libyaml's 1.1 scanner refuses (`[a:]`, `[:a]`): the gateway never
/// reads repository bytes, only what [`yaml::to_string`] renders.
fn assert_agrees(document: &str) {
    let ours = yaml::parse_value(document, RESOURCE_LIMITS);
    match (gateway_reading(document), ours) {
        (Gateway::Reads(expected), Ok(actual)) => {
            assert_eq!(actual, expected, "document {document:?}");
        }
        (Gateway::Reads(expected), Err(error)) => assert!(
            REFUSED_ON_PURPOSE.contains(&document),
            "refused {document:?} ({error}); the gateway reads {expected}"
        ),
        (Gateway::Lossy, Ok(actual)) => {
            panic!("accepted {document:?} as {actual}; the gateway reads it lossily")
        }
        (Gateway::Lossy | Gateway::Refuses, Err(_)) | (Gateway::Refuses, Ok(_)) => {}
    }
}

const TOKENS: [&str; 22] = [
    "0", "1", "7", "9", "-", "+", ".", "e", "E", "_", "x", "o", "b", "f", "inf", "nan", "Inf",
    "NaN", "INF", ":", "~", "a",
];

/// Every one-, two- and three-token plain scalar resolves as the gateway
/// resolves it: number, boolean, null or string.
#[test]
fn plain_scalars_resolve_like_the_gateway() {
    let mut scalars = vec![String::new()];
    for first in TOKENS {
        scalars.push(first.to_string());
        for second in TOKENS {
            scalars.push(format!("{first}{second}"));
            for third in TOKENS {
                scalars.push(format!("{first}{second}{third}"));
            }
        }
    }
    for scalar in &scalars {
        assert_agrees(&format!("k: {scalar}\n"));
        assert_agrees(&format!("[{scalar}]\n"));
        assert_agrees(&format!("k: '{scalar}'\n"));
    }
}

#[test]
fn named_scalars_resolve_like_the_gateway() {
    for scalar in [
        "yes",
        "no",
        "on",
        "off",
        "y",
        "n",
        "Yes",
        "ON",
        "true",
        "True",
        "TRUE",
        "tRue",
        "false",
        "null",
        "Null",
        "NULL",
        "nULL",
        "~",
        "017",
        "00",
        "-0",
        "+0",
        "0x1F",
        "0X1F",
        "-0x1F",
        "0o17",
        "-0o17",
        "0b101",
        "-0b101",
        "0x_1",
        "1_000",
        "1,000",
        "12:30",
        "12:30:45",
        "2001-12-14",
        "2001-12-14t21:59:43.10-05:00",
        "1e3",
        "1E3",
        "1e+3",
        "1e-3",
        ".5",
        "5.",
        "-.5",
        "+.5",
        "1e999",
        "-1e999",
        "inf",
        "nan",
        ".inf",
        "-.inf",
        "+.inf",
        ".nan",
        ".NaN",
        "18446744073709551615",
        "18446744073709551616",
        "-9223372036854775808",
        "-9223372036854775809",
        "340282366920938463463374607431768211455",
        "3402823669209384634633746074317682114550",
        "9007199254740993",
        "0.1",
        "1.0",
        "100000000000000000000000000000.5",
    ] {
        assert_agrees(&format!("k: {scalar}\n"));
        assert_agrees(&format!("k: !!str {scalar}\n"));
        assert_agrees(&format!("k: !!int {scalar}\n"));
        assert_agrees(&format!("k: !!float {scalar}\n"));
        assert_agrees(&format!("k: !!bool {scalar}\n"));
        assert_agrees(&format!("k: !!null {scalar}\n"));
        assert_agrees(&format!("{scalar}: v\n"));
    }
}

/// Document structure: quoting and escapes, block scalars and chomping,
/// anchors, flow collections, explicit keys, comments and markers.
#[test]
fn documents_compose_like_the_gateway() {
    for document in [
        "",
        "# only a comment\n",
        "---\n",
        "--- \nk: v\n...\n",
        "%YAML 1.2\n---\nk: v\n",
        "k: \"tab\\there \\u263A \\U0001F600 \\x41 \\\\ \\\" \\/ \\0\"\n",
        "k: 'it''s'\n",
        "k: \"line one\\\n  continued\"\n",
        "k: plain\n  continued\n  lines\n",
        "k: |\n  literal\n  text\n",
        "k: |-\n  strip\n\n",
        "k: |+\n  keep\n\n\n",
        "k: >\n  folded\n  text\n\n  para\n",
        "k: >-\n  folded\n",
        "k: |2\n    indented\n",
        "a: &x {b: [1, 2]}\nc: *x\n",
        "a: &x 1\nb: *x\na2: &x 2\nc: *x\n",
        "- &s str\n- *s\n- [*s, *s]\n",
        "<<: {a: 1}\nb: 2\n",
        "a: &d {x: 1}\nb:\n  <<: *d\n  y: 2\n",
        "'<<': 1\n",
        "{a: 1, b: [x, y], c: {d: e}}\n",
        "[a, b, ]\n",
        "{a: 1, }\n",
        "? a\n: b\n",
        "? [a, b]\n: c\n",
        "a:\n- 1\n- 2\n",
        "a:\n  - 1\n  -\n  - 3\n",
        "k: v # trailing comment\n",
        "k: v#not-a-comment\n",
        "k:v\n",
        "k: [a, {b: c}]\n",
        "\u{feff}k: bom\n",
        "k: v\r\nj: w\r\n",
        "k:\tv\n",
        "k: \"\u{85}\u{2028}\"\n",
        "k: !!str\n",
        "k: !!null\n",
        "!!map {a: 1}\n",
        "!!seq [1]\n",
        "k: !!binary aGk=\n",
        "k: !foo bar\n",
        "k: ! bar\n",
        "k: !<tag:yaml.org,2002:str> 5\n",
        "%TAG !e! tag:example.com,2000:\n---\nk: !e!x 1\n",
        "a: 1\na: 2\n",
        "a: 1\n'a': 2\n",
        "1: a\n'1': b\n",
        "null: a\n",
        ": a\n",
        "---\na: 1\n---\nb: 2\n",
        "a: *unknown\n",
        "a: &x [*x]\n",
        "k: @reserved\n",
        "k: `reserved\n",
        "k: [unclosed\n",
        "k: \"unclosed\n",
    ] {
        assert_agrees(document);
    }
}

fn hostile_strings() -> Vec<String> {
    let mut strings: Vec<String> = [
        "",
        " ",
        "017",
        "1_000",
        "00",
        "yes",
        "on",
        "y",
        "n",
        "No",
        "TRUE",
        "True",
        "~",
        "null",
        "NULL",
        ".inf",
        "-.inf",
        ".nan",
        "0x1F",
        "0o17",
        "0b101",
        "+12",
        "-0",
        "0.",
        "1e3",
        ".5",
        "12:30",
        "2001-12-14",
        "-",
        "- x",
        "a: b",
        "a:b",
        "#x",
        "x #y",
        " lead",
        "trail ",
        "\n",
        "a\nb",
        "a\n",
        "a\n\n",
        "\na",
        "\t",
        "a\tb",
        "'",
        "\"",
        "''",
        "@x",
        "`x",
        "*a",
        "&a",
        "!x",
        "!!str",
        "%x",
        "|",
        "> x",
        "? x",
        ":",
        "[x]",
        "{x}",
        ",",
        "é",
        "\u{0}",
        "\u{7}",
        "\u{1b}[31m",
        "\u{7f}",
        "\u{85}",
        "\u{a0}",
        "\u{2028}",
        "\u{2029}",
        "\u{feff}x",
        "\u{1F600}",
        "${gh-env-secret:alloc=generate}",
        "${gh-env-secret:alloc=require}",
        "<<",
        "=",
        "0",
        "1",
        "-1",
        "1.0",
        "+.inf",
        "9223372036854775808",
        "--- x",
        "---",
        "...",
        "x\r\ny",
        "\r",
        "a  b",
        "a\\b",
        "\\",
        "C:\\path",
        "%YAML",
        "a,b",
        "a]b",
        "a}b",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    strings.push("word ".repeat(40));
    strings.push("x".repeat(300));
    strings.push(format!("{}\n{}", "long line ".repeat(20), "tail "));
    strings
}

/// What gitforgeops emits reads back unchanged in the gateway and in
/// gitforgeops, as keys, values and sequence items.
#[test]
fn rendered_documents_read_back_identically() {
    for string in hostile_strings() {
        let document = json!({
            "k": string,
            string.clone(): {"nested": [string, {"deep": string}]},
            "list": [string, 1, -1, 0.1, -0.0, 1e300, u64::MAX, i64::MIN, true, null, {}, []],
        });
        let rendered = yaml::to_string(&document).unwrap();
        let gateway: serde_yaml::Value = serde_yaml::from_str(&rendered)
            .unwrap_or_else(|error| panic!("gateway refuses {rendered:?}: {error}"));
        assert_eq!(
            serde_json::to_value(gateway).unwrap(),
            document,
            "{rendered}"
        );
        assert_eq!(
            yaml::parse_value(&rendered, RESOURCE_LIMITS).unwrap(),
            document,
            "{rendered}"
        );
        assert_eq!(
            yaml::from_str::<Value>(&rendered).unwrap(),
            document,
            "{rendered}"
        );
        assert!(
            !rendered.contains(": |") && !rendered.contains(": >"),
            "{rendered}"
        );
    }
}

/// Typed settings read plain scalars into string fields as the gateway's
/// typed deserializer does, and refuse what it refuses.
#[test]
fn typed_settings_read_like_the_gateway() {
    #[derive(Debug, PartialEq, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Settings {
        name: String,
        #[serde(default)]
        count: Option<u32>,
        #[serde(default)]
        enabled: Option<bool>,
    }

    for document in [
        "name: plain\n",
        "name: 017\n",
        "name: yes\n",
        "name: 1_000\n",
        "name: '5'\ncount: 5\n",
        "name: x\ncount: 0x10\n",
        "name: x\nenabled: true\n",
        "name: x\nenabled: True\n",
        "name: x\nenabled: yes\n",
        "name: x\nenabled: on\n",
        "name: x\ncount: -1\n",
        "name: x\ncount: 1.5\n",
        "name: x\nother: 1\n",
        "name: x\nname: y\n",
        "name: !foo x\n",
        "<<: {name: x}\n",
        "a: &x {name: y}\n",
    ] {
        let gateway = serde_yaml::from_str::<Settings>(document).ok();
        let ours = yaml::from_str::<Settings>(document).ok();
        // serde_yaml ignores an application tag on a typed field; settings
        // refuse it, as resources do.
        let expected = if document.contains("!foo") {
            None
        } else {
            gateway
        };
        assert_eq!(ours, expected, "document {document:?}");
    }
}
