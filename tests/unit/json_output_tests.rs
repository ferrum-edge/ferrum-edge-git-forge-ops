use gitforgeops::json_output::{compact, pretty, terminate};

#[test]
fn terminate_leaves_exactly_one_trailing_newline() {
    assert_eq!(terminate("{}".to_string()), "{}\n");
    assert_eq!(terminate("{}\n".to_string()), "{}\n");
    assert_eq!(terminate("{}\n\n".to_string()), "{}\n");
}

#[test]
fn compact_and_pretty_end_with_exactly_one_newline() {
    let value = serde_json::json!({"ok": true});
    let compact_out = compact(&value).unwrap();
    let pretty_out = pretty(&value).unwrap();

    for output in [&compact_out, &pretty_out] {
        assert!(output.ends_with('\n'), "{output:?}");
        assert!(!output.ends_with("\n\n"), "{output:?}");
        serde_json::from_str::<serde_json::Value>(output).unwrap();
    }
}
