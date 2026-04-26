use gitforgeops::apply::ApplyResult;

#[test]
fn apply_result_into_result_rejects_partial_failure() {
    let result = ApplyResult {
        created: 1,
        updated: 2,
        deleted: 0,
        unmanaged_skipped: 0,
        errors: vec!["Proxy proxy-a update: 500".to_string()],
        ..Default::default()
    };

    let error = result.into_result().unwrap_err();
    let msg = error.to_string();
    assert!(msg.contains("Apply failed after partial success"));
    assert!(msg.contains("Proxy proxy-a update: 500"));
    // The successful-counts portion of the message is what cmd_apply
    // surfaces via the deferred-propagation path: state.record/save
    // runs first, then this error propagates to the CLI. The counts
    // tell operators exactly which portion landed in state.
    assert!(msg.contains("1 created"), "expected created count: {msg}");
    assert!(msg.contains("2 updated"), "expected updated count: {msg}");
    assert!(msg.contains("1 failed"), "expected failed count: {msg}");
}

#[test]
fn apply_result_into_result_propagates_via_err_for_deferred_pattern() {
    // cmd_apply now uses `raw.into_result().err()` to capture the
    // partial-failure error AFTER state.record/state.save runs. This
    // documents that pattern: into_result returns Err on partial
    // failure (even when created+updated > 0), and `.err()` yields
    // Some(error) for deferred propagation.
    let partial = ApplyResult {
        created: 3,
        updated: 0,
        deleted: 0,
        unmanaged_skipped: 0,
        errors: vec!["Consumer alice create: 500".to_string()],
        ..Default::default()
    };
    assert!(
        partial.into_result().err().is_some(),
        "partial failure must yield Some(err) so deferred propagation triggers"
    );

    // Pure success path: into_result returns Ok, .err() yields None →
    // deferred-propagation block is a no-op.
    let success = ApplyResult {
        created: 5,
        updated: 0,
        deleted: 0,
        unmanaged_skipped: 0,
        errors: vec![],
        ..Default::default()
    };
    assert!(
        success.into_result().err().is_none(),
        "clean apply must yield None — deferred propagation must not fire"
    );
}
