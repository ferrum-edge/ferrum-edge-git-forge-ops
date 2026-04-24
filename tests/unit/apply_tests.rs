use gitforgeops::apply::ApplyResult;

#[test]
fn apply_result_into_result_rejects_partial_failure() {
    let result = ApplyResult {
        created: 1,
        updated: 2,
        deleted: 0,
        unmanaged_skipped: 0,
        errors: vec!["Proxy proxy-a update: 500".to_string()],
    };

    let error = result.into_result().unwrap_err();
    assert!(error
        .to_string()
        .contains("Apply failed after partial success"));
    assert!(error.to_string().contains("Proxy proxy-a update: 500"));
}
