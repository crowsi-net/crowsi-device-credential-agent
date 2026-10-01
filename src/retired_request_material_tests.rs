use crate::retired_request_types::RetiredRefreshMaterialV1;

#[test]
fn refresh_material_is_a_closed_typed_union() {
    for wire in [
        r#"{"future_route":{"wire":"request"}}"#,
        r#"{"management_envelope":{"route":"source-approve","wire":"request","extra":1}}"#,
        r#"{"cancel_envelope":{"wire":"request","expected_body":{"pending":{"operations":[]}},"extra":1}}"#,
        r#"{"cancel_cleanup_complete":{"wire":"request","expected_body":{"pending":{"operations":[]}},"delivery":{},"extra":1}}"#,
        r#"{"revocation_finalize":{"wire":"request","extra":1}}"#,
        r#"{"independent_revocation_finalize":{"wire":"request","extra":1}}"#,
    ] {
        assert!(serde_json::from_str::<RetiredRefreshMaterialV1>(wire).is_err());
    }
}
