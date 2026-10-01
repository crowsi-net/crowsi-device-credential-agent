use std::{fs, path::Path};

#[test]
fn endpoint_production_surface_is_mtls_and_contract_only() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let manifest = fs::read_to_string(root.join("Cargo.toml")).expect("manifest");
    for forbidden in [
        "crowsi-credential-authority =",
        "crowsi-windows-custody-provider",
    ] {
        assert!(!manifest.contains(forbidden));
    }
    let library = fs::read_to_string(root.join("src/lib.rs")).expect("library");
    assert!(!library.contains("pub use core::AgentCore"));
    assert!(!library.contains("pub use transport::AuthorityTransport"));
    assert!(library.contains("test-support is forbidden in release builds"));
    let mut source = String::new();
    for entry in fs::read_dir(root.join("src")).expect("source") {
        let path = entry.expect("entry").path();
        if path.extension().is_some_and(|value| value == "rs") {
            source.push_str(&fs::read_to_string(path).expect("rust"));
        }
    }
    assert!(!source.contains("device-management-native-request/v1"));
    assert!(!source.contains("source_assertion"));
    assert!(source.contains("decode_management_request_strict"));
    assert!(source.contains("verify_management_projection_at"));
    assert!(source.contains("/proc/self/status"));
    assert!(!source.contains("metadata(\"/proc/self\")"));
    assert!(source.contains("DurableSecurityState::initialize_once"));
    assert!(source.contains("DurableSecurityState::open"));
    assert!(source.contains("endpoint_state_directory"));
    assert!(source.contains("endpoint_anchor_directory"));
}

#[test]
fn current_identity_callsites_observe_only_after_durable_orchestration() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut invoked = Vec::new();
    let mut direct = Vec::new();
    for entry in fs::read_dir(&root).expect("source") {
        let path = entry.expect("entry").path();
        if path.extension().is_none_or(|value| value != "rs") {
            continue;
        }
        let source = fs::read_to_string(&path).expect("rust");
        let name = path
            .file_name()
            .expect("name")
            .to_string_lossy()
            .into_owned();
        if source.contains(".invoke_current_identity(") {
            invoked.push(name.clone());
            assert!(source.contains("current_invoking"));
            assert!(source.contains("current_unknown"));
            assert!(
                source.contains("verify_and_observe")
                    || source.contains("target_approve_current::observe")
            );
        }
        if source.contains(".current_identity(") {
            direct.push(name);
            assert!(source.contains("verify_and_observe"));
        }
    }
    invoked.sort();
    direct.sort();
    assert_eq!(
        invoked,
        [
            "actor_options_identity_flow.rs",
            "cancel_identity_flow.rs",
            "independent_approve_identity_flow.rs",
            "independent_approve_reservation_identity_flow.rs",
            "reconcile.rs",
            "source_approve_identity_flow.rs",
            "source_approve_reservation_identity_flow.rs",
            "target_approve_identity_flow.rs",
        ]
    );
    assert_eq!(direct, ["core.rs", "source_options_prepare.rs"]);
    let client = fs::read_to_string(root.join("identity_client_current_response.rs"))
        .expect("identity current client");
    assert!(!client.contains("observe_current_evidence"));
}

#[test]
fn awaiting_final_cancel_reserves_and_retires_around_external_delivery() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let identity = fs::read_to_string(root.join("cancel_state_identity.rs")).expect("identity");
    let reserve = identity
        .find("cancel_state_capacity::reserve(record)")
        .expect("future capacity reserve");
    let admit = identity
        .find("cancel_state_capacity::admit(&prepared, &fresh, &journal, now)")
        .expect("aggregate capacity admission");
    let persist = admit
        + identity[admit..]
            .find("values.put(\"operation-journal\", &journal)")
            .expect("durable admission");
    assert!(reserve < admit && admit < persist);

    let flow = fs::read_to_string(root.join("cancel_cleanup_complete_flow.rs")).expect("flow");
    let prepared = flow
        .find("cleanup_complete_invoking")
        .expect("prepared delivery");
    let invoke = flow
        .find("revocation-execution-cancel-cleanup-complete")
        .expect("delivery route");
    assert!(prepared < invoke && flow[invoke..].contains("cleanup_complete_unknown"));

    let cleanup = fs::read_to_string(root.join("cancel_state_cleanup.rs")).expect("cleanup");
    let old = cleanup
        .find("operation(id,")
        .expect("old artifact retirement");
    let receipt = cleanup
        .find("retired_request_retire_cancel::retire")
        .expect("cancel receipt retirement");
    let active = cleanup
        .find(".cancellations\n        .remove")
        .expect("active removal");
    let index = cleanup
        .find("cancellation_index.remove")
        .expect("index removal");
    assert!(old < receipt && receipt < active && active < index);
}
