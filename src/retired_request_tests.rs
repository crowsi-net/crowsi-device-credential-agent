use crate::source_options_state_types::OperationJournalV1;
use crowsi_credential_authority_contracts::{
    MANAGEMENT_PROJECTION_SCHEMA, MANAGEMENT_REQUEST_SCHEMA, ManagementCommandV2,
    ManagementIntentV2, ManagementProjectionBodyV2, ManagementProjectionV2, ManagementRequestV2,
};
#[test]
fn thousands_of_terminal_ids_never_create_false_positive_replay_state() {
    let mut journal = OperationJournalV1::empty();
    for index in 0..5_000 {
        let request = browser(&format!("history-{index}"), index);
        retire(&mut journal, &request, index as u64 + 1, false);
        assert!(!crate::source_options_state_indexes::request_exists(
            &journal,
            &format!("fresh-{index}")
        ));
    }
    assert_eq!(journal.retired_request_receipts.len(), 32);
    assert!(!crate::source_options_state_indexes::request_exists(
        &journal,
        "history-0"
    ));
    assert!(crate::source_options_state_indexes::request_exists(
        &journal,
        "history-4999"
    ));
}
#[test]
fn material_eviction_keeps_same_id_mutation_closed_while_metadata_remains() {
    let mut journal = OperationJournalV1::empty();
    let request = browser("material-request", 1);
    retire(&mut journal, &request, 10, true);
    let receipt = journal
        .retired_request_receipts
        .get("material-request")
        .expect("metadata retained");
    assert!(receipt.refresh_material.is_none());
    assert!(receipt.response_json.is_none());
    assert!(receipt.response.is_none());
    let mutation = browser("material-request", 2);
    assert_ne!(request, mutation);
    assert!(crate::source_options_state_indexes::request_exists(
        &journal,
        &mutation.request_id
    ));
}

#[test]
fn metadata_expiry_and_capacity_eviction_release_same_id_for_a_new_command() {
    let mut expired = OperationJournalV1::empty();
    retire(&mut expired, &browser("reusable", 1), 10, false);
    assert!(crate::retired_request::prune(&mut expired, 610));
    assert!(!crate::source_options_state_indexes::request_exists(
        &expired, "reusable"
    ));
    let replacement = browser("reusable", 2);
    retire(&mut expired, &replacement, 611, false);
    assert_eq!(
        expired
            .retired_request_receipts
            .get("reusable")
            .expect("replacement receipt")
            .browser_request_digest_sha256,
        crowsi_credential_authority_contracts::management_command_digest(&replacement)
            .expect("replacement digest")
    );

    let mut evicted = OperationJournalV1::empty();
    retire(&mut evicted, &browser("reusable", 1), 10, false);
    for index in 0..32 {
        retire(
            &mut evicted,
            &browser(&format!("capacity-{index}"), index),
            index as u64 + 11,
            false,
        );
    }
    assert!(!crate::source_options_state_indexes::request_exists(
        &evicted, "reusable"
    ));
    let replacement = browser("reusable", 2);
    retire(&mut evicted, &replacement, 50, false);
    assert!(evicted.retired_request_receipts.contains_key("reusable"));
}

fn retire(
    journal: &mut OperationJournalV1,
    request: &ManagementRequestV2,
    now: u64,
    material: bool,
) {
    let envelope = material.then(|| "e".repeat(20_000));
    let response_json = material.then(|| "r".repeat(20_000));
    let response = material.then(|| projection(request));
    crate::retired_request_retire::artifact(
        journal,
        request,
        &"a".repeat(64),
        envelope,
        response_json,
        response,
        now,
    )
    .expect("retire");
}

fn browser(request: &str, nonce: usize) -> ManagementRequestV2 {
    ManagementRequestV2 {
        schema: MANAGEMENT_REQUEST_SCHEMA.into(),
        request_id: request.into(),
        command: ManagementCommandV2::SourceOptions {
            intent: ManagementIntentV2::DeviceTransfer {
                service_id: "service-a".into(),
                target_device_ref: "device-b".into(),
                credential_refs: vec!["credential-a".into()],
                expected_snapshot_revision: 1,
                nonce: format!("nonce-{nonce}"),
            },
        },
    }
}

fn projection(request: &ManagementRequestV2) -> ManagementProjectionV2 {
    ManagementProjectionV2 {
        schema: MANAGEMENT_PROJECTION_SCHEMA.into(),
        projection_id: "projection".into(),
        request_id: request.request_id.clone(),
        command_digest_sha256: "b".repeat(64),
        issuer: "issuer".into(),
        audience: "audience".into(),
        service_id: "service-a".into(),
        pairwise_subject: "subject".into(),
        opaque_account_ref: "owner".into(),
        current_device_ref: "device-a".into(),
        current_session_ref: "session".into(),
        subject_revocation_epoch: 1,
        service_revocation_epoch: 1,
        device_revocation_epoch: 1,
        session_revocation_epoch: 1,
        device_posture_state: "compliant".into(),
        device_posture_revision: 1,
        device_proof_key_ref: "proof".into(),
        snapshot_revision: 1,
        issued_at_epoch_s: 1,
        expires_at_epoch_s: 2,
        body: ManagementProjectionBodyV2::Pending { operations: vec![] },
        key_id: "key".into(),
        signature: "signature".into(),
    }
}
