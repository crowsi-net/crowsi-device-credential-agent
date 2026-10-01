use crowsi_credential_authority_contracts::*;

use crate::{
    cancel_support as support,
    management_support::{Fixture, NOW},
};

#[test]
fn unknown_retries_exact_central_envelope_after_identity_ttl() {
    let (fixture, request, wire, operation) = unknown("cancel-long-unknown");
    let before = cancel_wires(&fixture);
    fixture.respond(&request, 9, |value| {
        value.issued_at_epoch_s = NOW + 31;
        value.expires_at_epoch_s = NOW + 61;
        value.body = ManagementProjectionBodyV2::Operation {
            operation: support::cancelled(&operation),
        };
    });
    let response = fixture
        .core()
        .handle(&wire, NOW + 31)
        .expect("fresh historic exact receipt");
    let projection = decode_management_projection_strict(&response).expect("cancel projection");
    assert_eq!(projection.snapshot_revision, 9);
    let after = cancel_wires(&fixture);
    assert_eq!(after.len(), 2);
    assert_eq!(before[0], after[1]);
    assert_eq!(fixture.current_requests().len(), 1);
}

#[test]
fn complete_receipt_refreshes_exact_historic_cancel_after_projection_ttl() {
    let (fixture, request, wire, operation) = unknown("cancel-complete-ttl");
    fixture.respond(&request, 3, |value| {
        value.body = ManagementProjectionBodyV2::Operation {
            operation: support::cancelled(&operation),
        };
    });
    let core = fixture.core();
    core.handle(&wire, NOW).expect("complete cancel");
    let before = cancel_wires(&fixture);
    fixture.respond(&request, 9, |value| {
        value.issued_at_epoch_s = NOW + 31;
        value.expires_at_epoch_s = NOW + 61;
        value.body = ManagementProjectionBodyV2::Operation {
            operation: support::cancelled(&operation),
        };
    });
    let response = core
        .handle(&wire, NOW + 31)
        .expect("refresh completed cancel");
    let projection = decode_management_projection_strict(&response).expect("projection");
    assert_eq!(projection.snapshot_revision, 9);
    let after = cancel_wires(&fixture);
    assert_eq!(after.len(), before.len() + 1);
    assert_eq!(after.last(), before.last());
    assert_eq!(fixture.current_requests().len(), 1);
}

#[test]
fn awaiting_final_without_local_begin_fails_before_cancel_commit() {
    let fixture = Fixture::new();
    let prepared = support::revocation_prepared(NOW - 1);
    let operation = support::awaiting_final(&prepared);
    let request = support::request("cancel-expired-awaiting-final", &operation);
    let wire = serde_json::to_vec(&request).expect("cancel request");
    assert!(fixture.core().handle(&wire, NOW).is_err());
    let lookup_request = support::lookup_request(&fixture.requests());
    fixture.respond_lookup(
        support::lookup(&lookup_request, operation.clone(), prepared.clone()),
        |_| {},
    );
    assert_eq!(
        fixture.core().handle(&wire, NOW),
        Err(crowsi_device_credential_agent::AgentError::AuthorityRollback)
    );
    assert!(cancel_wires(&fixture).is_empty());
}

fn unknown(id: &str) -> (Fixture, ManagementRequestV2, Vec<u8>, ManagementOperationV2) {
    let fixture = Fixture::new();
    let prepared = support::prepared(NOW + 200);
    let operation = support::operation(&prepared);
    let request = support::request(id, &operation);
    let wire = serde_json::to_vec(&request).expect("cancel request");
    assert!(fixture.core().handle(&wire, NOW).is_err());
    let lookup_request = support::lookup_request(&fixture.requests());
    fixture.respond_lookup(
        support::lookup(&lookup_request, operation.clone(), prepared),
        |_| {},
    );
    assert!(fixture.core().handle(&wire, NOW).is_err());
    (fixture, request, wire, operation)
}

fn cancel_wires(fixture: &Fixture) -> Vec<Vec<u8>> {
    fixture
        .requests()
        .into_iter()
        .filter(|wire| {
            decode_endpoint_management_envelope_strict(wire).is_ok_and(|value| {
                matches!(value.evidence, EndpointManagementEvidenceV2::Cancel { .. })
            })
        })
        .collect()
}
