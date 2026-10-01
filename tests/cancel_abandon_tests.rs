use crowsi_credential_authority_contracts::*;
use crowsi_device_credential_agent::AgentError;

use crate::{
    cancel_support as support,
    management_support::{Fixture, NOW},
};

#[test]
fn expired_precentral_cancel_is_tombstoned_and_new_request_can_retry() {
    for phase in [Phase::Current, Phase::Lookup] {
        abandon_and_retry(phase);
    }
}

#[derive(Clone, Copy)]
enum Phase {
    Current,
    Lookup,
}

fn abandon_and_retry(phase: Phase) {
    let fixture = Fixture::new();
    let core = fixture.core();
    let prepared = support::prepared(NOW + 200);
    let operation = support::operation(&prepared);
    let old = support::request(
        match phase {
            Phase::Current => "cancel-abandon-current",
            Phase::Lookup => "cancel-abandon-lookup",
        },
        &operation,
    );
    let old_wire = serde_json::to_vec(&old).expect("old cancel");
    if matches!(phase, Phase::Current) {
        fixture.fail_current_once();
    }
    assert!(core.handle(&old_wire, NOW).is_err());
    let calls = fixture.current_requests().len();
    assert_eq!(
        core.handle(&old_wire, NOW + 14),
        Err(AgentError::OperationReplay)
    );
    assert_eq!(fixture.current_requests().len(), calls);
    let mut mutated = old.clone();
    let ManagementCommandV2::Cancel {
        expected_state_revision,
        ..
    } = &mut mutated.command
    else {
        unreachable!()
    };
    *expected_state_revision += 1;
    assert_eq!(
        core.handle(&serde_json::to_vec(&mutated).expect("mutated"), NOW + 14),
        Err(AgentError::OperationReplay)
    );
    let fresh = support::request("cancel-after-abandon", &operation);
    let fresh_wire = serde_json::to_vec(&fresh).expect("fresh cancel");
    assert!(core.handle(&fresh_wire, NOW + 14).is_err());
    assert_eq!(fixture.current_requests().len(), calls + 1);
    let lookup_request = latest_lookup(&fixture.requests());
    fixture.respond_lookup(
        support::lookup_at(&lookup_request, operation.clone(), prepared, NOW + 14),
        |_| {},
    );
    assert!(core.handle(&fresh_wire, NOW + 14).is_err());
    fixture.respond(&fresh, 3, |value| {
        value.issued_at_epoch_s = NOW + 14;
        value.expires_at_epoch_s = NOW + 44;
        value.body = ManagementProjectionBodyV2::Operation {
            operation: support::cancelled(&operation),
        };
    });
    core.handle(&fresh_wire, NOW + 14)
        .expect("fresh request cancels operation");
    let transport_calls = fixture.requests().len();
    assert_eq!(
        core.handle(&old_wire, NOW + 14),
        Err(AgentError::OperationReplay)
    );
    assert_eq!(fixture.requests().len(), transport_calls);
}

fn latest_lookup(wires: &[Vec<u8>]) -> EndpointPreparedLookupRequestV1 {
    wires
        .iter()
        .rev()
        .find_map(|wire| decode_endpoint_prepared_lookup_request_strict(wire).ok())
        .expect("fresh lookup request")
}
