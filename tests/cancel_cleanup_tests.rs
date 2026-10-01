use crowsi_credential_authority_contracts::{ManagementProjectionBodyV2, ManagementRequestV2};
use crowsi_device_credential_agent::AgentError;

use crate::{
    cancel_support as cancel,
    management_support::{Fixture, NOW},
    management_support_request, source_approve_support as approve,
    source_options_support as source,
};

#[test]
fn completed_cancel_removes_source_approval_but_retains_cancel_receipt() {
    let fixture = Fixture::new();
    let core = fixture.core();
    let snapshot = management_support_request::request("cancel-cleanup-snapshot");
    fixture.respond(&snapshot, 1, |value| {
        value.body = ManagementProjectionBodyV2::Snapshot {
            snapshot: source::snapshot(),
        };
    });
    core.handle(&serde_json::to_vec(&snapshot).expect("snapshot"), NOW)
        .expect("cache snapshot");
    let options = source::request("cancel-cleanup-options");
    let options_wire = serde_json::to_vec(&options).expect("source options");
    assert!(core.handle(&options_wire, NOW).is_err());
    let central = fixture.requests();
    let (prepared, begin) =
        source::source_evidence(central.last().expect("source options envelope"));
    let operation = source::operation(&prepared, &begin);
    fixture.respond(&options, 2, |value| {
        value.body = ManagementProjectionBodyV2::Operation {
            operation: operation.clone(),
        };
    });
    core.handle(&options_wire, NOW)
        .expect("source options complete");
    let approval = approve::request("cancel-cleanup-approval", &prepared, &begin);
    let approval_wire = serde_json::to_vec(&approval).expect("approval");
    fixture.fail_finish_once();
    assert_eq!(
        core.handle(&approval_wire, NOW),
        Err(AgentError::AuthorityUnavailable)
    );
    assert_eq!(fixture.finish_requests().len(), 1);
    let request = cancel::request("cancel-cleanup", &operation);
    let wire = serde_json::to_vec(&request).expect("cancel");
    assert!(core.handle(&wire, NOW).is_err());
    let lookup_request = cancel::lookup_request(&fixture.requests());
    fixture.respond_lookup(
        cancel::lookup(&lookup_request, operation.clone(), prepared),
        |_| {},
    );
    assert!(core.handle(&wire, NOW).is_err());
    fixture.respond(&request, 4, |value| {
        value.body = ManagementProjectionBodyV2::Operation {
            operation: cancel::cancelled(&operation),
        };
    });
    let receipt = core.handle(&wire, NOW).expect("cancel complete");
    assert_eq!(core.handle(&wire, NOW).expect("cancel retry"), receipt);
    assert_eq!(
        core.handle(&approval_wire, NOW),
        Err(AgentError::OperationReplay)
    );
    assert_eq!(fixture.finish_requests().len(), 1);
    assert_no_source_approve(&fixture.requests(), &approval);
}

fn assert_no_source_approve(wires: &[Vec<u8>], approval: &ManagementRequestV2) {
    let calls = wires
        .iter()
        .filter_map(|wire| {
            crowsi_credential_authority_contracts::decode_endpoint_management_envelope_strict(wire)
                .ok()
        })
        .filter(|value| value.browser_request == *approval)
        .count();
    assert_eq!(calls, 0);
}
