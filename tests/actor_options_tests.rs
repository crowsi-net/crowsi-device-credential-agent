use crowsi_credential_authority_contracts::{
    ManagementCommandV2, ManagementProjectionBodyV2, ManagementRequestV2,
};
use crowsi_device_credential_agent::AgentError;

use crate::{
    actor_options_support as support,
    management_support::{Fixture, NOW},
};

#[test]
fn target_options_retries_exact_lookup_begin_and_central_requests() {
    let fixture = Fixture::new();
    let core = fixture.core();
    let prepared = support::prepared();
    let request = support::request("target-options-request", &prepared.operation_id);
    let wire = serde_json::to_vec(&request).expect("request");
    assert_eq!(
        core.handle(&wire, NOW),
        Err(AgentError::AuthorityResponseInvalid)
    );
    let lookup_request = support::lookup_request(&fixture.requests());
    let lookup =
        fixture.respond_lookup(support::lookup_response(&lookup_request, prepared), |_| {});
    support::assert_lookup(&lookup_request, &lookup);
    assert_eq!(
        core.handle(&wire, NOW),
        Err(AgentError::AuthorityResponseInvalid)
    );
    let requests = fixture.requests();
    let central = requests.last().expect("central envelope").clone();
    fixture.respond(&request, 3, |value| {
        value.body = ManagementProjectionBodyV2::Operation {
            operation: support::actor_operation(&central),
        };
    });
    let first = core.handle(&wire, NOW).expect("unknown retry");
    let second = core.handle(&wire, NOW).expect("complete retry");
    assert_eq!(first, second);
    assert_eq!(fixture.current_requests().len(), 1);
    assert_eq!(fixture.begin_requests().len(), 1);
    let requests = fixture.requests();
    assert_eq!(requests.len(), 4);
    assert_eq!(requests[0], requests[1]);
    assert_eq!(requests[2], requests[3]);
}

#[test]
fn target_options_rejects_mutation_and_signed_wrong_phase() {
    let fixture = Fixture::new();
    let core = fixture.core();
    let prepared = support::prepared();
    let request = support::request("target-options-substitution", &prepared.operation_id);
    let wire = serde_json::to_vec(&request).expect("request");
    assert!(core.handle(&wire, NOW).is_err());
    let lookup_request = support::lookup_request(&fixture.requests());
    let lookup =
        fixture.respond_lookup(support::lookup_response(&lookup_request, prepared), |_| {});
    support::assert_lookup(&lookup_request, &lookup);
    assert!(core.handle(&wire, NOW).is_err());
    let central = fixture.requests().last().expect("central").clone();
    fixture.respond(&request, 3, |value| {
        let mut operation = support::actor_operation(&central);
        operation.state =
            crowsi_credential_authority_contracts::ManagementOperationState::Executing;
        value.body = ManagementProjectionBodyV2::Operation { operation };
    });
    assert_eq!(
        core.handle(&wire, NOW),
        Err(AgentError::AuthorityResponseInvalid)
    );
    let mut changed: ManagementRequestV2 = request;
    let ManagementCommandV2::TargetOptions {
        expected_state_revision,
        ..
    } = &mut changed.command
    else {
        unreachable!()
    };
    *expected_state_revision = 3;
    assert_eq!(
        core.handle(&serde_json::to_vec(&changed).expect("changed"), NOW),
        Err(AgentError::OperationReplay)
    );
}
