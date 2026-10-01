use crowsi_credential_authority_contracts::{ManagementProjectionBodyV2, ManagementRequestV2};
use crowsi_device_credential_agent::{AgentError, test_support::AgentCore};

use crate::{
    approval_options_support as support,
    management_support::{Fixture, NOW},
    management_support_identity::FakeIdentity,
    management_support_transport::FakeTransport,
};

#[test]
fn approval_options_retries_exact_lookup_and_central_requests() {
    let fixture = Fixture::new();
    let core = fixture.core();
    let prepared = support::prepared();
    let request = support::request("approval-options-retry", &prepared.operation_id);
    let wire = serde_json::to_vec(&request).expect("request");
    assert_eq!(
        core.handle(&wire, NOW),
        Err(AgentError::AuthorityResponseInvalid)
    );
    assert_eq!(
        core.handle(&wire, NOW),
        Err(AgentError::AuthorityResponseInvalid)
    );
    let requests = fixture.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0], requests[1]);
    let lookup_request = support::lookup_request(&requests);
    let lookup =
        fixture.respond_lookup(support::lookup_response(&lookup_request, prepared), |_| {});
    support::assert_lookup(&lookup_request, &lookup);
    assert_eq!(
        core.handle(&wire, NOW),
        Err(AgentError::AuthorityResponseInvalid)
    );
    assert_eq!(
        core.handle(&wire, NOW),
        Err(AgentError::AuthorityResponseInvalid)
    );
    let requests = fixture.requests();
    assert_eq!(requests.len(), 5);
    assert_eq!(requests[3], requests[4]);
    let central = requests[3].clone();
    fixture.respond(&request, 4, |value| {
        value.body = ManagementProjectionBodyV2::Operation {
            operation: support::actor_operation(&central),
        };
    });
    let first = core.handle(&wire, NOW).expect("unknown retry");
    let second = core.handle(&wire, NOW).expect("completed retry");
    assert_eq!(first, second);
    assert_eq!(fixture.current_requests().len(), 1);
    assert_eq!(fixture.begin_requests().len(), 1);
    let requests = fixture.requests();
    assert_eq!(requests.len(), 6);
    assert_eq!(requests[3], requests[5]);
}

fn reach_central(
    fixture: &Fixture,
    request: &ManagementRequestV2,
) -> (AgentCore<FakeTransport, FakeIdentity>, Vec<u8>) {
    let core = fixture.core();
    let wire = serde_json::to_vec(request).expect("request");
    assert!(core.handle(&wire, NOW).is_err());
    let lookup_request = support::lookup_request(&fixture.requests());
    let lookup = fixture.respond_lookup(
        support::lookup_response(&lookup_request, support::prepared()),
        |_| {},
    );
    support::assert_lookup(&lookup_request, &lookup);
    assert!(core.handle(&wire, NOW).is_err());
    let central = fixture.requests().last().expect("central envelope").clone();
    (core, central)
}

include!("approval_options_rejection_tests.rs");
