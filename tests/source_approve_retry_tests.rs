use crowsi_credential_authority_contracts::ManagementProjectionBodyV2;
use crowsi_device_credential_agent::AgentError;

use crate::{
    management_support::{Fixture, NOW},
    management_support_request, source_approve_support as approve,
    source_options_support as source,
};

#[test]
fn finish_and_current_transport_failures_retry_only_the_persisted_exact_requests() {
    let fixture = Fixture::new();
    let core = fixture.core();
    let snapshot = management_support_request::request("retry-snapshot");
    fixture.respond(&snapshot, 1, |value| {
        value.body = ManagementProjectionBodyV2::Snapshot {
            snapshot: source::snapshot(),
        };
    });
    core.handle(&serde_json::to_vec(&snapshot).expect("snapshot"), NOW)
        .expect("cache snapshot");
    let source_request = source::request("retry-source-options");
    let source_wire = serde_json::to_vec(&source_request).expect("source options");
    assert!(core.handle(&source_wire, NOW).is_err());
    let requests = fixture.requests();
    let (prepared, begin) = source::source_evidence(requests.last().expect("source envelope"));
    fixture.respond(&source_request, 2, |value| {
        value.body = ManagementProjectionBodyV2::Operation {
            operation: source::operation(&prepared, &begin),
        };
    });
    core.handle(&source_wire, NOW)
        .expect("complete source options");

    let approval = approve::request("retry-source-approve", &prepared, &begin);
    let wire = serde_json::to_vec(&approval).expect("approval");
    fixture.fail_finish_once();
    fixture.fail_current_once();
    assert_eq!(
        core.handle(&wire, NOW),
        Err(AgentError::AuthorityUnavailable)
    );
    assert_eq!(
        core.handle(&wire, NOW),
        Err(AgentError::AuthorityUnavailable)
    );
    assert!(core.handle(&wire, NOW).is_err());
    let finish = fixture.finish_requests();
    let current = fixture.current_requests();
    assert_eq!(finish.len(), 2);
    assert_eq!(finish[0], finish[1]);
    assert_eq!(current.len(), 2);
    assert_eq!(current[0], current[1]);
    assert_eq!(fixture.requests().len(), 4);
}
