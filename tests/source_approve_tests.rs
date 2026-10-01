use crowsi_credential_authority_contracts::{
    ManagementCommandV2, ManagementProjectionBodyV2, ManagementRequestV2,
};
use crowsi_device_credential_agent::AgentError;

use crate::{
    management_support::{Fixture, NOW},
    management_support_request, source_approve_support as approve,
    source_options_support as source,
};

#[test]
fn source_approve_reuses_exact_finish_current_and_central_requests_after_crashes() {
    let fixture = Fixture::new();
    let core = fixture.core();
    let snapshot = management_support_request::request("approval-snapshot");
    fixture.respond(&snapshot, 1, |value| {
        value.body = ManagementProjectionBodyV2::Snapshot {
            snapshot: source::snapshot(),
        };
    });
    core.handle(&serde_json::to_vec(&snapshot).expect("snapshot"), NOW)
        .expect("cache snapshot");

    let source_request = source::request("approval-source-options");
    let source_wire = serde_json::to_vec(&source_request).expect("source options");
    assert_eq!(
        core.handle(&source_wire, NOW),
        Err(AgentError::AuthorityResponseInvalid)
    );
    let central = fixture.requests();
    let (prepared, begin) = source::source_evidence(central.last().expect("source envelope"));
    fixture.respond(&source_request, 2, |value| {
        value.body = ManagementProjectionBodyV2::Operation {
            operation: source::operation(&prepared, &begin),
        };
    });
    core.handle(&source_wire, NOW)
        .expect("complete source options");

    let approval = approve::request("approval-source-approve", &prepared, &begin);
    let approval_wire = serde_json::to_vec(&approval).expect("approval");
    assert!(core.handle(&approval_wire, NOW).is_err());
    let requests = fixture.requests();
    let first_approval_envelope = requests.last().expect("approval envelope").clone();
    let mut changed: ManagementRequestV2 = approval.clone();
    let ManagementCommandV2::SourceApprove { assertion, .. } = &mut changed.command else {
        unreachable!()
    };
    assertion.signature_der_base64url = "c3Vic3RpdHV0ZWQ".into();
    assert_eq!(
        core.handle(&serde_json::to_vec(&changed).expect("changed"), NOW),
        Err(AgentError::OperationReplay)
    );
    fixture.respond(&approval, 3, |value| {
        value.body = ManagementProjectionBodyV2::Operation {
            operation: source::operation(&prepared, &begin),
        };
    });
    assert_eq!(
        core.handle(&approval_wire, NOW),
        Err(AgentError::ResponseInvalid)
    );
    fixture.respond(&approval, 3, |value| {
        value.body = ManagementProjectionBodyV2::Operation {
            operation: approve::operation(&prepared, &begin),
        };
    });
    let first = core.handle(&approval_wire, NOW).expect("unknown retry");
    let second = core.handle(&approval_wire, NOW).expect("completed retry");
    assert_eq!(first, second);
    assert_eq!(fixture.finish_requests().len(), 1);
    assert_eq!(fixture.current_requests().len(), 1);
    let requests = fixture.requests();
    assert_eq!(requests.len(), 6);
    assert_eq!(&requests[3], &first_approval_envelope);
    assert_eq!(&requests[4], &first_approval_envelope);
    assert_eq!(&requests[5], &first_approval_envelope);
    assert_eq!(core.handle(&approval_wire, NOW + 15), Ok(first));
    assert_eq!(fixture.requests().len(), 6);
}
