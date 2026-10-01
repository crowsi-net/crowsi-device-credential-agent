use crowsi_credential_authority_contracts::{ManagementProjectionBodyV2, ManagementRequestV2};
use crowsi_device_credential_agent::AgentError;

use crate::{
    management_support::{Fixture, NOW},
    management_support_request, source_options_support as support,
};

#[test]
fn source_options_crash_retry_reuses_exact_begin_and_central_envelope() {
    let fixture = Fixture::new();
    let core = fixture.core();
    let snapshot_request = management_support_request::request("source-options-snapshot");
    fixture.respond(&snapshot_request, 1, |value| {
        value.body = ManagementProjectionBodyV2::Snapshot {
            snapshot: support::snapshot(),
        };
    });
    core.handle(
        &serde_json::to_vec(&snapshot_request).expect("snapshot request"),
        NOW,
    )
    .expect("cache snapshot");

    let request = support::request("source-options-request");
    let wire = serde_json::to_vec(&request).expect("source request");
    assert_eq!(
        core.handle(&wire, NOW),
        Err(AgentError::AuthorityResponseInvalid)
    );
    let requests = fixture.requests();
    let source_wire = requests.last().expect("central source request").clone();
    let (prepared, begin) = support::source_evidence(&source_wire);
    fixture.respond(&request, 2, |value| {
        let mut operation = support::operation(&prepared, &begin);
        let crowsi_credential_authority_contracts::ManagementOperationScopeV2::DeviceTransfer {
            target_device_ref,
            ..
        } = &mut operation.scope
        else {
            unreachable!()
        };
        *target_device_ref = "device-c".into();
        value.body = ManagementProjectionBodyV2::Operation { operation };
    });
    assert_eq!(
        core.handle(&wire, NOW),
        Err(AgentError::AuthorityResponseInvalid)
    );
    fixture.respond(&request, 2, |value| {
        value.body = ManagementProjectionBodyV2::Operation {
            operation: support::operation(&prepared, &begin),
        };
    });

    let first = core.handle(&wire, NOW).expect("unknown retry");
    let second = core.handle(&wire, NOW).expect("completed retry");
    assert_eq!(first, second);
    assert_eq!(fixture.begin_requests().len(), 1);
    let central = fixture.requests();
    assert_eq!(central.len(), 4);
    assert_eq!(central[1], central[2]);
    assert_eq!(central[2], central[3]);
    assert_eq!(
        core.handle(&wire, NOW + 20),
        Err(AgentError::FreshUserVerificationRequired)
    );
    assert_eq!(fixture.requests().len(), 4);
}

#[test]
fn same_browser_request_id_with_changed_command_never_remints_evidence() {
    let fixture = Fixture::new();
    let core = fixture.core();
    let snapshot_request = management_support_request::request("mutation-snapshot");
    fixture.respond(&snapshot_request, 1, |value| {
        value.body = ManagementProjectionBodyV2::Snapshot {
            snapshot: support::snapshot(),
        };
    });
    core.handle(
        &serde_json::to_vec(&snapshot_request).expect("snapshot request"),
        NOW,
    )
    .expect("cache snapshot");
    let request = support::request("mutated-source-options");
    let _ = core.handle(&serde_json::to_vec(&request).expect("wire"), NOW);
    let mut changed: ManagementRequestV2 = request;
    let crowsi_credential_authority_contracts::ManagementCommandV2::SourceOptions { intent } =
        &mut changed.command
    else {
        unreachable!()
    };
    let crowsi_credential_authority_contracts::ManagementIntentV2::DeviceTransfer { nonce, .. } =
        intent
    else {
        unreachable!()
    };
    *nonce = "substituted-nonce".into();
    assert_eq!(
        core.handle(&serde_json::to_vec(&changed).expect("changed"), NOW),
        Err(AgentError::OperationReplay)
    );
    assert_eq!(fixture.begin_requests().len(), 1);
}
