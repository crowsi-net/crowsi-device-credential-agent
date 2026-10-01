use crowsi_credential_authority_contracts::*;
use crowsi_device_credential_agent::{AgentError, test_support::AgentCore};

use crate::{
    cancel_support as cancel,
    management_support::{Fixture, NOW},
    management_support_identity::FakeIdentity,
    management_support_request,
    management_support_transport::FakeTransport,
    source_approve_support as approve, source_self_revocation_support as source,
};

type Core = AgentCore<FakeTransport, FakeIdentity>;

#[test]
fn cancel_pending_cleanup_recovers_after_expiry_and_rotation_with_exact_requests() {
    let (fixture, core, prepared, preaccepted, _approval, approval_wire) = setup();
    let request = cancel::request("cancel-reserved-pending", &preaccepted);
    let wire = serde_json::to_vec(&request).expect("cancel wire");
    assert!(core.handle(&wire, NOW).is_err());
    let lookup_request = cancel::lookup_request(&fixture.requests());
    let accepted = accepted_digest(&fixture);
    fixture.respond_lookup(
        cancel::lookup_with_digest(
            &lookup_request,
            preaccepted.clone(),
            prepared.clone(),
            accepted.clone(),
        ),
        |_| {},
    );
    assert_eq!(
        core.handle(&wire, NOW),
        Err(AgentError::AuthorityResponseInvalid)
    );
    namespace_fits(&core);
    fixture.respond(&request, 4, |value| {
        value.body = ManagementProjectionBodyV2::Operation {
            operation: cancel::cancelled(&preaccepted),
        };
    });
    fixture.fail_execution_cancel_once();
    assert_eq!(
        core.handle(&wire, NOW),
        Err(AgentError::AuthorityUnavailable)
    );
    namespace_fits(&core);
    assert_eq!(
        execution_request(&fixture).pre_final_acceptance_request_sha256,
        accepted
    );
    drop(core);

    let rotated = fixture.rotated_identity_core(NOW + 301);
    fixture.fail_cancel_pending_once();
    assert_eq!(
        rotated.handle(&wire, NOW + 301),
        Err(AgentError::AuthorityUnavailable)
    );
    namespace_fits(&rotated);
    fixture.fail_cancel_finalize_once();
    assert_eq!(
        rotated.handle(&wire, NOW + 302),
        Err(AgentError::AuthorityUnavailable)
    );
    namespace_fits(&rotated);
    fixture.fail_cleanup_ack_once();
    assert_eq!(
        rotated.handle(&wire, NOW + 303),
        Err(AgentError::AuthorityUnavailable)
    );
    namespace_fits(&rotated);
    fixture.fail_cleanup_complete_once();
    assert_eq!(
        rotated.handle(&wire, NOW + 304),
        Err(AgentError::AuthorityUnavailable)
    );
    namespace_fits(&rotated);
    fixture.respond(&request, 9, |value| {
        value.issued_at_epoch_s = NOW + 305;
        value.expires_at_epoch_s = NOW + 335;
        value.body = ManagementProjectionBodyV2::Operation {
            operation: cancel::cancelled(&preaccepted),
        };
    });
    let response = rotated
        .handle(&wire, NOW + 305)
        .expect("cleanup acknowledged before terminal cancel receipt");
    decode_management_projection_strict(&response).expect("cancel projection");
    namespace_fits(&rotated);
    assert_eq!(
        rotated
            .cancel_retirement_state(&request.request_id, &preaccepted.operation_id)
            .expect("cancel retirement"),
        (false, false, true)
    );
    assert_exact_retries(&fixture);
    assert_eq!(
        rotated.handle(&approval_wire, NOW + 305),
        Err(AgentError::OperationReplay)
    );
}

fn namespace_fits(core: &Core) {
    assert!(core.operation_journal_bytes().expect("journal bytes") <= 131_072);
}

fn execution_request(fixture: &Fixture) -> EndpointRevocationExecutionCancelRequestV1 {
    decode_endpoint_revocation_execution_cancel_request_strict(
        fixture
            .execution_cancel_requests()
            .last()
            .expect("D request"),
    )
    .expect("strict D request")
}

fn accepted_digest(fixture: &Fixture) -> String {
    let wire = fixture
        .source_approve_requests()
        .first()
        .expect("pre-final request")
        .clone();
    let envelope = decode_endpoint_management_envelope_strict(&wire).expect("pre-final envelope");
    endpoint_management_phase_envelope_digest(&envelope).expect("pre-final digest")
}

include!("cancel_execution_cleanup_assert.rs");
include!("cancel_execution_cleanup_setup.rs");
