#![recursion_limit = "256"]

mod actor_options_support;
mod actor_options_tests;
mod approval_options_support;
mod approval_options_tests;
mod cancel_abandon_tests;
mod cancel_capacity_tests;
mod cancel_cleanup_tests;
mod cancel_execution_cleanup_tests;
mod cancel_support;
mod cancel_tests;
mod cancel_ttl_tests;
mod management_support;
mod management_support_cancellation;
mod management_support_cancellation_cleanup;
mod management_support_cancellation_cleanup_complete;
mod management_support_config;
mod management_support_identity;
mod management_support_identity_cancellation;
mod management_support_identity_current;
mod management_support_identity_current_approval;
mod management_support_identity_finish;
mod management_support_identity_fresh;
mod management_support_identity_revocation;
mod management_support_projection;
mod management_support_request;
mod management_support_reservation;
mod management_support_route;
mod management_support_state;
mod management_support_transport;
mod management_v2_security_tests;
mod reconcile_capacity_tests;
mod reconcile_poll_tests;
mod reconcile_support;
mod reconcile_tests;
mod source_approve_retry_tests;
mod source_approve_revocation_integration_tests;
mod source_approve_support;
mod source_approve_tests;
mod source_options_support;
mod source_options_tests;
mod source_revocation_support;
mod source_self_revocation_support;
mod source_self_revocation_tests;

use crowsi_device_credential_agent::AgentError;
use management_support::{Fixture, NOW};
use management_support_request::request;

#[test]
fn exact_signed_projection_is_returned_and_same_response_is_idempotent() {
    let fixture = Fixture::new();
    let request = request("request-a");
    fixture.respond(&request, 1, |_| {});
    let core = fixture.core();
    let wire = serde_json::to_vec(&request).expect("request");
    assert_eq!(
        core.handle(&wire, NOW).expect("first"),
        core.handle(&wire, NOW).expect("retry")
    );
    management_support_transport::assert_passive_requests(fixture.requests(), &request);
}

#[test]
fn fresh_request_at_same_snapshot_revision_is_not_a_rollback() {
    let fixture = Fixture::new();
    let first = request("request-first");
    fixture.respond(&first, 1, |_| {});
    let core = fixture.core();
    core.handle(&serde_json::to_vec(&first).expect("wire"), NOW)
        .expect("first request");
    let second = request("request-second");
    fixture.respond(&second, 1, |_| {});
    core.handle(&serde_json::to_vec(&second).expect("wire"), NOW)
        .expect("fresh request at unchanged authority revision");
}

#[test]
fn request_actor_session_epoch_signature_and_time_substitution_fail_closed() {
    for case in 0..12 {
        let fixture = Fixture::new();
        let request = request("request-a");
        fixture.respond(&request, 1, |value| match case {
            0 => value.request_id = "request-b".into(),
            1 => value.command_digest_sha256 = "bb".repeat(32),
            2 => value.opaque_account_ref = "psa_owner_0000000000000002".into(),
            3 => value.current_session_ref = format!("sref_{}", "b".repeat(64)),
            4 => value.subject_revocation_epoch = 2,
            5 => value.device_revocation_epoch = 2,
            6 => value.session_revocation_epoch = 2,
            7 => value.device_posture_state = "revoked".into(),
            8 => value.device_posture_revision = 2,
            9 => value.device_proof_key_ref = "device-proof:substituted".into(),
            10 => value.expires_at_epoch_s = NOW,
            _ => value.key_id = "wrong-key".into(),
        });
        let result = fixture
            .core()
            .handle(&serde_json::to_vec(&request).expect("wire"), NOW);
        assert_eq!(
            result,
            Err(AgentError::AuthorityResponseInvalid),
            "case {case}"
        );
    }
}

#[test]
fn signed_revision_rollback_is_rejected_by_durable_endpoint_state() {
    let fixture = Fixture::new();
    let first = request("request-first");
    fixture.respond(&first, 2, |_| {});
    let core = fixture.core();
    core.handle(&serde_json::to_vec(&first).expect("wire"), NOW)
        .expect("revision two");
    let older = request("request-older");
    fixture.respond(&older, 1, |_| {});
    assert_eq!(
        core.handle(&serde_json::to_vec(&older).expect("wire"), NOW),
        Err(AgentError::AuthorityRollback)
    );
}
