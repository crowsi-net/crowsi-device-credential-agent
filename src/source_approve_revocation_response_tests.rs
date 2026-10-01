use ihat_identity_assertion_contracts::{AuthorityResult, ResponseOutcome};

use crate::{
    AgentError, source_approve_revocation_final_request as final_request,
    source_approve_revocation_invoke as invoke, source_approve_revocation_request as request,
    source_approve_revocation_response_begin as begin_response,
    source_approve_revocation_response_final as final_response,
};

use super::{
    source_approve_revocation_test_transport::FixtureTransport,
    source_approve_revocation_test_values::{FixtureSigner, NOW, device, fresh},
};

#[test]
fn begin_response_rejects_substituted_target_digest() {
    let prepared = device("device-a");
    let fresh = fresh(&prepared);
    let request = request::begin(&FixtureSigner, &prepared, &fresh, NOW).expect("request");
    let transport = FixtureTransport::new(false);
    let mut begun = invoke::begin_with_trust(
        &transport,
        &transport.trust(),
        &prepared,
        &fresh,
        &request,
        NOW,
    )
    .expect("begin");
    let ResponseOutcome::Committed {
        result: AuthorityResult::RevocationBegun(value),
    } = &mut begun.response.outcome
    else {
        unreachable!()
    };
    value.target_digest = "AA".repeat(32);
    assert_eq!(
        begin_response::validate(&prepared, &fresh, &begun, NOW),
        Err(AgentError::AuthorityResponseInvalid)
    );
}

#[test]
fn final_response_rejects_revoked_count_drift() {
    let prepared = device("device-a");
    let fresh = fresh(&prepared);
    let begin_request = request::begin(&FixtureSigner, &prepared, &fresh, NOW).expect("request");
    let transport = FixtureTransport::new(false);
    let begun = invoke::begin_with_trust(
        &transport,
        &transport.trust(),
        &prepared,
        &fresh,
        &begin_request,
        NOW,
    )
    .expect("begin");
    let request = final_request::build(&prepared, &begun)
        .expect("prebuild")
        .expect("final request");
    let mut final_exchange = invoke::finalize_with_trust(
        &transport,
        &transport.trust(),
        &prepared,
        &begun,
        &request,
        false,
        NOW,
    )
    .expect("final");
    let ResponseOutcome::Committed {
        result: AuthorityResult::DeviceRevocation(value),
    } = &mut final_exchange.response.outcome
    else {
        unreachable!()
    };
    value.revoked_session_count += 1;
    assert_eq!(
        final_response::validate_unreserved_for_test(&prepared, &begun, &final_exchange, NOW),
        Err(AgentError::AuthorityResponseInvalid)
    );
}

#[test]
fn invoke_rejects_signed_response_generation_rollback() {
    let prepared = device("device-a");
    let fresh = fresh(&prepared);
    let request = request::begin(&FixtureSigner, &prepared, &fresh, NOW).expect("request");
    let transport = FixtureTransport::with_generation(false, 6);
    assert_eq!(
        invoke::begin_with_trust(
            &transport,
            &transport.trust(),
            &prepared,
            &fresh,
            &request,
            NOW,
        ),
        Err(AgentError::AuthorityResponseInvalid)
    );
}
