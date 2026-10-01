use crate::{
    AgentError, source_approve_revocation_final_request as final_request,
    source_approve_revocation_invoke as invoke, source_approve_revocation_request as request,
};

#[test]
fn fresh_final_rejects_expired_ceremony_before_transport() {
    let prepared = device("device-a");
    let fresh = fresh(&prepared);
    let begin_request =
        request::begin(&FixtureSigner, &prepared, &fresh, NOW).expect("begin request");
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
    let final_request = final_request::build(&prepared, &begun)
        .expect("prebuild")
        .expect("final request");
    assert_eq!(
        invoke::finalize_with_trust(
            &transport,
            &transport.trust(),
            &prepared,
            &begun,
            &final_request,
            false,
            NOW + 300,
        ),
        Err(AgentError::AuthorityResponseInvalid)
    );
    assert_eq!(transport.requests().len(), 1);
}

use super::{
    source_approve_revocation_test_transport::FixtureTransport,
    source_approve_revocation_test_values::{FixtureSigner, NOW, device, fresh},
};

#[test]
fn unreserved_unknown_final_cannot_recover_after_expiry() {
    let prepared = device("device-a");
    let fresh = fresh(&prepared);
    let begin_request =
        request::begin(&FixtureSigner, &prepared, &fresh, NOW).expect("begin request");
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
    let final_request = final_request::build(&prepared, &begun)
        .expect("prebuild")
        .expect("final request");
    assert_eq!(
        invoke::finalize_with_trust(
            &transport,
            &transport.trust(),
            &prepared,
            &begun,
            &final_request,
            true,
            NOW + 301,
        ),
        Err(AgentError::AuthorityResponseInvalid)
    );
    assert_eq!(transport.requests().len(), 2);
}
