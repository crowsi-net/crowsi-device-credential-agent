use ihat_identity_assertion_contracts::{AuthorityCommand, AuthorityResult, ResponseOutcome};

use crate::{
    source_approve_revocation_final_request as final_request,
    source_approve_revocation_invoke as invoke, source_approve_revocation_request as request,
};

use super::{
    source_approve_revocation_test_transport::FixtureTransport,
    source_approve_revocation_test_values::{FixtureSigner, NOW, device, fresh, session},
};

#[test]
fn self_device_retry_sends_identical_begin_and_invokes_exact_final() {
    let prepared = device("device-a");
    let fresh = fresh(&prepared);
    let request = request::begin(&FixtureSigner, &prepared, &fresh, NOW).expect("begin request");
    let transport = FixtureTransport::new(false);
    let trust = transport.trust();
    let begun = invoke::begin_with_trust(&transport, &trust, &prepared, &fresh, &request, NOW)
        .expect("begin");
    let retry = invoke::begin_with_trust(&transport, &trust, &prepared, &fresh, &request, NOW)
        .expect("retry");
    assert_eq!(begun, retry);
    let expected = serde_json::to_vec(&request).expect("request wire");
    let sent = transport.requests();
    assert_eq!(sent, vec![expected.clone(), expected]);

    let final_request = final_request::build(&prepared, &begun)
        .expect("final prebuild")
        .expect("self final");
    let final_exchange = invoke::finalize_with_trust(
        &transport,
        &trust,
        &prepared,
        &begun,
        &final_request,
        false,
        NOW,
    )
    .expect("final invoke");
    assert!(matches!(
        (
            &final_exchange.request.command,
            &final_exchange.response.outcome
        ),
        (
            AuthorityCommand::RevokeDeviceByRef(_),
            ResponseOutcome::Committed {
                result: AuthorityResult::DeviceRevocation(_)
            }
        )
    ));
    assert_eq!(
        transport.requests()[2],
        serde_json::to_vec(&final_request).expect("final wire")
    );
}

#[test]
fn cross_device_session_source_stops_after_begin() {
    let prepared = session("device-b");
    let fresh = fresh(&prepared);
    let request = request::begin(&FixtureSigner, &prepared, &fresh, NOW).expect("begin request");
    let transport = FixtureTransport::new(true);
    let begun = invoke::begin_with_trust(
        &transport,
        &transport.trust(),
        &prepared,
        &fresh,
        &request,
        NOW,
    )
    .expect("begin");
    assert_eq!(
        final_request::build(&prepared, &begun).expect("optional final"),
        None
    );
    assert_eq!(transport.requests().len(), 1);
}

#[test]
fn self_device_session_invokes_session_final() {
    let prepared = session("device-a");
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
        .expect("final prebuild")
        .expect("self final");
    let final_exchange = invoke::finalize_with_trust(
        &transport,
        &transport.trust(),
        &prepared,
        &begun,
        &final_request,
        false,
        NOW,
    )
    .expect("final");
    assert!(matches!(
        (
            &final_exchange.request.command,
            &final_exchange.response.outcome
        ),
        (
            AuthorityCommand::RevokeSessionByRef(_),
            ResponseOutcome::Committed {
                result: AuthorityResult::Revocation(_)
            }
        )
    ));
}
