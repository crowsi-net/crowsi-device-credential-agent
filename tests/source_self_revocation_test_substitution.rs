fn substituted_final_exchange(kind: support::Kind) {
    let (fixture, context) = setup(kind);
    respond_preaccepted(&fixture, &context);
    fixture.substitute_revocation_final_once();
    assert!(context.core.handle(&context.approval_wire, NOW).is_err());
    assert_eq!(fixture.revocation_final_requests().len(), 1);
    assert_eq!(fixture.reservation_requests().len(), 1);
    assert!(fixture.finalize_requests().is_empty());
}

fn substituted_finalize_projection(kind: support::Kind, case: u8) {
    let (fixture, context) = setup(kind);
    respond_preaccepted(&fixture, &context);
    fixture.fail_finalize_once();
    assert_eq!(
        context.core.handle(&context.approval_wire, NOW),
        Err(AgentError::AuthorityUnavailable)
    );
    let request = first_finalize_request(&fixture);
    let projection = support::finalize_projection(
        &request,
        context.preaccepted.as_ref(),
        support::FinalOutcome::Unknown,
        NOW,
    );
    fixture.respond_finalize(projection, |value| substitute(value, case));
    assert!(context.core.handle(&context.approval_wire, NOW).is_err());
    assert_eq!(fixture.revocation_final_requests().len(), 1);
    let attempts = fixture.finalize_requests();
    assert_eq!(attempts.len(), 2);
    assert_eq!(attempts[0], attempts[1]);

    let valid = support::finalize_projection(
        &request,
        context.preaccepted.as_ref(),
        support::FinalOutcome::Unknown,
        NOW,
    );
    fixture.respond_finalize(valid, |_| {});
    context
        .core
        .handle(&context.approval_wire, NOW)
        .expect("exact recovery");
    let recovered = fixture.finalize_requests();
    assert_eq!(recovered.len(), 3);
    assert!(recovered.windows(2).all(|pair| pair[0] == pair[1]));
}

fn substitute(value: &mut ManagementProjectionV2, case: u8) {
    match case {
        0 => value.request_id = "substituted-final-request".into(),
        1 => value.current_device_ref = "device-b".into(),
        2 => {
            let ManagementProjectionBodyV2::Operation { operation } = &mut value.body else {
                unreachable!()
            };
            operation.intent_digest_sha256 = "ab".repeat(32);
        }
        3 => {
            let ManagementProjectionBodyV2::Operation { operation } = &mut value.body else {
                unreachable!()
            };
            operation.state_revision = operation.state_revision.saturating_sub(1);
        }
        4 => value.command_digest_sha256 = "ac".repeat(32),
        _ => value.current_session_ref = format!("sref_{}", "c".repeat(64)),
    }
}
