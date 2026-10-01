fn preaccept_gate(kind: support::Kind) {
    let (fixture, context) = setup(kind);
    fixture.respond(context.approval.as_ref(), 3, |value| {
        let mut operation = context.preaccepted.as_ref().clone();
        operation.state_revision = 3;
        value.body = ManagementProjectionBodyV2::Operation { operation };
    });
    assert!(context.core.handle(&context.approval_wire, NOW).is_err());
    assert!(fixture.revocation_final_requests().is_empty());
    assert!(fixture.finalize_requests().is_empty());
    assert!(fixture.reservation_requests().is_empty());

    let mut changed = context.approval.as_ref().clone();
    let ManagementCommandV2::SourceApprove { assertion, .. } = &mut changed.command else {
        unreachable!()
    };
    assertion.signature_der_base64url = "c3Vic3RpdHV0ZWQ".into();
    assert_eq!(
        context
            .core
            .handle(&serde_json::to_vec(&changed).expect("changed wire"), NOW),
        Err(AgentError::OperationReplay)
    );
    assert!(fixture.revocation_final_requests().is_empty());
    assert!(fixture.finalize_requests().is_empty());
    drop(context);
    drop(fixture);

    let (unavailable, context) = setup(kind);
    respond_preaccepted(&unavailable, &context);
    unavailable.fail_source_approve_once();
    assert_eq!(
        context.core.handle(&context.approval_wire, NOW),
        Err(AgentError::AuthorityUnavailable)
    );
    assert!(unavailable.revocation_final_requests().is_empty());
    assert!(unavailable.finalize_requests().is_empty());
    assert!(unavailable.reservation_requests().is_empty());
}

fn durable_preaccept_before_final(kind: support::Kind) {
    let (fixture, context) = setup(kind);
    respond_preaccepted(&fixture, &context);
    fixture.fail_revocation_final_once();
    assert!(context.core.handle(&context.approval_wire, NOW).is_err());
    assert_eq!(fixture.source_approve_requests().len(), 1);
    assert_eq!(fixture.reservation_requests().len(), 1);
    assert_eq!(fixture.revocation_final_requests().len(), 1);
    assert!(fixture.finalize_requests().is_empty());

    fixture.fail_finalize_once();
    let Context {
        core,
        approval_wire,
        ..
    } = context;
    drop(core);
    assert_eq!(
        fixture.core().handle(&approval_wire, NOW),
        Err(AgentError::AuthorityUnavailable)
    );
    assert_eq!(fixture.source_approve_requests().len(), 1);
    assert_eq!(fixture.reservation_requests().len(), 1);
    let calls = fixture.revocation_final_requests();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0], calls[1]);
    assert_eq!(fixture.finalize_requests().len(), 1);
}
