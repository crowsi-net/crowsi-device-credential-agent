fn approve_source(fixture: &Fixture, context: &SourceContext) {
    let prepared = context.prepared.as_ref();
    let begin = context.begin.as_ref();
    let approval = Box::new(approve::request(
        "revocation-source-approve",
        prepared,
        begin,
    ));
    let approval_wire = serde_json::to_vec(approval.as_ref()).expect("source approve wire");
    fixture.fail_revocation_begin_once();
    assert_eq!(
        context.core.handle(&approval_wire, NOW),
        Err(AgentError::AuthorityUnavailable)
    );
    assert_eq!(fixture.revocation_begin_requests().len(), 1);

    fixture.respond(approval.as_ref(), 3, |value| {
        let mut operation = revocation::approved_operation(prepared, begin);
        operation.actor.required_approval_authority_ref = Some("substituted-authority".into());
        value.body = ManagementProjectionBodyV2::Operation { operation };
    });
    assert_eq!(
        context.core.handle(&approval_wire, NOW),
        Err(AgentError::ResponseInvalid)
    );
    let begun = fixture.revocation_begin_requests();
    assert_eq!(begun.len(), 2);
    assert_eq!(begun[0], begun[1]);
    let first_envelope = fixture
        .requests()
        .last()
        .expect("approval envelope")
        .clone();
    reject_browser_mutation(fixture, context, approval.as_ref());

    fixture.respond(approval.as_ref(), 3, |value| {
        value.body = ManagementProjectionBodyV2::Operation {
            operation: revocation::approved_operation(prepared, begin),
        };
    });
    let first = context
        .core
        .handle(&approval_wire, NOW)
        .expect("valid retry");
    let central_count = fixture.requests().len();
    let second = context
        .core
        .handle(&approval_wire, NOW)
        .expect("completed retry");
    assert_eq!(first, second);
    assert_eq!(fixture.requests().len(), central_count);
    assert_eq!(fixture.requests().last().expect("retry"), &first_envelope);
    assert_eq!(fixture.finish_requests().len(), 1);
    assert_eq!(fixture.current_requests().len(), 1);
    assert_ceremony(&first_envelope, &begun[0]);
}

fn reject_browser_mutation(
    fixture: &Fixture,
    context: &SourceContext,
    approval: &ManagementRequestV2,
) {
    let mut changed = Box::new(approval.clone());
    let ManagementCommandV2::SourceApprove { assertion, .. } = &mut changed.command else {
        unreachable!()
    };
    assertion.signature_der_base64url = "c3Vic3RpdHV0ZWQ".into();
    let before = fixture.requests().len();
    assert_eq!(
        context.core.handle(
            &serde_json::to_vec(changed.as_ref()).expect("mutated wire"),
            NOW
        ),
        Err(AgentError::OperationReplay)
    );
    assert_eq!(fixture.requests().len(), before);
}
