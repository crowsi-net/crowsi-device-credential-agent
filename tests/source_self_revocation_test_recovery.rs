fn recover_after_final(kind: support::Kind, outcome: support::FinalOutcome) {
    let (fixture, context) = setup(kind);
    respond_preaccepted(&fixture, &context);
    fixture.fail_revocation_final_once();
    assert!(context.core.handle(&context.approval_wire, NOW).is_err());
    let final_calls = fixture.revocation_final_requests();
    assert_eq!(final_calls.len(), 1);
    assert!(fixture.finalize_requests().is_empty());
    assert_eq!(fixture.source_approve_requests().len(), 1);
    assert_eq!(fixture.reservation_requests().len(), 1);
    let mut substituted = context.approval.as_ref().clone();
    let ManagementCommandV2::SourceApprove { assertion, .. } = &mut substituted.command else {
        unreachable!()
    };
    assertion.signature_der_base64url = "c3Vic3RpdHV0ZWQ".into();
    assert_eq!(
        context.core.handle(
            &serde_json::to_vec(&substituted).expect("substituted approval"),
            NOW,
        ),
        Err(AgentError::OperationReplay)
    );
    assert!(fixture.finalize_requests().is_empty());
    assert_eq!(fixture.revocation_final_requests().len(), 1);
    let Context {
        core,
        prepared,
        approval,
        approval_wire,
        preaccepted,
        ..
    } = context;
    drop(core);
    let rotated = fixture.rotated_identity_core(NOW + 301);
    fixture.fail_finalize_once();
    assert_eq!(
        rotated.handle(&approval_wire, NOW + 301),
        Err(AgentError::AuthorityUnavailable)
    );
    let final_calls = fixture.revocation_final_requests();
    assert_eq!(final_calls.len(), 2);
    assert_eq!(final_calls[0], final_calls[1]);
    let request = first_finalize_request(&fixture);
    assert_finalize_binding(
        &fixture,
        prepared.as_ref(),
        approval.as_ref(),
        &request,
        &final_calls[1],
    );
    assert_eq!(fixture.finalize_requests().len(), 1);
    let response = support::finalize_projection(&request, preaccepted.as_ref(), outcome, NOW + 301);
    fixture.respond_finalize(response, |_| {});
    let first = rotated
        .handle(&approval_wire, NOW + 301)
        .expect("historic finalize retry");
    let second = rotated
        .handle(&approval_wire, NOW + 301)
        .expect("completed endpoint retry");
    assert_eq!(first, second);
    let projection = decode_management_projection_strict(&first).expect("strict final projection");
    let ManagementProjectionBodyV2::Operation { operation } = projection.body else {
        panic!("final operation")
    };
    assert!(matches!(
        (outcome, operation.state),
        (
            support::FinalOutcome::Unknown,
            ManagementOperationState::Unknown
        ) | (
            support::FinalOutcome::Completed,
            ManagementOperationState::Completed
        )
    ));
    match outcome {
        support::FinalOutcome::Unknown => {
            assert_eq!(operation.state_revision, 4);
            assert_eq!(operation.actor.role, RequiredActorRole::ReconcileOnly);
            assert_eq!(
                operation.reason,
                Some(ManagementReasonCode::ProviderOutcomeUnknown)
            );
            assert!(operation.reconcile_digest.is_some());
        }
        support::FinalOutcome::Completed => {
            assert_eq!(operation.state_revision, 5);
            assert_eq!(operation.actor.role, RequiredActorRole::NoActor);
            assert_eq!(operation.reason, None);
            assert_eq!(operation.reconcile_digest, None);
        }
    }
    assert_eq!(fixture.revocation_final_requests().len(), 2);
    assert_eq!(fixture.source_approve_requests().len(), 1);
    let retried = fixture.finalize_requests();
    assert_eq!(retried.len(), 2);
    assert_eq!(retried[0], retried[1]);
    let fresh = support::finalize_projection(&request, preaccepted.as_ref(), outcome, NOW + 332);
    fixture.respond_finalize(fresh, |_| {});
    let refreshed = rotated
        .handle(&approval_wire, NOW + 332)
        .expect("finalize fresh-sign retry");
    let exact = rotated
        .handle(&approval_wire, NOW + 332)
        .expect("finalize stored retry");
    assert_eq!(refreshed, exact);
    let requests = fixture.finalize_requests();
    assert_eq!(requests.len(), 3);
    assert!(requests.windows(2).all(|pair| pair[0] == pair[1]));
}
