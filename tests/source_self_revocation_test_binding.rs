fn assert_finalize_binding(
    fixture: &Fixture,
    prepared: &EndpointPreparedOperationV2,
    approval: &ManagementRequestV2,
    request: &EndpointRevocationFinalizeRequestV1,
    final_call: &ihat_identity_assertion_contracts::AuthorityRequestV1,
) {
    assert_eq!(request.expected_state_revision, 3);
    assert_eq!(request.pre_final_state_revision, 2);
    assert_eq!(request.reconcile_digest, "44".repeat(32));
    assert_eq!(request.source_approve_request, *approval);
    assert_eq!(request.operation_id, prepared.operation_id);
    assert_eq!(request.prepared, *prepared);
    assert_eq!(request.final_revoke_exchange.request, *final_call);
    let current = fixture.current_requests();
    let accepted = crate::management_support_identity_current_approval::exchange(
        current.first().expect("accepted current identity request"),
    )
    .expect("accepted identity");
    assert_eq!(request.accepted_identity_exchange, accepted);
    let reserve_wire = fixture.reservation_requests();
    let reserve = decode_endpoint_revocation_execution_reserve_request_strict(
        reserve_wire.first().expect("reserve request"),
    )
    .expect("strict reserve request");
    assert_eq!(reserve.accepted_identity_exchange, accepted);
    assert_eq!(reserve.original_request, *approval);
    assert_eq!(reserve.prepared, *prepared);
    assert_eq!(
        reserve.pre_final_acceptance_request_sha256,
        request.pre_final_request_sha256
    );
    assert_eq!(
        reserve.reservation_identity_exchange,
        crate::management_support_identity_current_approval::exchange(
            current
                .last()
                .expect("reservation current identity request")
        )
        .expect("reservation identity")
    );
}
