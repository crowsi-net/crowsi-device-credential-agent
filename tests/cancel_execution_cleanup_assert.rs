fn assert_exact_retries(fixture: &Fixture) {
    let execution = fixture.execution_cancel_requests();
    assert_eq!(execution.len(), 2);
    assert_eq!(execution[0], execution[1]);
    let finalize = fixture.cancel_finalize_requests();
    assert_eq!(finalize.len(), 3);
    assert!(finalize.windows(2).all(|pair| pair[0] == pair[1]));
    let pending = fixture.cancel_pending_requests();
    assert_eq!(pending.len(), 2);
    assert!(pending.windows(2).all(|pair| pair[0] == pair[1]));
    let acknowledgement = fixture.cleanup_ack_requests();
    assert_eq!(acknowledgement.len(), 3);
    assert!(acknowledgement.windows(2).all(|pair| pair[0] == pair[1]));
    let complete = fixture.cleanup_complete_requests();
    assert_eq!(complete.len(), 2);
    let first =
        decode_endpoint_revocation_execution_cancel_cleanup_complete_request_strict(&complete[0])
            .expect("first cleanup complete");
    let second =
        decode_endpoint_revocation_execution_cancel_cleanup_complete_request_strict(&complete[1])
            .expect("second cleanup complete");
    assert_eq!(first.request_id, second.request_id);
    assert_eq!(
        endpoint_revocation_execution_cancel_cleanup_complete_request_digest(&first),
        endpoint_revocation_execution_cancel_cleanup_complete_request_digest(&second)
    );
    assert_eq!(first.cleanup.cleanup_id, second.cleanup.cleanup_id);
    assert_eq!(first.cleanup.token, second.cleanup.token);
    assert_eq!(
        first.acknowledge_exchange.request,
        second.acknowledge_exchange.request
    );
    assert_eq!(
        first.acknowledge_exchange.response.outcome,
        second.acknowledge_exchange.response.outcome
    );
    assert_ne!(complete[0], complete[1]);
}
