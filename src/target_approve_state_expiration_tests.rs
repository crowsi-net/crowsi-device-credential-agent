#[test]
fn historic_receipt_wrappers_do_not_end_the_selected_actor_window() {
    let begin_issued_at = 100;
    let selected_identity_wrapper_expires_at = 129;
    let lookup_wrapper_expires_at = 130;
    let begin_wrapper_expires_at = 130;
    let retry_at = begin_issued_at + 31;
    let expires = crate::target_approve_state::historic_base(400, 400, 220);

    assert!(retry_at >= selected_identity_wrapper_expires_at);
    assert!(retry_at >= lookup_wrapper_expires_at);
    assert!(retry_at >= begin_wrapper_expires_at);
    assert!(retry_at < expires);
    assert_eq!(expires, 220);
}

#[test]
fn signed_actor_options_and_operation_expiry_still_bound_approval() {
    assert_eq!(
        crate::target_approve_state::historic_base(190, 180, 220),
        180
    );
    assert_eq!(
        crate::target_approve_state::historic_base(170, 180, 220),
        170
    );
}

#[test]
fn only_central_ambiguity_and_completed_receipts_resume_after_expiry() {
    use crate::target_approve_state_types::TargetApprovePhaseV1 as P;
    for phase in [P::CentralInvoking, P::Unknown, P::Complete] {
        assert!(crate::target_approve_state::phase_can_resume_expired(phase));
    }
    for phase in [
        P::FinishUnknown,
        P::CurrentUnknown,
        P::PaUnknown,
        P::CustodyUnknown,
    ] {
        assert!(!crate::target_approve_state::phase_can_resume_expired(
            phase
        ));
    }
}
