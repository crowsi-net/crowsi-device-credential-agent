use crate::source_approve_state_types::{SourceApprovePhaseV1 as P, SourceApproveRecordV1};

pub(crate) fn historic(value: &SourceApproveRecordV1) -> bool {
    (value.revocation_final_request.is_none() && central_receipt(value.phase))
        || (value.revocation_final_request.is_some()
            && matches!(
                value.phase,
                P::CentralPrepared
                    | P::CentralInvoking
                    | P::Unknown
                    | P::ReservationCurrentPrepared
                    | P::ReservationCurrentInvoking
                    | P::ReservationCurrentUnknown
                    | P::ReservationCurrentObservePrepared
                    | P::ReservationCurrentObserveInvoking
                    | P::ReservationCurrentObserveUnknown
                    | P::ExecutionReservePrepared
                    | P::ExecutionReserveInvoking
                    | P::ExecutionReserveUnknown
                    | P::RevocationFinalPrepared
                    | P::RevocationFinalInvoking
                    | P::RevocationFinalUnknown
                    | P::FinalizePrepared
                    | P::FinalizeInvoking
                    | P::FinalizeUnknown
                    | P::Complete
            ))
}

pub(crate) fn can_resume_expired(value: &SourceApproveRecordV1, now: u64) -> bool {
    if value.revocation_final_request.is_none() && central_receipt(value.phase) {
        return true;
    }
    let exact_replay = exact_replay(value.phase, value.revocation_finalize_request.is_some());
    let pending = matches!(value.phase, P::CentralInvoking | P::Unknown)
        && begin_expiration(value).is_some_and(|expires| now < expires);
    exact_replay || pending
}

fn exact_replay(phase: P, finalized: bool) -> bool {
    matches!(
        phase,
        P::ExecutionReserveInvoking
            | P::ExecutionReserveUnknown
            | P::RevocationFinalPrepared
            | P::RevocationFinalInvoking
            | P::RevocationFinalUnknown
            | P::FinalizePrepared
            | P::FinalizeInvoking
            | P::FinalizeUnknown
    ) || (phase == P::Complete && finalized)
}

const fn central_receipt(value: P) -> bool {
    matches!(value, P::CentralInvoking | P::Unknown | P::Complete)
}

pub(super) fn begin_expiration(value: &SourceApproveRecordV1) -> Option<u64> {
    let exchange = value.revocation_begin_exchange.as_ref()?;
    let ihat_identity_assertion_contracts::ResponseOutcome::Committed {
        result: ihat_identity_assertion_contracts::AuthorityResult::RevocationBegun(metadata),
    } = &exchange.response.outcome
    else {
        return None;
    };
    Some(metadata.expires_at_epoch_s)
}

pub(crate) fn empty(value: &SourceApproveRecordV1) -> bool {
    value.pre_final_response_json.is_none()
        && value.pre_final_response.is_none()
        && value.revocation_finalize_request_id.is_none()
        && crate::source_approve_state_reservation_shape::empty(value)
        && value.revocation_finalize_request_json.is_none()
        && value.revocation_finalize_request.is_none()
}

pub(crate) fn accepted(value: &SourceApproveRecordV1) -> bool {
    value.pre_final_response_json.is_some()
        && value.pre_final_response.is_some()
        && value.revocation_finalize_request_id.is_some()
        && value.revocation_finalize_request_json.is_none()
        && value.revocation_finalize_request.is_none()
}

pub(crate) fn prepared(value: &SourceApproveRecordV1) -> bool {
    value.pre_final_response_json.is_some()
        && value.pre_final_response.is_some()
        && value.revocation_finalize_request_id.is_some()
        && value.revocation_finalize_request_json.is_some()
        && value.revocation_finalize_request.is_some()
}

#[cfg(test)]
mod tests {
    use crate::source_approve_state_types::SourceApprovePhaseV1 as P;

    #[test]
    fn only_ambiguous_or_completed_non_final_mutations_resume_historically() {
        for phase in [P::CentralInvoking, P::Unknown, P::Complete] {
            assert!(super::central_receipt(phase));
        }
        for phase in [P::CentralPrepared, P::FinishPrepared, P::CurrentPrepared] {
            assert!(!super::central_receipt(phase));
        }
    }

    #[test]
    fn reservation_makes_prepared_final_and_all_ambiguous_calls_expiry_independent() {
        for phase in [
            P::ExecutionReserveInvoking,
            P::ExecutionReserveUnknown,
            P::RevocationFinalPrepared,
            P::RevocationFinalInvoking,
            P::RevocationFinalUnknown,
            P::FinalizePrepared,
            P::FinalizeInvoking,
            P::FinalizeUnknown,
        ] {
            assert!(super::exact_replay(phase, false));
        }
        for phase in [
            P::ReservationCurrentPrepared,
            P::ExecutionReservePrepared,
            P::CentralPrepared,
        ] {
            assert!(!super::exact_replay(phase, false));
        }
        assert!(super::exact_replay(P::Complete, true));
        assert!(!super::exact_replay(P::Complete, false));
    }
}
