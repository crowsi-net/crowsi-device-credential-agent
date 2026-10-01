use crate::source_approve_state_types::{SourceApprovePhaseV1 as P, SourceApproveRecordV1};

pub(super) const fn owns(phase: P) -> bool {
    crate::source_approve_reserved_flow::owns(phase) || matches!(phase, P::Complete)
}

pub(super) fn valid(value: &SourceApproveRecordV1) -> bool {
    let common = value.finish_exchange.is_some()
        && value.current_request.is_some()
        && value.current_exchange.is_some()
        && value.current_observed_at_epoch_s.is_some()
        && value.central_envelope.is_some()
        && value.central_envelope_json.is_some();
    match value.phase {
        P::ReservationCurrentPrepared
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
        | P::RevocationFinalUnknown => {
            common
                && crate::source_approve_state_revocation::awaiting_final(value)
                && crate::source_approve_state_finalization::accepted(value)
                && value.response.is_none()
                && value.response_json.is_none()
        }
        P::FinalizePrepared | P::FinalizeInvoking | P::FinalizeUnknown => {
            common
                && crate::source_approve_state_revocation::finalized(value)
                && crate::source_approve_state_finalization::prepared(value)
                && value.response.is_none()
                && value.response_json.is_none()
        }
        P::Complete => {
            common
                && completed_revocation(value)
                && value.response.is_some()
                && value.response_json.is_some()
                && (crate::source_approve_state_finalization::empty(value)
                    || crate::source_approve_state_finalization::prepared(value))
        }
        _ => false,
    }
}

fn completed_revocation(value: &SourceApproveRecordV1) -> bool {
    crate::source_approve_state_revocation::none(value)
        || crate::source_approve_state_revocation::begun(value)
        || crate::source_approve_state_revocation::finalized(value)
}
