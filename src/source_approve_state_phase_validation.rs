use crate::source_approve_state_types::{SourceApprovePhaseV1, SourceApproveRecordV1};

pub(crate) fn valid(value: &SourceApproveRecordV1) -> bool {
    if !crate::source_approve_state_reservation_shape::valid(value) {
        return false;
    }
    if crate::source_approve_state_phase_validation_late::owns(value.phase) {
        return crate::source_approve_state_phase_validation_late::valid(value);
    }
    let finish = value.finish_exchange.is_some();
    let current_request = value.current_request.is_some();
    let current = value.current_exchange.is_some();
    let observed = value.current_observed_at_epoch_s.is_some();
    let envelope = value.central_envelope.is_some() && value.central_envelope_json.is_some();
    let finalization_empty = crate::source_approve_state_finalization::empty(value);
    let no_revocation = crate::source_approve_state_revocation::none(value);
    let begun = crate::source_approve_state_revocation::begun(value);
    match value.phase {
        SourceApprovePhaseV1::FinishPrepared => {
            !finish
                && !current_request
                && !current
                && !observed
                && no_revocation
                && finalization_empty
                && !envelope
                && value.response.is_none()
        }
        SourceApprovePhaseV1::CurrentPrepared
        | SourceApprovePhaseV1::CurrentInvoking
        | SourceApprovePhaseV1::CurrentUnknown => {
            finish
                && current_request
                && !current
                && !observed
                && no_revocation
                && finalization_empty
                && !envelope
                && value.response.is_none()
        }
        SourceApprovePhaseV1::CurrentObservePrepared
        | SourceApprovePhaseV1::CurrentObserveInvoking
        | SourceApprovePhaseV1::CurrentObserveUnknown => {
            finish
                && current_request
                && current
                && !observed
                && no_revocation
                && finalization_empty
                && !envelope
                && value.response.is_none()
        }
        SourceApprovePhaseV1::RevocationBeginPrepared => {
            finish
                && current_request
                && current
                && observed
                && value.revocation_begin_request.is_some()
                && value.revocation_begin_exchange.is_none()
                && value.revocation_final_request.is_none()
                && value.revocation_final_exchange.is_none()
                && finalization_empty
                && !envelope
                && value.response.is_none()
        }
        SourceApprovePhaseV1::CentralPrepared
        | SourceApprovePhaseV1::CentralInvoking
        | SourceApprovePhaseV1::Unknown => {
            finish
                && current_request
                && current
                && observed
                && (no_revocation || begun || value.revocation_final_request.is_some())
                && finalization_empty
                && envelope
                && value.response.is_none()
        }
        _ => false,
    }
}
