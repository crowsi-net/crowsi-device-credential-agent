use crate::{
    cancel_state_capacity::PHASE_IMAGE_BYTES,
    cancel_state_phase_validation_support::{central, compact_cancellation, no_reserve, none},
    cancel_state_types::{CancelPhaseV1 as P, CancelRecordV1},
};

pub(super) fn artifacts(value: &CancelRecordV1) -> bool {
    let early = value.revocation_begin_exchange.is_some()
        && value.revocation_response_trust.is_some()
        && value.pre_final_acceptance_request_sha256.is_some();
    let early_empty = value.revocation_begin_exchange.is_none()
        && value.revocation_response_trust.is_none()
        && value.pre_final_acceptance_request_sha256.is_none();
    let response_pin = value.revocation_begin_exchange.is_none()
        && value.revocation_response_trust.is_some()
        && value.pre_final_acceptance_request_sha256.is_none();
    let execution = value.execution_cancel_request.is_some();
    let cancellation =
        value.execution_cancellation.is_some() && value.execution_cancellation_trust.is_some();
    let finalize = value.cancel_finalize_request.is_some();
    let cleanup =
        value.cancellation_cleanup.is_some() && value.cancellation_cleanup_trust.is_some();
    let ack = value.cleanup_ack_exchange.is_some() && value.cleanup_response_trust.is_some();
    let complete_request = value.cleanup_complete_request.is_some();
    let complete_response =
        value.cleanup_complete_response.is_some() && value.cleanup_complete_trust.is_some();
    let marker = value.cleanup_completed_id.is_some();
    let cancelled = value.cancelled_projection_body.is_some();
    if value.future_bytes_reserved > PHASE_IMAGE_BYTES {
        return false;
    }
    match value.phase {
        P::CurrentPrepared
        | P::CurrentInvoking
        | P::CurrentUnknown
        | P::CurrentObservePrepared
        | P::CurrentObserveInvoking
        | P::CurrentObserveUnknown
        | P::LookupPrepared => early_empty && !cancelled && none(value) && no_reserve(value),
        P::CentralPrepared | P::CentralInvoking | P::Unknown => {
            central(value, early, early_empty) && !cancelled && !marker
        }
        P::ExecutionCancelPrepared | P::ExecutionCancelInvoking | P::ExecutionCancelUnknown => {
            cancelled
                && response_pin
                && execution
                && !cancellation
                && !finalize
                && !cleanup
                && !ack
                && !marker
        }
        P::CancelPendingPrepared | P::CancelPendingInvoking | P::CancelPendingUnknown => {
            cancelled
                && response_pin
                && execution
                && cancellation
                && !finalize
                && !cleanup
                && !ack
                && !marker
        }
        P::CancelFinalizePrepared | P::CancelFinalizeInvoking | P::CancelFinalizeUnknown => {
            cancelled
                && response_pin
                && !execution
                && compact_cancellation(value)
                && finalize
                && !cleanup
                && !ack
                && !marker
        }
        P::CleanupAckPrepared | P::CleanupAckInvoking | P::CleanupAckUnknown => {
            cancelled
                && response_pin
                && !execution
                && compact_cancellation(value)
                && finalize
                && cleanup
                && !ack
                && !marker
        }
        P::CleanupCompletePrepared
        | P::CleanupCompleteInvoking
        | P::CleanupCompleteUnknown
        | P::CleanupCompleteCleanupPrepared
        | P::CleanupCompleteCleanupInvoking
        | P::CleanupCompleteCleanupUnknown
        => {
            cancelled
                && response_pin
                && !execution
                && compact_cancellation(value)
                && !finalize
                && !cleanup
                && !ack
                && complete_request
                && !complete_response
                && !marker
        }
        P::CleanupCompleteAckPrepared
        | P::CleanupCompleteAckInvoking
        | P::CleanupCompleteAckUnknown => {
            cancelled
                && response_pin
                && !execution
                && compact_cancellation(value)
                && !finalize
                && cleanup
                && !ack
                && complete_request
                && !complete_response
                && !marker
        }
        P::CleanupCompleteAccepted => {
            cancelled
                && response_pin
                && !execution
                && compact_cancellation(value)
                && !finalize
                && !cleanup
                && !ack
                && complete_request
                && complete_response
                && !marker
        }
        P::Complete => cancelled && early_empty && none(value) && no_reserve(value),
    }
}
