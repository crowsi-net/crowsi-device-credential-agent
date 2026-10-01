use serde::Serialize;

use crate::{
    cancel_state_types::{CancelPhaseV1 as P, CancelRecordV1},
    source_options_state::MAXIMUM_PHASE_WIRE_BYTES,
};

pub(super) fn valid(value: &CancelRecordV1) -> bool {
    match value.phase {
        P::ExecutionCancelPrepared | P::ExecutionCancelInvoking | P::ExecutionCancelUnknown => {
            pair(
                value.cancelled_projection_body.as_ref(),
                value.execution_cancel_request.as_ref(),
            )
        }
        P::CancelPendingPrepared | P::CancelPendingInvoking | P::CancelPendingUnknown => pair(
            value.execution_cancel_request.as_ref(),
            value.execution_cancellation.as_ref(),
        ),
        P::CancelFinalizePrepared | P::CancelFinalizeInvoking | P::CancelFinalizeUnknown => {
            single(value.cancel_finalize_request.as_ref())
        }
        P::CleanupAckPrepared | P::CleanupAckInvoking | P::CleanupAckUnknown => pair(
            value.cancel_finalize_request.as_ref(),
            value.cancellation_cleanup.as_ref(),
        ),
        P::CleanupCompletePrepared
        | P::CleanupCompleteInvoking
        | P::CleanupCompleteUnknown
        | P::CleanupCompleteCleanupPrepared
        | P::CleanupCompleteCleanupInvoking
        | P::CleanupCompleteCleanupUnknown => single(value.cleanup_complete_request.as_ref()),
        P::CleanupCompleteAckPrepared
        | P::CleanupCompleteAckInvoking
        | P::CleanupCompleteAckUnknown => pair(
            value.cleanup_complete_request.as_ref(),
            value.cancellation_cleanup.as_ref(),
        ),
        P::CleanupCompleteAccepted => pair(
            value.cleanup_complete_request.as_ref(),
            value.cleanup_complete_response.as_ref(),
        ),
        _ => true,
    }
}

fn single<T: Serialize>(value: Option<&T>) -> bool {
    wire(value).is_some_and(|bytes| bytes <= MAXIMUM_PHASE_WIRE_BYTES)
}

fn pair<L: Serialize, R: Serialize>(left: Option<&L>, right: Option<&R>) -> bool {
    let Some((left, right)) = wire(left).zip(wire(right)) else {
        return false;
    };
    pair_fits(left, right)
}

fn wire<T: Serialize>(value: Option<&T>) -> Option<usize> {
    value.and_then(|value| serde_json::to_vec(value).ok().map(|wire| wire.len()))
}

fn pair_fits(left: usize, right: usize) -> bool {
    left <= MAXIMUM_PHASE_WIRE_BYTES
        && right <= MAXIMUM_PHASE_WIRE_BYTES
        && left
            .checked_add(right)
            .is_some_and(|total| total <= 2 * MAXIMUM_PHASE_WIRE_BYTES)
}

#[cfg(test)]
mod tests {
    use super::{MAXIMUM_PHASE_WIRE_BYTES as MAX, pair_fits};

    #[test]
    fn two_wire_boundary_excludes_persistent_record_overhead() {
        assert!(pair_fits(MAX, MAX));
        assert!(!pair_fits(MAX, MAX + 1));
    }
}
