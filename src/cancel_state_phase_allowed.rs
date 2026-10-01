use crate::cancel_state_types::CancelPhaseV1 as P;

pub(super) const fn valid(current: P, next: P) -> bool {
    matches!(
        (current, next),
        (P::CurrentPrepared, P::CurrentInvoking)
            | (P::CurrentInvoking, P::CurrentUnknown)
            | (P::CurrentUnknown, P::CurrentInvoking)
            | (P::CurrentObservePrepared, P::CurrentObserveInvoking)
            | (P::CurrentObserveInvoking, P::CurrentObserveUnknown)
            | (P::CurrentObserveUnknown, P::CurrentObserveInvoking)
            | (P::CentralPrepared, P::CentralInvoking)
            | (P::CentralInvoking, P::Unknown)
            | (P::Unknown, P::CentralInvoking)
            | (P::ExecutionCancelPrepared, P::ExecutionCancelInvoking)
            | (P::ExecutionCancelInvoking, P::ExecutionCancelUnknown)
            | (P::ExecutionCancelUnknown, P::ExecutionCancelInvoking)
            | (P::CancelPendingPrepared, P::CancelPendingInvoking)
            | (P::CancelPendingInvoking, P::CancelPendingUnknown)
            | (P::CancelPendingUnknown, P::CancelPendingInvoking)
            | (P::CancelFinalizePrepared, P::CancelFinalizeInvoking)
            | (P::CancelFinalizeInvoking, P::CancelFinalizeUnknown)
            | (P::CancelFinalizeUnknown, P::CancelFinalizeInvoking)
            | (P::CleanupAckPrepared, P::CleanupAckInvoking)
            | (P::CleanupAckInvoking, P::CleanupAckUnknown)
            | (P::CleanupAckUnknown, P::CleanupAckInvoking)
            | (P::CleanupCompletePrepared, P::CleanupCompleteInvoking)
            | (P::CleanupCompleteInvoking, P::CleanupCompleteUnknown)
            | (P::CleanupCompleteUnknown, P::CleanupCompleteCleanupPrepared)
            | (
                P::CleanupCompleteCleanupPrepared,
                P::CleanupCompleteCleanupInvoking
            )
            | (
                P::CleanupCompleteCleanupInvoking,
                P::CleanupCompleteCleanupUnknown
            )
            | (
                P::CleanupCompleteCleanupUnknown,
                P::CleanupCompleteCleanupInvoking
            )
            | (P::CleanupCompleteAckPrepared, P::CleanupCompleteAckInvoking)
            | (P::CleanupCompleteAckInvoking, P::CleanupCompleteAckUnknown)
            | (P::CleanupCompleteAckUnknown, P::CleanupCompleteAckInvoking)
    )
}
