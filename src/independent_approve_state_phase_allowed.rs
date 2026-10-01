use crate::independent_approve_state_types::IndependentApprovePhaseV1 as P;

pub(super) const fn allowed(current: P, next: P) -> bool {
    matches!(
        (current, next),
        (P::FinishPrepared | P::FinishUnknown, P::FinishInvoking)
            | (P::FinishInvoking, P::FinishUnknown)
            | (P::CurrentPrepared | P::CurrentUnknown, P::CurrentInvoking)
            | (P::CurrentInvoking, P::CurrentUnknown)
            | (
                P::CurrentObservePrepared | P::CurrentObserveUnknown,
                P::CurrentObserveInvoking
            )
            | (P::CurrentObserveInvoking, P::CurrentObserveUnknown)
            | (
                P::ApprovalPrepared | P::ApprovalUnknown,
                P::ApprovalInvoking
            )
            | (P::ApprovalInvoking, P::ApprovalUnknown)
            | (
                P::PreFinalPrepared | P::PreFinalUnknown,
                P::PreFinalInvoking
            )
            | (P::PreFinalInvoking, P::PreFinalUnknown)
            | (
                P::ReservationCurrentPrepared | P::ReservationCurrentUnknown,
                P::ReservationCurrentInvoking
            )
            | (P::ReservationCurrentInvoking, P::ReservationCurrentUnknown)
            | (
                P::ReservationCurrentObservePrepared | P::ReservationCurrentObserveUnknown,
                P::ReservationCurrentObserveInvoking
            )
            | (
                P::ReservationCurrentObserveInvoking,
                P::ReservationCurrentObserveUnknown
            )
            | (
                P::ExecutionReservePrepared | P::ExecutionReserveUnknown,
                P::ExecutionReserveInvoking
            )
            | (P::ExecutionReserveInvoking, P::ExecutionReserveUnknown)
            | (P::FinalPrepared | P::FinalUnknown, P::FinalInvoking)
            | (P::FinalInvoking, P::FinalUnknown)
            | (
                P::FinalizePrepared | P::FinalizeUnknown,
                P::FinalizeInvoking
            )
            | (P::FinalizeInvoking, P::FinalizeUnknown)
    )
}
