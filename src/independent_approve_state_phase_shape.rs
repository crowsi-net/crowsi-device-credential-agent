use crate::independent_approve_state_types::{
    IndependentApprovePhaseV1 as P, IndependentApproveRecordV1,
};

const FINISH: u32 = 1 << 0;
const CURRENT_REQUEST: u32 = 1 << 1;
const CURRENT: u32 = 1 << 2;
const OBSERVED: u32 = 1 << 3;
const APPROVAL_REQUEST: u32 = 1 << 4;
const APPROVAL: u32 = 1 << 5;
const PRE_FINAL_REQUEST: u32 = 1 << 6;
const PRE_FINAL_RESPONSE: u32 = 1 << 7;
const RESERVATION_CURRENT_REQUEST: u32 = 1 << 8;
const RESERVATION_CURRENT: u32 = 1 << 9;
const RESERVATION_OBSERVED: u32 = 1 << 10;
const RESERVE_REQUEST: u32 = 1 << 11;
const RESERVATION: u32 = 1 << 12;
const FINAL: u32 = 1 << 13;
const FINALIZE_REQUEST: u32 = 1 << 14;
const RESPONSE: u32 = 1 << 15;

pub(super) fn present(value: &IndependentApproveRecordV1) -> Option<u32> {
    let fields = [
        (value.finish_exchange.is_some(), FINISH),
        (value.current_request.is_some(), CURRENT_REQUEST),
        (value.current_exchange.is_some(), CURRENT),
        (value.current_observed_at_epoch_s.is_some(), OBSERVED),
        (approval_request(value)?, APPROVAL_REQUEST),
        (value.approval_exchange.is_some(), APPROVAL),
        (
            pair(&value.pre_final_request_json, &value.pre_final_request)?,
            PRE_FINAL_REQUEST,
        ),
        (pre_final_response(value)?, PRE_FINAL_RESPONSE),
        (
            value.reservation_current_request.is_some(),
            RESERVATION_CURRENT_REQUEST,
        ),
        (
            value.reservation_current_exchange.is_some(),
            RESERVATION_CURRENT,
        ),
        (
            value.reservation_current_observed_at_epoch_s.is_some(),
            RESERVATION_OBSERVED,
        ),
        (
            pair(
                &value.execution_reserve_request_json,
                &value.execution_reserve_request,
            )?,
            RESERVE_REQUEST,
        ),
        (reservation(value)?, RESERVATION),
        (value.final_exchange.is_some(), FINAL),
        (
            pair(&value.finalize_request_json, &value.finalize_request)?,
            FINALIZE_REQUEST,
        ),
        (pair(&value.response_json, &value.response)?, RESPONSE),
    ];
    Some(fields.into_iter().filter(|v| v.0).map(|v| v.1).sum())
}

pub(super) const fn expected(phase: P) -> u32 {
    match phase {
        P::FinishPrepared | P::FinishInvoking | P::FinishUnknown => 0,
        P::CurrentRequestPrepared => FINISH,
        P::CurrentPrepared | P::CurrentInvoking | P::CurrentUnknown => FINISH | CURRENT_REQUEST,
        P::CurrentObservePrepared | P::CurrentObserveInvoking | P::CurrentObserveUnknown => {
            before_approval() | CURRENT
        }
        P::ApprovalPrepared | P::ApprovalInvoking | P::ApprovalUnknown => {
            before_approval() | CURRENT | OBSERVED | APPROVAL_REQUEST
        }
        P::ApprovalAccepted => through_approval(),
        P::PreFinalPrepared | P::PreFinalInvoking | P::PreFinalUnknown => {
            through_approval() | PRE_FINAL_REQUEST
        }
        P::PreFinalAccepted => through_pre_final(),
        P::ReservationCurrentPrepared
        | P::ReservationCurrentInvoking
        | P::ReservationCurrentUnknown => through_pre_final() | RESERVATION_CURRENT_REQUEST,
        P::ReservationCurrentObservePrepared
        | P::ReservationCurrentObserveInvoking
        | P::ReservationCurrentObserveUnknown => {
            through_pre_final() | RESERVATION_CURRENT_REQUEST | RESERVATION_CURRENT
        }
        P::ExecutionReservePrepared | P::ExecutionReserveInvoking | P::ExecutionReserveUnknown => {
            before_reservation() | RESERVATION_OBSERVED | RESERVE_REQUEST
        }
        P::FinalPrepared | P::FinalInvoking | P::FinalUnknown => {
            before_reservation() | RESERVATION_OBSERVED | RESERVE_REQUEST | RESERVATION
        }
        P::FinalAccepted => through_reservation() | FINAL,
        P::FinalizePrepared | P::FinalizeInvoking | P::FinalizeUnknown => {
            through_reservation() | FINAL | FINALIZE_REQUEST
        }
        P::Complete => through_reservation() | FINAL | FINALIZE_REQUEST | RESPONSE,
    }
}

include!("independent_approve_state_phase_shape_support.rs");
