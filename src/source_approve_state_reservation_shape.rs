use crate::source_approve_state_types::{SourceApprovePhaseV1 as P, SourceApproveRecordV1};

const CURRENT_REQUEST: u8 = 1 << 0;
const CURRENT: u8 = 1 << 1;
const OBSERVED: u8 = 1 << 2;
const RESERVE_REQUEST: u8 = 1 << 3;
const RESERVATION: u8 = 1 << 4;

pub(super) fn valid(value: &SourceApproveRecordV1) -> bool {
    present(value).is_some_and(|present| present == expected(value))
}

pub(super) fn empty(value: &SourceApproveRecordV1) -> bool {
    present(value) == Some(0)
}

fn present(value: &SourceApproveRecordV1) -> Option<u8> {
    let fields = [
        (value.reservation_current_request.is_some(), CURRENT_REQUEST),
        (value.reservation_current_exchange.is_some(), CURRENT),
        (
            value.reservation_current_observed_at_epoch_s.is_some(),
            OBSERVED,
        ),
        (
            pair(
                &value.execution_reserve_request_json,
                &value.execution_reserve_request,
            )?,
            RESERVE_REQUEST,
        ),
        (
            same([
                value.execution_reservation_json.is_some(),
                value.execution_reservation.is_some(),
                value.execution_reservation_trust.is_some(),
            ])?,
            RESERVATION,
        ),
    ];
    Some(
        fields
            .into_iter()
            .filter(|field| field.0)
            .map(|field| field.1)
            .sum(),
    )
}

fn expected(value: &SourceApproveRecordV1) -> u8 {
    match value.phase {
        P::ReservationCurrentPrepared
        | P::ReservationCurrentInvoking
        | P::ReservationCurrentUnknown => CURRENT_REQUEST,
        P::ReservationCurrentObservePrepared
        | P::ReservationCurrentObserveInvoking
        | P::ReservationCurrentObserveUnknown => CURRENT_REQUEST | CURRENT,
        P::ExecutionReservePrepared | P::ExecutionReserveInvoking | P::ExecutionReserveUnknown => {
            CURRENT_REQUEST | CURRENT | OBSERVED | RESERVE_REQUEST
        }
        P::RevocationFinalPrepared
        | P::RevocationFinalInvoking
        | P::RevocationFinalUnknown
        | P::FinalizePrepared
        | P::FinalizeInvoking
        | P::FinalizeUnknown => {
            CURRENT_REQUEST | CURRENT | OBSERVED | RESERVE_REQUEST | RESERVATION
        }
        P::Complete if value.revocation_finalize_request.is_some() => {
            CURRENT_REQUEST | CURRENT | OBSERVED | RESERVE_REQUEST | RESERVATION
        }
        _ => 0,
    }
}

fn pair<A, B>(left: &Option<A>, right: &Option<B>) -> Option<bool> {
    same([left.is_some(), right.is_some()])
}

fn same<const N: usize>(values: [bool; N]) -> Option<bool> {
    values
        .iter()
        .all(|value| *value == values[0])
        .then_some(values[0])
}
