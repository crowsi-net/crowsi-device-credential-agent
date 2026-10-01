use crate::cancel_state_types::{CancelPhaseV1 as P, CancelRecordV1};

pub(super) fn valid(value: &CancelRecordV1) -> bool {
    coherent(value) && base(value) && crate::cancel_state_phase_validation_groups::artifacts(value)
}

fn base(value: &CancelRecordV1) -> bool {
    let current = value.current_exchange.is_some();
    let observed = value.current_observed_at_epoch_s.is_some();
    let request = value.lookup_request.is_some();
    let lookup = value.lookup_response.is_some();
    let envelope = value.central_envelope.is_some();
    let raw_response = value.response_json.is_some();
    let response = value.response.is_some();
    let cancelled = value.cancelled_projection_body.is_some();
    match value.phase {
        P::CurrentPrepared | P::CurrentInvoking | P::CurrentUnknown => {
            !current
                && !observed
                && !request
                && !lookup
                && !envelope
                && !raw_response
                && !response
                && !cancelled
        }
        P::CurrentObservePrepared | P::CurrentObserveInvoking | P::CurrentObserveUnknown => {
            current
                && !observed
                && !request
                && !lookup
                && !envelope
                && !raw_response
                && !response
                && !cancelled
        }
        P::LookupPrepared => {
            current
                && observed
                && request
                && !lookup
                && !envelope
                && !raw_response
                && !response
                && !cancelled
        }
        P::CentralPrepared | P::CentralInvoking | P::Unknown => {
            current
                && observed
                && request
                && lookup
                && envelope
                && !raw_response
                && !response
                && !cancelled
        }
        P::ExecutionCancelPrepared | P::ExecutionCancelInvoking | P::ExecutionCancelUnknown => {
            compact(current, observed, request, lookup)
                && envelope
                && !raw_response
                && !response
                && cancelled
        }
        P::Complete if value.cleanup_completed_id.is_none() => {
            current
                && observed
                && request
                && lookup
                && envelope
                && raw_response
                && !response
                && !cancelled
        }
        P::Complete => {
            compact(current, observed, request, lookup) && envelope && !response && cancelled
        }
        _ => {
            compact(current, observed, request, lookup)
                && envelope
                && !raw_response
                && !response
                && cancelled
        }
    }
}

fn coherent(value: &CancelRecordV1) -> bool {
    let complete = value.cleanup_complete_request.is_some();
    let ack = value.cleanup_ack_exchange.is_some();
    let ack_trust = value.cleanup_response_trust.is_some();
    let refreshing = value.cancellation_cleanup.is_some()
        && value.cancellation_cleanup_trust.is_some()
        && !ack
        && !ack_trust;
    !(value.response_json.is_some() && value.response.is_some())
        && value.cleanup_complete_response.is_some() == value.cleanup_complete_trust.is_some()
        && ((!complete && ack == ack_trust) || (complete && !ack && (ack_trust || refreshing)))
}

const fn compact(current: bool, observed: bool, request: bool, lookup: bool) -> bool {
    !current && !observed && !request && !lookup
}
