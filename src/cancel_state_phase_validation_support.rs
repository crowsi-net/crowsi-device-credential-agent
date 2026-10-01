use crate::{
    cancel_state_capacity::PHASE_IMAGE_BYTES, cancel_state_types::CancelRecordV1,
};

pub(super) fn central(value: &CancelRecordV1, early: bool, early_empty: bool) -> bool {
    let reserve = value.future_bytes_reserved;
    ((early && reserve == PHASE_IMAGE_BYTES) || (early_empty && reserve == 0)) && none(value)
}

pub(super) fn compact_cancellation(value: &CancelRecordV1) -> bool {
    value.execution_cancellation.is_none() && value.execution_cancellation_trust.is_some()
}

const fn no_cancellation(value: &CancelRecordV1) -> bool {
    value.execution_cancellation.is_none() && value.execution_cancellation_trust.is_none()
}

pub(super) fn none(value: &CancelRecordV1) -> bool {
    value.execution_cancel_request.is_none()
        && no_cancellation(value)
        && value.cancel_finalize_request.is_none()
        && value.cancellation_cleanup.is_none()
        && value.cancellation_cleanup_trust.is_none()
        && value.cleanup_ack_exchange.is_none()
        && value.cleanup_response_trust.is_none()
        && value.cleanup_complete_request.is_none()
        && value.cleanup_complete_response.is_none()
        && value.cleanup_complete_trust.is_none()
}

pub(super) const fn no_reserve(value: &CancelRecordV1) -> bool {
    value.future_bytes_reserved == 0
}
