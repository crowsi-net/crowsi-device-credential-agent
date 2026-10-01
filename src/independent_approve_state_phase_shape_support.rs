const fn before_approval() -> u32 {
    FINISH | CURRENT_REQUEST
}

const fn through_approval() -> u32 {
    before_approval() | CURRENT | OBSERVED | APPROVAL_REQUEST | APPROVAL
}

const fn through_pre_final() -> u32 {
    through_approval() | PRE_FINAL_REQUEST | PRE_FINAL_RESPONSE
}

const fn before_reservation() -> u32 {
    through_pre_final() | RESERVATION_CURRENT_REQUEST | RESERVATION_CURRENT
}

const fn through_reservation() -> u32 {
    before_reservation() | RESERVATION_OBSERVED | RESERVE_REQUEST | RESERVATION
}

fn approval_request(value: &IndependentApproveRecordV1) -> Option<bool> {
    same([
        value.approval_request_json.is_some(),
        value.approval_request.is_some(),
        value.approval_key_id.is_some(),
        value.approval_key_fingerprint.is_some(),
        value.approval_public_key_hex.is_some(),
    ])
}

fn pre_final_response(value: &IndependentApproveRecordV1) -> Option<bool> {
    same([
        value.pre_final_response_json.is_some(),
        value.pre_final_response.is_some(),
        value.pre_final_trust.is_some(),
    ])
}

fn reservation(value: &IndependentApproveRecordV1) -> Option<bool> {
    same([
        value.execution_reservation_json.is_some(),
        value.execution_reservation.is_some(),
        value.execution_reservation_trust.is_some(),
        value.final_request_json.is_some(),
        value.final_request.is_some(),
    ])
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
