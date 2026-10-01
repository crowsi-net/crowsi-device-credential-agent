use crate::independent_approve_state_types::IndependentApproveRecordV1;

pub(super) fn valid(value: &IndependentApproveRecordV1) -> bool {
    crate::independent_approve_state_phase_shape::present(value).is_some_and(|present| {
        present == crate::independent_approve_state_phase_shape::expected(value.phase)
    })
}
