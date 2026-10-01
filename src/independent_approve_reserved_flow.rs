use crowsi_credential_authority_contracts::ManagementRequestV2;

use crate::{
    AgentError, VerifiedConfig,
    identity_provider::IdentityEvidenceProvider,
    independent_approve_state_types::{
        IndependentApprovePhaseV1 as Phase, IndependentApproveResume,
    },
    replay::DurableSecurityState,
    transport::AuthorityTransport,
};

pub(super) fn handle<T: AuthorityTransport, I: IdentityEvidenceProvider>(
    config: &VerifiedConfig,
    state: &DurableSecurityState,
    transport: &T,
    identity: &I,
    browser: &ManagementRequestV2,
    mut value: IndependentApproveResume,
    now: u64,
) -> Result<Vec<u8>, AgentError> {
    loop {
        value = crate::independent_approve_prepare::unexpired(value, now)?;
        let operation = value.approval.operation_id.clone();
        value = match value.approval.phase {
            Phase::PreFinalAccepted => {
                crate::independent_approve_reservation_identity_flow::prepare(
                    config, state, identity, value, now,
                )?
            }
            Phase::ReservationCurrentInvoking => {
                crate::independent_approve_state_phase::reservation_current_unknown(
                    state, &operation, now,
                )?
            }
            Phase::ReservationCurrentPrepared | Phase::ReservationCurrentUnknown => {
                crate::independent_approve_reservation_identity_flow::invoke(
                    config, state, identity, value, now,
                )?
            }
            Phase::ReservationCurrentObserveInvoking => {
                crate::independent_approve_state_phase::reservation_observe_unknown(
                    state, &operation, now,
                )?
            }
            Phase::ReservationCurrentObservePrepared | Phase::ReservationCurrentObserveUnknown => {
                crate::independent_approve_reservation_identity_flow::observe(
                    config, state, identity, value, now,
                )?
            }
            Phase::ExecutionReserveInvoking => {
                crate::independent_approve_state_phase::execution_reserve_unknown(
                    state, &operation, now,
                )?
            }
            Phase::ExecutionReservePrepared | Phase::ExecutionReserveUnknown => {
                crate::independent_approve_execution_reserve_flow::invoke(
                    config, state, transport, value, now,
                )?
            }
            Phase::FinalInvoking => {
                crate::independent_approve_state_phase::final_unknown(state, &operation, now)?
            }
            Phase::FinalPrepared | Phase::FinalUnknown => {
                crate::independent_approve_final_flow::invoke(state, identity, value, now)?
            }
            Phase::FinalAccepted => {
                crate::independent_approve_finalize_flow::prepare(state, value, now)?
            }
            Phase::FinalizeInvoking => {
                crate::independent_approve_state_phase::finalize_unknown(state, &operation, now)?
            }
            Phase::FinalizePrepared | Phase::FinalizeUnknown => {
                return crate::independent_approve_finalize_flow::invoke(
                    config, state, transport, browser, value, now,
                );
            }
            Phase::Complete => {
                return crate::independent_approve_finalize_flow::completed(
                    config, state, transport, browser, &value, now,
                );
            }
            _ => return Err(AgentError::AuthorityRollback),
        };
    }
}
