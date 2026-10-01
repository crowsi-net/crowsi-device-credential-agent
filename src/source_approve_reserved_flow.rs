use crowsi_credential_authority_contracts::ManagementRequestV2;

use crate::{
    AgentError, VerifiedConfig,
    identity_provider::IdentityEvidenceProvider,
    replay::DurableSecurityState,
    source_approve_state_types::{SourceApprovePhaseV1 as P, SourceApproveResume},
    transport::AuthorityTransport,
};

pub(super) const fn owns(phase: P) -> bool {
    matches!(
        phase,
        P::ReservationCurrentPrepared
            | P::ReservationCurrentInvoking
            | P::ReservationCurrentUnknown
            | P::ReservationCurrentObservePrepared
            | P::ReservationCurrentObserveInvoking
            | P::ReservationCurrentObserveUnknown
            | P::ExecutionReservePrepared
            | P::ExecutionReserveInvoking
            | P::ExecutionReserveUnknown
            | P::RevocationFinalPrepared
            | P::RevocationFinalInvoking
            | P::RevocationFinalUnknown
            | P::FinalizePrepared
            | P::FinalizeInvoking
            | P::FinalizeUnknown
    )
}

pub(super) fn handle<T: AuthorityTransport, I: IdentityEvidenceProvider>(
    config: &VerifiedConfig,
    state: &DurableSecurityState,
    transport: &T,
    identity: &I,
    browser: &ManagementRequestV2,
    mut value: SourceApproveResume,
    now: u64,
) -> Result<Vec<u8>, AgentError> {
    loop {
        value = crate::source_approve_prepare::unexpired(value, now)?;
        let operation = value.approval.operation_id.clone();
        value = match value.approval.phase {
            P::ReservationCurrentInvoking => {
                crate::source_approve_state_phase::reservation_current_unknown(
                    state, &operation, now,
                )?
            }
            P::ReservationCurrentPrepared | P::ReservationCurrentUnknown => {
                crate::source_approve_reservation_identity_flow::invoke(
                    config, state, identity, value, now,
                )?
            }
            P::ReservationCurrentObserveInvoking => {
                crate::source_approve_state_phase::reservation_observe_unknown(
                    state, &operation, now,
                )?
            }
            P::ReservationCurrentObservePrepared | P::ReservationCurrentObserveUnknown => {
                crate::source_approve_reservation_identity_flow::observe(
                    config, state, identity, value, now,
                )?
            }
            P::ExecutionReserveInvoking => {
                crate::source_approve_state_phase::execution_reserve_unknown(
                    state, &operation, now,
                )?
            }
            P::ExecutionReservePrepared | P::ExecutionReserveUnknown => {
                crate::source_approve_execution_reserve_flow::invoke(
                    config, state, transport, value, now,
                )?
            }
            P::RevocationFinalInvoking => {
                crate::source_approve_revocation_final_phase::unknown(state, &operation, now)?
            }
            P::RevocationFinalPrepared | P::RevocationFinalUnknown => {
                crate::source_approve_revocation_finalize_flow::finalize(
                    config, state, identity, &value, now,
                )?
            }
            P::FinalizeInvoking => {
                crate::source_approve_finalization_phase::unknown(state, &operation, now)?
            }
            P::FinalizePrepared | P::FinalizeUnknown => {
                return crate::source_approve_finalization_response::invoke(
                    config, state, transport, browser, value, now,
                );
            }
            _ => return Err(AgentError::AuthorityRollback),
        };
    }
}
