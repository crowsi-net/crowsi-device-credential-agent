use crowsi_credential_authority_contracts::ManagementRequestV2;

use crate::{
    AgentError, VerifiedConfig,
    cancel_state_types::{CancelPhaseV1 as P, CancelRecordV1},
    identity_provider::IdentityEvidenceProvider,
    replay::DurableSecurityState,
    transport::AuthorityTransport,
};

pub(super) const fn owns(phase: P) -> bool {
    matches!(
        phase,
        P::ExecutionCancelPrepared
            | P::ExecutionCancelInvoking
            | P::ExecutionCancelUnknown
            | P::CancelPendingPrepared
            | P::CancelPendingInvoking
            | P::CancelPendingUnknown
            | P::CancelFinalizePrepared
            | P::CancelFinalizeInvoking
            | P::CancelFinalizeUnknown
            | P::CleanupAckPrepared
            | P::CleanupAckInvoking
            | P::CleanupAckUnknown
            | P::CleanupCompletePrepared
            | P::CleanupCompleteInvoking
            | P::CleanupCompleteUnknown
            | P::CleanupCompleteCleanupPrepared
            | P::CleanupCompleteCleanupInvoking
            | P::CleanupCompleteCleanupUnknown
            | P::CleanupCompleteAckPrepared
            | P::CleanupCompleteAckInvoking
            | P::CleanupCompleteAckUnknown
            | P::CleanupCompleteAccepted
    )
}

pub(super) fn handle<T: AuthorityTransport, I: IdentityEvidenceProvider>(
    config: &VerifiedConfig,
    state: &DurableSecurityState,
    transport: &T,
    identity: &I,
    browser: &ManagementRequestV2,
    mut value: Box<CancelRecordV1>,
    now: u64,
) -> Result<Vec<u8>, AgentError> {
    loop {
        value = crate::cancel_prepare::unexpired(value, now)?;
        let operation = value.operation_id.clone();
        value = match value.phase {
            P::ExecutionCancelInvoking => {
                crate::cancel_state_phase::execution_cancel_unknown(state, &operation, now)?
            }
            P::ExecutionCancelPrepared | P::ExecutionCancelUnknown => {
                crate::cancel_execution_flow::invoke(config, state, transport, value, now)?
            }
            P::CancelPendingInvoking => {
                crate::cancel_state_phase::cancel_pending_unknown(state, &operation, now)?
            }
            P::CancelPendingPrepared | P::CancelPendingUnknown => {
                crate::cancel_pending_flow::invoke(config, state, identity, value, now)?
            }
            P::CancelFinalizeInvoking => {
                crate::cancel_state_phase::cancel_finalize_unknown(state, &operation, now)?
            }
            P::CancelFinalizePrepared | P::CancelFinalizeUnknown => {
                crate::cancel_cleanup_flow::invoke(config, state, transport, value, now)?
            }
            P::CleanupAckInvoking => {
                crate::cancel_state_phase::cleanup_ack_unknown(state, &operation, now)?
            }
            P::CleanupAckPrepared | P::CleanupAckUnknown => {
                crate::cancel_cleanup_ack_flow::invoke(config, state, identity, value, now)?
            }
            P::CleanupCompleteInvoking => {
                crate::cancel_state_phase::cleanup_complete_unknown(state, &operation, now)?
            }
            P::CleanupCompletePrepared => {
                crate::cancel_cleanup_complete_flow::invoke(config, state, transport, value, now)?
            }
            P::CleanupCompleteUnknown => {
                crate::cancel_state_phase::cleanup_complete_cleanup_prepared(
                    state, &operation, now,
                )?
            }
            P::CleanupCompleteCleanupInvoking => {
                crate::cancel_state_phase::cleanup_complete_cleanup_unknown(state, &operation, now)?
            }
            P::CleanupCompleteCleanupPrepared | P::CleanupCompleteCleanupUnknown => {
                crate::cancel_cleanup_complete_cleanup_flow::invoke(
                    config, state, transport, value, now,
                )?
            }
            P::CleanupCompleteAckInvoking => {
                crate::cancel_state_phase::cleanup_complete_ack_unknown(state, &operation, now)?
            }
            P::CleanupCompleteAckPrepared | P::CleanupCompleteAckUnknown => {
                crate::cancel_cleanup_complete_ack_flow::invoke(
                    config, state, identity, value, now,
                )?
            }
            P::CleanupCompleteAccepted => {
                crate::cancel_state_cleanup_complete::complete(state, &operation, now)?;
                return crate::retired_request::handle(config, state, transport, browser, now)
                    .ok_or(AgentError::AuthorityRollback)?;
            }
            _ => return Err(AgentError::AuthorityRollback),
        };
    }
}
