use crowsi_credential_authority_contracts::verify_endpoint_revocation_execution_reservation_historic;

use crate::{
    AgentError, VerifiedConfig, identity_provider::IdentityEvidenceProvider,
    replay::DurableSecurityState, source_approve_state_types::SourceApproveResume,
};

pub(crate) fn finalize<I: IdentityEvidenceProvider>(
    _config: &VerifiedConfig,
    state: &DurableSecurityState,
    identity: &I,
    value: &SourceApproveResume,
    now: u64,
) -> Result<SourceApproveResume, AgentError> {
    let operation = &value.source.prepared.operation_id;
    let invoking = crate::source_approve_revocation_final_phase::invoking(state, operation, now)?;
    let prepared = &invoking.source.prepared;
    let begun = invoking
        .approval
        .revocation_begin_exchange
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    let request = invoking
        .approval
        .revocation_final_request
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    let reserve = invoking
        .approval
        .execution_reserve_request
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    let reservation = invoking
        .approval
        .execution_reservation
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    let pin = invoking
        .approval
        .execution_reservation_trust
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    let reservation_trust = crate::source_approve_revocation_response_final::reservation_trust(pin);
    verify_endpoint_revocation_execution_reservation_historic(
        reservation,
        reserve,
        &pin.peer_device_ref,
        &reservation_trust,
    )
    .map_err(|_| AgentError::AuthorityRollback)?;
    let trust = crate::source_approve_state_revocation_trust::trust(&invoking.approval)?;
    let final_exchange = identity.invoke_source_revocation_final(
        &trust,
        prepared,
        begun,
        reserve,
        reservation,
        &reservation_trust,
        &pin.peer_device_ref,
        request,
        now,
    );
    if final_exchange.is_err() {
        crate::source_approve_revocation_final_phase::unknown(state, operation, now)?;
    }
    let final_exchange = final_exchange?;
    let unknown = crate::source_approve_revocation_final_phase::unknown(state, operation, now)?;
    let finalize_request =
        crate::source_approve_revocation_finalize::build(&unknown, &final_exchange)?;
    crate::source_approve_state_revocation_transition_final::ready(
        state,
        operation,
        &final_exchange,
        &finalize_request,
        now,
    )
}
