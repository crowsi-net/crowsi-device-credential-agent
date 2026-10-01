use crowsi_credential_authority_contracts::{
    EndpointRevocationExecutionReservationHistoricTrustV1,
    verify_endpoint_revocation_execution_reservation_historic,
};

use crate::{
    AgentError, identity_provider::IdentityEvidenceProvider,
    independent_approve_state_types::IndependentApproveResume, replay::DurableSecurityState,
};

pub(super) fn skeleton<I: IdentityEvidenceProvider>(
    identity: &I,
    value: &IndependentApproveResume,
) -> Result<ihat_identity_assertion_contracts::AuthorityRequestV1, AgentError> {
    let (key_id, public) = crate::independent_approve_ceremony_context::approval_pin(value)?;
    identity.prepare_independent_revocation_final(
        key_id,
        public,
        &value.lookup.response.prepared,
        crate::independent_approve_ceremony_context::begun(value)?,
        crate::independent_approve_ceremony_context::current(value)?,
        value
            .approval
            .approval_exchange
            .as_ref()
            .ok_or(AgentError::AuthorityRollback)?,
    )
}

pub(super) fn invoke<I: IdentityEvidenceProvider>(
    state: &DurableSecurityState,
    identity: &I,
    value: IndependentApproveResume,
    now: u64,
) -> Result<IndependentApproveResume, AgentError> {
    let operation = value.approval.operation_id.clone();
    let invoking = crate::independent_approve_state_phase::final_invoking(state, &operation, now)?;
    let context = Context::new(&invoking)?;
    let trust = crate::independent_approve_trust::current(&invoking.approval, context.begun)?;
    let reservation_trust = context.reservation_trust();
    verify_endpoint_revocation_execution_reservation_historic(
        context.reservation,
        context.reserve,
        &context.pin.peer_device_ref,
        &reservation_trust,
    )
    .map_err(|_| AgentError::AuthorityRollback)?;
    let exchange = identity.invoke_independent_revocation_final(
        &trust,
        context.approval_key_id,
        context.approval_public_key,
        &invoking.lookup.response.prepared,
        context.begun,
        context.current,
        context.approval,
        context.reserve,
        context.reservation,
        &reservation_trust,
        &context.pin.peer_device_ref,
        context.request,
        context.wire,
        true,
        now,
    );
    let exchange = match exchange {
        Ok(value) => value,
        Err(error) => {
            crate::independent_approve_state_phase::final_unknown(state, &operation, now)?;
            return Err(error);
        }
    };
    crate::independent_approve_state_phase::final_unknown(state, &operation, now)?;
    crate::independent_approve_state_ceremony::final_received(state, &operation, &exchange, now)
}

include!("independent_approve_final_flow_context.rs");
