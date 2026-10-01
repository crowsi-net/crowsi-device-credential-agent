use crate::{
    AgentError,
    identity_provider::IdentityEvidenceProvider,
    independent_approve_state_types::{
        IndependentApprovePhaseV1 as Phase, IndependentApproveResume,
    },
    replay::DurableSecurityState,
};

pub(super) fn approval<I: IdentityEvidenceProvider>(
    state: &DurableSecurityState,
    identity: &I,
    value: IndependentApproveResume,
    now: u64,
) -> Result<IndependentApproveResume, AgentError> {
    let operation = value.approval.operation_id.clone();
    let historic = value.approval.phase == Phase::ApprovalUnknown;
    let invoking =
        crate::independent_approve_state_phase::approval_invoking(state, &operation, now)?;
    let begun = crate::independent_approve_ceremony_context::begun(&invoking)?;
    let current = crate::independent_approve_ceremony_context::current(&invoking)?;
    let request = invoking
        .approval
        .approval_request
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    let wire = invoking
        .approval
        .approval_request_json
        .as_deref()
        .ok_or(AgentError::AuthorityRollback)?;
    let (key_id, public) = crate::independent_approve_ceremony_context::approval_pin(&invoking)?;
    let trust = crate::independent_approve_trust::current(&invoking.approval, begun)?;
    let exchange = identity.invoke_independent_revocation_approval(
        &trust,
        key_id,
        public,
        &invoking.lookup.response.prepared,
        begun,
        current,
        request,
        wire,
        historic,
        now,
    );
    let exchange = match exchange {
        Ok(value) => value,
        Err(error) => {
            crate::independent_approve_state_phase::approval_unknown(state, &operation, now)?;
            return Err(error);
        }
    };
    crate::independent_approve_state_phase::approval_unknown(state, &operation, now)?;
    crate::independent_approve_state_ceremony::approval_received(state, &operation, &exchange, now)
}
