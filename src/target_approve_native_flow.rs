use crate::{
    AgentError, VerifiedConfig, replay::DurableSecurityState,
    target_approve_native::TargetApprovalPort, target_approve_state_types::TargetApproveResume,
};

pub(super) fn pa<P: TargetApprovalPort>(
    config: &VerifiedConfig,
    state: &DurableSecurityState,
    port: &P,
    value: TargetApproveResume,
    now: u64,
) -> Result<TargetApproveResume, AgentError> {
    let operation = value.approval.operation_id.clone();
    let invoking = crate::target_approve_state_phase::pa_invoking(state, &operation, now)?;
    let (wire, returned) = match port.authorize(&config.0, &invoking, now) {
        Ok(response) => response,
        Err(error) => {
            crate::target_approve_state_phase::pa_unknown(state, &operation, now)?;
            return Err(error);
        }
    };
    let unknown = crate::target_approve_state_phase::pa_unknown(state, &operation, now)?;
    let verified = crate::target_approve_pa_verify::response(&config.0, &unknown, &wire, now)?;
    if verified != returned {
        return Err(AgentError::TargetKeyProofInvalid);
    }
    crate::target_approve_state_external::pa_complete(state, &operation, &wire, &verified, now)
}

pub(super) fn custody<P: TargetApprovalPort>(
    config: &VerifiedConfig,
    state: &DurableSecurityState,
    port: &P,
    value: TargetApproveResume,
    now: u64,
) -> Result<TargetApproveResume, AgentError> {
    let operation = value.approval.operation_id.clone();
    let invoking = crate::target_approve_state_phase::custody_invoking(state, &operation, now)?;
    let (wire, response) = match port.sign(&config.0, &invoking) {
        Ok(response) => response,
        Err(error) => {
            crate::target_approve_state_phase::custody_unknown(state, &operation, now)?;
            return Err(error);
        }
    };
    let unknown = crate::target_approve_state_phase::custody_unknown(state, &operation, now)?;
    let proof = crate::target_approve_proof::signed(&config.0, &unknown, &response, now)?;
    let envelope = crate::target_approve_proof::envelope(&unknown, &proof)?;
    crate::target_approve_state_external::custody_complete(
        state, &operation, &wire, &response, &proof, &envelope, now,
    )
}
