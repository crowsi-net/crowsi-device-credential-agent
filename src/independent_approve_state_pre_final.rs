use crowsi_credential_authority_contracts::{
    EndpointIndependentRevocationPreFinalRequestV1, ManagementProjectionV2,
};

use crate::{
    AgentError,
    independent_approve_state_types::{
        IndependentApprovePhaseV1 as P, IndependentApproveResume, IndependentProjectionTrustPinV1,
    },
    replay::DurableSecurityState,
};

pub(super) fn prepared(
    state: &DurableSecurityState,
    operation: &str,
    request: &EndpointIndependentRevocationPreFinalRequestV1,
    now: u64,
) -> Result<IndependentApproveResume, AgentError> {
    let wire = serde_json::to_string(request).map_err(|_| AgentError::RequestInvalid)?;
    crate::independent_approve_state_update::apply(state, operation, now, |record| {
        if record.phase != P::ApprovalAccepted {
            return Err(AgentError::OperationReplay);
        }
        record.pre_final_request_json = Some(wire.clone());
        record.pre_final_request = Some(request.clone());
        record.phase = P::PreFinalPrepared;
        Ok(())
    })
}

pub(super) fn accepted(
    state: &DurableSecurityState,
    operation: &str,
    response_wire: &[u8],
    response: &ManagementProjectionV2,
    trust: IndependentProjectionTrustPinV1,
    now: u64,
) -> Result<IndependentApproveResume, AgentError> {
    if response_wire.len() > crate::source_options_state::MAXIMUM_PHASE_WIRE_BYTES {
        return Err(AgentError::ResponseInvalid);
    }
    let wire = std::str::from_utf8(response_wire)
        .map_err(|_| AgentError::ResponseInvalid)?
        .to_owned();
    state.transaction_namespaces(|values| {
        let (prepared, fresh, mut journal) = crate::source_options_state::documents(values)?;
        let record = journal
            .independent_approvals
            .get_mut(operation)
            .ok_or(AgentError::AuthorityRollback)?;
        if record.phase != P::PreFinalUnknown {
            return Err(AgentError::OperationReplay);
        }
        record.pre_final_response_json = Some(wire);
        record.pre_final_response = Some(response.clone());
        record.pre_final_trust = Some(trust);
        record.phase = P::PreFinalAccepted;
        record.updated_at_epoch_s = now;
        crate::source_options_state::validate(&prepared, &fresh, &journal)?;
        let result =
            crate::independent_approve_state::resume(operation, &prepared, &fresh, &journal)?;
        crate::management_state::observe_in_transaction(values, response)?;
        values.put("operation-journal", &journal)?;
        Ok((result, true))
    })
}
