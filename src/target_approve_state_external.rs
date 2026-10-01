use crowsi_credential_authority_contracts::{
    EndpointManagementEnvelopeV2, SignedTargetDeviceProofV2,
};
use crowsi_windows_operation_contracts::{OperationOnlyRequest, OperationOnlyResponse};

use crate::{
    AgentError,
    replay::DurableSecurityState,
    source_options_state,
    target_approve_state_types::{TargetApprovePhaseV1, TargetApproveResume},
};

pub(crate) fn pa_complete(
    state: &DurableSecurityState,
    operation: &str,
    wire: &[u8],
    response: &OperationOnlyRequest,
    now: u64,
) -> Result<TargetApproveResume, AgentError> {
    let wire = bounded(wire)?;
    update(state, operation, now, |record| {
        if record.phase != TargetApprovePhaseV1::PaUnknown {
            let same = record.phase == TargetApprovePhaseV1::CustodyPrepared
                && record.pa_response.as_ref() == Some(response)
                && record.pa_response_json.as_deref() == Some(wire.as_str());
            return same.then_some(()).ok_or(AgentError::OperationReplay);
        }
        record.pa_response_json = Some(wire.clone());
        record.pa_response = Some(response.clone());
        record.phase = TargetApprovePhaseV1::CustodyPrepared;
        Ok(())
    })
}

pub(crate) fn custody_complete(
    state: &DurableSecurityState,
    operation: &str,
    wire: &[u8],
    response: &OperationOnlyResponse,
    proof: &SignedTargetDeviceProofV2,
    envelope: &EndpointManagementEnvelopeV2,
    now: u64,
) -> Result<TargetApproveResume, AgentError> {
    let custody_wire = bounded(wire)?;
    let envelope_wire = serde_json::to_string(envelope).map_err(|_| AgentError::RequestInvalid)?;
    if envelope_wire.len() > source_options_state::MAXIMUM_PHASE_WIRE_BYTES {
        return Err(AgentError::RequestInvalid);
    }
    update(state, operation, now, |record| {
        if record.phase != TargetApprovePhaseV1::CustodyUnknown {
            let same = record.phase == TargetApprovePhaseV1::CentralPrepared
                && record.custody_response.as_ref() == Some(response)
                && record.custody_response_json.as_deref() == Some(custody_wire.as_str())
                && record.target_proof.as_ref() == Some(proof)
                && record.central_envelope.as_ref() == Some(envelope)
                && record.central_envelope_json.as_deref() == Some(envelope_wire.as_str());
            return same.then_some(()).ok_or(AgentError::OperationReplay);
        }
        record.custody_response_json = Some(custody_wire.clone());
        record.custody_response = Some(response.clone());
        record.target_proof = Some(proof.clone());
        record.central_envelope_json = Some(envelope_wire.clone());
        record.central_envelope = Some(envelope.clone());
        record.phase = TargetApprovePhaseV1::CentralPrepared;
        Ok(())
    })
}

fn bounded(wire: &[u8]) -> Result<String, AgentError> {
    if wire.is_empty() || wire.len() > source_options_state::MAXIMUM_PHASE_WIRE_BYTES {
        return Err(AgentError::ResponseInvalid);
    }
    std::str::from_utf8(wire)
        .map(str::to_owned)
        .map_err(|_| AgentError::ResponseInvalid)
}

fn update(
    state: &DurableSecurityState,
    operation: &str,
    now: u64,
    change: impl FnOnce(
        &mut crate::target_approve_state_types::TargetApproveRecordV1,
    ) -> Result<(), AgentError>,
) -> Result<TargetApproveResume, AgentError> {
    state.transaction_namespaces(|values| {
        let (prepared, fresh, mut journal) = source_options_state::documents(values)?;
        {
            let record = journal
                .target_approvals
                .get_mut(operation)
                .ok_or(AgentError::AuthorityRollback)?;
            if now < record.updated_at_epoch_s {
                return Err(AgentError::AuthorityRollback);
            }
            change(record)?;
            record.updated_at_epoch_s = now;
        }
        let value = crate::target_approve_state::resume(operation, &prepared, &fresh, &journal)?;
        let expires = crate::target_approve_state_expiration::expiration(&value)?;
        if now >= expires {
            return Err(AgentError::FreshUserVerificationRequired);
        }
        journal
            .target_approvals
            .get_mut(operation)
            .ok_or(AgentError::AuthorityRollback)?
            .expires_at_epoch_s = expires;
        source_options_state::validate(&prepared, &fresh, &journal)?;
        let result = crate::target_approve_state::resume(operation, &prepared, &fresh, &journal)?;
        values.put("operation-journal", &journal)?;
        Ok((result, true))
    })
}
