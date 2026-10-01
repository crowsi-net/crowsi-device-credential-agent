use crowsi_credential_authority_contracts::{
    ENDPOINT_MANAGEMENT_ENVELOPE_SCHEMA, EndpointManagementEnvelopeV2,
    EndpointManagementEvidenceV2, SignedTargetDeviceProofV2,
    decode_endpoint_management_envelope_strict, fresh_uv_from_finish_exchange,
    identity_evidence_from_exchange, verify_target_device_proof_at,
};
use crowsi_windows_operation_contracts::{
    OPERATION_RESPONSE_SCHEMA, OperationOnlyAction, OperationOnlyResponse, OperationOnlyResult,
};

use crate::{
    AgentError, config::AgentConfigDocument, target_approve_state_types::TargetApproveResume,
};

pub(crate) fn signed(
    config: &AgentConfigDocument,
    value: &TargetApproveResume,
    response: &OperationOnlyResponse,
    now: u64,
) -> Result<SignedTargetDeviceProofV2, AgentError> {
    let pa = value
        .approval
        .pa_response
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    let input = value
        .approval
        .pa_request
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    let signature = match (&pa.action, &response.result) {
        (
            OperationOnlyAction::Sign { algorithm, .. },
            OperationOnlyResult::Signature {
                algorithm: actual,
                value_hex,
            },
        ) if algorithm == actual && lower_hex(value_hex, 64) => value_hex,
        _ => return Err(AgentError::TargetKeyProofInvalid),
    };
    let exact = response.schema == OPERATION_RESPONSE_SCHEMA
        && response.request_id == pa.request_id
        && response.credential_id == pa.credential_id
        && response.revision == pa.expected_revision
        && !response.contains_secret_values
        && !response.secret_follows;
    if !exact {
        return Err(AgentError::TargetKeyProofInvalid);
    }
    let proof = SignedTargetDeviceProofV2 {
        binding: input.target_device_proof.clone(),
        signature_hex: signature.clone(),
    };
    let identity = identity_evidence_from_exchange(&input.current_identity_exchange)
        .map_err(|_| AgentError::AuthorityResponseInvalid)?;
    let fresh =
        fresh_uv_from_finish_exchange(&input.finish_exchange, &input.management_request.command)
            .map_err(|_| AgentError::AuthorityResponseInvalid)?;
    let key = crate::target_approve_key::device_key(config, value)?;
    verify_target_device_proof_at(
        identity,
        &input.prepared,
        fresh,
        &proof,
        &key.device_proof_key_ref,
        &key.public_key_hex,
        now,
    )
    .map_err(|_| AgentError::TargetKeyProofInvalid)?;
    Ok(proof)
}

pub(crate) fn envelope(
    value: &TargetApproveResume,
    proof: &SignedTargetDeviceProofV2,
) -> Result<EndpointManagementEnvelopeV2, AgentError> {
    let current = value
        .approval
        .current_exchange
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    let finish = value
        .approval
        .finish_exchange
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    let envelope = EndpointManagementEnvelopeV2 {
        schema: ENDPOINT_MANAGEMENT_ENVELOPE_SCHEMA.into(),
        browser_request: value.approval.browser_request.clone(),
        evidence: EndpointManagementEvidenceV2::TargetApprove {
            identity_exchange: current.clone(),
            prepared: value.lookup.response.prepared.clone(),
            finish_uv_exchange: finish.clone(),
            target_proof: proof.clone(),
        },
    };
    let wire = serde_json::to_vec(&envelope).map_err(|_| AgentError::RequestInvalid)?;
    let decoded = decode_endpoint_management_envelope_strict(&wire)
        .map_err(|_| AgentError::TargetKeyProofInvalid)?;
    (decoded == envelope)
        .then_some(decoded)
        .ok_or(AgentError::TargetKeyProofInvalid)
}

fn lower_hex(value: &str, bytes: usize) -> bool {
    value.len() == bytes * 2
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}
