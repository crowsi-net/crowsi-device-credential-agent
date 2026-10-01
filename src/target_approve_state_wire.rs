use crate::{AgentError, target_approve_state_types::TargetApproveResume};
use crowsi_credential_authority_contracts::{
    EndpointManagementEvidenceV2, decode_endpoint_management_envelope_strict,
    decode_management_projection_strict, identity_evidence_from_exchange,
};
use crowsi_windows_operation_contracts::{
    OPERATION_RESPONSE_SCHEMA, OperationOnlyAction, OperationOnlyResponse, OperationOnlyResult,
    decode_operation_authorize_once_request, decode_operation_request,
};
pub(super) fn exact(value: &TargetApproveResume) -> Result<(), AgentError> {
    current(value)?;
    pa_request(value)?;
    pa_response(value)?;
    custody(value)?;
    envelope(value)?;
    response(value)
}
fn current(value: &TargetApproveResume) -> Result<(), AgentError> {
    let Some(request) = &value.approval.current_request else {
        return Ok(());
    };
    crate::current_request_validation::exact(
        request,
        value
            .approval
            .current_exchange
            .as_ref()
            .map(|exchange| &exchange.request),
    )
}
fn pa_request(value: &TargetApproveResume) -> Result<(), AgentError> {
    let Some(wire) = value.approval.pa_request_json.as_deref() else {
        return Ok(());
    };
    let decoded = decode_operation_authorize_once_request(wire.as_bytes())
        .map_err(|_| AgentError::AuthorityRollback)?;
    let exact = value.approval.pa_request.as_ref() == Some(&decoded)
        && decoded.selected_identity_exchange == value.selected_identity
        && decoded.selected_begin_exchange == value.selected_begin
        && value.approval.finish_exchange.as_ref() == Some(&decoded.finish_exchange)
        && value.approval.current_exchange.as_ref() == Some(&decoded.current_identity_exchange)
        && decoded.prepared == value.lookup.response.prepared
        && decoded.management_request == value.approval.browser_request;
    exact.then_some(()).ok_or(AgentError::AuthorityRollback)
}
fn pa_response(value: &TargetApproveResume) -> Result<(), AgentError> {
    let Some(wire) = value.approval.pa_response_json.as_deref() else {
        return Ok(());
    };
    let decoded =
        decode_operation_request(wire.as_bytes()).map_err(|_| AgentError::AuthorityRollback)?;
    let request = value
        .approval
        .pa_request
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    let identity = identity_evidence_from_exchange(&request.current_identity_exchange)
        .map_err(|_| AgentError::AuthorityRollback)?;
    let exact = value.approval.pa_response.as_ref() == Some(&decoded)
        && decoded.request_id == request.sign_intent.request_id
        && decoded.credential_id == request.sign_intent.credential_id
        && decoded.expected_revision == request.sign_intent.expected_revision
        && decoded.credential_class == request.sign_intent.credential_class
        && &decoded.current_device_status == &identity.current_status
        && matches!(&decoded.action, OperationOnlyAction::Sign { algorithm, digest_sha256 }
            if *algorithm == request.sign_intent.algorithm
                && digest_sha256 == &request.sign_intent.digest_sha256);
    exact.then_some(()).ok_or(AgentError::AuthorityRollback)
}
fn custody(value: &TargetApproveResume) -> Result<(), AgentError> {
    let Some(wire) = value.approval.custody_response_json.as_deref() else {
        return Ok(());
    };
    let mut decoder = serde_json::Deserializer::from_slice(wire.as_bytes());
    let decoded: OperationOnlyResponse =
        serde::Deserialize::deserialize(&mut decoder).map_err(|_| AgentError::AuthorityRollback)?;
    decoder.end().map_err(|_| AgentError::AuthorityRollback)?;
    let request = value
        .approval
        .pa_response
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    let signature = signature(request, &decoded)?;
    let proof = value.approval.target_proof.as_ref();
    let exact = value.approval.custody_response.as_ref() == Some(&decoded)
        && decoded.schema == OPERATION_RESPONSE_SCHEMA
        && decoded.request_id == request.request_id
        && decoded.credential_id == request.credential_id
        && decoded.revision == request.expected_revision
        && !decoded.contains_secret_values
        && !decoded.secret_follows
        && proof.is_none_or(|proof| {
            value.approval.pa_request.as_ref().is_some_and(|pa| {
                proof.binding == pa.target_device_proof && proof.signature_hex == signature
            })
        });
    exact.then_some(()).ok_or(AgentError::AuthorityRollback)
}
fn signature<'a>(
    request: &crowsi_windows_operation_contracts::OperationOnlyRequest,
    response: &'a OperationOnlyResponse,
) -> Result<&'a str, AgentError> {
    let (
        OperationOnlyAction::Sign { algorithm, .. },
        OperationOnlyResult::Signature {
            algorithm: result_algorithm,
            value_hex,
        },
    ) = (&request.action, &response.result)
    else {
        return Err(AgentError::AuthorityRollback);
    };
    (*algorithm == *result_algorithm && lower_hex(value_hex, 64))
        .then_some(value_hex.as_str())
        .ok_or(AgentError::AuthorityRollback)
}
fn envelope(value: &TargetApproveResume) -> Result<(), AgentError> {
    let Some(wire) = value.approval.central_envelope_json.as_deref() else {
        return Ok(());
    };
    let decoded = decode_endpoint_management_envelope_strict(wire.as_bytes())
        .map_err(|_| AgentError::AuthorityRollback)?;
    let exact = value.approval.central_envelope.as_ref() == Some(&decoded)
        && decoded.browser_request == value.approval.browser_request
        && matches!(&decoded.evidence, EndpointManagementEvidenceV2::TargetApprove {
            identity_exchange, prepared, finish_uv_exchange, target_proof
        } if Some(identity_exchange) == value.approval.current_exchange.as_ref()
            && prepared == &value.lookup.response.prepared
            && Some(finish_uv_exchange) == value.approval.finish_exchange.as_ref()
            && Some(target_proof) == value.approval.target_proof.as_ref());
    exact.then_some(()).ok_or(AgentError::AuthorityRollback)
}
fn response(value: &TargetApproveResume) -> Result<(), AgentError> {
    let Some(wire) = value.approval.response_json.as_deref() else {
        return Ok(());
    };
    let decoded = decode_management_projection_strict(wire.as_bytes())
        .map_err(|_| AgentError::AuthorityRollback)?;
    (value.approval.response.as_ref() == Some(&decoded))
        .then_some(())
        .ok_or(AgentError::AuthorityRollback)
}

fn lower_hex(value: &str, bytes: usize) -> bool {
    value.len() == bytes * 2
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}
