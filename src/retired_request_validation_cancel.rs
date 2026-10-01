use crowsi_credential_authority_contracts::{
    EndpointManagementEvidenceV2, EndpointRevocationExecutionCancellationCleanupCompleteV1,
    ManagementOperationState, ManagementProjectionBodyV2,
    decode_endpoint_management_envelope_strict,
    decode_endpoint_revocation_execution_cancellation_cleanup_complete_strict,
};

use crate::{
    AgentError,
    retired_request_types::{RetiredCancelCleanupCompleteV1, RetiredRequestReceiptV1},
};

pub(super) fn exact(
    request: &str,
    value: &RetiredRequestReceiptV1,
    wire: &str,
    expected: &ManagementProjectionBodyV2,
    material: Option<&RetiredCancelCleanupCompleteV1>,
) -> Result<(), AgentError> {
    crate::retired_request_validation::management(request, value, "cancel", wire)?;
    let ManagementProjectionBodyV2::Operation { operation } = expected else {
        return Err(AgentError::AuthorityRollback);
    };
    if operation.operation_id != value.operation_id
        || operation.state != ManagementOperationState::Cancelled
    {
        return Err(AgentError::AuthorityRollback);
    }
    let Some(material) = material else {
        return Ok(());
    };
    let delivery: &EndpointRevocationExecutionCancellationCleanupCompleteV1 = &material.delivery;
    let envelope = decode_endpoint_management_envelope_strict(wire.as_bytes())
        .map_err(|_| AgentError::AuthorityRollback)?;
    let EndpointManagementEvidenceV2::Cancel { prepared, .. } = &envelope.evidence else {
        return Err(AgentError::AuthorityRollback);
    };
    let delivery_wire = serde_json::to_vec(delivery).map_err(|_| AgentError::AuthorityRollback)?;
    let decoded =
        decode_endpoint_revocation_execution_cancellation_cleanup_complete_strict(&delivery_wire)
            .map_err(|_| AgentError::AuthorityRollback)?;
    let exact = decoded == *delivery
        && decoded.operation == *operation
        && decoded.operation.operation_id == value.operation_id
        && decoded.cleanup_complete_request_sha256 == material.cleanup_complete_request_sha256
        && decoded.acknowledge_result_digest_sha256 == material.acknowledge_result_digest_sha256
        && decoded.source_device_ref == prepared.source_device_ref
        && decoded.token.proof_id == decoded.cleanup_complete_id
        && decoded.token.binding_sha256 == material.cleanup_complete_request_sha256
        && decoded.token.issued_at_epoch_s <= value.retired_at_epoch_s;
    exact.then_some(()).ok_or(AgentError::AuthorityRollback)
}
