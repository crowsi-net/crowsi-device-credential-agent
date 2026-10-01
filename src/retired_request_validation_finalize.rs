use crowsi_credential_authority_contracts::{
    decode_endpoint_independent_revocation_finalize_request_strict,
    decode_endpoint_revocation_finalize_request_strict, management_command_digest,
};

use crate::{AgentError, retired_request_types::RetiredRequestReceiptV1};

pub(super) fn independent(
    request: &str,
    value: &RetiredRequestReceiptV1,
    wire: &str,
) -> Result<(), AgentError> {
    let decoded = decode_endpoint_independent_revocation_finalize_request_strict(wire.as_bytes())
        .map_err(|_| AgentError::AuthorityRollback)?;
    let digest = management_command_digest(&decoded.approve_revocation_request)
        .map_err(|_| AgentError::AuthorityRollback)?;
    let exact = value.route == "independent-revocation-finalize"
        && decoded.approve_revocation_request.request_id == request
        && digest == value.browser_request_digest_sha256
        && decoded.operation_id == value.operation_id
        && decoded.prepared.operation_id == value.operation_id;
    exact.then_some(()).ok_or(AgentError::AuthorityRollback)
}

pub(super) fn source(
    request: &str,
    value: &RetiredRequestReceiptV1,
    wire: &str,
) -> Result<(), AgentError> {
    let decoded = decode_endpoint_revocation_finalize_request_strict(wire.as_bytes())
        .map_err(|_| AgentError::AuthorityRollback)?;
    let digest = management_command_digest(&decoded.source_approve_request)
        .map_err(|_| AgentError::AuthorityRollback)?;
    let exact = value.route == "revocation-finalize"
        && decoded.source_approve_request.request_id == request
        && digest == value.browser_request_digest_sha256
        && decoded.operation_id == value.operation_id
        && decoded.prepared.operation_id == value.operation_id;
    exact.then_some(()).ok_or(AgentError::AuthorityRollback)
}
