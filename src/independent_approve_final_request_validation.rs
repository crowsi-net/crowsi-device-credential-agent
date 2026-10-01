use crowsi_credential_authority_contracts::{
    EndpointPreparedOperationV2, ManagementIntentV2, SignedAuthorityExchangeV1,
};
use ihat_identity_assertion_contracts::{
    AUTHORITY_REQUEST_SCHEMA, AuthorityCommand, AuthorityRequestV1, decode_authority_request_strict,
};
use sha2::{Digest, Sha256};

use crate::AgentError;

#[allow(clippy::too_many_arguments)]
pub(crate) fn validate(
    approval_key_id: &str,
    approval_public_key_hex: &str,
    prepared: &EndpointPreparedOperationV2,
    begun: &SignedAuthorityExchangeV1,
    current: &SignedAuthorityExchangeV1,
    approval: &SignedAuthorityExchangeV1,
    request: &AuthorityRequestV1,
) -> Result<(), AgentError> {
    crate::independent_approve_response_approval::validate(
        approval_key_id,
        approval_public_key_hex,
        prepared,
        begun,
        current,
        approval,
    )?;
    let authority = &prepared
        .revocation
        .as_ref()
        .ok_or(AgentError::RequestInvalid)?
        .finalization_authority_id;
    let exact = command(prepared, authority, &request.command);
    (request.schema == AUTHORITY_REQUEST_SCHEMA
        && request.request_id == request_id(prepared, begun, approval)?
        && request.evidence.is_empty()
        && exact)
        .then_some(())
        .ok_or(AgentError::RequestInvalid)
}

fn command(
    prepared: &EndpointPreparedOperationV2,
    authority: &str,
    value: &AuthorityCommand,
) -> bool {
    match (&prepared.intent, value) {
        (
            ManagementIntentV2::DeviceRevocation {
                service_id,
                target_device_ref,
                expected_device_revocation_epoch,
                ..
            },
            AuthorityCommand::RevokeDeviceByRef(value),
        ) => {
            value.command_id == prepared.operation_id
                && value.service_id == *service_id
                && value.pairwise_subject == prepared.pairwise_subject
                && value.target_device_id == *target_device_ref
                && value.expected_device_epoch == *expected_device_revocation_epoch
                && value.authority_id == authority
        }
        (
            ManagementIntentV2::SessionRevocation {
                service_id,
                target_session_ref,
                expected_session_revocation_epoch,
                ..
            },
            AuthorityCommand::RevokeSessionByRef(value),
        ) => {
            value.command_id == prepared.operation_id
                && value.service_id == *service_id
                && value.pairwise_subject == prepared.pairwise_subject
                && value.session_ref == *target_session_ref
                && value.expected_epoch == *expected_session_revocation_epoch
                && value.authority_id == authority
        }
        _ => false,
    }
}

pub(super) fn request_id(
    prepared: &EndpointPreparedOperationV2,
    begun: &SignedAuthorityExchangeV1,
    approval: &SignedAuthorityExchangeV1,
) -> Result<String, AgentError> {
    let metadata = crate::source_approve_revocation_response_begin::metadata(prepared, begun)?;
    let mut digest = Sha256::new();
    digest.update(b"CROWSI-INDEPENDENT-REVOCATION-FINAL-REQUEST-V1\0");
    for field in [
        &prepared.operation_id,
        &metadata.attempt_id,
        &approval.request.request_id,
    ] {
        let length = u32::try_from(field.len()).map_err(|_| AgentError::RequestInvalid)?;
        digest.update(length.to_be_bytes());
        digest.update(field.as_bytes());
    }
    Ok(hex::encode(digest.finalize()))
}

pub(super) fn strict(value: AuthorityRequestV1) -> Result<AuthorityRequestV1, AgentError> {
    let wire = serde_json::to_vec(&value).map_err(|_| AgentError::RequestInvalid)?;
    let decoded = decode_authority_request_strict(&wire).map_err(|_| AgentError::RequestInvalid)?;
    (decoded == value)
        .then_some(decoded)
        .ok_or(AgentError::RequestInvalid)
}
