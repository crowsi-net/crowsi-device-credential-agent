use crowsi_credential_authority_contracts::{
    EndpointPreparedOperationV2, ManagementIntentV2, RevocationRequirementsV2,
    endpoint_operation_digest,
};
use ihat_identity_assertion_contracts::FreshUvV1;

use crate::{AgentError, validation};

pub(crate) fn requirements(
    prepared: &EndpointPreparedOperationV2,
) -> Result<&RevocationRequirementsV2, AgentError> {
    let value = prepared
        .revocation
        .as_ref()
        .ok_or(AgentError::RequestInvalid)?;
    let shape = match &prepared.intent {
        ManagementIntentV2::DeviceTransfer { .. } => false,
        ManagementIntentV2::DeviceRevocation {
            target_device_ref, ..
        } => {
            value.target_device_ref == *target_device_ref
                && value.expected_revoked_session_count.is_some()
        }
        ManagementIntentV2::SessionRevocation { .. } => {
            value.expected_revoked_session_count.is_none()
        }
    };
    let independent = value.target_device_ref != prepared.source_device_ref;
    let exact = shape
        && value.required_approval_authority_ref.is_some() == independent
        && identifier(&value.target_device_ref)
        && identifier(&value.finalization_authority_id)
        && value
            .required_approval_authority_ref
            .as_deref()
            .is_none_or(identifier);
    exact.then_some(value).ok_or(AgentError::RequestInvalid)
}

pub(crate) fn fresh(
    prepared: &EndpointPreparedOperationV2,
    value: &FreshUvV1,
    now: u64,
) -> Result<(), AgentError> {
    let operation = endpoint_operation_digest(prepared).map_err(|_| AgentError::RequestInvalid)?;
    let service = service(&prepared.intent);
    let exact = prepared.issued_at_epoch_s <= now
        && now < prepared.expires_at_epoch_s
        && value.issued_at_epoch_s <= now
        && now < value.expires_at_epoch_s
        && value.expires_at_epoch_s <= prepared.expires_at_epoch_s
        && value.user_verified
        && value.identity_nonce == prepared.source_identity_nonce
        && value.source_device_id == prepared.source_device_ref
        && value.service_id == service
        && value.pairwise_subject == prepared.pairwise_subject
        && value.session_ref == prepared.source_session_ref
        && value.operation_digest_sha256 == operation;
    exact.then_some(()).ok_or(AgentError::RequestInvalid)
}

pub(crate) fn independent(prepared: &EndpointPreparedOperationV2) -> Result<bool, AgentError> {
    Ok(requirements(prepared)?.target_device_ref != prepared.source_device_ref)
}

pub(crate) fn service(value: &ManagementIntentV2) -> &str {
    match value {
        ManagementIntentV2::DeviceTransfer { service_id, .. }
        | ManagementIntentV2::DeviceRevocation { service_id, .. }
        | ManagementIntentV2::SessionRevocation { service_id, .. } => service_id,
    }
}

fn identifier(value: &str) -> bool {
    validation::id(value, 128)
}
