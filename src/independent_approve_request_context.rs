use crowsi_credential_authority_contracts::EndpointPreparedOperationV2;
use sha2::{Digest, Sha256};

use crate::{AgentError, config::AgentConfigDocument};

pub(super) fn authority<'a>(
    config: &'a AgentConfigDocument,
    prepared: &'a EndpointPreparedOperationV2,
    actor: &str,
) -> Result<&'a str, AgentError> {
    let required = required(prepared, actor)?;
    (required == config.revocation_approval_authority_ref)
        .then_some(required)
        .ok_or(AgentError::RequestInvalid)
}

pub(super) fn required<'a>(
    prepared: &'a EndpointPreparedOperationV2,
    actor: &str,
) -> Result<&'a str, AgentError> {
    let requirements = prepared
        .revocation
        .as_ref()
        .ok_or(AgentError::RequestInvalid)?;
    let required = requirements
        .required_approval_authority_ref
        .as_deref()
        .ok_or(AgentError::RequestInvalid)?;
    (actor != prepared.source_device_ref && actor != requirements.target_device_ref)
        .then_some(required)
        .ok_or(AgentError::RequestInvalid)
}

pub(super) fn id(label: &str, fields: &[&str]) -> Result<String, AgentError> {
    let mut digest = Sha256::new();
    digest.update(b"CROWSI-INDEPENDENT-REVOCATION-APPROVAL-V1\0");
    for field in std::iter::once(label).chain(fields.iter().copied()) {
        let length = u32::try_from(field.len()).map_err(|_| AgentError::RequestInvalid)?;
        digest.update(length.to_be_bytes());
        digest.update(field.as_bytes());
    }
    Ok(hex::encode(digest.finalize()))
}
