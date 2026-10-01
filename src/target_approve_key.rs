use crowsi_credential_authority_contracts::identity_evidence_from_exchange;

use crate::{
    AgentError,
    config::{AgentConfigDocument, DeviceProofKeyTrust},
    target_approve_state_types::TargetApproveResume,
};

pub(super) fn device_key<'a>(
    config: &'a AgentConfigDocument,
    value: &TargetApproveResume,
) -> Result<&'a DeviceProofKeyTrust, AgentError> {
    let current = value
        .approval
        .current_exchange
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    let identity = identity_evidence_from_exchange(current)
        .map_err(|_| AgentError::AuthorityResponseInvalid)?;
    let prepared = &value.lookup.response.prepared;
    let mut owners = config.owner_mappings.iter().filter(|item| {
        item.issuer == identity.assertion.issuer
            && item.service_id == identity.assertion.service_id
            && item.pairwise_subject == identity.assertion.pairwise_subject
    });
    let owner = owners.next().ok_or(AgentError::OwnerMappingUnknown)?;
    if owners.next().is_some() || owner.opaque_owner_ref != prepared.opaque_owner_ref {
        return Err(AgentError::OwnerMappingUnknown);
    }
    let mut keys = config.device_proof_keys.iter().filter(|item| {
        item.opaque_owner_ref == prepared.opaque_owner_ref
            && item.device_id == identity.assertion.device_id
            && item.device_proof_key_ref == identity.assertion.device_proof_key_ref
    });
    let key = keys.next().ok_or(AgentError::OwnerMappingUnknown)?;
    if keys.next().is_some() {
        return Err(AgentError::OwnerMappingUnknown);
    }
    Ok(key)
}
