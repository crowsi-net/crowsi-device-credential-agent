use crowsi_credential_authority_contracts::{
    EndpointPreparedOperationV2, ManagementCommandV2, ManagementRequestV2, endpoint_operation_id,
    management_command_digest, validate_endpoint_prepared_at,
};
use ihat_identity_assertion_contracts::IdentityEvidenceMetadata;

use crate::{AgentError, config::AgentConfigDocument, management_state::CachedManagementSnapshot};

pub(crate) fn build(
    request: &ManagementRequestV2,
    identity: &IdentityEvidenceMetadata,
    cached: &CachedManagementSnapshot,
    config: &AgentConfigDocument,
    now: u64,
) -> Result<EndpointPreparedOperationV2, AgentError> {
    let ManagementCommandV2::SourceOptions { intent } = &request.command else {
        return Err(AgentError::RequestInvalid);
    };
    crate::prepared_operation_snapshot::validate(
        &cached.snapshot,
        cached.revision,
        intent,
        identity,
    )?;
    let expires = now.checked_add(300).ok_or(AgentError::RequestInvalid)?;
    let mut value = EndpointPreparedOperationV2 {
        operation_id: String::new(),
        origin_command_digest_sha256: management_command_digest(request)
            .map_err(|_| AgentError::RequestInvalid)?,
        source_device_ref: identity.assertion.device_id.clone(),
        source_session_ref: identity.assertion.session_ref.clone(),
        pairwise_subject: identity.assertion.pairwise_subject.clone(),
        opaque_owner_ref: config
            .management_projection_trust
            .opaque_account_ref
            .clone(),
        source_identity_nonce: identity.assertion.nonce.clone(),
        nonce: crate::random_id::create("operation-nonce")?,
        issued_at_epoch_s: now,
        expires_at_epoch_s: expires,
        intent: intent.clone(),
        revocation: crate::prepared_operation_revocation::build(
            &cached.snapshot,
            intent,
            identity,
            &config.identity_finalization_authority_id,
            &config.revocation_approval_authority_ref,
        )?,
    };
    value.operation_id = endpoint_operation_id(&value).map_err(|_| AgentError::RequestInvalid)?;
    validate_endpoint_prepared_at(&value, identity, now).map_err(|_| AgentError::RequestInvalid)?;
    Ok(value)
}
