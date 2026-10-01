use crowsi_credential_authority_contracts::{
    EndpointAuthorityResponseTrustV2, EndpointFreshUvTrustV2, EndpointIdentityTrustV2,
    ManagementIntentV2, TargetDeviceProofBindingV2, endpoint_operation_digest,
    identity_evidence_from_exchange, target_device_proof_digest, verify_endpoint_approval_at,
};
use crowsi_windows_operation_contracts::{
    OPERATION_AUTHORIZE_ONCE_REQUEST_SCHEMA, OperationAuthorizeOnceRequestV2,
    OperationOnlyCredentialClass, OperationOnlySignIntentV1, SigningAlgorithm,
    decode_operation_authorize_once_request,
};

use crate::{
    AgentError, config::AgentConfigDocument, target_approve_state_types::TargetApproveResume,
};

pub(crate) fn pa_request(
    config: &AgentConfigDocument,
    value: &TargetApproveResume,
    now: u64,
) -> Result<OperationAuthorizeOnceRequestV2, AgentError> {
    approval(config, value, now)?;
    let finish = value
        .approval
        .finish_exchange
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    let current = value
        .approval
        .current_exchange
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    let identity = identity_evidence_from_exchange(current)
        .map_err(|_| AgentError::AuthorityResponseInvalid)?;
    let key = crate::target_approve_key::device_key(config, value)?;
    let prepared = &value.lookup.response.prepared;
    let ManagementIntentV2::DeviceTransfer { service_id, .. } = &prepared.intent else {
        return Err(AgentError::RequestInvalid);
    };
    let expires = now
        .saturating_add(60)
        .min(value.approval.expires_at_epoch_s);
    if expires <= now {
        return Err(AgentError::FreshUserVerificationRequired);
    }
    let target = TargetDeviceProofBindingV2 {
        schema: "crowsi://identity/target-device-key-proof/v2".into(),
        owner_ref: prepared.opaque_owner_ref.clone(),
        service_id: service_id.clone(),
        pairwise_subject: identity.assertion.pairwise_subject.clone(),
        operation_id: prepared.operation_id.clone(),
        challenge_digest_sha256: endpoint_operation_digest(prepared)
            .map_err(|_| AgentError::RequestInvalid)?,
        source_device_ref: prepared.source_device_ref.clone(),
        target_device_ref: identity.assertion.device_id.clone(),
        device_proof_key_ref: identity.assertion.device_proof_key_ref.clone(),
        custody_revision: key.custody_expected_revision.clone(),
        status_nonce: identity.current_status.nonce.clone(),
        issued_at_epoch_s: now,
        expires_at_epoch_s: expires,
        nonce: prepared.nonce.clone(),
        key_id: key.device_proof_key_ref.clone(),
    };
    let proof_digest =
        target_device_proof_digest(&target).map_err(|_| AgentError::TargetKeyProofInvalid)?;
    strict(OperationAuthorizeOnceRequestV2 {
        schema: OPERATION_AUTHORIZE_ONCE_REQUEST_SCHEMA.into(),
        selected_identity_exchange: value.selected_identity.clone(),
        selected_begin_exchange: value.selected_begin.clone(),
        finish_exchange: finish.clone(),
        current_identity_exchange: current.clone(),
        prepared: prepared.clone(),
        management_request: value.approval.browser_request.clone(),
        target_device_proof: target,
        sign_intent: OperationOnlySignIntentV1 {
            request_id: value.approval.browser_request.request_id.clone(),
            credential_id: key.custody_credential_id.clone(),
            expected_revision: key.custody_expected_revision.clone(),
            credential_class: OperationOnlyCredentialClass::Ed25519SigningKey,
            algorithm: SigningAlgorithm::Ed25519,
            digest_sha256: format!("sha256:{}", hex::encode(proof_digest)),
        },
    })
}

fn strict(
    value: OperationAuthorizeOnceRequestV2,
) -> Result<OperationAuthorizeOnceRequestV2, AgentError> {
    let wire = serde_json::to_vec(&value).map_err(|_| AgentError::RequestInvalid)?;
    let decoded = decode_operation_authorize_once_request(&wire)
        .map_err(|_| AgentError::TargetKeyProofInvalid)?;
    (decoded == value)
        .then_some(decoded)
        .ok_or(AgentError::TargetKeyProofInvalid)
}

fn approval(
    config: &AgentConfigDocument,
    value: &TargetApproveResume,
    now: u64,
) -> Result<(), AgentError> {
    let finish = value
        .approval
        .finish_exchange
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    let current = value
        .approval
        .current_exchange
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    verify_endpoint_approval_at(
        &value.selected_identity,
        &value.selected_begin,
        finish,
        current,
        &value.lookup.response.prepared,
        &value.approval.browser_request.command,
        &EndpointAuthorityResponseTrustV2 {
            minimum_config_generation: config.minimum_identity_config_generation,
            key_id: &config.authority_response_key_id,
            public_key_hex: &config.authority_response_public_key_hex,
        },
        &EndpointIdentityTrustV2 {
            issuer: &config.identity_issuer,
            audience: &config.identity_audience,
            assertion_key_id: &config.identity_key_id,
            assertion_public_key_hex: &config.identity_public_key_hex,
            current_status_key_id: &config.current_status_key_id,
            current_status_public_key_hex: &config.current_status_public_key_hex,
            now_epoch_s: now,
        },
        &EndpointFreshUvTrustV2 {
            account_binding_sha256: &config.user_verification_account_binding_sha256,
            key_id: &config.user_verification_key_id,
            public_key_hex: &config.user_verification_public_key_hex,
            now_epoch_s: now,
        },
    )
    .map(|_| ())
    .map_err(|_| AgentError::AuthorityResponseInvalid)
}
