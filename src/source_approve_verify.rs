use crowsi_credential_authority_contracts::{
    ENDPOINT_MANAGEMENT_ENVELOPE_SCHEMA, EndpointAuthorityResponseTrustV2, EndpointFreshUvTrustV2,
    EndpointIdentityTrustV2, EndpointManagementEnvelopeV2, EndpointManagementEvidenceV2,
    EndpointPreparedOperationV2, ManagementRequestV2, RevocationSourceCeremonyV1,
    SignedAuthorityExchangeV1, decode_endpoint_management_envelope_strict,
    fresh_uv_from_finish_exchange, validate_finish_uv_continuity, verify_authority_exchange_at,
    verify_endpoint_approval_at,
};

use crate::{AgentError, config::AgentConfigDocument};

pub(crate) struct Evidence<'a> {
    pub selected_identity: &'a SignedAuthorityExchangeV1,
    pub selected_begin: &'a SignedAuthorityExchangeV1,
    pub finish: &'a SignedAuthorityExchangeV1,
    pub current_identity: &'a SignedAuthorityExchangeV1,
    pub revocation: Option<RevocationSourceCeremonyV1>,
}

pub(crate) fn finish(
    config: &AgentConfigDocument,
    browser: &ManagementRequestV2,
    selected: &SignedAuthorityExchangeV1,
    value: &SignedAuthorityExchangeV1,
    now: u64,
) -> Result<(), AgentError> {
    verify_authority_exchange_at(
        value,
        "finish_fresh_user_verification",
        config.minimum_identity_config_generation,
        &config.authority_response_key_id,
        &config.authority_response_public_key_hex,
        now,
    )
    .map_err(|_| AgentError::AuthorityResponseInvalid)?;
    let fresh = fresh_uv_from_finish_exchange(value, &browser.command)
        .map_err(|_| AgentError::AuthorityResponseInvalid)?;
    validate_finish_uv_continuity(selected, value, &browser.command)
        .map_err(|_| AgentError::AuthorityResponseInvalid)?;
    let causal = selected.response.config_generation <= value.response.config_generation
        && selected.response.issued_at_epoch_s <= value.response.issued_at_epoch_s
        && value.response.issued_at_epoch_s <= fresh.issued_at_epoch_s
        && now < fresh.expires_at_epoch_s;
    causal.then_some(()).ok_or(AgentError::AuthorityRollback)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn envelope(
    config: &AgentConfigDocument,
    browser: &ManagementRequestV2,
    prepared: &EndpointPreparedOperationV2,
    evidence: Evidence<'_>,
    now: u64,
) -> Result<EndpointManagementEnvelopeV2, AgentError> {
    let authority = EndpointAuthorityResponseTrustV2 {
        minimum_config_generation: config.minimum_identity_config_generation,
        key_id: &config.authority_response_key_id,
        public_key_hex: &config.authority_response_public_key_hex,
    };
    let identity = EndpointIdentityTrustV2 {
        issuer: &config.identity_issuer,
        audience: &config.identity_audience,
        assertion_key_id: &config.identity_key_id,
        assertion_public_key_hex: &config.identity_public_key_hex,
        current_status_key_id: &config.current_status_key_id,
        current_status_public_key_hex: &config.current_status_public_key_hex,
        now_epoch_s: now,
    };
    let fresh = EndpointFreshUvTrustV2 {
        account_binding_sha256: &config.user_verification_account_binding_sha256,
        key_id: &config.user_verification_key_id,
        public_key_hex: &config.user_verification_public_key_hex,
        now_epoch_s: now,
    };
    verify_endpoint_approval_at(
        evidence.selected_identity,
        evidence.selected_begin,
        evidence.finish,
        evidence.current_identity,
        prepared,
        &browser.command,
        &authority,
        &identity,
        &fresh,
    )
    .map_err(|_| AgentError::AuthorityResponseInvalid)?;
    let value = EndpointManagementEnvelopeV2 {
        schema: ENDPOINT_MANAGEMENT_ENVELOPE_SCHEMA.into(),
        browser_request: browser.clone(),
        evidence: EndpointManagementEvidenceV2::SourceApprove {
            identity_exchange: evidence.current_identity.clone(),
            prepared: prepared.clone(),
            finish_uv_exchange: evidence.finish.clone(),
            revocation_ceremony: evidence.revocation,
        },
    };
    let wire = serde_json::to_vec(&value).map_err(|_| AgentError::RequestInvalid)?;
    let decoded = decode_endpoint_management_envelope_strict(&wire)
        .map_err(|_| AgentError::AuthorityResponseInvalid)?;
    (decoded == value)
        .then_some(decoded)
        .ok_or(AgentError::AuthorityResponseInvalid)
}
