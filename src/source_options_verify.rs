use crate::{AgentError, config::AgentConfigDocument};
use crowsi_credential_authority_contracts::{
    ENDPOINT_MANAGEMENT_ENVELOPE_SCHEMA, EndpointManagementEnvelopeV2,
    EndpointManagementEvidenceV2, EndpointPreparedOperationV2, ManagementOperationState,
    ManagementProjectionBodyV2, ManagementProjectionV2, ManagementRequestV2, RequiredActorRole,
    SignedAuthorityExchangeV1, WebAuthnOptionsV2, decode_endpoint_management_envelope_strict,
    endpoint_operation_digest, identity_evidence_from_exchange, validate_authority_exchange,
};
use ihat_identity_assertion_contracts::{
    AuthorityCommand, AuthorityResult, BeginFreshUvCommand, FreshUvRequestOptions, ResponseOutcome,
    command_digest,
};
const INVALID: AgentError = AgentError::AuthorityResponseInvalid;
#[allow(clippy::too_many_arguments)]
pub(crate) fn envelope(
    config: &AgentConfigDocument,
    browser_request: &ManagementRequestV2,
    identity_exchange: &SignedAuthorityExchangeV1,
    prepared: &EndpointPreparedOperationV2,
    uv_options: &SignedAuthorityExchangeV1,
    now: u64,
) -> Result<EndpointManagementEnvelopeV2, AgentError> {
    let credential = &config.user_verification_credential_id;
    validate_begin(credential, identity_exchange, prepared, uv_options, now)?;
    strict(EndpointManagementEnvelopeV2 {
        schema: ENDPOINT_MANAGEMENT_ENVELOPE_SCHEMA.into(),
        browser_request: browser_request.clone(),
        evidence: EndpointManagementEvidenceV2::SourceOptions {
            identity_exchange: identity_exchange.clone(),
            prepared: prepared.clone(),
            uv_options: uv_options.clone(),
        },
    })
}
pub(crate) fn projection(
    prepared: &EndpointPreparedOperationV2,
    uv_options: &SignedAuthorityExchangeV1,
    cached_snapshot_revision: u64,
    value: &ManagementProjectionV2,
) -> Result<(), AgentError> {
    let (_, fresh) = begin(uv_options)?;
    let expected_revision = cached_snapshot_revision
        .checked_add(1)
        .ok_or(AgentError::AuthorityResponseInvalid)?;
    let ManagementProjectionBodyV2::Operation { operation } = &value.body else {
        return Err(AgentError::AuthorityResponseInvalid);
    };
    let actor = &operation.actor;
    let exact = value.snapshot_revision >= expected_revision
        && operation.operation_id == prepared.operation_id
        && operation.source_device_ref == prepared.source_device_ref
        && operation.intent_digest_sha256 == prepared.origin_command_digest_sha256
        && operation.expires_at_epoch_s == prepared.expires_at_epoch_s
        && operation.state == ManagementOperationState::AwaitingSourceUv
        && operation.state_revision == 1
        && actor.role == RequiredActorRole::SourceDevice
        && actor.required_actor_device_ref.as_deref() == Some(&prepared.source_device_ref)
        && actor.required_approval_authority_ref.is_none()
        && actor.excluded_actor_device_refs.is_empty()
        && operation.webauthn_options.as_ref() == Some(&webauthn(fresh))
        && operation.reason.is_none()
        && operation.reconcile_digest.is_none();
    exact.then_some(()).ok_or(INVALID)
}
pub(crate) fn validate_begin(
    configured_credential: &str,
    identity_exchange: &SignedAuthorityExchangeV1,
    prepared: &EndpointPreparedOperationV2,
    exchange: &SignedAuthorityExchangeV1,
    now: u64,
) -> Result<(), AgentError> {
    let identity = identity_evidence_from_exchange(identity_exchange)
        .map_err(|_| AgentError::AuthorityResponseInvalid)?;
    let (command, options) = begin(exchange)?;
    let epochs = &identity.assertion.revocation_epochs;
    let issued = exchange.response.issued_at_epoch_s;
    let causal_floor = identity_exchange
        .response
        .issued_at_epoch_s
        .max(identity.assertion.issued_at_epoch_s)
        .max(identity.current_status.issued_at_epoch_s)
        .max(prepared.issued_at_epoch_s);
    let epochs_exact = command.subject_epoch == epochs.subject
        && command.service_epoch == epochs.service
        && command.device_epoch == epochs.device
        && command.session_epoch == epochs.session;
    let exact = exchange.request.evidence.is_empty()
        && command.credential_id == configured_credential
        && options.credential_id == configured_credential
        && command.identity_nonce == identity.assertion.nonce
        && command.source_device_id == prepared.source_device_ref
        && command.service_id == identity.assertion.service_id
        && command.pairwise_subject == prepared.pairwise_subject
        && command.session_ref == prepared.source_session_ref
        && command.operation_digest_sha256
            == endpoint_operation_digest(prepared)
                .map_err(|_| AgentError::AuthorityResponseInvalid)?
        && epochs_exact
        && options.command_binding_sha256
            == command_digest(&exchange.request)
                .map_err(|_| AgentError::AuthorityResponseInvalid)?
        && exchange.response.config_generation >= identity_exchange.response.config_generation
        && issued >= causal_floor
        && issued <= now
        && now < exchange.response.expires_at_epoch_s
        && exchange.response.expires_at_epoch_s <= prepared.expires_at_epoch_s
        && issued < options.expires_at_epoch_s
        && now < options.expires_at_epoch_s
        && options.expires_at_epoch_s <= prepared.expires_at_epoch_s;
    exact.then_some(()).ok_or(INVALID)
}
fn begin(
    value: &SignedAuthorityExchangeV1,
) -> Result<(&BeginFreshUvCommand, &FreshUvRequestOptions), AgentError> {
    validate_authority_exchange(value, "begin_fresh_user_verification")
        .map_err(|_| AgentError::AuthorityResponseInvalid)?;
    match (&value.request.command, &value.response.outcome) {
        (
            AuthorityCommand::BeginFreshUserVerification(command),
            ResponseOutcome::Committed {
                result: AuthorityResult::FreshUvBegun(options),
            },
        ) => Ok((command, options)),
        _ => Err(AgentError::AuthorityResponseInvalid),
    }
}
fn strict(value: EndpointManagementEnvelopeV2) -> Result<EndpointManagementEnvelopeV2, AgentError> {
    let wire = serde_json::to_vec(&value).map_err(|_| AgentError::RequestInvalid)?;
    let decoded = decode_endpoint_management_envelope_strict(&wire)
        .map_err(|_| AgentError::AuthorityResponseInvalid)?;
    (decoded == value).then_some(decoded).ok_or(INVALID)
}

pub(crate) fn webauthn(value: &FreshUvRequestOptions) -> WebAuthnOptionsV2 {
    WebAuthnOptionsV2 {
        attempt_id: value.attempt_id.clone(),
        challenge: value.challenge.clone(),
        rp_id: value.rp_id.clone(),
        origin: value.origin.clone(),
        credential_id: value.credential_id.clone(),
        timeout_ms: value.timeout_ms,
        expires_at_epoch_s: value.expires_at_epoch_s,
        command_binding_sha256: value.command_binding_sha256.clone(),
    }
}

#[cfg(test)]
#[path = "source_options_verify_tests.rs"]
mod tests;
