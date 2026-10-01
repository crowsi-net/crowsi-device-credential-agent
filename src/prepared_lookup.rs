use crowsi_credential_authority_contracts::{
    ENDPOINT_PREPARED_LOOKUP_REQUEST_SCHEMA, EndpointPreparedLookupPhaseV1,
    EndpointPreparedLookupRequestV1, EndpointPreparedLookupResponseV1, ManagementCommandV2,
    ManagementRequestV2, SignedAuthorityExchangeV1, decode_endpoint_prepared_lookup_request_strict,
    decode_endpoint_prepared_lookup_response_strict, identity_evidence_from_exchange,
    verify_endpoint_prepared_lookup_response_at,
};

use crate::{AgentError, config::AgentConfigDocument, random_id, transport::AuthorityTransport};

pub(crate) struct VerifiedPreparedLookup {
    pub value: EndpointPreparedLookupResponseV1,
    pub wire: String,
    pub revocation_response_trust:
        Option<crate::actor_options_state_types::PreparedRevocationResponseTrustV1>,
}

pub(crate) fn build(
    browser: &ManagementRequestV2,
    phase: EndpointPreparedLookupPhaseV1,
    identity: &SignedAuthorityExchangeV1,
) -> Result<EndpointPreparedLookupRequestV1, AgentError> {
    let (operation_id, expected_state_revision, expected) = match &browser.command {
        ManagementCommandV2::TargetOptions {
            operation_id,
            expected_state_revision,
        } => (
            operation_id,
            expected_state_revision,
            EndpointPreparedLookupPhaseV1::Target,
        ),
        ManagementCommandV2::ApprovalOptions {
            operation_id,
            expected_state_revision,
        } => (
            operation_id,
            expected_state_revision,
            EndpointPreparedLookupPhaseV1::Approval,
        ),
        ManagementCommandV2::Cancel {
            operation_id,
            expected_state_revision,
        } => (
            operation_id,
            expected_state_revision,
            EndpointPreparedLookupPhaseV1::Cancel,
        ),
        ManagementCommandV2::Reconcile {
            operation_id,
            expected_state_revision,
            ..
        } => (
            operation_id,
            expected_state_revision,
            EndpointPreparedLookupPhaseV1::Reconcile,
        ),
        _ => return Err(AgentError::RequestInvalid),
    };
    if phase != expected {
        return Err(AgentError::RequestInvalid);
    }
    let value = EndpointPreparedLookupRequestV1 {
        schema: ENDPOINT_PREPARED_LOOKUP_REQUEST_SCHEMA.into(),
        request_id: random_id::create("prepared-lookup-request")?,
        operation_id: operation_id.clone(),
        expected_state_revision: *expected_state_revision,
        phase,
        identity_exchange: identity.clone(),
    };
    let wire = serde_json::to_vec(&value).map_err(|_| AgentError::RequestInvalid)?;
    let decoded = decode_endpoint_prepared_lookup_request_strict(&wire)
        .map_err(|_| AgentError::RequestInvalid)?;
    (decoded == value)
        .then_some(decoded)
        .ok_or(AgentError::RequestInvalid)
}

pub(crate) fn invoke<T: AuthorityTransport>(
    config: &AgentConfigDocument,
    transport: &T,
    request: &EndpointPreparedLookupRequestV1,
    now: u64,
) -> Result<VerifiedPreparedLookup, AgentError> {
    let request_wire = serde_json::to_vec(request).map_err(|_| AgentError::RequestInvalid)?;
    let response = transport.exchange("lookup-prepared", &request_wire, now)?;
    let value = decode_endpoint_prepared_lookup_response_strict(&response)
        .map_err(|_| AgentError::AuthorityResponseInvalid)?;
    let trust = &config.management_projection_trust;
    verify_endpoint_prepared_lookup_response_at(
        &value,
        request,
        &trust.key_id,
        &trust.public_key_hex,
        now,
    )
    .map_err(|_| AgentError::AuthorityResponseInvalid)?;
    let identity = identity_evidence_from_exchange(&request.identity_exchange)
        .map_err(|_| AgentError::IdentityUnavailable)?;
    let causal_floor = request
        .identity_exchange
        .response
        .issued_at_epoch_s
        .max(identity.assertion.issued_at_epoch_s)
        .max(identity.current_status.issued_at_epoch_s);
    if value.issued_at_epoch_s < causal_floor {
        return Err(AgentError::AuthorityRollback);
    }
    let revocation_response_trust =
        crate::prepared_lookup_revocation_trust::verify(config, request, &value, now)?;
    let wire = std::str::from_utf8(&response)
        .map_err(|_| AgentError::AuthorityResponseInvalid)?
        .to_owned();
    Ok(VerifiedPreparedLookup {
        value,
        wire,
        revocation_response_trust,
    })
}
