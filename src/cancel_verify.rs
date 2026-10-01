use crate::{
    AgentError, VerifiedConfig, cancel_state_types::CancelRecordV1, replay::DurableSecurityState,
};
use crowsi_credential_authority_contracts::{
    ActorRequirementV2, ENDPOINT_MANAGEMENT_ENVELOPE_SCHEMA,
    EndpointHistoricCancelProjectionTrustV1, EndpointManagementEnvelopeV2,
    EndpointManagementEvidenceV2, EndpointPreparedLookupResponseV1, ManagementCommandV2,
    ManagementOperationState, ManagementProjectionBodyV2, ManagementProjectionV2,
    ManagementReasonCode, ManagementRequestV2, RequiredActorRole, SignedAuthorityExchangeV1,
    decode_endpoint_management_envelope_strict, decode_management_projection_strict,
    verify_endpoint_historic_cancel_projection_at,
};
pub(crate) fn envelope(
    browser: &ManagementRequestV2,
    current: &SignedAuthorityExchangeV1,
    lookup: &EndpointPreparedLookupResponseV1,
) -> Result<EndpointManagementEnvelopeV2, AgentError> {
    let value = EndpointManagementEnvelopeV2 {
        schema: ENDPOINT_MANAGEMENT_ENVELOPE_SCHEMA.into(),
        browser_request: browser.clone(),
        evidence: EndpointManagementEvidenceV2::Cancel {
            identity_exchange: current.clone(),
            prepared: lookup.prepared.clone(),
        },
    };
    let wire = serde_json::to_vec(&value).map_err(|_| AgentError::RequestInvalid)?;
    let decoded = decode_endpoint_management_envelope_strict(&wire)
        .map_err(|_| AgentError::RequestInvalid)?;
    (decoded == value)
        .then_some(decoded)
        .ok_or(AgentError::RequestInvalid)
}

pub(crate) fn response(
    config: &VerifiedConfig,
    state: &DurableSecurityState,
    browser: &ManagementRequestV2,
    value: &CancelRecordV1,
    wire: &[u8],
    now: u64,
) -> Result<ManagementProjectionV2, AgentError> {
    let projection = decode_management_projection_strict(wire)
        .map_err(|_| AgentError::AuthorityResponseInvalid)?;
    let envelope = value
        .central_envelope
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    let trust = &config.0.management_projection_trust;
    verify_endpoint_historic_cancel_projection_at(
        &projection,
        envelope,
        &trust.current_device_ref,
        &EndpointHistoricCancelProjectionTrustV1 {
            issuer: &trust.issuer,
            audience: &trust.audience,
            key_id: &trust.key_id,
            public_key_hex: &trust.public_key_hex,
            minimum_snapshot_revision: trust.minimum_snapshot_revision,
            now_epoch_s: now,
        },
    )
    .map_err(|_| AgentError::AuthorityResponseInvalid)?;
    crate::cancel_verify_minima::projection(trust, &projection)?;
    crate::cancel_verify_minima::locator(config, state, &projection)?;
    exact_operation(browser, value, &projection)?;
    Ok(projection)
}

pub(crate) fn retired_response(
    config: &VerifiedConfig,
    envelope: &EndpointManagementEnvelopeV2,
    expected: &ManagementProjectionBodyV2,
    wire: &[u8],
    now: u64,
) -> Result<ManagementProjectionV2, AgentError> {
    let projection = decode_management_projection_strict(wire)
        .map_err(|_| AgentError::AuthorityResponseInvalid)?;
    let trust = &config.0.management_projection_trust;
    verify_endpoint_historic_cancel_projection_at(
        &projection,
        envelope,
        &trust.current_device_ref,
        &EndpointHistoricCancelProjectionTrustV1 {
            issuer: &trust.issuer,
            audience: &trust.audience,
            key_id: &trust.key_id,
            public_key_hex: &trust.public_key_hex,
            minimum_snapshot_revision: trust.minimum_snapshot_revision,
            now_epoch_s: now,
        },
    )
    .map_err(|_| AgentError::AuthorityResponseInvalid)?;
    crate::cancel_verify_minima::projection(trust, &projection)?;
    (projection.body == *expected)
        .then_some(projection)
        .ok_or(AgentError::AuthorityResponseInvalid)
}

fn exact_operation(
    browser: &ManagementRequestV2,
    value: &CancelRecordV1,
    projection: &ManagementProjectionV2,
) -> Result<(), AgentError> {
    let ManagementCommandV2::Cancel {
        operation_id,
        expected_state_revision,
    } = &browser.command
    else {
        return Err(AgentError::RequestInvalid);
    };
    let Some(lookup) = value.lookup_response.as_ref() else {
        return value
            .cleanup_completed_id
            .is_some()
            .then_some(())
            .ok_or(AgentError::AuthorityRollback);
    };
    let mut expected = lookup.operation.clone();
    expected.state = ManagementOperationState::Cancelled;
    expected.state_revision = expected_state_revision
        .checked_add(1)
        .ok_or(AgentError::AuthorityResponseInvalid)?;
    expected.actor = no_actor();
    expected.webauthn_options = None;
    expected.reason = Some(ManagementReasonCode::OperationCancelled);
    expected.reconcile_digest = None;
    let exact = operation_id == &value.operation_id
        && lookup.prepared.operation_id == *operation_id
        && lookup.operation.operation_id == *operation_id
        && lookup.operation.state_revision == *expected_state_revision
        && matches!(
            &projection.body,
            ManagementProjectionBodyV2::Operation { operation } if operation == &expected
        );
    exact
        .then_some(())
        .ok_or(AgentError::AuthorityResponseInvalid)
}

fn no_actor() -> ActorRequirementV2 {
    ActorRequirementV2 {
        role: RequiredActorRole::NoActor,
        required_actor_device_ref: None,
        required_approval_authority_ref: None,
        excluded_actor_device_refs: Vec::new(),
    }
}
