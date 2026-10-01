use crowsi_credential_authority_contracts::{
    ENDPOINT_MANAGEMENT_ENVELOPE_SCHEMA, EndpointManagementEnvelopeV2,
    EndpointManagementEvidenceV2, ManagementCommandV2, ManagementOperationState,
    ManagementProjectionBodyV2, ManagementProjectionV2, ManagementRequestV2,
    SignedAuthorityExchangeV1, decode_endpoint_management_envelope_strict,
};

use crate::{AgentError, reconcile_state_types::ReconcileRecordV1};

pub(crate) fn envelope(
    browser: &ManagementRequestV2,
    current: &SignedAuthorityExchangeV1,
    prepared: &crowsi_credential_authority_contracts::EndpointPreparedOperationV2,
) -> Result<EndpointManagementEnvelopeV2, AgentError> {
    strict(EndpointManagementEnvelopeV2 {
        schema: ENDPOINT_MANAGEMENT_ENVELOPE_SCHEMA.into(),
        browser_request: browser.clone(),
        evidence: EndpointManagementEvidenceV2::Reconcile {
            identity_exchange: current.clone(),
            prepared: prepared.clone(),
        },
    })
}

fn strict(value: EndpointManagementEnvelopeV2) -> Result<EndpointManagementEnvelopeV2, AgentError> {
    let wire = serde_json::to_vec(&value).map_err(|_| AgentError::RequestInvalid)?;
    let decoded = decode_endpoint_management_envelope_strict(&wire)
        .map_err(|_| AgentError::RequestInvalid)?;
    (decoded == value)
        .then_some(decoded)
        .ok_or(AgentError::RequestInvalid)
}

pub(crate) fn projection(
    browser: &ManagementRequestV2,
    value: &ReconcileRecordV1,
    projection: &ManagementProjectionV2,
) -> Result<(), AgentError> {
    let ManagementCommandV2::Reconcile {
        operation_id,
        expected_state_revision,
        reconcile_digest,
    } = &browser.command
    else {
        return Err(AgentError::RequestInvalid);
    };
    let lookup = value
        .lookup_response
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    let ManagementProjectionBodyV2::Operation { operation } = &projection.body else {
        return Err(AgentError::AuthorityResponseInvalid);
    };
    let prior = &lookup.operation;
    let immutable = operation.operation_id == prior.operation_id
        && operation.kind == prior.kind
        && operation.intent_digest_sha256 == prior.intent_digest_sha256
        && operation.created_at_epoch_s == prior.created_at_epoch_s
        && operation.expires_at_epoch_s == prior.expires_at_epoch_s
        && operation.source_device_ref == prior.source_device_ref
        && operation.scope == prior.scope;
    let revision = expected_state_revision
        .checked_add(1)
        .ok_or(AgentError::AuthorityResponseInvalid)?;
    let outcome = operation.state == ManagementOperationState::Unknown
        && operation.actor == prior.actor
        && operation.webauthn_options.is_none()
        && operation.reason
            == Some(
                crowsi_credential_authority_contracts::ManagementReasonCode::ProviderOutcomeUnknown,
            )
        && operation.reconcile_digest.as_ref() == Some(reconcile_digest);
    let exact = operation_id == &value.operation_id
        && lookup.prepared.operation_id == *operation_id
        && prior.operation_id == *operation_id
        && prior.state == ManagementOperationState::Unknown
        && prior.state_revision == *expected_state_revision
        && operation.state_revision == revision
        && immutable
        && prior.reconcile_digest.as_ref() == Some(reconcile_digest)
        && outcome;
    exact
        .then_some(())
        .ok_or(AgentError::AuthorityResponseInvalid)
}
