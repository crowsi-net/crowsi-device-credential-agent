use crowsi_credential_authority_contracts::{
    ActorRequirementV2, ENDPOINT_MANAGEMENT_ENVELOPE_SCHEMA, EndpointManagementEnvelopeV2,
    EndpointManagementEvidenceV2, EndpointPreparedLookupResponseV1, ManagementCommandV2,
    ManagementOperationState, ManagementProjectionBodyV2, ManagementProjectionV2,
    ManagementRequestV2, RequiredActorRole, SignedAuthorityExchangeV1,
    decode_endpoint_management_envelope_strict,
};
use ihat_identity_assertion_contracts::{AuthorityResult, ResponseOutcome};

use crate::{AgentError, config::AgentConfigDocument};

pub(crate) fn envelope(
    config: &AgentConfigDocument,
    browser: &ManagementRequestV2,
    lookup: &EndpointPreparedLookupResponseV1,
    identity: &SignedAuthorityExchangeV1,
    begin: &SignedAuthorityExchangeV1,
    now: u64,
) -> Result<EndpointManagementEnvelopeV2, AgentError> {
    crate::actor_options_begin::validate(config, identity, &lookup.prepared, begin, now)?;
    let value = EndpointManagementEnvelopeV2 {
        schema: ENDPOINT_MANAGEMENT_ENVELOPE_SCHEMA.into(),
        browser_request: browser.clone(),
        evidence: EndpointManagementEvidenceV2::ActorOptions {
            identity_exchange: identity.clone(),
            prepared: lookup.prepared.clone(),
            uv_options: begin.clone(),
        },
    };
    let wire = serde_json::to_vec(&value).map_err(|_| AgentError::RequestInvalid)?;
    let decoded = decode_endpoint_management_envelope_strict(&wire)
        .map_err(|_| AgentError::AuthorityResponseInvalid)?;
    (decoded == value)
        .then_some(decoded)
        .ok_or(AgentError::AuthorityResponseInvalid)
}

pub(crate) fn projection(
    browser: &ManagementRequestV2,
    lookup: &EndpointPreparedLookupResponseV1,
    begin: &SignedAuthorityExchangeV1,
    value: &ManagementProjectionV2,
) -> Result<(), AgentError> {
    let ResponseOutcome::Committed {
        result: AuthorityResult::FreshUvBegun(options),
    } = &begin.response.outcome
    else {
        return Err(AgentError::AuthorityResponseInvalid);
    };
    let mut expected = lookup.operation.clone();
    expected.state_revision = expected
        .state_revision
        .checked_add(1)
        .ok_or(AgentError::AuthorityRollback)?;
    expected.webauthn_options = Some(crate::source_options_verify::webauthn(options));
    let source = lookup.prepared.source_device_ref.clone();
    match &browser.command {
        ManagementCommandV2::TargetOptions { .. } => {
            expected.state = ManagementOperationState::AwaitingTargetUv;
            expected.actor = ActorRequirementV2 {
                role: RequiredActorRole::TargetDevice,
                required_actor_device_ref: Some(lookup.actor_device_ref.clone()),
                required_approval_authority_ref: None,
                excluded_actor_device_refs: vec![source],
            };
        }
        ManagementCommandV2::ApprovalOptions { .. } => {
            let target = lookup
                .prepared
                .revocation
                .as_ref()
                .ok_or(AgentError::AuthorityResponseInvalid)?
                .target_device_ref
                .clone();
            expected.state = ManagementOperationState::AwaitingApprovalUv;
            expected.actor = ActorRequirementV2 {
                role: RequiredActorRole::IndependentApproval,
                required_actor_device_ref: Some(lookup.actor_device_ref.clone()),
                required_approval_authority_ref: None,
                excluded_actor_device_refs: vec![source, target],
            };
        }
        _ => return Err(AgentError::RequestInvalid),
    }
    let exact = matches!(&value.body, ManagementProjectionBodyV2::Operation { operation }
        if operation == &expected);
    exact
        .then_some(())
        .ok_or(AgentError::AuthorityResponseInvalid)
}
