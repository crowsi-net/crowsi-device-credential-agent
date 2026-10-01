use crowsi_credential_authority_contracts::{
    EndpointManagementEvidenceV2, EndpointPreparedLookupPhaseV1, ManagementCommandV2,
    decode_endpoint_management_envelope_strict, decode_endpoint_prepared_lookup_response_strict,
    decode_management_projection_strict,
};
use ihat_identity_assertion_contracts::{AuthorityCommand, decode_authority_request_strict};

use crate::{
    AgentError,
    actor_options_state_types::{ActorOptionsRecordV1, ActorPreparedLookupV1},
    source_options_state_types::FreshUvAttemptV1,
};

pub(super) fn exact(
    value: &ActorOptionsRecordV1,
    prepared: Option<&ActorPreparedLookupV1>,
    fresh: Option<&FreshUvAttemptV1>,
) -> Result<(), AgentError> {
    crate::current_request_validation::exact(
        &value.current_request,
        value.current_exchange.as_ref().map(|item| &item.request),
    )?;
    lookup(value, prepared)?;
    begin(value, fresh)?;
    envelope(value, prepared, fresh)?;
    response(value)
}

fn lookup(
    value: &ActorOptionsRecordV1,
    prepared: Option<&ActorPreparedLookupV1>,
) -> Result<(), AgentError> {
    let Some(request) = &value.lookup_request else {
        return prepared
            .is_none()
            .then_some(())
            .ok_or(AgentError::AuthorityRollback);
    };
    let phase = match value.browser_request.command {
        ManagementCommandV2::TargetOptions { .. } => EndpointPreparedLookupPhaseV1::Target,
        ManagementCommandV2::ApprovalOptions { .. } => EndpointPreparedLookupPhaseV1::Approval,
        _ => return Err(AgentError::AuthorityRollback),
    };
    let exact = request.phase == phase
        && value.current_exchange.as_ref() == Some(&request.identity_exchange);
    if !exact {
        return Err(AgentError::AuthorityRollback);
    }
    let Some(prepared) = prepared else {
        return Ok(());
    };
    let decoded =
        decode_endpoint_prepared_lookup_response_strict(prepared.response_json.as_bytes())
            .map_err(|_| AgentError::AuthorityRollback)?;
    crate::actor_options_state_lookup_trust::valid(prepared)?;
    (prepared.operation_id == value.operation_id
        && prepared.request == *request
        && prepared.response == decoded
        && decoded.prepared.operation_id == value.operation_id)
        .then_some(())
        .ok_or(AgentError::AuthorityRollback)
}

fn begin(value: &ActorOptionsRecordV1, fresh: Option<&FreshUvAttemptV1>) -> Result<(), AgentError> {
    let Some(fresh) = fresh else { return Ok(()) };
    let wire = serde_json::to_vec(&fresh.request).map_err(|_| AgentError::AuthorityRollback)?;
    let decoded =
        decode_authority_request_strict(&wire).map_err(|_| AgentError::AuthorityRollback)?;
    let exact = fresh.operation_id == value.operation_id
        && decoded == fresh.request
        && fresh.request.evidence.is_empty()
        && matches!(
            fresh.request.command,
            AuthorityCommand::BeginFreshUserVerification(_)
        )
        && fresh
            .exchange
            .as_ref()
            .is_none_or(|item| item.request == fresh.request);
    exact.then_some(()).ok_or(AgentError::AuthorityRollback)
}

fn envelope(
    value: &ActorOptionsRecordV1,
    prepared: Option<&ActorPreparedLookupV1>,
    fresh: Option<&FreshUvAttemptV1>,
) -> Result<(), AgentError> {
    let Some(wire) = value.central_envelope_json.as_deref() else {
        return Ok(());
    };
    let decoded = decode_endpoint_management_envelope_strict(wire.as_bytes())
        .map_err(|_| AgentError::AuthorityRollback)?;
    let exact = value.central_envelope.as_ref() == Some(&decoded)
        && decoded.browser_request == value.browser_request
        && matches!((&decoded.evidence, prepared, fresh),
            (EndpointManagementEvidenceV2::ActorOptions { identity_exchange, prepared, uv_options },
             Some(stored), Some(begin))
            if Some(identity_exchange) == value.current_exchange.as_ref()
                && prepared == &stored.response.prepared
                && begin.exchange.as_ref() == Some(uv_options));
    exact.then_some(()).ok_or(AgentError::AuthorityRollback)
}

fn response(value: &ActorOptionsRecordV1) -> Result<(), AgentError> {
    let Some(wire) = value.response_json.as_deref() else {
        return Ok(());
    };
    let decoded = decode_management_projection_strict(wire.as_bytes())
        .map_err(|_| AgentError::AuthorityRollback)?;
    (value.response.as_ref() == Some(&decoded))
        .then_some(())
        .ok_or(AgentError::AuthorityRollback)
}
