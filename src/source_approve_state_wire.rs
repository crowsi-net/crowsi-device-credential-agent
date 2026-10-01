use crate::{
    AgentError, source_approve_state_types::SourceApproveRecordV1,
    source_options_state_types::PreparedSourceOptionsV1,
};
use crowsi_credential_authority_contracts::{
    EndpointManagementEvidenceV2, decode_endpoint_management_envelope_strict,
    decode_endpoint_revocation_finalize_request_strict, decode_management_projection_strict,
};

pub(super) fn validate(
    value: &SourceApproveRecordV1,
    source: &PreparedSourceOptionsV1,
) -> Result<(), AgentError> {
    envelope(value, source)?;
    current(value)?;
    pre_final(value)?;
    crate::source_approve_state_wire_reservation::exact(value, source)?;
    finalize(value)?;
    response(value)
}

fn pre_final(value: &SourceApproveRecordV1) -> Result<(), AgentError> {
    let Some(wire) = value.pre_final_response_json.as_deref() else {
        return Ok(());
    };
    let decoded = decode_management_projection_strict(wire.as_bytes())
        .map_err(|_| AgentError::AuthorityRollback)?;
    (value.pre_final_response.as_ref() == Some(&decoded))
        .then_some(())
        .ok_or(AgentError::AuthorityRollback)
}

fn finalize(value: &SourceApproveRecordV1) -> Result<(), AgentError> {
    let Some(id) = value.revocation_finalize_request_id.as_deref() else {
        return Ok(());
    };
    if !crate::validation::id(id, 128) {
        return Err(AgentError::AuthorityRollback);
    }
    let Some(wire) = value.revocation_finalize_request_json.as_deref() else {
        return Ok(());
    };
    let decoded = decode_endpoint_revocation_finalize_request_strict(wire.as_bytes())
        .map_err(|_| AgentError::AuthorityRollback)?;
    (value.revocation_finalize_request.as_ref() == Some(&decoded)
        && decoded.request_id == id
        && decoded.source_approve_request == value.browser_request)
        .then_some(())
        .ok_or(AgentError::AuthorityRollback)
}

fn current(value: &SourceApproveRecordV1) -> Result<(), AgentError> {
    let Some(request) = &value.current_request else {
        return Ok(());
    };
    crate::current_request_validation::exact(
        request,
        value.current_exchange.as_ref().map(|value| &value.request),
    )
}

fn envelope(
    value: &SourceApproveRecordV1,
    source: &PreparedSourceOptionsV1,
) -> Result<(), AgentError> {
    let Some(wire) = value.central_envelope_json.as_deref() else {
        return Ok(());
    };
    let decoded = decode_endpoint_management_envelope_strict(wire.as_bytes())
        .map_err(|_| AgentError::AuthorityRollback)?;
    let exact = value.central_envelope.as_ref() == Some(&decoded)
        && decoded.browser_request == value.browser_request
        && matches!(&decoded.evidence, EndpointManagementEvidenceV2::SourceApprove {
            identity_exchange, prepared, finish_uv_exchange, revocation_ceremony
        } if Some(identity_exchange) == value.current_exchange.as_ref()
            && prepared == &source.prepared
            && Some(finish_uv_exchange) == value.finish_exchange.as_ref()
            && revocation_ceremony == &crate::source_approve_state_revocation::ceremony(value));
    exact.then_some(()).ok_or(AgentError::AuthorityRollback)
}

fn response(value: &SourceApproveRecordV1) -> Result<(), AgentError> {
    let Some(wire) = value.response_json.as_deref() else {
        return Ok(());
    };
    let decoded = decode_management_projection_strict(wire.as_bytes())
        .map_err(|_| AgentError::AuthorityRollback)?;
    (value.response.as_ref() == Some(&decoded))
        .then_some(())
        .ok_or(AgentError::AuthorityRollback)
}
