fn finalize(
    value: &IndependentApproveResume,
    pre_final: Option<
        &crowsi_credential_authority_contracts::EndpointIndependentRevocationPreFinalRequestV1,
    >,
    reserve: Option<
        &crowsi_credential_authority_contracts::EndpointRevocationExecutionReserveRequestV1,
    >,
) -> Result<(), AgentError> {
    let Some(wire) = value.approval.finalize_request_json.as_deref() else {
        return Ok(());
    };
    let request = decode_endpoint_independent_revocation_finalize_request_strict(wire.as_bytes())
        .map_err(|_| AgentError::AuthorityRollback)?;
    if value.approval.finalize_request.as_ref() != Some(&request) {
        return Err(AgentError::AuthorityRollback);
    }
    validate_endpoint_independent_revocation_finalize_against_acceptance(
        &request,
        pre_final.ok_or(AgentError::AuthorityRollback)?,
        reserve.ok_or(AgentError::AuthorityRollback)?,
        value
            .approval
            .execution_reservation
            .as_ref()
            .ok_or(AgentError::AuthorityRollback)?,
    )
    .map_err(|_| AgentError::AuthorityRollback)
}

fn response(value: &IndependentApproveResume) -> Result<(), AgentError> {
    let Some(wire) = value.approval.response_json.as_deref() else {
        return Ok(());
    };
    let response = decode_management_projection_strict(wire.as_bytes())
        .map_err(|_| AgentError::AuthorityRollback)?;
    (value.approval.response.as_ref() == Some(&response))
        .then_some(())
        .ok_or(AgentError::AuthorityRollback)
}

fn decode_pair<T: Clone + PartialEq>(
    wire: Option<&str>,
    stored: Option<&T>,
    decode: impl FnOnce(&[u8]) -> Result<T, crowsi_credential_authority_contracts::ContractError>,
) -> Result<Option<T>, AgentError> {
    let Some(wire) = wire else {
        return Ok(None);
    };
    let decoded = decode(wire.as_bytes()).map_err(|_| AgentError::AuthorityRollback)?;
    (stored == Some(&decoded))
        .then_some(Some(decoded))
        .ok_or(AgentError::AuthorityRollback)
}
