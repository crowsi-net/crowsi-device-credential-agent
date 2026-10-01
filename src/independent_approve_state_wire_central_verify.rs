fn pre_final_response(
    value: &IndependentApproveResume,
    request: Option<
        &crowsi_credential_authority_contracts::EndpointIndependentRevocationPreFinalRequestV1,
    >,
) -> Result<(), AgentError> {
    let Some(wire) = value.approval.pre_final_response_json.as_deref() else {
        return Ok(());
    };
    let response = decode_management_projection_strict(wire.as_bytes())
        .map_err(|_| AgentError::AuthorityRollback)?;
    let pin = value
        .approval
        .pre_final_trust
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    if value.approval.pre_final_response.as_ref() != Some(&response) {
        return Err(AgentError::AuthorityRollback);
    }
    verify_endpoint_independent_revocation_pre_final_projection_historic(
        &response,
        request.ok_or(AgentError::AuthorityRollback)?,
        &pin.peer_device_ref,
        &EndpointIndependentRevocationPreFinalProjectionHistoricTrustV1 {
            issuer: &pin.issuer,
            audience: &pin.audience,
            key_id: &pin.key_id,
            public_key_hex: &pin.public_key_hex,
            minimum_snapshot_revision: pin.minimum_snapshot_revision,
            accepted_at_epoch_s: pin.accepted_at_epoch_s,
        },
    )
    .map_err(|_| AgentError::AuthorityRollback)
}

fn reservation(
    value: &IndependentApproveResume,
    request: Option<
        &crowsi_credential_authority_contracts::EndpointRevocationExecutionReserveRequestV1,
    >,
) -> Result<(), AgentError> {
    let Some(wire) = value.approval.execution_reservation_json.as_deref() else {
        return Ok(());
    };
    let response = decode_endpoint_revocation_execution_reservation_strict(wire.as_bytes())
        .map_err(|_| AgentError::AuthorityRollback)?;
    let pin = value
        .approval
        .execution_reservation_trust
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    if value.approval.execution_reservation.as_ref() != Some(&response) {
        return Err(AgentError::AuthorityRollback);
    }
    verify_endpoint_revocation_execution_reservation_historic(
        &response,
        request.ok_or(AgentError::AuthorityRollback)?,
        &pin.peer_device_ref,
        &EndpointRevocationExecutionReservationHistoricTrustV1 {
            issuer: &pin.issuer,
            audience: &pin.audience,
            key_id: &pin.key_id,
            public_key_hex: &pin.public_key_hex,
            minimum_config_generation: pin.minimum_config_generation,
            reservation_key_id: &pin.reservation_key_id,
            reservation_public_key_hex: &pin.reservation_public_key_hex,
            minimum_reservation_config_generation: pin.minimum_reservation_config_generation,
            minimum_snapshot_revision: pin.minimum_snapshot_revision,
            accepted_at_epoch_s: pin.accepted_at_epoch_s,
        },
    )
    .map_err(|_| AgentError::AuthorityRollback)
}

include!("independent_approve_state_wire_central_final.rs");
