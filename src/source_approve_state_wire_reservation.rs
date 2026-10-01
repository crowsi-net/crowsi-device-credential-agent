use crowsi_credential_authority_contracts::{
    ManagementProjectionBodyV2, decode_endpoint_revocation_execution_reservation_strict,
    decode_endpoint_revocation_execution_reserve_request_strict,
    endpoint_management_phase_envelope_digest,
    verify_endpoint_revocation_execution_reservation_historic,
};

use crate::{
    AgentError, source_approve_state_types::SourceApproveRecordV1,
    source_options_state_types::PreparedSourceOptionsV1,
};

pub(super) fn exact(
    value: &SourceApproveRecordV1,
    source: &PreparedSourceOptionsV1,
) -> Result<(), AgentError> {
    let Some(wire) = value.execution_reserve_request_json.as_deref() else {
        return Ok(());
    };
    let request = decode_endpoint_revocation_execution_reserve_request_strict(wire.as_bytes())
        .map_err(|_| AgentError::AuthorityRollback)?;
    let response = value
        .pre_final_response
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    let ManagementProjectionBodyV2::Operation { operation } = &response.body else {
        return Err(AgentError::AuthorityRollback);
    };
    let envelope = value
        .central_envelope
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    let exact = value.execution_reserve_request.as_ref() == Some(&request)
        && request.operation_id == value.operation_id
        && request.original_request == value.browser_request
        && request.prepared == source.prepared
        && request.expected_state_revision == operation.state_revision
        && Some(&request.reconcile_digest) == operation.reconcile_digest.as_ref()
        && request.pre_final_acceptance_request_sha256
            == endpoint_management_phase_envelope_digest(envelope)
                .map_err(|_| AgentError::AuthorityRollback)?
        && Some(&request.accepted_identity_exchange) == value.current_exchange.as_ref()
        && Some(&request.reservation_identity_exchange)
            == value.reservation_current_exchange.as_ref()
        && Some(&request.begin_exchange) == value.revocation_begin_exchange.as_ref()
        && request.approval_exchange.is_none();
    if !exact {
        return Err(AgentError::AuthorityRollback);
    }
    reservation(value, &request)
}

fn reservation(
    value: &SourceApproveRecordV1,
    request: &crowsi_credential_authority_contracts::EndpointRevocationExecutionReserveRequestV1,
) -> Result<(), AgentError> {
    let Some(wire) = value.execution_reservation_json.as_deref() else {
        return Ok(());
    };
    let response = decode_endpoint_revocation_execution_reservation_strict(wire.as_bytes())
        .map_err(|_| AgentError::AuthorityRollback)?;
    let pin = value
        .execution_reservation_trust
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    if value.execution_reservation.as_ref() != Some(&response) {
        return Err(AgentError::AuthorityRollback);
    }
    verify_endpoint_revocation_execution_reservation_historic(
        &response,
        request,
        &pin.peer_device_ref,
        &crate::source_approve_revocation_response_final::reservation_trust(pin),
    )
    .map_err(|_| AgentError::AuthorityRollback)
}
