use crowsi_credential_authority_contracts::{
    EndpointPreparedOperationV2, SignedAuthorityExchangeV1,
    attach_revocation_execution_reservation, endpoint_management_phase_envelope_digest,
    validate_endpoint_revocation_finalize_against_acceptance,
    verify_endpoint_revocation_execution_reservation_historic,
};

use crate::{AgentError, source_approve_state_types::SourceApproveRecordV1};

pub(crate) fn validate(
    value: &SourceApproveRecordV1,
    prepared: &EndpointPreparedOperationV2,
    begun: &SignedAuthorityExchangeV1,
) -> Result<(), AgentError> {
    let independent = crate::source_approve_revocation_binding::independent(prepared)?;
    let Some(request) = value.revocation_final_request.as_ref() else {
        return (independent && value.revocation_final_exchange.is_none())
            .then_some(())
            .ok_or(AgentError::AuthorityRollback);
    };
    if independent {
        return Err(AgentError::AuthorityRollback);
    }
    request_exact(value, prepared, begun, request)?;
    let Some(exchange) = value.revocation_final_exchange.as_ref() else {
        return Ok(());
    };
    exact_request(request, exchange)?;
    response(value, prepared, begun, exchange)?;
    if let Some(finalize) = &value.revocation_finalize_request {
        let reserve = value
            .execution_reserve_request
            .as_ref()
            .ok_or(AgentError::AuthorityRollback)?;
        let reservation = value
            .execution_reservation
            .as_ref()
            .ok_or(AgentError::AuthorityRollback)?;
        (finalize.final_revoke_exchange == *exchange)
            .then_some(())
            .ok_or(AgentError::AuthorityRollback)?;
        let envelope = value
            .central_envelope
            .as_ref()
            .ok_or(AgentError::AuthorityRollback)?;
        let pre_final_digest = endpoint_management_phase_envelope_digest(envelope)
            .map_err(|_| AgentError::AuthorityRollback)?;
        validate_endpoint_revocation_finalize_against_acceptance(
            finalize,
            &pre_final_digest,
            begun,
            reserve,
            reservation,
        )
        .map_err(|_| AgentError::AuthorityRollback)?;
    }
    Ok(())
}

fn request_exact(
    value: &SourceApproveRecordV1,
    prepared: &EndpointPreparedOperationV2,
    begun: &SignedAuthorityExchangeV1,
    request: &ihat_identity_assertion_contracts::AuthorityRequestV1,
) -> Result<(), AgentError> {
    let Some(reserve) = value.execution_reserve_request.as_ref() else {
        return crate::source_approve_revocation_final_request::validate(prepared, begun, request);
    };
    if value.execution_reservation.is_none() {
        let exact = value.execution_reservation_trust.is_none()
            && reserve.final_revoke_request == *request;
        exact
            .then_some(())
            .ok_or(AgentError::AuthorityRollback)?;
        return crate::source_approve_revocation_final_request::validate(
            prepared,
            begun,
            request,
        );
    }
    let reservation = value
        .execution_reservation
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    let pin = value
        .execution_reservation_trust
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    let trust = crate::source_approve_revocation_response_final::reservation_trust(pin);
    verify_endpoint_revocation_execution_reservation_historic(
        reservation,
        reserve,
        &pin.peer_device_ref,
        &trust,
    )
    .map_err(|_| AgentError::AuthorityRollback)?;
    crate::source_approve_revocation_final_request::validate(
        prepared,
        begun,
        &reserve.final_revoke_request,
    )?;
    let attached =
        attach_revocation_execution_reservation(&reserve.final_revoke_request, reservation)
            .map_err(|_| AgentError::AuthorityRollback)?;
    (attached == *request)
        .then_some(())
        .ok_or(AgentError::AuthorityRollback)
}

fn response(
    value: &SourceApproveRecordV1,
    prepared: &EndpointPreparedOperationV2,
    begun: &SignedAuthorityExchangeV1,
    exchange: &SignedAuthorityExchangeV1,
) -> Result<(), AgentError> {
    let reserve = value
        .execution_reserve_request
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    let reservation = value
        .execution_reservation
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    let pin = value
        .execution_reservation_trust
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    let reservation_trust = crate::source_approve_revocation_response_final::reservation_trust(pin);
    let response_trust = crate::source_approve_state_revocation_trust::trust(value)?;
    crate::source_approve_revocation_response_final::validate_reserved(
        prepared,
        begun,
        reserve,
        reservation,
        &reservation_trust,
        &pin.peer_device_ref,
        &response_trust,
        exchange,
        value.updated_at_epoch_s,
    )
    .map_err(|_| AgentError::AuthorityRollback)
}

pub(crate) fn exact_request(
    request: &ihat_identity_assertion_contracts::AuthorityRequestV1,
    exchange: &SignedAuthorityExchangeV1,
) -> Result<(), AgentError> {
    (exchange.request == *request)
        .then_some(())
        .ok_or(AgentError::AuthorityRollback)
}
