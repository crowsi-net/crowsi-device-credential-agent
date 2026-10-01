use crowsi_credential_authority_contracts::{
    ManagementOperationState, decode_endpoint_revocation_execution_cancel_request_strict,
    decode_endpoint_revocation_execution_cancellation_strict, verify_authority_exchange_historic,
    verify_endpoint_revocation_execution_cancellation_historic,
};

use crate::{AgentError, cancel_state_types::CancelRecordV1};

pub(super) fn exact(value: &CancelRecordV1) -> Result<(), AgentError> {
    context(value)?;
    request(value)?;
    cancellation(value)?;
    crate::cancel_state_wire_revocation_final::exact(value)
}

fn context(value: &CancelRecordV1) -> Result<(), AgentError> {
    let begin = value
        .revocation_begin_exchange
        .as_ref()
        .or_else(|| {
            value
                .execution_cancel_request
                .as_ref()
                .map(|request| &request.begin_exchange)
        })
        .or_else(|| {
            value
                .cancel_finalize_request
                .as_ref()
                .map(|request| &request.cancellation_request.begin_exchange)
        })
        .or_else(|| {
            value.cleanup_complete_request.as_ref().map(|request| {
                &request
                    .cancel_finalize_request
                    .cancellation_request
                    .begin_exchange
            })
        });
    let Some(begin) = begin else {
        return value
            .revocation_response_trust
            .is_none()
            .then_some(())
            .ok_or(AgentError::AuthorityRollback);
    };
    let pin = value
        .revocation_response_trust
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    if value.revocation_begin_exchange.is_some() {
        let lookup = value
            .lookup_response
            .as_ref()
            .ok_or(AgentError::AuthorityRollback)?;
        let digest = value
            .pre_final_acceptance_request_sha256
            .as_ref()
            .ok_or(AgentError::AuthorityRollback)?;
        let exact = lookup.operation.state == ManagementOperationState::AwaitingRevocationFinal
            && lookup.pre_final_acceptance_request_sha256.as_ref() == Some(digest);
        if !exact {
            return Err(AgentError::AuthorityRollback);
        }
        crate::source_approve_revocation_response_begin::metadata(&lookup.prepared, begin)
            .map_err(|_| AgentError::AuthorityRollback)?;
    }
    if begin.response.key_id != pin.key_id
        || begin.response.config_generation != pin.minimum_config_generation
    {
        return Err(AgentError::AuthorityRollback);
    }
    verify_authority_exchange_historic(
        begin,
        begin.request.command.type_name(),
        pin.minimum_config_generation,
        &pin.key_id,
        &pin.public_key_hex,
    )
    .map_err(|_| AgentError::AuthorityRollback)
}

fn request(value: &CancelRecordV1) -> Result<(), AgentError> {
    let Some(request) = value.execution_cancel_request.as_ref() else {
        return Ok(());
    };
    let wire = serde_json::to_vec(request).map_err(|_| AgentError::AuthorityRollback)?;
    let decoded = decode_endpoint_revocation_execution_cancel_request_strict(&wire)
        .map_err(|_| AgentError::AuthorityRollback)?;
    let exact = decoded == **request
        && value.central_envelope.as_deref() == Some(&decoded.cancel_envelope)
        && decoded.operation_id == value.operation_id;
    exact.then_some(()).ok_or(AgentError::AuthorityRollback)
}

fn cancellation(value: &CancelRecordV1) -> Result<(), AgentError> {
    let Some(cancellation) = value.execution_cancellation.as_ref() else {
        return Ok(());
    };
    let wire = serde_json::to_vec(cancellation).map_err(|_| AgentError::AuthorityRollback)?;
    let decoded = decode_endpoint_revocation_execution_cancellation_strict(&wire)
        .map_err(|_| AgentError::AuthorityRollback)?;
    let request = value
        .execution_cancel_request
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    let pin = value
        .execution_cancellation_trust
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    verify_endpoint_revocation_execution_cancellation_historic(
        &decoded,
        request,
        &pin.peer_device_ref,
        &crate::cancel_central_trust::cancellation_historic(pin),
    )
    .map_err(|_| AgentError::AuthorityRollback)?;
    (decoded == *cancellation)
        .then_some(())
        .ok_or(AgentError::AuthorityRollback)
}
