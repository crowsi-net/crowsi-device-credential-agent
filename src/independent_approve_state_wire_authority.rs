use crate::{AgentError, independent_approve_state_types::IndependentApproveResume};

pub(super) fn exact(value: &IndependentApproveResume) -> Result<(), AgentError> {
    let begun = crate::independent_approve_ceremony_context::begun(value)?;
    let trust = crate::independent_approve_trust::current(&value.approval, begun)?;
    let Some(request) = value.approval.approval_request.as_ref() else {
        return Ok(());
    };
    let (key_id, public) = crate::independent_approve_ceremony_context::approval_pin(value)?;
    fingerprint(value, public)?;
    let current = crate::independent_approve_ceremony_context::current(value)?;
    crate::independent_approve_request_validation::historic(
        key_id,
        public,
        &value.lookup.response.prepared,
        begun,
        current,
        request,
    )
    .map_err(|_| AgentError::AuthorityRollback)?;
    if let Some(approval) = value.approval.approval_exchange.as_ref() {
        crate::independent_approve_response_approval::validate(
            key_id,
            public,
            &value.lookup.response.prepared,
            begun,
            current,
            approval,
        )
        .map_err(|_| AgentError::AuthorityRollback)?;
        historic_exchange(approval, "approve_revocation", &trust)?;
    }
    if let Some(final_exchange) = value.approval.final_exchange.as_ref() {
        let reserve = value
            .approval
            .execution_reserve_request
            .as_ref()
            .ok_or(AgentError::AuthorityRollback)?;
        let reservation = value
            .approval
            .execution_reservation
            .as_ref()
            .ok_or(AgentError::AuthorityRollback)?;
        let pin = value
            .approval
            .execution_reservation_trust
            .as_ref()
            .ok_or(AgentError::AuthorityRollback)?;
        let reservation_trust = crate::independent_approve_response_final::reservation_trust(pin);
        crate::independent_approve_response_final::validate_reserved(
            key_id,
            public,
            &value.lookup.response.prepared,
            begun,
            current,
            value
                .approval
                .approval_exchange
                .as_ref()
                .ok_or(AgentError::AuthorityRollback)?,
            reserve,
            reservation,
            &reservation_trust,
            &pin.peer_device_ref,
            &trust,
            final_exchange,
            value.approval.updated_at_epoch_s,
        )
        .map_err(|_| AgentError::AuthorityRollback)?;
        historic_exchange(
            final_exchange,
            final_exchange.request.command.type_name(),
            &trust,
        )?;
    }
    Ok(())
}

fn historic_exchange(
    value: &crowsi_credential_authority_contracts::SignedAuthorityExchangeV1,
    expected: &str,
    trust: &crowsi_credential_authority_contracts::EndpointAuthorityResponseTrustV2<'_>,
) -> Result<(), AgentError> {
    crowsi_credential_authority_contracts::verify_authority_exchange_historic(
        value,
        expected,
        trust.minimum_config_generation,
        trust.key_id,
        trust.public_key_hex,
    )
    .map_err(|_| AgentError::AuthorityRollback)
}

fn fingerprint(value: &IndependentApproveResume, public: &str) -> Result<(), AgentError> {
    let expected = value
        .approval
        .approval_key_fingerprint
        .as_deref()
        .ok_or(AgentError::AuthorityRollback)?;
    let bytes = hex::decode(public).map_err(|_| AgentError::AuthorityRollback)?;
    (crate::crypto::key_fingerprint(&bytes) == expected)
        .then_some(())
        .ok_or(AgentError::AuthorityRollback)
}
