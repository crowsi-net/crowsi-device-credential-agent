use crowsi_credential_authority_contracts::{
    EndpointManagementEnvelopeV2, EndpointPreparedLookupRequestV1, SignedAuthorityExchangeV1,
};

use crate::{
    AgentError,
    cancel_state_types::{CancelPhaseV1, CancelRecordV1},
    prepared_lookup::VerifiedPreparedLookup,
    replay::DurableSecurityState,
    source_options_state,
};

pub(crate) fn current_received(
    state: &DurableSecurityState,
    operation: &str,
    current: &SignedAuthorityExchangeV1,
    now: u64,
) -> Result<Box<CancelRecordV1>, AgentError> {
    state.transaction_namespaces(|values| {
        let (prepared, fresh, mut journal) = source_options_state::documents(values)?;
        let record = journal
            .cancellations
            .get_mut(operation)
            .ok_or(AgentError::AuthorityRollback)?;
        if record.phase != CancelPhaseV1::CurrentUnknown
            || current.request != record.current_request
        {
            return Err(AgentError::AuthorityResponseInvalid);
        }
        record.current_exchange = Some(current.clone());
        record.phase = CancelPhaseV1::CurrentObservePrepared;
        record.expires_at_epoch_s = crate::cancel_state::expiration(record)?;
        record.updated_at_epoch_s = now;
        source_options_state::validate(&prepared, &fresh, &journal)?;
        let result = crate::cancel_state::resume(operation, &journal)?;
        values.put("operation-journal", &journal)?;
        Ok((result, true))
    })
}

pub(crate) fn observation_complete(
    state: &DurableSecurityState,
    operation: &str,
    lookup: &EndpointPreparedLookupRequestV1,
    observed_at: u64,
    now: u64,
) -> Result<Box<CancelRecordV1>, AgentError> {
    state.transaction_namespaces(|values| {
        let (prepared, fresh, mut journal) = source_options_state::documents(values)?;
        let record = journal
            .cancellations
            .get_mut(operation)
            .ok_or(AgentError::AuthorityRollback)?;
        let current = record
            .current_exchange
            .as_ref()
            .ok_or(AgentError::AuthorityRollback)?;
        if record.phase != CancelPhaseV1::CurrentObserveUnknown
            || lookup.identity_exchange != *current
        {
            return Err(AgentError::OperationReplay);
        }
        record.current_observed_at_epoch_s = Some(observed_at);
        record.lookup_request = Some(lookup.clone());
        record.phase = CancelPhaseV1::LookupPrepared;
        record.expires_at_epoch_s = crate::cancel_state::expiration(record)?;
        record.updated_at_epoch_s = now;
        source_options_state::validate(&prepared, &fresh, &journal)?;
        let result = crate::cancel_state::resume(operation, &journal)?;
        values.put("operation-journal", &journal)?;
        Ok((result, true))
    })
}

pub(crate) fn lookup_complete(
    state: &DurableSecurityState,
    operation: &str,
    lookup: &VerifiedPreparedLookup,
    envelope: &EndpointManagementEnvelopeV2,
    now: u64,
) -> Result<Box<CancelRecordV1>, AgentError> {
    let envelope_wire = serde_json::to_vec(envelope).map_err(|_| AgentError::RequestInvalid)?;
    if envelope_wire.len() > source_options_state::MAXIMUM_PHASE_WIRE_BYTES
        || lookup.wire.len() > source_options_state::MAXIMUM_PHASE_WIRE_BYTES
    {
        return Err(AgentError::ResponseInvalid);
    }
    state.transaction_namespaces(|values| {
        let (prepared, fresh, mut journal) = source_options_state::documents(values)?;
        let context = crate::cancel_revocation_context::load(&prepared, &journal, &lookup.value)?;
        let record = journal
            .cancellations
            .get_mut(operation)
            .ok_or(AgentError::AuthorityRollback)?;
        if record.phase != CancelPhaseV1::LookupPrepared {
            let same = record.phase == CancelPhaseV1::CentralPrepared
                && record.lookup_response.as_ref() == Some(&lookup.value)
                && record.central_envelope.as_deref() == Some(envelope);
            if same {
                let result = crate::cancel_state::resume(operation, &journal)?;
                return Ok((result, false));
            }
            return Err(AgentError::OperationReplay);
        }
        let request = record
            .lookup_request
            .as_ref()
            .ok_or(AgentError::AuthorityRollback)?;
        let request_digest =
            crowsi_credential_authority_contracts::endpoint_prepared_lookup_request_digest(request)
                .map_err(|_| AgentError::AuthorityRollback)?;
        if lookup.value.request_id != request.request_id
            || lookup.value.request_digest_sha256 != request_digest
            || lookup.value.prepared.operation_id != operation
        {
            return Err(AgentError::AuthorityResponseInvalid);
        }
        record.lookup_response = Some(lookup.value.clone());
        record.central_envelope = Some(Box::new(envelope.clone()));
        if let Some(context) = context {
            record.revocation_begin_exchange = Some(context.begin);
            record.revocation_response_trust = Some(context.response_trust);
            record.pre_final_acceptance_request_sha256 = Some(context.pre_final_digest);
            crate::cancel_state_capacity::reserve(record);
        }
        record.phase = CancelPhaseV1::CentralPrepared;
        record.expires_at_epoch_s = crate::cancel_state::expiration(record)?;
        record.updated_at_epoch_s = now;
        crate::cancel_state_capacity::admit(&prepared, &fresh, &journal, now)?;
        source_options_state::validate(&prepared, &fresh, &journal)?;
        let result = crate::cancel_state::resume(operation, &journal)?;
        values.put("operation-journal", &journal)?;
        Ok((result, true))
    })
}
