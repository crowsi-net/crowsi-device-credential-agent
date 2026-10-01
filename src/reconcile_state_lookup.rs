use crowsi_credential_authority_contracts::{
    EndpointManagementEnvelopeV2, endpoint_prepared_lookup_request_digest,
};

use crate::{
    AgentError,
    prepared_lookup::VerifiedPreparedLookup,
    reconcile_state_types::{ReconcilePhaseV1, ReconcileRecordV1},
    replay::DurableSecurityState,
    source_options_state,
};

pub(crate) fn complete(
    state: &DurableSecurityState,
    key: &str,
    lookup: &VerifiedPreparedLookup,
    envelope: &EndpointManagementEnvelopeV2,
    now: u64,
) -> Result<ReconcileRecordV1, AgentError> {
    let envelope_wire = serde_json::to_string(envelope).map_err(|_| AgentError::RequestInvalid)?;
    if envelope_wire.len() > source_options_state::MAXIMUM_PHASE_WIRE_BYTES
        || lookup.wire.len() > source_options_state::MAXIMUM_PHASE_WIRE_BYTES
    {
        return Err(AgentError::ResponseInvalid);
    }
    state.transaction_namespaces(|values| {
        let (prepared, fresh, mut journal) = source_options_state::documents(values)?;
        let record = journal
            .reconciliations
            .get_mut(key)
            .ok_or(AgentError::AuthorityRollback)?;
        if record.phase != ReconcilePhaseV1::LookupUnknown {
            return Err(AgentError::OperationReplay);
        }
        let request = record
            .lookup_request
            .as_ref()
            .ok_or(AgentError::AuthorityRollback)?;
        let digest = endpoint_prepared_lookup_request_digest(request)
            .map_err(|_| AgentError::AuthorityRollback)?;
        let exact = lookup.value.request_id == request.request_id
            && lookup.value.request_digest_sha256 == digest
            && lookup.value.prepared.operation_id == record.operation_id
            && envelope.browser_request == record.browser_request;
        if !exact {
            return Err(AgentError::AuthorityResponseInvalid);
        }
        record.lookup_response_json = Some(lookup.wire.clone());
        record.lookup_response = Some(lookup.value.clone());
        record.central_envelope_json = Some(envelope_wire);
        record.central_envelope = Some(envelope.clone());
        record.phase = ReconcilePhaseV1::CentralPrepared;
        record.expires_at_epoch_s = crate::reconcile_state::expiration(record)?;
        record.updated_at_epoch_s = now;
        if now >= record.expires_at_epoch_s {
            return Err(AgentError::IdentityUnavailable);
        }
        source_options_state::validate(&prepared, &fresh, &journal)?;
        let result = crate::reconcile_state::resume(key, &journal)?;
        values.put("operation-journal", &journal)?;
        Ok((result, true))
    })
}
