use crowsi_credential_authority_contracts::{
    EndpointPreparedLookupRequestV1, SignedAuthorityExchangeV1,
};

use crate::{
    AgentError,
    reconcile_state_types::{ReconcilePhaseV1, ReconcileRecordV1},
    replay::DurableSecurityState,
    source_options_state,
};

pub(crate) fn current_received(
    state: &DurableSecurityState,
    key: &str,
    current: &SignedAuthorityExchangeV1,
    now: u64,
) -> Result<ReconcileRecordV1, AgentError> {
    update(state, key, now, |record| {
        if record.phase != ReconcilePhaseV1::CurrentUnknown
            || current.request != record.current_request
        {
            return Err(AgentError::AuthorityResponseInvalid);
        }
        record.current_exchange = Some(current.clone());
        record.phase = ReconcilePhaseV1::CurrentObservePrepared;
        Ok(())
    })
}

pub(crate) fn observation_complete(
    state: &DurableSecurityState,
    key: &str,
    lookup: &EndpointPreparedLookupRequestV1,
    observed_at: u64,
    now: u64,
) -> Result<ReconcileRecordV1, AgentError> {
    update(state, key, now, |record| {
        let current = record
            .current_exchange
            .as_ref()
            .ok_or(AgentError::AuthorityRollback)?;
        if record.phase != ReconcilePhaseV1::CurrentObserveUnknown
            || lookup.identity_exchange != *current
        {
            return Err(AgentError::OperationReplay);
        }
        record.current_observed_at_epoch_s = Some(observed_at);
        record.lookup_request = Some(lookup.clone());
        record.phase = ReconcilePhaseV1::LookupPrepared;
        Ok(())
    })
}

fn update(
    state: &DurableSecurityState,
    key: &str,
    now: u64,
    change: impl FnOnce(&mut ReconcileRecordV1) -> Result<(), AgentError>,
) -> Result<ReconcileRecordV1, AgentError> {
    state.transaction_namespaces(|values| {
        let (prepared, fresh, mut journal) = source_options_state::documents(values)?;
        let record = journal
            .reconciliations
            .get_mut(key)
            .ok_or(AgentError::AuthorityRollback)?;
        if now < record.updated_at_epoch_s {
            return Err(AgentError::AuthorityRollback);
        }
        change(record)?;
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
