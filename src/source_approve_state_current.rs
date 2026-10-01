use crowsi_credential_authority_contracts::SignedAuthorityExchangeV1;

use crate::{
    AgentError,
    replay::DurableSecurityState,
    source_approve_state_types::{SourceApprovePhaseV1, SourceApproveResume},
    source_options_state,
};

pub(crate) fn received(
    state: &DurableSecurityState,
    operation: &str,
    current: &SignedAuthorityExchangeV1,
    now: u64,
) -> Result<SourceApproveResume, AgentError> {
    state.transaction_namespaces(|values| {
        let (prepared, fresh, mut journal) = source_options_state::documents(values)?;
        let selected = fresh
            .records
            .get(operation)
            .and_then(|value| value.exchange.as_ref())
            .ok_or(AgentError::AuthorityRollback)?;
        let record = journal
            .source_approvals
            .get_mut(operation)
            .ok_or(AgentError::AuthorityRollback)?;
        if record.phase != SourceApprovePhaseV1::CurrentUnknown
            || record.current_request.as_ref() != Some(&current.request)
        {
            return Err(AgentError::AuthorityResponseInvalid);
        }
        record.current_exchange = Some(current.clone());
        record.phase = SourceApprovePhaseV1::CurrentObservePrepared;
        record.expires_at_epoch_s = crate::source_approve_state::expiration(selected, record)?;
        record.updated_at_epoch_s = now;
        if now >= record.expires_at_epoch_s {
            return Err(AgentError::FreshUserVerificationRequired);
        }
        source_options_state::validate(&prepared, &fresh, &journal)?;
        let result = crate::source_approve_state::resume(operation, &prepared, &fresh, &journal)?;
        values.put("operation-journal", &journal)?;
        Ok((result, true))
    })
}
