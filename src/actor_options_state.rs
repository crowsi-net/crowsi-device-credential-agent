use ihat_identity_assertion_contracts::{AuthorityEvidence, AuthorityResult, ResponseOutcome};

use crate::{
    AgentError,
    actor_options_state_types::{ActorOptionsRecordV1, ActorOptionsResume},
    source_options_state_types::{FreshUvAttemptsV1, OperationJournalV1, PreparedOperationsV1},
};

pub(crate) fn resume(
    operation: &str,
    prepared: &PreparedOperationsV1,
    fresh: &FreshUvAttemptsV1,
    journal: &OperationJournalV1,
) -> Result<ActorOptionsResume, AgentError> {
    Ok(ActorOptionsResume {
        prepared: prepared
            .actor_records
            .get(operation)
            .cloned()
            .map(Box::new),
        fresh: fresh
            .actor_records
            .get(operation)
            .cloned()
            .map(Box::new),
        journal: journal
            .actor_options
            .get(operation)
            .cloned()
            .ok_or(AgentError::AuthorityRollback)?,
    })
}

pub(super) fn expiration(
    record: &ActorOptionsRecordV1,
    prepared: Option<&crate::actor_options_state_types::ActorPreparedLookupV1>,
    fresh: Option<&crate::source_options_state_types::FreshUvAttemptV1>,
) -> Result<u64, AgentError> {
    let [AuthorityEvidence::Signed(sender)] = record.current_request.evidence.as_slice() else {
        return Err(AgentError::AuthorityRollback);
    };
    let mut expires = sender.expires_at_epoch_s;
    if let Some(exchange) = &record.current_exchange {
        let identity =
            crowsi_credential_authority_contracts::identity_evidence_from_exchange(exchange)
                .map_err(|_| AgentError::AuthorityRollback)?;
        expires = expires
            .min(exchange.response.expires_at_epoch_s)
            .min(identity.assertion.expires_at_epoch_s)
            .min(identity.current_status.expires_at_epoch_s);
    }
    if let Some(value) = prepared {
        expires = expires
            .min(value.response.expires_at_epoch_s)
            .min(value.response.prepared.expires_at_epoch_s);
    }
    if let Some(value) = fresh.and_then(|value| value.exchange.as_ref()) {
        let ResponseOutcome::Committed {
            result: AuthorityResult::FreshUvBegun(options),
        } = &value.response.outcome
        else {
            return Err(AgentError::AuthorityRollback);
        };
        expires = expires
            .min(value.response.expires_at_epoch_s)
            .min(options.expires_at_epoch_s);
    }
    Ok(expires)
}
