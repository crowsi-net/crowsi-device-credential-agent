use crowsi_credential_authority_contracts::{
    ManagementCommandV2, ManagementRequestV2, management_command_digest,
};
use ihat_identity_assertion_contracts::AuthorityRequestV1;

use crate::{
    AgentError,
    actor_options_state_types::{ActorOptionsPhaseV1, ActorOptionsRecordV1, ActorOptionsResume},
    replay::DurableSecurityState,
    source_options_state,
};

pub(crate) fn load(
    state: &DurableSecurityState,
    browser: &ManagementRequestV2,
) -> Result<Option<ActorOptionsResume>, AgentError> {
    let digest = management_command_digest(browser).map_err(|_| AgentError::RequestInvalid)?;
    state.transaction_namespaces(|values| {
        let (prepared, fresh, journal) = source_options_state::documents(values)?;
        let Some(operation) = journal.actor_options_index.get(&browser.request_id) else {
            return Ok((None, false));
        };
        let value = crate::actor_options_state::resume(operation, &prepared, &fresh, &journal)?;
        if value.journal.browser_request != *browser
            || value.journal.browser_request_digest_sha256 != digest
        {
            return Err(AgentError::OperationReplay);
        }
        Ok((Some(value), false))
    })
}

pub(crate) fn reserve(
    state: &DurableSecurityState,
    browser: &ManagementRequestV2,
    current_request: &AuthorityRequestV1,
    now: u64,
) -> Result<ActorOptionsResume, AgentError> {
    let operation = match &browser.command {
        ManagementCommandV2::TargetOptions { operation_id, .. }
        | ManagementCommandV2::ApprovalOptions { operation_id, .. } => operation_id,
        _ => return Err(AgentError::RequestInvalid),
    };
    let digest = management_command_digest(browser).map_err(|_| AgentError::RequestInvalid)?;
    state.transaction_namespaces(|values| {
        let (prepared, fresh, mut journal) = source_options_state::documents(values)?;
        if let Some(existing) = journal.actor_options_index.get(&browser.request_id) {
            let value = crate::actor_options_state::resume(existing, &prepared, &fresh, &journal)?;
            if value.journal.browser_request == *browser
                && value.journal.browser_request_digest_sha256 == digest
            {
                return Ok((value, false));
            }
            return Err(AgentError::OperationReplay);
        }
        if journal.actor_options.contains_key(operation) {
            return Err(AgentError::OperationReplay);
        }
        let mut record = ActorOptionsRecordV1 {
            operation_id: operation.clone(),
            browser_request: browser.clone(),
            browser_request_digest_sha256: digest,
            phase: ActorOptionsPhaseV1::CurrentPrepared,
            current_request: current_request.clone(),
            current_exchange: None,
            current_observed_at_epoch_s: None,
            lookup_request: None,
            central_envelope_json: None,
            central_envelope: None,
            response_json: None,
            response: None,
            expires_at_epoch_s: 0,
            updated_at_epoch_s: now,
        };
        record.expires_at_epoch_s = crate::actor_options_state::expiration(&record, None, None)?;
        if now >= record.expires_at_epoch_s {
            return Err(AgentError::IdentityUnavailable);
        }
        journal
            .actor_options_index
            .insert(browser.request_id.clone(), operation.clone());
        journal
            .actor_options
            .insert(operation.clone(), Box::new(record));
        source_options_state::validate(&prepared, &fresh, &journal)?;
        let result = crate::actor_options_state::resume(operation, &prepared, &fresh, &journal)?;
        values.put("operation-journal", &journal)?;
        Ok((result, true))
    })
}
