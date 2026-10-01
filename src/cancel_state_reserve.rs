use crowsi_credential_authority_contracts::{
    ManagementCommandV2, ManagementRequestV2, management_command_digest,
};
use ihat_identity_assertion_contracts::AuthorityRequestV1;

use crate::{
    AgentError,
    cancel_state_types::{CancelPhaseV1, CancelRecordV1},
    replay::DurableSecurityState,
    source_options_state,
};

pub(crate) fn load(
    state: &DurableSecurityState,
    browser: &ManagementRequestV2,
    now: u64,
) -> Result<Option<Box<CancelRecordV1>>, AgentError> {
    let digest = management_command_digest(browser).map_err(|_| AgentError::RequestInvalid)?;
    let ManagementCommandV2::Cancel { operation_id, .. } = &browser.command else {
        return Err(AgentError::RequestInvalid);
    };
    let outcome = state.transaction_namespaces(|values| {
        let (prepared, fresh, mut journal) = source_options_state::documents(values)?;
        let mut changed = crate::cancel_state_tombstone::prune(&mut journal, now);
        let outcome = if crate::cancel_state_tombstone::replayed(&journal, &browser.request_id) {
            LoadOutcome::Replay
        } else if let Some(existing) = journal.cancellation_index.get(&browser.request_id).cloned()
        {
            if crate::cancel_state_tombstone::abandon(&mut journal, &existing, now)? {
                changed = true;
                LoadOutcome::Replay
            } else {
                let value = crate::cancel_state::resume(&existing, &journal)?;
                if crate::cancel_state::exact_retry(&value, browser, &digest) {
                    LoadOutcome::Value(value)
                } else {
                    LoadOutcome::Replay
                }
            }
        } else if journal.cancellations.contains_key(operation_id) {
            if crate::cancel_state_tombstone::abandon(&mut journal, operation_id, now)? {
                changed = true;
                LoadOutcome::Absent
            } else {
                LoadOutcome::Replay
            }
        } else {
            LoadOutcome::Absent
        };
        if changed {
            source_options_state::validate(&prepared, &fresh, &journal)?;
            values.put("operation-journal", &journal)?;
        }
        Ok((outcome, changed))
    })?;
    match outcome {
        LoadOutcome::Value(value) => Ok(Some(value)),
        LoadOutcome::Absent => Ok(None),
        LoadOutcome::Replay => Err(AgentError::OperationReplay),
    }
}

enum LoadOutcome {
    Value(Box<CancelRecordV1>),
    Absent,
    Replay,
}

pub(crate) fn reserve(
    state: &DurableSecurityState,
    browser: &ManagementRequestV2,
    current: &AuthorityRequestV1,
    now: u64,
) -> Result<Box<CancelRecordV1>, AgentError> {
    let ManagementCommandV2::Cancel { operation_id, .. } = &browser.command else {
        return Err(AgentError::RequestInvalid);
    };
    crate::current_request_validation::exact(current, None)?;
    let digest = management_command_digest(browser).map_err(|_| AgentError::RequestInvalid)?;
    state.transaction_namespaces(|values| {
        let (prepared, fresh, mut journal) = source_options_state::documents(values)?;
        if crate::source_options_state_indexes::request_exists(&journal, &browser.request_id)
            || journal.cancellations.contains_key(operation_id)
        {
            return Err(AgentError::OperationReplay);
        }
        crate::cancel_state_tombstone::make_room(&mut journal, now)?;
        let mut record = CancelRecordV1 {
            operation_id: operation_id.clone(),
            browser_request: browser.clone(),
            browser_request_digest_sha256: digest,
            phase: CancelPhaseV1::CurrentPrepared,
            current_request: current.clone(),
            current_exchange: None,
            current_observed_at_epoch_s: None,
            lookup_request: None,
            lookup_response: None,
            central_envelope: None,
            response_json: None,
            response: None,
            cancelled_projection_body: None,
            revocation_begin_exchange: None,
            revocation_response_trust: None,
            pre_final_acceptance_request_sha256: None,
            execution_cancel_request: None,
            execution_cancellation: None,
            execution_cancellation_trust: None,
            cancel_finalize_request: None,
            cancellation_cleanup: None,
            cancellation_cleanup_trust: None,
            cleanup_ack_exchange: None,
            cleanup_response_trust: None,
            cleanup_complete_request: None,
            cleanup_complete_response: None,
            cleanup_complete_trust: None,
            cleanup_completed_id: None,
            future_bytes_reserved: 0,
            expires_at_epoch_s: 0,
            updated_at_epoch_s: now,
        };
        record.expires_at_epoch_s = crate::cancel_state::expiration(&record)?;
        if now >= record.expires_at_epoch_s {
            return Err(AgentError::IdentityUnavailable);
        }
        journal
            .cancellation_index
            .insert(browser.request_id.clone(), operation_id.clone());
        journal
            .cancellations
            .insert(operation_id.clone(), Box::new(record));
        source_options_state::validate(&prepared, &fresh, &journal)?;
        let result = crate::cancel_state::resume(operation_id, &journal)?;
        values.put("operation-journal", &journal)?;
        Ok((result, true))
    })
}
