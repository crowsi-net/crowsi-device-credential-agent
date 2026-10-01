use crate::{
    AgentError,
    source_options_state_types::{FreshUvAttemptsV1, OperationJournalV1, PreparedOperationsV1},
};

pub(crate) use crate::retired_request_retire_artifact::artifact;

pub(crate) fn operation(
    id: &str,
    prepared: &PreparedOperationsV1,
    _fresh: &FreshUvAttemptsV1,
    journal: &mut OperationJournalV1,
    now: u64,
) -> Result<(), AgentError> {
    let source = prepared.records.get(id).cloned();
    let source_record = journal.records.get(id).cloned();
    if let (Some(source), Some(record)) = (source, source_record) {
        artifact(
            journal,
            &source.browser_request,
            id,
            record.central_envelope_json.clone(),
            record.response_json.clone(),
            record.response.clone(),
            now,
        )?;
    }
    if let Some(record) = journal.source_approvals.get(id).cloned() {
        if let Some(wire) = record.revocation_finalize_request_json {
            crate::retired_request_retire_artifact::revocation_finalize(
                journal,
                &record.browser_request,
                id,
                wire,
                record.response_json,
                record.response,
                now,
            )?;
        } else {
            artifact(
                journal,
                &record.browser_request,
                id,
                record.central_envelope_json,
                record.response_json,
                record.response,
                now,
            )?;
        }
    }
    if let Some(record) = journal.actor_options.get(id).cloned() {
        artifact(
            journal,
            &record.browser_request,
            id,
            record.central_envelope_json,
            record.response_json,
            record.response,
            now,
        )?;
    }
    if let Some(record) = journal.target_approvals.get(id).cloned() {
        artifact(
            journal,
            &record.browser_request,
            id,
            record.central_envelope_json,
            record.response_json,
            record.response,
            now,
        )?;
    }
    if let Some(record) = journal.independent_approvals.get(id).cloned() {
        if let Some(wire) = record.finalize_request_json {
            crate::retired_request_retire_artifact::independent_revocation_finalize(
                journal,
                &record.browser_request,
                id,
                wire,
                record.response_json,
                record.response,
                now,
            )?;
        } else {
            artifact(
                journal,
                &record.browser_request,
                id,
                None,
                record.response_json,
                record.response,
                now,
            )?;
        }
    }
    Ok(())
}
