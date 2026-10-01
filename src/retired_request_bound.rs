use crate::{AgentError, source_options_state_types::OperationJournalV1};

pub(crate) fn protected(
    journal: &mut OperationJournalV1,
    protected: Option<&str>,
) -> Result<(), AgentError> {
    while journal.retired_request_receipts.len() > 32 {
        remove_oldest(journal, false, protected)?;
    }
    while crate::retired_request_material::bytes(journal)? > 32_768 {
        let request = oldest(journal, true, None).ok_or(AgentError::AuthorityRollback)?;
        let value = journal
            .retired_request_receipts
            .get_mut(&request)
            .ok_or(AgentError::AuthorityRollback)?;
        value.refresh_material = None;
        value.response_json = None;
        value.response = None;
    }
    while !crate::cancel_state_capacity::within(journal) {
        remove_oldest(journal, false, protected)?;
    }
    Ok(())
}

fn remove_oldest(
    journal: &mut OperationJournalV1,
    material_only: bool,
    protected: Option<&str>,
) -> Result<(), AgentError> {
    let request =
        oldest(journal, material_only, protected).ok_or(AgentError::AuthorityUnavailable)?;
    journal.retired_request_receipts.remove(&request);
    Ok(())
}

fn oldest(
    journal: &OperationJournalV1,
    material_only: bool,
    protected: Option<&str>,
) -> Option<String> {
    journal
        .retired_request_receipts
        .iter()
        .filter(|(request, value)| {
            protected != Some(request.as_str())
                && (!material_only || value.refresh_material.is_some())
        })
        .min_by_key(|(request, value)| (value.retired_at_epoch_s, (*request).clone()))
        .map(|(request, _)| request.clone())
}
