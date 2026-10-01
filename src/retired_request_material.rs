use crate::{
    AgentError, retired_request_types::RetiredRefreshMaterialV1,
    source_options_state_types::OperationJournalV1,
};

pub(super) fn bytes(journal: &OperationJournalV1) -> Result<usize, AgentError> {
    journal
        .retired_request_receipts
        .values()
        .try_fold(0usize, |total, value| {
            let refresh = value
                .refresh_material
                .as_ref()
                .filter(|material| {
                    !matches!(
                        material,
                        RetiredRefreshMaterialV1::CancelEnvelope(_)
                            | RetiredRefreshMaterialV1::CancelCleanupComplete(_)
                    )
                })
                .map(serde_json::to_vec)
                .transpose()
                .map_err(|_| AgentError::AuthorityRollback)?
                .map_or(0, |wire| wire.len());
            let projection = value
                .response
                .as_ref()
                .map(serde_json::to_vec)
                .transpose()
                .map_err(|_| AgentError::AuthorityRollback)?
                .map_or(0, |wire| wire.len());
            total
                .checked_add(refresh)
                .and_then(|size| {
                    size.checked_add(value.response_json.as_ref().map_or(0, String::len))
                })
                .and_then(|size| size.checked_add(projection))
                .ok_or(AgentError::AuthorityRollback)
        })
}
