use crowsi_credential_authority_contracts::{ManagementProjectionV2, ManagementRequestV2};

use crate::{
    AgentError,
    retired_request_types::{
        RetiredIndependentRevocationFinalizeV1, RetiredManagementEnvelopeV1,
        RetiredRefreshMaterialV1, RetiredRequestReceiptV1, RetiredRevocationFinalizeV1,
    },
    source_options_state_types::OperationJournalV1,
};

#[allow(clippy::too_many_arguments)]
pub(crate) fn artifact(
    journal: &mut OperationJournalV1,
    browser: &ManagementRequestV2,
    operation: &str,
    envelope: Option<String>,
    response_json: Option<String>,
    response: Option<ManagementProjectionV2>,
    now: u64,
) -> Result<(), AgentError> {
    let route = crate::core::command_route(&browser.command).to_owned();
    let material = envelope.map(|wire| {
        RetiredRefreshMaterialV1::ManagementEnvelope(RetiredManagementEnvelopeV1 {
            route: route.clone(),
            wire,
        })
    });
    store(
        journal,
        browser,
        operation,
        route,
        material,
        response_json,
        response,
        now,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn independent_revocation_finalize(
    journal: &mut OperationJournalV1,
    browser: &ManagementRequestV2,
    operation: &str,
    wire: String,
    response_json: Option<String>,
    response: Option<ManagementProjectionV2>,
    now: u64,
) -> Result<(), AgentError> {
    let material = RetiredRefreshMaterialV1::IndependentRevocationFinalize(
        RetiredIndependentRevocationFinalizeV1 { wire },
    );
    store(
        journal,
        browser,
        operation,
        "independent-revocation-finalize".into(),
        Some(material),
        response_json,
        response,
        now,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn revocation_finalize(
    journal: &mut OperationJournalV1,
    browser: &ManagementRequestV2,
    operation: &str,
    wire: String,
    response_json: Option<String>,
    response: Option<ManagementProjectionV2>,
    now: u64,
) -> Result<(), AgentError> {
    let material =
        RetiredRefreshMaterialV1::RevocationFinalize(RetiredRevocationFinalizeV1 { wire });
    store(
        journal,
        browser,
        operation,
        "revocation-finalize".into(),
        Some(material),
        response_json,
        response,
        now,
    )
}

#[allow(clippy::too_many_arguments)]
fn store(
    journal: &mut OperationJournalV1,
    browser: &ManagementRequestV2,
    operation: &str,
    route: String,
    material: Option<RetiredRefreshMaterialV1>,
    response_json: Option<String>,
    response: Option<ManagementProjectionV2>,
    now: u64,
) -> Result<(), AgentError> {
    let digest = crowsi_credential_authority_contracts::management_command_digest(browser)
        .map_err(|_| AgentError::AuthorityRollback)?;
    let accepted = response_json.is_some() && response.is_some();
    let retain_until = now.checked_add(600).ok_or(AgentError::AuthorityRollback)?;
    let value = RetiredRequestReceiptV1 {
        browser_request_digest_sha256: digest,
        operation_id: operation.into(),
        route,
        refresh_material: accepted.then_some(material).flatten(),
        response_json: accepted.then_some(response_json).flatten(),
        response: accepted.then_some(response).flatten(),
        refresh_until_epoch_s: retain_until,
        retired_at_epoch_s: now,
        retain_until_epoch_s: retain_until,
    };
    if let Some(existing) = journal.retired_request_receipts.get(&browser.request_id) {
        return (existing == &value)
            .then_some(())
            .ok_or(AgentError::AuthorityRollback);
    }
    journal
        .retired_request_receipts
        .insert(browser.request_id.clone(), value);
    crate::retired_request_bound::protected(journal, Some(&browser.request_id))
}
