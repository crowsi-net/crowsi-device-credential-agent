use crowsi_credential_authority_contracts::{
    EndpointPreparedOperationV2, ManagementOperationKind, ManagementOperationScopeV2,
    ManagementRequestV2, SignedAuthorityExchangeV1, management_command_digest,
};
use ihat_identity_assertion_contracts::AuthorityRequestV1;

use crate::{
    AgentError,
    replay::DurableSecurityState,
    source_options_state::{self, SourceOptionsPhaseV1, SourceOptionsResume},
    source_options_state_types::{
        FreshUvAttemptV1, PreparedSourceOptionsV1, SourceOptionsJournalRecordV1,
    },
};

pub(crate) fn reserve(
    state: &DurableSecurityState,
    browser: &ManagementRequestV2,
    prepared_value: &EndpointPreparedOperationV2,
    expected_kind: &ManagementOperationKind,
    expected_scope: &ManagementOperationScopeV2,
    identity: &SignedAuthorityExchangeV1,
    begin: &AuthorityRequestV1,
    now: u64,
) -> Result<SourceOptionsResume, AgentError> {
    let digest = management_command_digest(browser).map_err(|_| AgentError::RequestInvalid)?;
    if digest != prepared_value.origin_command_digest_sha256 {
        return Err(AgentError::RequestInvalid);
    }
    state.transaction_namespaces(|values| {
        let (mut prepared, mut fresh, mut journal) = source_options_state::documents(values)?;
        if let Some(operation) = journal.request_index.get(&browser.request_id) {
            let value = source_options_state::resume(operation, &prepared, &fresh, &journal)?;
            if value.prepared.browser_request == *browser
                && value.prepared.browser_request_digest_sha256 == digest
            {
                return Ok((value, false));
            }
            return Err(AgentError::OperationReplay);
        }
        let operation = prepared_value.operation_id.clone();
        if prepared.records.contains_key(&operation) {
            return Err(AgentError::OperationReplay);
        }
        let prepared_record = PreparedSourceOptionsV1 {
            browser_request: browser.clone(),
            browser_request_digest_sha256: digest.clone(),
            prepared: prepared_value.clone(),
            expected_operation_kind: *expected_kind,
            expected_operation_scope: expected_scope.clone(),
            selected_identity_exchange: identity.clone(),
        };
        let fresh_record = FreshUvAttemptV1 {
            operation_id: operation.clone(),
            request: begin.clone(),
            exchange: None,
        };
        let expires_at_epoch_s =
            crate::source_options_state_validation::expiration(&prepared_record, &fresh_record)?;
        prepared.records.insert(operation.clone(), prepared_record);
        fresh.records.insert(operation.clone(), fresh_record);
        journal
            .request_index
            .insert(browser.request_id.clone(), operation.clone());
        journal.records.insert(
            operation.clone(),
            SourceOptionsJournalRecordV1 {
                operation_id: operation.clone(),
                browser_request_id: browser.request_id.clone(),
                browser_request_digest_sha256: digest,
                phase: SourceOptionsPhaseV1::BeginPrepared,
                central_envelope_json: None,
                central_envelope_digest_sha256: None,
                response_json: None,
                response: None,
                expires_at_epoch_s,
                updated_at_epoch_s: now,
            },
        );
        source_options_state::validate(&prepared, &fresh, &journal)?;
        let result = source_options_state::resume(&operation, &prepared, &fresh, &journal)?;
        values.put("prepared-operation", &prepared)?;
        values.put("fresh-uv-attempt", &fresh)?;
        values.put("operation-journal", &journal)?;
        Ok((result, true))
    })
}

pub(crate) fn load(
    state: &DurableSecurityState,
    browser: &ManagementRequestV2,
) -> Result<Option<SourceOptionsResume>, AgentError> {
    let digest = management_command_digest(browser).map_err(|_| AgentError::RequestInvalid)?;
    state.transaction_namespaces(|values| {
        let (prepared, fresh, journal) = source_options_state::documents(values)?;
        let Some(operation) = journal.request_index.get(&browser.request_id) else {
            return Ok((None, false));
        };
        let value = source_options_state::resume(operation, &prepared, &fresh, &journal)?;
        if value.prepared.browser_request != *browser
            || value.prepared.browser_request_digest_sha256 != digest
        {
            return Err(AgentError::OperationReplay);
        }
        Ok((Some(value), false))
    })
}
