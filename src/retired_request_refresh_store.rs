use crowsi_credential_authority_contracts::{ManagementProjectionV2, ManagementRequestV2};

use crate::{
    AgentError, VerifiedConfig, replay::DurableSecurityState,
    retired_request_types::RetiredRequestReceiptV1, source_options_state,
};

pub(super) fn store(
    config: &VerifiedConfig,
    state: &DurableSecurityState,
    browser: &ManagementRequestV2,
    expected: &RetiredRequestReceiptV1,
    wire: &[u8],
    projection: &ManagementProjectionV2,
    now: u64,
) -> Result<(), AgentError> {
    if matches!(
        expected.refresh_material.as_ref(),
        Some(crate::retired_request_types::RetiredRefreshMaterialV1::CancelEnvelope(_))
            | Some(
                crate::retired_request_types::RetiredRefreshMaterialV1::CancelCleanupComplete(_)
            )
    ) {
        return observe(config, state, browser, expected, projection, now);
    }
    let response = std::str::from_utf8(wire)
        .map_err(|_| AgentError::ResponseInvalid)?
        .to_owned();
    state.transaction_namespaces(|values| {
        let (prepared, fresh, mut journal) = source_options_state::documents(values)?;
        let value = journal
            .retired_request_receipts
            .get_mut(&browser.request_id)
            .ok_or(AgentError::OperationReplay)?;
        let exact = value.browser_request_digest_sha256 == expected.browser_request_digest_sha256
            && value.operation_id == expected.operation_id
            && value.route == expected.route
            && value.refresh_material == expected.refresh_material;
        if !exact {
            return Err(AgentError::AuthorityRollback);
        }
        value.response_json = Some(response);
        value.response = Some(projection.clone());
        value.retired_at_epoch_s = now;
        let retain = now.checked_add(600).ok_or(AgentError::AuthorityRollback)?;
        value.refresh_until_epoch_s = retain;
        value.retain_until_epoch_s = retain;
        crate::retired_request_bound::protected(&mut journal, Some(&browser.request_id))?;
        source_options_state::validate(&prepared, &fresh, &journal)?;
        crate::management_state::observe_in_transaction(values, projection)?;
        crate::identity_locator_io::observe_projection_in(values, &config.0, projection, now)?;
        values.put("operation-journal", &journal)?;
        Ok(((), true))
    })
}

fn observe(
    config: &VerifiedConfig,
    state: &DurableSecurityState,
    browser: &ManagementRequestV2,
    expected: &RetiredRequestReceiptV1,
    projection: &ManagementProjectionV2,
    now: u64,
) -> Result<(), AgentError> {
    state.transaction_namespaces(|values| {
        let (prepared, fresh, journal) = source_options_state::documents(values)?;
        let value = journal
            .retired_request_receipts
            .get(&browser.request_id)
            .ok_or(AgentError::OperationReplay)?;
        if value != expected {
            return Err(AgentError::AuthorityRollback);
        }
        source_options_state::validate(&prepared, &fresh, &journal)?;
        crate::management_state::observe_in_transaction(values, projection)?;
        crate::identity_locator_io::observe_projection_in(values, &config.0, projection, now)?;
        Ok(((), true))
    })
}
