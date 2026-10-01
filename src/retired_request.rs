use crowsi_credential_authority_contracts::{ManagementRequestV2, management_command_digest};

use crate::{
    AgentError, VerifiedConfig, replay::DurableSecurityState,
    retired_request_types::RetiredRequestReceiptV1, source_options_state,
    transport::AuthorityTransport,
};

pub(crate) fn handle<T: AuthorityTransport>(
    config: &VerifiedConfig,
    state: &DurableSecurityState,
    transport: &T,
    browser: &ManagementRequestV2,
    now: u64,
) -> Option<Result<Vec<u8>, AgentError>> {
    match load(state, browser, now) {
        Ok(Some(value)) => Some(crate::retired_request_refresh::response(
            config, state, transport, browser, value, now,
        )),
        Ok(None) => None,
        Err(error) => Some(Err(error)),
    }
}

fn load(
    state: &DurableSecurityState,
    browser: &ManagementRequestV2,
    now: u64,
) -> Result<Option<RetiredRequestReceiptV1>, AgentError> {
    let digest = management_command_digest(browser).map_err(|_| AgentError::RequestInvalid)?;
    let outcome = state.transaction_namespaces(|values| {
        let (prepared, fresh, mut journal) = source_options_state::documents(values)?;
        let changed = prune(&mut journal, now);
        let outcome = match journal.retired_request_receipts.get(&browser.request_id) {
            Some(value) if value.browser_request_digest_sha256 == digest => {
                Load::Value(value.clone())
            }
            Some(_) => Load::Replay,
            None => Load::Absent,
        };
        if changed {
            source_options_state::validate(&prepared, &fresh, &journal)?;
            values.put("operation-journal", &journal)?;
        }
        Ok((outcome, changed))
    })?;
    match outcome {
        Load::Value(value) => Ok(Some(value)),
        Load::Absent => Ok(None),
        Load::Replay => Err(AgentError::OperationReplay),
    }
}

pub(super) fn prune(
    journal: &mut crate::source_options_state_types::OperationJournalV1,
    now: u64,
) -> bool {
    let before = journal.retired_request_receipts.len();
    journal
        .retired_request_receipts
        .retain(|_, value| now < value.retain_until_epoch_s);
    before != journal.retired_request_receipts.len()
}

enum Load {
    Value(RetiredRequestReceiptV1),
    Absent,
    Replay,
}
