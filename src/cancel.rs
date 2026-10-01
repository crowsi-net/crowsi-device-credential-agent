use crowsi_credential_authority_contracts::ManagementRequestV2;

use crate::{
    AgentError, VerifiedConfig, cancel_state_types::CancelPhaseV1,
    identity_provider::IdentityEvidenceProvider, replay::DurableSecurityState,
    transport::AuthorityTransport,
};

pub(crate) fn handle<T: AuthorityTransport, I: IdentityEvidenceProvider>(
    config: &VerifiedConfig,
    state: &DurableSecurityState,
    transport: &T,
    identity: &I,
    browser: &ManagementRequestV2,
    now: u64,
) -> Result<Vec<u8>, AgentError> {
    let mut value = crate::cancel_prepare::load_or_reserve(config, state, identity, browser, now)?;
    loop {
        value = crate::cancel_prepare::unexpired(value, now)?;
        if crate::cancel_reserved_flow::owns(value.phase) {
            return crate::cancel_reserved_flow::handle(
                config, state, transport, identity, browser, value, now,
            );
        }
        let operation = value.operation_id.clone();
        match value.phase {
            CancelPhaseV1::CurrentInvoking => {
                value = crate::cancel_state_phase::current_unknown(state, &operation, now)?;
            }
            CancelPhaseV1::CurrentPrepared | CancelPhaseV1::CurrentUnknown => {
                value = crate::cancel_identity_flow::current(config, state, identity, value, now)?;
            }
            CancelPhaseV1::CurrentObserveInvoking => {
                value = crate::cancel_state_phase::observe_unknown(state, &operation, now)?;
            }
            CancelPhaseV1::CurrentObservePrepared | CancelPhaseV1::CurrentObserveUnknown => {
                value = crate::cancel_identity_flow::observe(config, state, browser, value, now)?;
            }
            CancelPhaseV1::LookupPrepared => {
                let request = value
                    .lookup_request
                    .as_ref()
                    .ok_or(AgentError::AuthorityRollback)?;
                let lookup = crate::prepared_lookup::invoke(&config.0, transport, request, now)?;
                let current = value
                    .current_exchange
                    .as_ref()
                    .ok_or(AgentError::AuthorityRollback)?;
                let envelope = crate::cancel_verify::envelope(browser, current, &lookup.value)?;
                value = crate::cancel_state_identity::lookup_complete(
                    state, &operation, &lookup, &envelope, now,
                )?;
            }
            CancelPhaseV1::CentralInvoking => {
                value = crate::cancel_state_phase::unknown(state, &operation, now)?;
            }
            CancelPhaseV1::CentralPrepared | CancelPhaseV1::Unknown => {
                match crate::cancel_response::invoke(config, state, transport, browser, value, now)?
                {
                    crate::cancel_response::CancelInvokeOutcome::Continue(next) => value = next,
                    crate::cancel_response::CancelInvokeOutcome::Complete(wire) => return Ok(wire),
                }
            }
            CancelPhaseV1::Complete => {
                return crate::cancel_response::completed(
                    config, state, transport, browser, &value, now,
                );
            }
            _ => return Err(AgentError::AuthorityRollback),
        }
    }
}
