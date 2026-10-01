use crowsi_credential_authority_contracts::{EndpointPreparedLookupPhaseV1, ManagementRequestV2};

use crate::{
    AgentError, VerifiedConfig, cancel_state_types::CancelRecordV1,
    identity_provider::IdentityEvidenceProvider, replay::DurableSecurityState,
};

pub(crate) fn current<I: IdentityEvidenceProvider>(
    config: &VerifiedConfig,
    state: &DurableSecurityState,
    identity: &I,
    value: Box<CancelRecordV1>,
    now: u64,
) -> Result<Box<CancelRecordV1>, AgentError> {
    let operation = &value.operation_id;
    crate::cancel_state_phase::current_invoking(state, operation, now)?;
    let response = match identity.invoke_current_identity(&config.0, &value.current_request, now) {
        Ok(response) => response,
        Err(error) => {
            crate::cancel_state_phase::current_unknown(state, operation, now)?;
            return Err(error);
        }
    };
    crate::cancel_state_phase::current_unknown(state, operation, now)?;
    crate::core_identity::verify(config, state, &response, now)?;
    crate::cancel_state_identity::current_received(state, operation, &response, now)
}

pub(crate) fn observe(
    config: &VerifiedConfig,
    state: &DurableSecurityState,
    browser: &ManagementRequestV2,
    value: Box<CancelRecordV1>,
    now: u64,
) -> Result<Box<CancelRecordV1>, AgentError> {
    let operation = &value.operation_id;
    crate::cancel_state_phase::observe_invoking(state, operation, now)?;
    let current = value
        .current_exchange
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    if let Err(error) = crate::core_identity::verify_and_observe(config, state, current, now) {
        crate::cancel_state_phase::observe_unknown(state, operation, now)?;
        return Err(error);
    }
    crate::cancel_state_phase::observe_unknown(state, operation, now)?;
    let lookup =
        crate::prepared_lookup::build(browser, EndpointPreparedLookupPhaseV1::Cancel, current)?;
    crate::cancel_state_identity::observation_complete(state, operation, &lookup, now, now)
}
