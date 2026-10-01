use crowsi_credential_authority_contracts::{EndpointPreparedLookupPhaseV1, ManagementRequestV2};

use crate::{
    AgentError, VerifiedConfig, identity_provider::IdentityEvidenceProvider,
    reconcile_state_types::ReconcilePhaseV1, replay::DurableSecurityState,
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
    let mut value =
        crate::reconcile_prepare::load_or_reserve(config, state, identity, browser, now)?;
    loop {
        value = crate::reconcile_prepare::unexpired(value, now)?;
        let key = value.browser_request_digest_sha256.clone();
        value = match value.phase {
            ReconcilePhaseV1::CurrentInvoking => {
                crate::reconcile_state_phase::current_unknown(state, &key, now)?
            }
            ReconcilePhaseV1::CurrentPrepared | ReconcilePhaseV1::CurrentUnknown => {
                current(config, state, identity, value, now)?
            }
            ReconcilePhaseV1::CurrentObserveInvoking => {
                crate::reconcile_state_phase::observe_unknown(state, &key, now)?
            }
            ReconcilePhaseV1::CurrentObservePrepared | ReconcilePhaseV1::CurrentObserveUnknown => {
                observe(config, state, identity, browser, value, now)?
            }
            ReconcilePhaseV1::LookupInvoking => {
                crate::reconcile_state_phase::lookup_unknown(state, &key, now)?
            }
            ReconcilePhaseV1::LookupPrepared | ReconcilePhaseV1::LookupUnknown => {
                lookup(config, state, transport, browser, value, now)?
            }
            ReconcilePhaseV1::CentralInvoking => {
                crate::reconcile_state_phase::central_unknown(state, &key, now)?
            }
            ReconcilePhaseV1::CentralPrepared | ReconcilePhaseV1::Unknown => {
                return crate::reconcile_response::invoke(
                    config, state, transport, browser, value, now,
                );
            }
            ReconcilePhaseV1::Complete => {
                return crate::reconcile_response::completed(
                    config, state, transport, browser, &value, now,
                );
            }
        };
    }
}

fn current<I: IdentityEvidenceProvider>(
    config: &VerifiedConfig,
    state: &DurableSecurityState,
    identity: &I,
    value: crate::reconcile_state_types::ReconcileRecordV1,
    now: u64,
) -> Result<crate::reconcile_state_types::ReconcileRecordV1, AgentError> {
    let key = &value.browser_request_digest_sha256;
    crate::reconcile_state_phase::current_invoking(state, key, now)?;
    let response = match identity.invoke_current_identity(&config.0, &value.current_request, now) {
        Ok(response) => response,
        Err(error) => {
            crate::reconcile_state_phase::current_unknown(state, key, now)?;
            return Err(error);
        }
    };
    crate::reconcile_state_phase::current_unknown(state, key, now)?;
    crate::core_identity::verify(config, state, &response, now)?;
    crate::reconcile_state_identity::current_received(state, key, &response, now)
}

fn observe<I: IdentityEvidenceProvider>(
    config: &VerifiedConfig,
    state: &DurableSecurityState,
    _identity: &I,
    browser: &ManagementRequestV2,
    value: crate::reconcile_state_types::ReconcileRecordV1,
    now: u64,
) -> Result<crate::reconcile_state_types::ReconcileRecordV1, AgentError> {
    let key = &value.browser_request_digest_sha256;
    crate::reconcile_state_phase::observe_invoking(state, key, now)?;
    let current = value
        .current_exchange
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    if let Err(error) = crate::core_identity::verify_and_observe(config, state, current, now) {
        crate::reconcile_state_phase::observe_unknown(state, key, now)?;
        return Err(error);
    }
    crate::reconcile_state_phase::observe_unknown(state, key, now)?;
    let request =
        crate::prepared_lookup::build(browser, EndpointPreparedLookupPhaseV1::Reconcile, current)?;
    crate::reconcile_state_identity::observation_complete(state, key, &request, now, now)
}

fn lookup<T: AuthorityTransport>(
    config: &VerifiedConfig,
    state: &DurableSecurityState,
    transport: &T,
    browser: &ManagementRequestV2,
    value: crate::reconcile_state_types::ReconcileRecordV1,
    now: u64,
) -> Result<crate::reconcile_state_types::ReconcileRecordV1, AgentError> {
    let key = &value.browser_request_digest_sha256;
    let request = value
        .lookup_request
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    crate::reconcile_state_phase::lookup_invoking(state, key, now)?;
    let response = match crate::prepared_lookup::invoke(&config.0, transport, request, now) {
        Ok(response) => response,
        Err(error) => {
            crate::reconcile_state_phase::lookup_unknown(state, key, now)?;
            return Err(error);
        }
    };
    crate::reconcile_state_phase::lookup_unknown(state, key, now)?;
    let envelope = crate::reconcile_verify::envelope(
        browser,
        &request.identity_exchange,
        &response.value.prepared,
    )?;
    crate::reconcile_state_lookup::complete(state, key, &response, &envelope, now)
}
