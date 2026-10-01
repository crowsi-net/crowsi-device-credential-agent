use crowsi_credential_authority_contracts::ManagementRequestV2;

use crate::{
    AgentError, VerifiedConfig, identity_provider::IdentityEvidenceProvider,
    replay::DurableSecurityState, source_approve_state_types::SourceApprovePhaseV1,
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
        crate::source_approve_prepare::load_or_reserve(config, state, identity, browser, now)?;
    loop {
        value = crate::source_approve_prepare::unexpired(value, now)?;
        let operation = value.source.prepared.operation_id.clone();
        match value.approval.phase {
            SourceApprovePhaseV1::FinishPrepared => {
                let finish = identity.invoke_finish_fresh_uv(
                    &config.0,
                    &value.approval.finish_request,
                    &browser.command,
                    now,
                )?;
                crate::source_approve_verify::finish(
                    &config.0,
                    browser,
                    &value.selected_begin,
                    &finish,
                    now,
                )?;
                let current = identity.prepare_current_identity(&config.0, now)?;
                value = crate::source_approve_state_transition::finish_complete(
                    state, &operation, &finish, &current, now,
                )?;
            }
            SourceApprovePhaseV1::CurrentInvoking => {
                value = crate::source_approve_state_phase::current_unknown(state, &operation, now)?;
            }
            SourceApprovePhaseV1::CurrentPrepared | SourceApprovePhaseV1::CurrentUnknown => {
                value = crate::source_approve_identity_flow::current(
                    config, state, identity, value, now,
                )?;
            }
            SourceApprovePhaseV1::CurrentObserveInvoking => {
                value = crate::source_approve_state_phase::observe_unknown(state, &operation, now)?;
            }
            SourceApprovePhaseV1::CurrentObservePrepared
            | SourceApprovePhaseV1::CurrentObserveUnknown => {
                value = crate::source_approve_identity_flow::observe(
                    config, state, identity, browser, value, now,
                )?;
            }
            SourceApprovePhaseV1::RevocationBeginPrepared => {
                value = crate::source_approve_revocation_flow::begin(
                    config, state, identity, browser, &value, now,
                )?;
            }
            SourceApprovePhaseV1::CentralInvoking => {
                value = crate::source_approve_state_phase::unknown(state, &operation, now)?;
            }
            SourceApprovePhaseV1::CentralPrepared | SourceApprovePhaseV1::Unknown => {
                if value.approval.revocation_final_request.is_some()
                    && value.approval.pre_final_response.is_none()
                {
                    value = crate::source_approve_pre_final_response::invoke(
                        config, state, transport, identity, browser, value, now,
                    )?;
                    continue;
                }
                return crate::source_approve_response::invoke(
                    config, state, transport, browser, value, now,
                );
            }
            phase if crate::source_approve_reserved_flow::owns(phase) => {
                return crate::source_approve_reserved_flow::handle(
                    config, state, transport, identity, browser, value, now,
                );
            }
            SourceApprovePhaseV1::Complete => {
                if value.approval.revocation_finalize_request.is_some() {
                    return crate::source_approve_finalization_response::completed(
                        config, state, transport, browser, &value, now,
                    );
                }
                return crate::source_approve_response::completed(
                    config, state, transport, browser, &value, now,
                );
            }
            _ => return Err(AgentError::AuthorityRollback),
        }
    }
}
