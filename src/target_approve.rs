use crowsi_credential_authority_contracts::ManagementRequestV2;

use crate::{
    AgentError, VerifiedConfig,
    identity_provider::IdentityEvidenceProvider,
    replay::DurableSecurityState,
    target_approve_native::{NativeTargetApprovalPort, TargetApprovalPort},
    target_approve_state_types::TargetApprovePhaseV1,
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
    handle_with_port(
        config,
        state,
        transport,
        identity,
        &NativeTargetApprovalPort,
        browser,
        now,
    )
}

fn handle_with_port<T: AuthorityTransport, I: IdentityEvidenceProvider, P: TargetApprovalPort>(
    config: &VerifiedConfig,
    state: &DurableSecurityState,
    transport: &T,
    identity: &I,
    port: &P,
    browser: &ManagementRequestV2,
    now: u64,
) -> Result<Vec<u8>, AgentError> {
    let mut value =
        crate::target_approve_prepare::load_or_reserve(config, state, identity, browser, now)?;
    loop {
        value = crate::target_approve_prepare::unexpired(value, now)?;
        let operation = value.approval.operation_id.clone();
        value = match value.approval.phase {
            TargetApprovePhaseV1::FinishInvoking => {
                crate::target_approve_state_identity_phase::finish_unknown(state, &operation, now)?
            }
            TargetApprovePhaseV1::FinishPrepared | TargetApprovePhaseV1::FinishUnknown => {
                crate::target_approve_identity_flow::finish(config, state, identity, value, now)?
            }
            TargetApprovePhaseV1::CurrentRequestPrepared => {
                crate::target_approve_identity_flow::prepare_current(
                    config, state, identity, value, now,
                )?
            }
            TargetApprovePhaseV1::CurrentInvoking => {
                crate::target_approve_state_identity_phase::current_unknown(state, &operation, now)?
            }
            TargetApprovePhaseV1::CurrentPrepared | TargetApprovePhaseV1::CurrentUnknown => {
                crate::target_approve_identity_flow::current(config, state, identity, value, now)?
            }
            TargetApprovePhaseV1::CurrentObserveInvoking => {
                crate::target_approve_state_identity_phase::observe_unknown(state, &operation, now)?
            }
            TargetApprovePhaseV1::CurrentObservePrepared
            | TargetApprovePhaseV1::CurrentObserveUnknown => {
                crate::target_approve_identity_flow::observe(config, state, value, now)?
            }
            TargetApprovePhaseV1::PaInvoking => {
                crate::target_approve_state_phase::pa_unknown(state, &operation, now)?
            }
            TargetApprovePhaseV1::PaPrepared | TargetApprovePhaseV1::PaUnknown => {
                crate::target_approve_native_flow::pa(config, state, port, value, now)?
            }
            TargetApprovePhaseV1::CustodyInvoking => {
                crate::target_approve_state_phase::custody_unknown(state, &operation, now)?
            }
            TargetApprovePhaseV1::CustodyPrepared | TargetApprovePhaseV1::CustodyUnknown => {
                crate::target_approve_native_flow::custody(config, state, port, value, now)?
            }
            TargetApprovePhaseV1::CentralInvoking => {
                crate::target_approve_state_phase::central_unknown(state, &operation, now)?
            }
            TargetApprovePhaseV1::CentralPrepared | TargetApprovePhaseV1::Unknown => {
                return crate::target_approve_response::invoke(
                    config, state, transport, browser, value, now,
                );
            }
            TargetApprovePhaseV1::Complete => {
                return crate::target_approve_response::completed(
                    config, state, transport, browser, &value, now,
                );
            }
        };
    }
}
