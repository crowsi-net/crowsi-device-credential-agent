use crowsi_credential_authority_contracts::ManagementRequestV2;

use crate::{
    AgentError, VerifiedConfig, identity_provider::IdentityEvidenceProvider,
    independent_approve_state_types::IndependentApprovePhaseV1 as Phase,
    replay::DurableSecurityState, transport::AuthorityTransport,
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
        crate::independent_approve_prepare::load_or_reserve(config, state, identity, browser, now)?;
    loop {
        value = crate::independent_approve_prepare::unexpired(value, now)?;
        let operation = value.approval.operation_id.clone();
        value = match value.approval.phase {
            Phase::FinishInvoking => {
                crate::independent_approve_state_phase::finish_unknown(state, &operation, now)?
            }
            Phase::FinishPrepared | Phase::FinishUnknown => {
                crate::independent_approve_identity_flow::finish(
                    config, state, identity, value, now,
                )?
            }
            Phase::CurrentRequestPrepared => {
                crate::independent_approve_identity_flow::prepare_current(
                    config, state, identity, value, now,
                )?
            }
            Phase::CurrentInvoking => {
                crate::independent_approve_state_phase::current_unknown(state, &operation, now)?
            }
            Phase::CurrentPrepared | Phase::CurrentUnknown => {
                crate::independent_approve_identity_flow::current(
                    config, state, identity, value, now,
                )?
            }
            Phase::CurrentObserveInvoking => {
                crate::independent_approve_state_phase::observe_unknown(state, &operation, now)?
            }
            Phase::CurrentObservePrepared | Phase::CurrentObserveUnknown => {
                crate::independent_approve_identity_flow::observe(
                    config, state, identity, value, now,
                )?
            }
            Phase::ApprovalInvoking => {
                crate::independent_approve_state_phase::approval_unknown(state, &operation, now)?
            }
            Phase::ApprovalPrepared | Phase::ApprovalUnknown => {
                crate::independent_approve_ceremony_flow::approval(state, identity, value, now)?
            }
            Phase::ApprovalAccepted => {
                crate::independent_approve_pre_final_flow::prepare(state, value, now)?
            }
            Phase::PreFinalInvoking => {
                crate::independent_approve_state_phase::pre_final_unknown(state, &operation, now)?
            }
            Phase::PreFinalPrepared | Phase::PreFinalUnknown => {
                crate::independent_approve_pre_final_flow::invoke(
                    config, state, transport, value, now,
                )?
            }
            Phase::PreFinalAccepted
            | Phase::ReservationCurrentPrepared
            | Phase::ReservationCurrentInvoking
            | Phase::ReservationCurrentUnknown
            | Phase::ReservationCurrentObservePrepared
            | Phase::ReservationCurrentObserveInvoking
            | Phase::ReservationCurrentObserveUnknown
            | Phase::ExecutionReservePrepared
            | Phase::ExecutionReserveInvoking
            | Phase::ExecutionReserveUnknown
            | Phase::FinalPrepared
            | Phase::FinalInvoking
            | Phase::FinalUnknown
            | Phase::FinalAccepted
            | Phase::FinalizePrepared
            | Phase::FinalizeInvoking
            | Phase::FinalizeUnknown
            | Phase::Complete => {
                return crate::independent_approve_reserved_flow::handle(
                    config, state, transport, identity, browser, value, now,
                );
            }
        };
    }
}
