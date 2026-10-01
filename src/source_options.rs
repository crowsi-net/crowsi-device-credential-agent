use crowsi_credential_authority_contracts::ManagementRequestV2;

use crate::{
    AgentError, VerifiedConfig, identity_provider::IdentityEvidenceProvider,
    replay::DurableSecurityState, source_options_state::SourceOptionsPhaseV1,
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
        crate::source_options_prepare::load_or_reserve(config, state, identity, browser, now)?;
    loop {
        value = crate::source_options_prepare::unexpired(value, now)?;
        match value.journal.phase {
            SourceOptionsPhaseV1::BeginPrepared => {
                let exchange =
                    identity.invoke_begin_fresh_uv(&config.0, &value.fresh_uv.request, now)?;
                let envelope = crate::source_options_verify::envelope(
                    &config.0,
                    browser,
                    &value.prepared.selected_identity_exchange,
                    &value.prepared.prepared,
                    &exchange,
                    now,
                )?;
                value = crate::source_options_state_transition::begin_complete(
                    state,
                    &value.prepared.prepared.operation_id,
                    &exchange,
                    &envelope,
                    now,
                )?;
            }
            SourceOptionsPhaseV1::CentralInvoking => {
                value = crate::source_options_state_transition::unknown(
                    state,
                    &value.prepared.prepared.operation_id,
                    now,
                )?;
            }
            SourceOptionsPhaseV1::CentralPrepared | SourceOptionsPhaseV1::Unknown => {
                return crate::source_options_response::invoke(
                    config, state, transport, browser, value, now,
                );
            }
            SourceOptionsPhaseV1::Complete => {
                return crate::source_options_response::completed(
                    config, state, transport, browser, &value, now,
                );
            }
        }
    }
}
