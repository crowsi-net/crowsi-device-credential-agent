use crowsi_credential_authority_contracts::{
    ManagementRequestV2, RevocationSourceCeremonyV1, SignedAuthorityExchangeV1,
    fresh_uv_from_finish_exchange,
};

use crate::{
    AgentError, VerifiedConfig, identity_provider::IdentityEvidenceProvider,
    replay::DurableSecurityState, source_approve_state_types::SourceApproveResume,
};

pub(crate) fn after_current<I: IdentityEvidenceProvider>(
    config: &VerifiedConfig,
    state: &DurableSecurityState,
    identity: &I,
    browser: &ManagementRequestV2,
    value: &SourceApproveResume,
    current: &SignedAuthorityExchangeV1,
    now: u64,
) -> Result<SourceApproveResume, AgentError> {
    let finish = value
        .approval
        .finish_exchange
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    let fresh = fresh_uv_from_finish_exchange(finish, &browser.command)
        .map_err(|_| AgentError::AuthorityResponseInvalid)?;
    let request = identity.prepare_source_revocation_begin(&value.source.prepared, fresh, now)?;
    crate::source_approve_revocation_request::validate_begin(
        &value.source.prepared,
        fresh,
        &request,
        now,
    )?;
    let _ = config;
    crate::source_approve_state_revocation_transition_begin::current_ready(
        state,
        &value.source.prepared.operation_id,
        current,
        &request,
        now,
    )
}

pub(crate) fn begin<I: IdentityEvidenceProvider>(
    config: &VerifiedConfig,
    state: &DurableSecurityState,
    identity: &I,
    browser: &ManagementRequestV2,
    value: &SourceApproveResume,
    now: u64,
) -> Result<SourceApproveResume, AgentError> {
    let prepared = &value.source.prepared;
    let finish = value
        .approval
        .finish_exchange
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    let fresh = fresh_uv_from_finish_exchange(finish, &browser.command)
        .map_err(|_| AgentError::AuthorityResponseInvalid)?;
    let request = value
        .approval
        .revocation_begin_request
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    let begun =
        identity.invoke_source_revocation_begin(&config.0, prepared, fresh, request, now)?;
    let final_request = identity.prepare_source_revocation_final(prepared, &begun)?;
    let envelope = envelope(config, browser, value, &begun, now)?;
    crate::source_approve_state_revocation_transition_begin::begun_ready(
        state,
        &prepared.operation_id,
        &begun,
        &crate::source_approve_revocation_invoke::trust(&config.0),
        final_request.as_ref(),
        &envelope,
        now,
    )
}

fn envelope(
    config: &VerifiedConfig,
    browser: &ManagementRequestV2,
    value: &SourceApproveResume,
    begun: &SignedAuthorityExchangeV1,
    now: u64,
) -> Result<crowsi_credential_authority_contracts::EndpointManagementEnvelopeV2, AgentError> {
    let finish = value
        .approval
        .finish_exchange
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    let current = value
        .approval
        .current_exchange
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    crate::source_approve_verify::envelope(
        &config.0,
        browser,
        &value.source.prepared,
        crate::source_approve_verify::Evidence {
            selected_identity: &value.source.selected_identity_exchange,
            selected_begin: &value.selected_begin,
            finish,
            current_identity: current,
            revocation: Some(RevocationSourceCeremonyV1 {
                begin: begun.clone(),
                final_revoke: None,
            }),
        },
        now,
    )
}
