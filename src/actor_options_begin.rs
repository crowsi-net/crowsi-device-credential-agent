use crowsi_credential_authority_contracts::{
    EndpointPreparedOperationV2, SignedAuthorityExchangeV1, endpoint_operation_digest,
    identity_evidence_from_exchange, validate_authority_exchange,
};
use ihat_identity_assertion_contracts::{
    AuthorityCommand, AuthorityResult, ResponseOutcome, command_digest,
};

use crate::{AgentError, config::AgentConfigDocument};

pub(crate) fn validate(
    config: &AgentConfigDocument,
    selected: &SignedAuthorityExchangeV1,
    prepared: &EndpointPreparedOperationV2,
    begin: &SignedAuthorityExchangeV1,
    now: u64,
) -> Result<(), AgentError> {
    let identity = identity_evidence_from_exchange(selected)
        .map_err(|_| AgentError::AuthorityResponseInvalid)?;
    validate_authority_exchange(begin, "begin_fresh_user_verification")
        .map_err(|_| AgentError::AuthorityResponseInvalid)?;
    let (
        AuthorityCommand::BeginFreshUserVerification(command),
        ResponseOutcome::Committed {
            result: AuthorityResult::FreshUvBegun(options),
        },
    ) = (&begin.request.command, &begin.response.outcome)
    else {
        return Err(AgentError::AuthorityResponseInvalid);
    };
    let assertion = &identity.assertion;
    let epochs = &assertion.revocation_epochs;
    let issued = begin.response.issued_at_epoch_s;
    let causal = selected
        .response
        .issued_at_epoch_s
        .max(assertion.issued_at_epoch_s)
        .max(identity.current_status.issued_at_epoch_s)
        .max(prepared.issued_at_epoch_s);
    let exact = begin.request.evidence.is_empty()
        && command.credential_id == config.user_verification_credential_id
        && options.credential_id == config.user_verification_credential_id
        && command.identity_nonce == assertion.nonce
        && command.source_device_id == assertion.device_id
        && command.service_id == assertion.service_id
        && command.pairwise_subject == assertion.pairwise_subject
        && command.session_ref == assertion.session_ref
        && (
            command.subject_epoch,
            command.service_epoch,
            command.device_epoch,
            command.session_epoch,
        ) == (
            epochs.subject,
            epochs.service,
            epochs.device,
            epochs.session,
        )
        && command.operation_digest_sha256
            == endpoint_operation_digest(prepared)
                .map_err(|_| AgentError::AuthorityResponseInvalid)?
        && options.command_binding_sha256
            == command_digest(&begin.request).map_err(|_| AgentError::AuthorityResponseInvalid)?
        && begin.response.config_generation >= selected.response.config_generation
        && issued >= causal
        && issued <= now
        && now < begin.response.expires_at_epoch_s
        && begin.response.expires_at_epoch_s <= prepared.expires_at_epoch_s
        && issued < options.expires_at_epoch_s
        && now < options.expires_at_epoch_s
        && options.expires_at_epoch_s <= prepared.expires_at_epoch_s;
    exact
        .then_some(())
        .ok_or(AgentError::AuthorityResponseInvalid)
}
